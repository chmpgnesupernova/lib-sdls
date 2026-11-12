"""TM_SDLP_myExtractPacket tests.

Frames come from SatTmFramer, a port of the satellite side TM_SDLP_myForwardPacket, and the
ground side must return exactly the packets the satellite forwarded.
"""

import ctypes
import random
import unittest

import sdls_binding as b
from sat_reference import SatTmFramer, make_spp


def data_of(total_packet_size, fill=0x5A):
    """Data bytes for a packet whose total size (header + data) is total_packet_size."""
    return bytes([fill]) * (total_packet_size - 6)


class TmExtractPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdls = b.Sdls()

    def extract_raw(self, frame, cursor_value=0, frame_size=None):
        cursor = ctypes.c_size_t(cursor_value)
        offset = ctypes.c_size_t(0)
        size = len(frame) if frame_size is None else frame_size
        status = self.sdls.lib.TM_SDLP_myExtractPacket(frame, size, ctypes.byref(cursor), ctypes.byref(offset))
        return status, cursor.value, offset.value

    @staticmethod
    def frames_for(packets):
        framer = SatTmFramer()
        for packet in packets:
            framer.forward_packet(packet)
        framer.send_frame()
        return framer.sent

    # --- satellite interoperability ---------------------------------------------------

    def test_single_packet_frame(self):
        packet = make_spp(0x100, b"\x01\x02\x03\x04")
        (frame,) = self.frames_for([packet])
        self.assertEqual(len(frame), b.TM_FRAME_SIZE)
        self.assertEqual(self.sdls.tm_extract_packets(frame), [packet])

    def test_several_packets_in_one_frame(self):
        packets = [make_spp(0x100 + i, bytes([i]) * (10 + i)) for i in range(5)]
        (frame,) = self.frames_for(packets)
        self.assertEqual(self.sdls.tm_extract_packets(frame), packets)

    def test_packet_filling_data_field_exactly(self):
        packet = make_spp(0x101, data_of(b.TM_DATA_LENGTH))
        (frame,) = self.frames_for([packet])
        self.assertEqual(self.sdls.tm_extract_packets(frame), [packet])

    def test_packet_leaving_minimum_idle_packet(self):
        packet = make_spp(0x102, data_of(b.TM_DATA_LENGTH - b.TM_IDLE_MIN_LENGTH))
        (frame,) = self.frames_for([packet])
        self.assertEqual(self.sdls.tm_extract_packets(frame), [packet])

    def test_random_stream_round_trip(self):
        rng = random.Random(20261112)
        sizes = [7, 8, 50, 300, 1000, b.TM_DATA_LENGTH - b.TM_IDLE_MIN_LENGTH, b.TM_DATA_LENGTH]
        packets = [
            make_spp(rng.randrange(0x7FF), bytes(rng.randrange(256) for _ in range(rng.choice(sizes) - 6)))
            for _ in range(300)
        ]
        frames = self.frames_for(packets)
        self.assertGreater(len(frames), 1)

        extracted = []
        for frame in frames:
            extracted.extend(self.sdls.tm_extract_packets(frame))
        self.assertEqual(extracted, packets)

    def test_cursor_and_offset_progression(self):
        packets = [make_spp(0x110, b"\xAA" * 9), make_spp(0x111, b"\xBB" * 19)]
        (frame,) = self.frames_for(packets)

        status, cursor, offset = self.extract_raw(frame)
        self.assertEqual((status, offset, cursor), (len(packets[0]), b.TM_DATA_OFFSET, b.TM_DATA_OFFSET + 15))

        status, cursor, offset = self.extract_raw(frame, cursor)
        self.assertEqual((status, offset, cursor), (len(packets[1]), b.TM_DATA_OFFSET + 15, b.TM_DATA_OFFSET + 40))

        # The idle packet ends the frame and moves the cursor to the data field end.
        status, cursor, _ = self.extract_raw(frame, cursor)
        self.assertEqual((status, cursor), (0, b.TM_DATA_END))

        # Calling again after the end keeps returning 0.
        status, cursor, _ = self.extract_raw(frame, cursor)
        self.assertEqual((status, cursor), (0, b.TM_DATA_END))

    def test_channel_ids_are_not_checked(self):
        """Mirrors the satellite side: one channel, so TFVN/SCID/VCID are not checked."""
        framer = SatTmFramer(scid=0x2AB, vcid=6)
        packet = make_spp(0x120, b"\x01")
        framer.forward_packet(packet)
        framer.send_frame()
        self.assertEqual(self.sdls.tm_extract_packets(framer.sent[0]), [packet])

    def test_security_header_area_is_skipped(self):
        packet = make_spp(0x121, b"\x01\x02")
        frame = bytearray(self.frames_for([packet])[0])
        frame[b.TMTF_PRIHDR_LENGTH : b.TM_DATA_OFFSET] = b"\xFF" * b.TM_SDLS_HDR_LENGTH
        self.assertEqual(self.sdls.tm_extract_packets(bytes(frame)), [packet])

    # --- error codes -----------------------------------------------------------------

    def test_wrong_frame_size_is_invalid_length(self):
        (frame,) = self.frames_for([make_spp(0x130, b"\x00")])
        self.assertEqual(self.extract_raw(frame[:-1])[0], b.TM_INVALID_LENGTH)
        self.assertEqual(self.extract_raw(frame + b"\x00")[0], b.TM_INVALID_LENGTH)
        # Also checked when the cursor is past the first packet.
        self.assertEqual(self.extract_raw(frame, cursor_value=b.TM_DATA_OFFSET, frame_size=100)[0], b.TM_INVALID_LENGTH)

    def test_segment_length_id_other_than_packet_is_invalid_header(self):
        frame = bytearray(self.frames_for([make_spp(0x131, b"\x00")])[0])
        frame[4] &= 0xE7  # Segment Length ID = 0
        self.assertEqual(self.extract_raw(bytes(frame))[0], b.TM_INVALID_HEADER)

    def test_nonzero_first_header_pointer_is_invalid_header(self):
        frame = bytearray(self.frames_for([make_spp(0x132, b"\x00")])[0])
        frame[5] = 0x01
        self.assertEqual(self.extract_raw(bytes(frame))[0], b.TM_INVALID_HEADER)

    def test_packet_longer_than_data_field_is_invalid_packet(self):
        frame = bytearray(self.frames_for([make_spp(0x133, b"\x00")])[0])
        frame[b.TM_DATA_OFFSET + 4] = 0xFF  # length field far beyond the frame
        frame[b.TM_DATA_OFFSET + 5] = 0xFF
        self.assertEqual(self.extract_raw(bytes(frame))[0], b.TM_INVALID_PACKET)

    def test_remainder_shorter_than_one_packet_is_invalid_packet(self):
        (frame,) = self.frames_for([make_spp(0x134, b"\x00")])
        self.assertEqual(self.extract_raw(frame, cursor_value=b.TM_DATA_END - 6)[0], b.TM_INVALID_PACKET)

    def test_cursor_out_of_range_is_invalid_argument(self):
        (frame,) = self.frames_for([make_spp(0x135, b"\x00")])
        self.assertEqual(self.extract_raw(frame, cursor_value=b.TM_DATA_OFFSET - 1)[0], b.TM_INVALID_ARGUMENT)
        self.assertEqual(self.extract_raw(frame, cursor_value=b.TM_DATA_END + 1)[0], b.TM_INVALID_ARGUMENT)

    def test_null_pointers_are_invalid_argument(self):
        (frame,) = self.frames_for([make_spp(0x136, b"\x00")])
        cursor = ctypes.c_size_t(0)
        offset = ctypes.c_size_t(0)
        f = self.sdls.lib.TM_SDLP_myExtractPacket
        self.assertEqual(f(None, len(frame), ctypes.byref(cursor), ctypes.byref(offset)), b.TM_INVALID_ARGUMENT)
        self.assertEqual(f(frame, len(frame), None, ctypes.byref(offset)), b.TM_INVALID_ARGUMENT)
        self.assertEqual(f(frame, len(frame), ctypes.byref(cursor), None), b.TM_INVALID_ARGUMENT)

    def test_wrapper_raises_sdls_error(self):
        with self.assertRaises(b.SdlsError) as ctx:
            self.sdls.tm_extract_packets(bytes(100))
        self.assertEqual(ctx.exception.code, b.TM_INVALID_LENGTH)


class SatTmFramerSanityTest(unittest.TestCase):
    """Checks the satellite reference itself, so a test failure points at the library."""

    def test_empty_frame_is_not_sent(self):
        framer = SatTmFramer()
        framer.send_frame()
        self.assertEqual(framer.sent, [])

    def test_oversized_packet_is_dropped(self):
        framer = SatTmFramer()
        self.assertFalse(framer.forward_packet(make_spp(0x140, data_of(b.TM_DATA_LENGTH + 1))))
        self.assertFalse(framer.forward_packet(make_spp(0x140, data_of(b.TM_DATA_LENGTH - 1))))
        framer.send_frame()
        self.assertEqual(framer.sent, [])

    def test_master_channel_frame_count_increments(self):
        framer = SatTmFramer()
        for _ in range(3):
            framer.forward_packet(make_spp(0x141, data_of(b.TM_DATA_LENGTH)))
        self.assertEqual([f[2] for f in framer.sent], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
