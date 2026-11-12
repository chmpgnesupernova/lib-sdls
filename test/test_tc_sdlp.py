"""TC_SDLP_myInit / TC_SDLP_myBuildFrame tests.

Every frame built by the ground side must pass the satellite side TC_SDLP_myExtractPacket.
"""

import ctypes
import pathlib
import shutil
import tempfile
import unittest

import sdls_binding as b
from sat_reference import make_spp, sat_tc_extract_packet, tc_header_fields

MAX_DATA_LENGTH = b.TC_MAX_PACKET_LENGTH - b.TC_SPP_HDR_LENGTH


class TcBuildFrameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdls = b.Sdls()
        cls.sdls.tc_init()

    def build_raw(self, packet, buf_size=b.TCTF_MAX_FRAME_LENGTH, packet_size=None):
        buf = ctypes.create_string_buffer(buf_size)
        size = len(packet) if packet_size is None else packet_size
        return self.sdls.lib.TC_SDLP_myBuildFrame(packet, size, buf, buf_size)

    # --- satellite interoperability ---------------------------------------------------

    def test_satellite_accepts_frames_of_every_size_class(self):
        for data_length in (1, 2, 100, 512, MAX_DATA_LENGTH - 1, MAX_DATA_LENGTH):
            with self.subTest(data_length=data_length):
                packet = make_spp(0x18, bytes(i & 0xFF for i in range(data_length)))
                frame = self.sdls.tc_build_frame(packet)
                self.assertEqual(sat_tc_extract_packet(frame), packet)

    def test_frame_size_is_header_plus_packet(self):
        packet = make_spp(0x18, b"\xAA" * 40)
        frame = self.sdls.tc_build_frame(packet)
        self.assertEqual(len(frame), b.TCTF_PRIHDR_LENGTH + len(packet))
        self.assertEqual(frame[b.TCTF_PRIHDR_LENGTH :], packet)

    def test_header_fields_match_satellite_expectation(self):
        packet = make_spp(0x18, b"\x01\x02\x03")
        frame = self.sdls.tc_build_frame(packet)
        hdr = tc_header_fields(frame)
        self.assertEqual(hdr["tfvn"], b.TC_DUMMY_TFVN)
        self.assertEqual(hdr["bypass"], b.TC_BYPASS_FLG)
        self.assertEqual(hdr["ctlcmd"], b.TC_CTLCMD_FLG)
        self.assertEqual(hdr["scid"], b.TC_DUMMY_SCID)
        self.assertEqual(hdr["vcid"], b.TC_DUMMY_VCID)
        self.assertEqual(hdr["framelen"], len(frame) - 1)
        self.assertEqual(frame[0] & 0x0C, 0, "spare bits must be 0")

    def test_sequence_number_increments_and_wraps(self):
        packet = make_spp(0x18, b"\x00")
        seqs = [tc_header_fields(self.sdls.tc_build_frame(packet))["seq"] for _ in range(300)]
        for prev, cur in zip(seqs, seqs[1:]):
            self.assertEqual(cur, (prev + 1) & 0xFF)

    def test_input_packet_is_not_modified(self):
        packet = make_spp(0x18, b"\x10\x20\x30")
        src = ctypes.create_string_buffer(packet, len(packet))
        buf = ctypes.create_string_buffer(b.TCTF_MAX_FRAME_LENGTH)
        self.sdls.lib.TC_SDLP_myBuildFrame(src, len(packet), buf, len(buf))
        self.assertEqual(src.raw, packet)

    def test_buffer_of_exact_frame_size_is_enough(self):
        packet = make_spp(0x18, b"\x55" * 10)
        self.assertEqual(self.build_raw(packet, buf_size=5 + len(packet)), 5 + len(packet))

    # --- error codes -----------------------------------------------------------------

    def test_packet_shorter_than_minimum_is_invalid_length(self):
        self.assertEqual(self.build_raw(b"\x00" * 6), b.TC_INVALID_LENGTH)

    def test_packet_longer_than_one_frame_is_invalid_length(self):
        packet = make_spp(0x18, bytes(MAX_DATA_LENGTH + 1))
        self.assertEqual(self.build_raw(packet, buf_size=2048), b.TC_INVALID_LENGTH)

    def test_length_field_mismatch_is_invalid_packet(self):
        packet = bytearray(make_spp(0x18, bytes(10)))
        packet[5] = 0  # length field now says 1 data byte
        self.assertEqual(self.build_raw(bytes(packet)), b.TC_INVALID_PACKET)

    def test_size_argument_mismatch_is_invalid_packet(self):
        packet = make_spp(0x18, bytes(10))
        self.assertEqual(self.build_raw(packet, packet_size=len(packet) - 1), b.TC_INVALID_PACKET)

    def test_small_buffer_is_buffer_too_small(self):
        packet = make_spp(0x18, bytes(10))
        self.assertEqual(self.build_raw(packet, buf_size=5 + len(packet) - 1), b.TC_BUFFER_TOO_SMALL)

    def test_null_pointers_are_invalid_argument(self):
        packet = make_spp(0x18, bytes(10))
        buf = ctypes.create_string_buffer(64)
        self.assertEqual(self.sdls.lib.TC_SDLP_myBuildFrame(None, len(packet), buf, 64), b.TC_INVALID_ARGUMENT)
        self.assertEqual(self.sdls.lib.TC_SDLP_myBuildFrame(packet, len(packet), None, 64), b.TC_INVALID_ARGUMENT)

    def test_wrapper_raises_sdls_error(self):
        with self.assertRaises(b.SdlsError) as ctx:
            self.sdls.tc_build_frame(b"\x00" * 6)
        self.assertEqual(ctx.exception.code, b.TC_INVALID_LENGTH)


class TcNotInitializedTest(unittest.TestCase):
    """Uses a private copy of the library so its static state is fresh (no Init yet)."""

    def test_build_before_init_is_not_initialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy_path = pathlib.Path(tmp) / "libsdls_fresh.so"
            shutil.copy(b.find_library(), copy_path)
            fresh = b.Sdls(str(copy_path))
            packet = make_spp(0x18, b"\x00")
            buf = ctypes.create_string_buffer(64)

            self.assertEqual(fresh.lib.TC_SDLP_myBuildFrame(packet, len(packet), buf, 64), b.TC_NOT_INITIALIZED)
            fresh.tc_init()
            self.assertEqual(fresh.lib.TC_SDLP_myBuildFrame(packet, len(packet), buf, 64), 5 + len(packet))


if __name__ == "__main__":
    unittest.main()
