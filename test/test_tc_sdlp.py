"""TC_SDLP_myInit / TC_SDLP_myBuildFrame tests.

Every frame built by the ground side must pass the satellite side TC_SDLP_myExtractPacket.
Frame: [Primary Header 5][Security Header 14: SPI 2 + IV 12][Space Packet][MAC 16].
SA00 frames carry the packet in clear with a zero MAC; SA01 frames are AES-256-GCM.
"""

import ctypes
import os
import pathlib
import shutil
import tempfile
import unittest

import sdls_binding as b
from sat_reference import make_spp, sat_tc_extract_packet, tc_header_fields, tc_sechdr_fields
from test_sa_shm import KEY_A, SaShmTestBase

MAX_DATA_LENGTH = b.TC_MAX_PACKET_LENGTH - b.TC_SPP_HDR_LENGTH
DATA_OFFSET = b.TCTF_PRIHDR_LENGTH + b.TC_SDLS_HDR_LENGTH
OVERHEAD = DATA_OFFSET + b.TC_SDLS_TRL_LENGTH  # frame size = OVERHEAD + packet size


class TcBuildFrameTest(SaShmTestBase):
    """SaShmTestBase gives every test a fresh SA DB: SA00 Operational, SA01 Unkeyed."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sdls.tc_init()

    def build_raw(self, packet, buf_size=b.TCTF_MAX_FRAME_LENGTH, packet_size=None, spi=b.SPI_SA00):
        buf = ctypes.create_string_buffer(buf_size)
        size = len(packet) if packet_size is None else packet_size
        return self.sdls.lib.TC_SDLP_myBuildFrame(spi, packet, size, buf, buf_size)

    def seq_of_next_frame(self):
        return tc_header_fields(self.sdls.tc_build_frame(b.SPI_SA00, make_spp(0x18, b"\x00")))["seq"]

    # --- satellite interoperability ---------------------------------------------------

    def test_satellite_accepts_frames_of_every_size_class(self):
        self.bring_up_tc()
        for spi in (b.SPI_SA00, b.SPI_SA01):
            for data_length in (1, 2, 100, 512, MAX_DATA_LENGTH - 1, MAX_DATA_LENGTH):
                with self.subTest(spi=spi, data_length=data_length):
                    packet = make_spp(0x18, bytes(i & 0xFF for i in range(data_length)))
                    frame = self.sdls.tc_build_frame(spi, packet)
                    self.assertEqual(sat_tc_extract_packet(frame, tc_key=KEY_A), packet)

    def test_frame_layout(self):
        packet = make_spp(0x18, b"\xAA" * 40)
        frame = self.sdls.tc_build_frame(b.SPI_SA00, packet)
        self.assertEqual(len(frame), OVERHEAD + len(packet))
        self.assertEqual(frame[DATA_OFFSET:-b.TC_SDLS_TRL_LENGTH], packet)
        self.assertEqual(frame[-b.TC_SDLS_TRL_LENGTH:], bytes(b.TC_SDLS_TRL_LENGTH))  # SA00: zero MAC

    def test_max_packet_fills_the_frame(self):
        frame = self.sdls.tc_build_frame(b.SPI_SA00, make_spp(0x18, bytes(MAX_DATA_LENGTH)))
        self.assertEqual(len(frame), b.TCTF_MAX_FRAME_LENGTH)

    def test_header_fields_match_satellite_expectation(self):
        packet = make_spp(0x18, b"\x01\x02\x03")
        frame = self.sdls.tc_build_frame(b.SPI_SA00, packet)
        hdr = tc_header_fields(frame)
        self.assertEqual(hdr["tfvn"], b.TC_DUMMY_TFVN)
        self.assertEqual(hdr["bypass"], b.TC_BYPASS_FLG)
        self.assertEqual(hdr["ctlcmd"], b.TC_CTLCMD_FLG)
        self.assertEqual(hdr["scid"], b.TC_DUMMY_SCID)
        self.assertEqual(hdr["vcid"], b.TC_DUMMY_VCID)
        self.assertEqual(hdr["framelen"], len(frame) - 1)
        self.assertEqual(frame[0] & 0x0C, 0, "spare bits must be 0")

    def test_sequence_number_increments_and_wraps(self):
        seqs = [self.seq_of_next_frame() for _ in range(300)]
        for prev, cur in zip(seqs, seqs[1:]):
            self.assertEqual(cur, (prev + 1) & 0xFF)

    def test_input_packet_is_not_modified(self):
        packet = make_spp(0x18, b"\x10\x20\x30")
        src = ctypes.create_string_buffer(packet, len(packet))
        buf = ctypes.create_string_buffer(b.TCTF_MAX_FRAME_LENGTH)
        self.sdls.lib.TC_SDLP_myBuildFrame(b.SPI_SA00, src, len(packet), buf, len(buf))
        self.assertEqual(src.raw, packet)

    def test_buffer_of_exact_frame_size_is_enough(self):
        packet = make_spp(0x18, b"\x55" * 10)
        self.assertEqual(self.build_raw(packet, buf_size=OVERHEAD + len(packet)), OVERHEAD + len(packet))
        self.assertEqual(self.build_raw(packet, buf_size=OVERHEAD + len(packet) - 1), b.TC_BUFFER_TOO_SMALL)

    # --- Security Header --------------------------------------------------------------

    def test_ep_sa_header_has_spi_0_and_zero_iv(self):
        frame = self.sdls.tc_build_frame(b.SPI_SA00, make_spp(0x18, b"\x01"))
        self.assertEqual(frame[b.TCTF_PRIHDR_LENGTH : DATA_OFFSET], bytes(b.SECHDR_LENGTH))

    def test_session_sa_header_has_spi_and_counting_iv(self):
        self.bring_up_tc()
        packet = make_spp(0x18, b"\x01")
        fields = [tc_sechdr_fields(self.sdls.tc_build_frame(b.SPI_SA01, packet)) for _ in range(3)]
        self.assertEqual(fields, [{"spi": b.SPI_SA01, "iv": n} for n in (1, 2, 3)])
        frame = self.sdls.tc_build_frame(b.SPI_SA01, packet)
        self.assertEqual(frame[b.TCTF_PRIHDR_LENGTH : DATA_OFFSET], b"\x00\x01" + (4).to_bytes(12, "big"))

    def test_ep_frames_do_not_consume_session_ivs(self):
        self.bring_up_tc()
        packet = make_spp(0x18, b"\x01")
        self.sdls.tc_build_frame(b.SPI_SA00, packet)
        self.assertEqual(tc_sechdr_fields(self.sdls.tc_build_frame(b.SPI_SA01, packet))["iv"], 1)

    def test_sa_that_cannot_send_is_security_error(self):
        packet = make_spp(0x18, b"\x01")
        cases = {
            "SA01 Unkeyed": b.SPI_SA01,
            "SA10 is TM": b.SPI_SA10,
            "SA11 is TM": b.SPI_SA11,
            "unknown SPI": 0x1234,
        }
        for name, spi in cases.items():
            with self.subTest(name):
                self.assertEqual(self.build_raw(packet, spi=spi), b.TC_SECURITY_ERROR)

    def test_stopped_sa_is_security_error(self):
        self.bring_up_tc()
        self.sdls.sa_stop(b.SPI_SA01)
        self.assertEqual(self.build_raw(make_spp(0x18, b"\x01"), spi=b.SPI_SA01), b.TC_SECURITY_ERROR)

    def test_security_error_keeps_sequence_number(self):
        before = self.seq_of_next_frame()
        self.assertEqual(self.build_raw(make_spp(0x18, b"\x01"), spi=b.SPI_SA01), b.TC_SECURITY_ERROR)
        self.assertEqual(self.seq_of_next_frame(), (before + 1) & 0xFF)

    def test_refused_frames_do_not_consume_ivs(self):
        self.bring_up_tc()
        packet = make_spp(0x18, bytes(10))
        self.assertEqual(self.build_raw(b"\x00" * 6, spi=b.SPI_SA01), b.TC_INVALID_LENGTH)
        self.assertEqual(self.build_raw(packet, buf_size=DATA_OFFSET + len(packet) - 1, spi=b.SPI_SA01),
                         b.TC_BUFFER_TOO_SMALL)
        self.assertEqual(tc_sechdr_fields(self.sdls.tc_build_frame(b.SPI_SA01, packet))["iv"], 1)

    def test_wrapper_raises_security_error(self):
        with self.assertRaises(b.SdlsError) as ctx:
            self.sdls.tc_build_frame(b.SPI_SA01, make_spp(0x18, b"\x01"))
        self.assertEqual(ctx.exception.code, b.TC_SECURITY_ERROR)

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
        self.assertEqual(self.build_raw(packet, buf_size=DATA_OFFSET + len(packet) - 1), b.TC_BUFFER_TOO_SMALL)

    def test_null_pointers_are_invalid_argument(self):
        packet = make_spp(0x18, bytes(10))
        buf = ctypes.create_string_buffer(64)
        f = self.sdls.lib.TC_SDLP_myBuildFrame
        self.assertEqual(f(b.SPI_SA00, None, len(packet), buf, 64), b.TC_INVALID_ARGUMENT)
        self.assertEqual(f(b.SPI_SA00, packet, len(packet), None, 64), b.TC_INVALID_ARGUMENT)

    def test_wrapper_raises_sdls_error(self):
        with self.assertRaises(b.SdlsError) as ctx:
            self.sdls.tc_build_frame(b.SPI_SA00, b"\x00" * 6)
        self.assertEqual(ctx.exception.code, b.TC_INVALID_LENGTH)


class TcFreshLibraryTest(unittest.TestCase):
    """Uses a private copy of the library so its static state is fresh
    (no TC_SDLP_myInit and no SA_myOpen yet)."""

    def test_build_needs_init_and_sa_db(self):
        name = f"/sdls_test_tcfresh_{os.getpid()}"
        with tempfile.TemporaryDirectory() as tmp:
            copy_path = pathlib.Path(tmp) / "libsdls_fresh.so"
            shutil.copy(b.find_library(), copy_path)
            fresh = b.Sdls(str(copy_path))
            packet = make_spp(0x18, b"\x00")
            buf = ctypes.create_string_buffer(64)

            def build():
                return fresh.lib.TC_SDLP_myBuildFrame(b.SPI_SA00, packet, len(packet), buf, 64)

            self.assertEqual(build(), b.TC_NOT_INITIALIZED)
            fresh.tc_init()
            self.assertEqual(build(), b.TC_SECURITY_ERROR)  # SA DB not open
            try:
                fresh.sa_open(name)
                self.assertEqual(build(), OVERHEAD + len(packet))
            finally:
                fresh.sa_close()
                fresh.sa_unlink(name)


if __name__ == "__main__":
    unittest.main()
