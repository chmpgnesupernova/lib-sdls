"""SDLS Security Header (SECHDR_my*) tests.

The header is SPI 2 bytes + IV 12 bytes, big endian. The expected bytes are built
independently here with struct/int.to_bytes, not with the library.
"""

import ctypes
import struct
import unittest

import sdls_binding as b
from test_sa_shm import SaShmTestBase, iv_bytes, iv_int


def make_sechdr(spi, iv):
    return struct.pack(">H", spi) + iv


class SecHdrApplyTcTest(SaShmTestBase):
    def test_protected_sa_writes_spi_and_fresh_iv(self):
        self.bring_up_tc()
        for expected in (1, 2, 3):
            with self.subTest(iv=expected):
                hdr, iv = self.sdls.sechdr_apply_tc(b.SPI_SA01)
                self.assertEqual(hdr, make_sechdr(b.SPI_SA01, iv_bytes(expected)))
                self.assertEqual(iv, iv_bytes(expected))

    def test_header_and_next_iv_share_one_counter(self):
        self.bring_up_tc()
        self.sdls.sechdr_apply_tc(b.SPI_SA01)
        self.assertEqual(iv_int(self.sdls.sa_next_iv(b.SPI_SA01)), 2)
        _, iv = self.sdls.sechdr_apply_tc(b.SPI_SA01)
        self.assertEqual(iv_int(iv), 3)

    def test_spi_is_big_endian(self):
        self.bring_up_tc()
        hdr, _ = self.sdls.sechdr_apply_tc(b.SPI_SA01)
        self.assertEqual(hdr[:2], b"\x00\x01")

    def test_unprotected_sa_zero_fills_iv(self):
        for _ in range(2):
            hdr, iv = self.sdls.sechdr_apply_tc(b.SPI_SA00)
            self.assertEqual(hdr, bytes(b.SECHDR_LENGTH))
            self.assertEqual(iv, bytes(b.SECHDR_IV_LENGTH))

    def test_unprotected_sa_does_not_consume_ivs(self):
        self.bring_up_tc()
        self.sdls.sechdr_apply_tc(b.SPI_SA00)
        _, iv = self.sdls.sechdr_apply_tc(b.SPI_SA01)
        self.assertEqual(iv_int(iv), 1)

    def test_refused_sas(self):
        cases = (
            (b.SPI_SA01, b.SA_INVALID_STATE),  # Unkeyed
            (b.SPI_SA10, b.SA_INVALID_STATE),  # TM SA
            (b.SPI_SA11, b.SA_INVALID_STATE),
            (0x1234, b.SA_UNKNOWN_SPI),
        )
        for spi, code in cases:
            with self.subTest(spi=spi):
                self.assertSaError(code, self.sdls.sechdr_apply_tc, spi)

    def test_stopped_sa_is_refused(self):
        self.bring_up_tc()
        self.sdls.sa_stop(b.SPI_SA01)
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sechdr_apply_tc, b.SPI_SA01)

    def test_refused_call_leaves_buffer_and_counter(self):
        self.bring_up_tc()
        self.sdls.sa_stop(b.SPI_SA01)
        buf = ctypes.create_string_buffer(b"\xEE" * b.SECHDR_LENGTH, b.SECHDR_LENGTH)
        status = self.sdls.lib.SECHDR_myApplyTc(b.SPI_SA01, buf, len(buf), None)
        self.assertEqual(status, b.SA_INVALID_STATE)
        self.assertEqual(buf.raw, b"\xEE" * b.SECHDR_LENGTH)
        self.sdls.sa_start(b.SPI_SA01)
        self.assertEqual(iv_int(self.sdls.sechdr_apply_tc(b.SPI_SA01)[1]), 1)

    def test_arguments(self):
        self.bring_up_tc()
        small = ctypes.create_string_buffer(b.SECHDR_LENGTH - 1)
        self.assertEqual(self.sdls.lib.SECHDR_myApplyTc(b.SPI_SA01, small, len(small), None), b.SA_INVALID_ARGUMENT)
        self.assertEqual(self.sdls.lib.SECHDR_myApplyTc(b.SPI_SA01, None, 64, None), b.SA_INVALID_ARGUMENT)
        # NULL pIv is allowed.
        buf = ctypes.create_string_buffer(b.SECHDR_LENGTH)
        self.assertEqual(self.sdls.lib.SECHDR_myApplyTc(b.SPI_SA01, buf, len(buf), None), b.SA_SUCCESS)
        self.assertEqual(buf.raw, make_sechdr(b.SPI_SA01, iv_bytes(1)))


class SecHdrProcessTmTest(SaShmTestBase):
    def test_protected_sa_returns_spi_and_iv(self):
        self.bring_up_tm()  # last accepted ARSN = 0
        spi, iv = self.sdls.sechdr_process_tm(make_sechdr(b.SPI_SA11, iv_bytes(2)))
        self.assertEqual((spi, iv), (b.SPI_SA11, iv_bytes(2)))

    def test_process_does_not_commit(self):
        self.bring_up_tm()
        hdr = make_sechdr(b.SPI_SA11, iv_bytes(2))
        self.sdls.sechdr_process_tm(hdr)
        self.sdls.sechdr_process_tm(hdr)  # still accepted: nothing recorded yet
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA11).iv)), 0)

    def test_replay_after_commit(self):
        self.bring_up_tm()
        hdr = make_sechdr(b.SPI_SA11, iv_bytes(2))
        spi, iv = self.sdls.sechdr_process_tm(hdr)
        self.sdls.sa_commit_arsn(spi, iv)  # done by the caller after the MAC verifies
        self.assertSaError(b.SA_REPLAY, self.sdls.sechdr_process_tm, hdr)
        self.assertSaError(b.SA_REPLAY, self.sdls.sechdr_process_tm, make_sechdr(b.SPI_SA11, iv_bytes(1)))

    def test_outside_window_is_refused(self):
        self.bring_up_tm()
        self.sdls.sechdr_process_tm(make_sechdr(b.SPI_SA11, iv_bytes(64)))
        self.assertSaError(b.SA_REPLAY, self.sdls.sechdr_process_tm, make_sechdr(b.SPI_SA11, iv_bytes(65)))

    def test_unprotected_sa_ignores_iv(self):
        for iv in (bytes(12), b"\xFF" * 12):
            with self.subTest(iv=iv.hex()):
                spi, out = self.sdls.sechdr_process_tm(make_sechdr(b.SPI_SA10, iv))
                self.assertEqual((spi, out), (b.SPI_SA10, iv))

    def test_spi_is_read_big_endian(self):
        # 0xFFFF reads the same both ways, so check SA11 (0x0002): little endian would
        # read 0x0200, an unknown SPI.
        self.bring_up_tm()
        spi, _ = self.sdls.sechdr_process_tm(b"\x00\x02" + iv_bytes(2))
        self.assertEqual(spi, b.SPI_SA11)
        self.assertSaError(b.SA_UNKNOWN_SPI, self.sdls.sechdr_process_tm, b"\x02\x00" + iv_bytes(2))

    def test_refused_sas(self):
        cases = (
            (b.SPI_SA11, b.SA_INVALID_STATE),  # Unkeyed
            (b.SPI_SA00, b.SA_INVALID_STATE),  # TC SA
            (b.SPI_SA01, b.SA_INVALID_STATE),
            (0x1234, b.SA_UNKNOWN_SPI),
        )
        for spi, code in cases:
            with self.subTest(spi=spi):
                self.assertSaError(code, self.sdls.sechdr_process_tm, make_sechdr(spi, iv_bytes(2)))

    def test_header_inside_a_tm_frame(self):
        """The header sits right after the 6 byte TM Primary Header."""
        self.bring_up_tm()
        frame = bytearray(b.TM_FRAME_SIZE)
        frame[b.TMTF_PRIHDR_LENGTH : b.TM_DATA_OFFSET] = make_sechdr(b.SPI_SA11, iv_bytes(7))
        self.assertEqual(b.TM_DATA_OFFSET - b.TMTF_PRIHDR_LENGTH, b.SECHDR_LENGTH)
        spi, iv = self.sdls.sechdr_process_tm(frame[b.TMTF_PRIHDR_LENGTH :])
        self.assertEqual((spi, iv_int(iv)), (b.SPI_SA11, 7))

    def test_arguments(self):
        self.bring_up_tm()
        hdr = make_sechdr(b.SPI_SA11, iv_bytes(2))
        spi = ctypes.c_uint16()
        iv = ctypes.create_string_buffer(b.SECHDR_IV_LENGTH)
        lib = self.sdls.lib
        self.assertEqual(lib.SECHDR_myProcessTm(hdr, len(hdr) - 1, ctypes.byref(spi), iv), b.SA_INVALID_ARGUMENT)
        self.assertEqual(lib.SECHDR_myProcessTm(None, len(hdr), ctypes.byref(spi), iv), b.SA_INVALID_ARGUMENT)
        self.assertEqual(lib.SECHDR_myProcessTm(hdr, len(hdr), None, iv), b.SA_INVALID_ARGUMENT)
        self.assertEqual(lib.SECHDR_myProcessTm(hdr, len(hdr), ctypes.byref(spi), None), b.SA_INVALID_ARGUMENT)


if __name__ == "__main__":
    unittest.main()
