"""SDLS frame protection tests (SDLS_myApplySecurityTc / SDLS_myProcessSecurityTm).

Session SAs use AES-256-GCM with
    AAD = (Primary Header AND mask) || SPI,   nonce = IV,   MAC = 16 byte tag.
The satellite side (sat_reference) builds the AAD on its own from that rule, so every
round trip here also checks that both ends agree on the AAD byte for byte.
"""

import ctypes
import unittest

import sdls_binding as b
from sat_reference import (
    TC_AUTH_MASK,
    TM_AUTH_MASK,
    SatTcDrop,
    SatTmFramer,
    make_spp,
    masked,
    sat_tc_extract_packet,
)
from test_sa_shm import KEY_A, KEY_B, SaShmTestBase

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # optional: only the independent cross check needs it
    AESGCM = None

TC_DATA = b.TCTF_PRIHDR_LENGTH + b.TC_SDLS_HDR_LENGTH
TM_DATA = b.TM_DATA_OFFSET
TRL = b.SDLS_TRAILER_LENGTH


def tm_frame(packets, first_iv=1, key=KEY_B, spi=b.SPI_SA11, **args):
    framer = SatTmFramer(spi=spi, first_iv=first_iv, key=key, **args)
    for packet in packets:
        framer.forward_packet(packet)
    framer.send_frame()
    (frame,) = framer.sent
    return frame


def flip(frame, index, mask=0x01):
    out = bytearray(frame)
    out[index] ^= mask
    return bytes(out)


def arsn(sdls):
    return int.from_bytes(bytes(sdls.sa_get(b.SPI_SA11).iv), "big")


class TcProtectionTest(SaShmTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sdls.tc_init()

    def setUp(self):
        super().setUp()
        self.bring_up_tc()  # SA01 Operational with KEY_A
        self.packet = make_spp(0x18, bytes(range(40)))

    def build(self, spi=b.SPI_SA01, packet=None):
        return self.sdls.tc_build_frame(spi, self.packet if packet is None else packet)

    def test_session_frame_is_encrypted_and_satellite_decrypts_it(self):
        frame = self.build()
        self.assertNotEqual(frame[TC_DATA:-TRL], self.packet)
        self.assertNotEqual(frame[-TRL:], bytes(TRL))
        self.assertEqual(sat_tc_extract_packet(frame, tc_key=KEY_A), self.packet)

    def test_same_packet_gives_different_ciphertext_per_iv(self):
        first, second = self.build(), self.build()
        self.assertNotEqual(first[TC_DATA:], second[TC_DATA:])

    def test_satellite_refuses_any_modified_byte(self):
        frame = self.build()
        cases = {
            "Primary Header (sequence number)": 4,
            "Primary Header (VCID)": 2,
            "SPI": b.TCTF_PRIHDR_LENGTH + 1,
            "IV": b.TCTF_PRIHDR_LENGTH + 2 + 11,
            "ciphertext": TC_DATA + 3,
            "MAC": len(frame) - 1,
        }
        for name, index in cases.items():
            with self.subTest(name):
                with self.assertRaises(SatTcDrop):
                    sat_tc_extract_packet(flip(frame, index, 0x04), tc_key=KEY_A)

    def test_satellite_with_another_key_refuses(self):
        with self.assertRaises(SatTcDrop):
            sat_tc_extract_packet(self.build(), tc_key=KEY_B)

    def test_ep_frame_stays_clear_with_zero_mac(self):
        frame = self.build(spi=b.SPI_SA00)
        self.assertEqual(frame[TC_DATA:-TRL], self.packet)
        self.assertEqual(frame[-TRL:], bytes(TRL))

    def test_apply_security_directly(self):
        """The SDLS call on its own, as tc_sdlp uses it."""
        hdr = self.build(spi=b.SPI_SA00)[: b.TCTF_PRIHDR_LENGTH]  # a real Primary Header
        size = TC_DATA + len(self.packet) + TRL
        buf = ctypes.create_string_buffer(hdr + bytes(b.SECHDR_LENGTH) + self.packet + bytes(TRL), size)
        rc = self.sdls.lib.SDLS_myApplySecurityTc(b.SPI_SA01, buf, b.TCTF_PRIHDR_LENGTH, len(self.packet), size)
        self.assertEqual(rc, b.SA_SUCCESS)
        self.assertEqual(
            self.sdls.lib.SDLS_myApplySecurityTc(b.SPI_SA01, buf, b.TCTF_PRIHDR_LENGTH, len(self.packet), size - 1),
            b.SA_INVALID_ARGUMENT,
        )


class TmProtectionTest(SaShmTestBase):
    def setUp(self):
        super().setUp()
        self.bring_up_tm()  # SA11 Operational with KEY_B
        self.packets = [make_spp(0x100, b"\xAA" * 10), make_spp(0x101, b"\xBB" * 20)]

    def raw_process(self, frame):
        buf = ctypes.create_string_buffer(bytes(frame), len(frame))
        spi = ctypes.c_uint16(0)
        rc = self.sdls.lib.SDLS_myProcessSecurityTm(buf, len(frame), b.TMTF_PRIHDR_LENGTH, ctypes.byref(spi))
        return rc, buf.raw, spi.value

    def test_session_frame_decrypts_and_reports_spi(self):
        frame = tm_frame(self.packets)
        self.assertNotIn(self.packets[0], frame)  # really encrypted on the wire
        self.assertEqual(self.sdls.tm_extract(frame), (b.SPI_SA11, self.packets))

    def test_ep_frame_reports_spi_sa10_and_ignores_the_mac(self):
        frame = bytearray(tm_frame(self.packets, spi=b.SPI_SA10, key=None))
        frame[-TRL:] = b"\x5A" * TRL
        self.assertEqual(self.sdls.tm_extract(bytes(frame)), (b.SPI_SA10, self.packets))

    def test_mc_frame_count_is_not_authenticated(self):
        """The TM mask leaves the MC Frame Count out of the AAD (355.0 §4.2.2.6.2 d)."""
        self.assertEqual(self.sdls.tm_extract_packets(flip(tm_frame(self.packets), 2, 0xFF)), self.packets)

    def test_any_other_modified_byte_is_refused(self):
        frame = tm_frame(self.packets, first_iv=5)
        cases = {
            "Primary Header (SCID/VCID)": 1,
            "Primary Header (data field status)": 5,
            "IV": b.TMTF_PRIHDR_LENGTH + 2 + 11,
            "ciphertext": TM_DATA + 7,
            "ciphertext end": b.TM_DATA_END - 1,
            "MAC": b.TM_FRAME_SIZE - 1,
        }
        for name, index in cases.items():
            with self.subTest(name):
                rc, _, _ = self.raw_process(flip(frame, index, 0x10))
                self.assertIn(rc, (b.SDLS_AUTH_FAIL, b.SA_REPLAY))
                self.assertEqual(arsn(self.sdls), 0, "a refused frame must not move the ARSN")
        self.assertEqual(self.sdls.tm_extract_packets(frame), self.packets)  # the genuine one still passes

    def test_forged_frame_with_a_future_iv_does_not_block_genuine_frames(self):
        forged = flip(tm_frame(self.packets, first_iv=60), TM_DATA)  # IV 60, broken MAC
        self.assertEqual(self.raw_process(forged)[0], b.SDLS_AUTH_FAIL)
        self.assertEqual(arsn(self.sdls), 0)
        self.assertEqual(self.sdls.tm_extract_packets(tm_frame(self.packets, first_iv=1)), self.packets)

    def test_wrong_key_is_auth_fail_and_data_is_wiped(self):
        rc, out, _ = self.raw_process(tm_frame(self.packets, key=KEY_A))
        self.assertEqual(rc, b.SDLS_AUTH_FAIL)
        self.assertEqual(out[TM_DATA : b.TM_DATA_END], bytes(b.TM_DATA_LENGTH))

    def test_replay_after_success(self):
        frame = tm_frame(self.packets)
        self.assertEqual(self.raw_process(frame)[0], b.SA_SUCCESS)
        self.assertEqual(self.raw_process(frame)[0], b.SA_REPLAY)

    def test_extract_maps_auth_fail_to_security_error(self):
        with self.assertRaises(b.SdlsError) as ctx:
            self.sdls.tm_extract(flip(tm_frame(self.packets), TM_DATA))
        self.assertEqual(ctx.exception.code, b.TM_SECURITY_ERROR)

    def test_short_frame_is_invalid_argument(self):
        frame = tm_frame(self.packets)[: b.TMTF_PRIHDR_LENGTH + b.SECHDR_LENGTH + TRL - 1]
        self.assertEqual(self.raw_process(frame)[0], b.SA_INVALID_ARGUMENT)


@unittest.skipIf(AESGCM is None, "python 'cryptography' not installed")
class IndependentAesGcmTest(SaShmTestBase):
    """Checks the wire format against a crypto implementation unrelated to wolfSSL."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sdls.tc_init()

    def test_ground_tc_frame_decrypts_with_another_implementation(self):
        self.bring_up_tc()
        packet = make_spp(0x18, b"independent check")
        frame = self.sdls.tc_build_frame(b.SPI_SA01, packet)
        hdr_end = b.TCTF_PRIHDR_LENGTH
        aad = masked(frame[:hdr_end], TC_AUTH_MASK) + frame[hdr_end : hdr_end + 2]
        iv = frame[hdr_end + 2 : hdr_end + b.SECHDR_LENGTH]
        self.assertEqual(AESGCM(KEY_A).decrypt(iv, frame[TC_DATA:], aad), packet)

    def test_tm_frame_from_another_implementation_is_accepted(self):
        self.bring_up_tm()
        packets = [make_spp(0x200, b"from cryptography")]
        frame = bytearray(tm_frame(packets, spi=b.SPI_SA11, key=None, first_iv=3))  # clear data, zero MAC
        hdr_end = b.TMTF_PRIHDR_LENGTH
        aad = masked(frame[:hdr_end], TM_AUTH_MASK) + frame[hdr_end : hdr_end + 2]
        iv = bytes(frame[hdr_end + 2 : hdr_end + b.SECHDR_LENGTH])
        sealed = AESGCM(KEY_B).encrypt(iv, bytes(frame[TM_DATA : b.TM_DATA_END]), aad)
        frame[TM_DATA:] = sealed  # ciphertext || tag
        self.assertEqual(self.sdls.tm_extract(bytes(frame)), (b.SPI_SA11, packets))


if __name__ == "__main__":
    unittest.main()
