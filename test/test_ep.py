"""Key exchange (EP_my*) tests, ground end against the test satellite (libsdls_satsim.so).

    satellite: ML-KEM key pair  --ek-->  ground: EP_myAcceptKemPublicKey -> ct (SA01/SA11 Keyed)
    satellite: decaps + HKDF   <--ct--   ground: StartSA signed with EP_mySign
    satellite confirms                   ground: EP_myStartSessions (Operational)
"""

import unittest

import sdls_binding as b
from sat_reference import SatTcDrop, SatTmFramer, make_spp, sat_crypto, sat_tc_extract_packet
from test_sa_shm import SaShmTestBase


def _worker_pending_ct(name):
    """Sender process: reads the ciphertext the receiver process produced."""
    sdls = b.Sdls()
    sdls.sa_open(name)
    return sdls.ep_pending_ciphertext()


def _worker_sign(name, msg):
    """Sender process: signs with the DSA key another process loaded."""
    sdls = b.Sdls()
    sdls.sa_open(name)
    return sdls.ep_sign(msg)


class KeyExchangeTest(SaShmTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sdls.tc_init()
        cls.sat = sat_crypto()

    def exchange(self):
        """Runs the exchange up to Keyed on both ends. Returns (ct, sat K_TC, sat K_TM)."""
        ek, sk = self.sat.kem_keygen()
        ct = self.sdls.ep_accept_kem_public_key(ek)
        ktc, ktm = self.sat.kem_accept(sk, ct)
        return ct, ktc, ktm

    def state(self, spi):
        return self.sdls.sa_get(spi).state

    # --- happy path ---------------------------------------------------------------------

    def test_full_exchange_then_protected_traffic_both_ways(self):
        ct, ktc, ktm = self.exchange()
        self.assertEqual(len(ct), b.KEM_CT_LEN)
        self.assertEqual((self.state(b.SPI_SA01), self.state(b.SPI_SA11)), (b.SA_STATE_KEYED,) * 2)

        self.sdls.ep_start_sessions()
        self.assertEqual((self.state(b.SPI_SA01), self.state(b.SPI_SA11)), (b.SA_STATE_OPERATIONAL,) * 2)

        command = make_spp(0x18, b"first protected command")
        frame = self.sdls.tc_build_frame(b.SPI_SA01, command)
        self.assertEqual(sat_tc_extract_packet(frame, tc_key=ktc), command)

        telemetry = [make_spp(0x100, b"first protected telemetry")]
        framer = SatTmFramer(spi=b.SPI_SA11, key=ktm)
        framer.forward_packet(telemetry[0])
        framer.send_frame()
        self.assertEqual(self.sdls.tm_extract(framer.sent[0]), (b.SPI_SA11, telemetry))

    def test_tc_and_tm_keys_differ(self):
        _, ktc, ktm = self.exchange()
        self.assertNotEqual(ktc, ktm)
        self.sdls.ep_start_sessions()
        frame = self.sdls.tc_build_frame(b.SPI_SA01, make_spp(0x18, b"x"))
        with self.assertRaises(SatTcDrop):
            sat_tc_extract_packet(frame, tc_key=ktm)  # the TM key does not open TC

    def test_pending_ciphertext_is_shared_with_another_process(self):
        ct, _, _ = self.exchange()
        with self.ctx.Pool(1) as pool:
            self.assertEqual(pool.apply(_worker_pending_ct, (self.name,)), ct)

    def test_start_clears_the_pending_ciphertext(self):
        self.exchange()
        self.sdls.ep_start_sessions()
        self.assertSaError(b.EP_NO_PENDING, self.sdls.ep_pending_ciphertext)

    def test_new_exchange_while_operational_replaces_the_keys(self):
        _, old_ktc, _ = self.exchange()
        self.sdls.ep_start_sessions()
        for _ in range(3):
            self.sdls.tc_build_frame(b.SPI_SA01, make_spp(0x18, b"x"))

        _, new_ktc, _ = self.exchange()
        self.assertEqual((self.state(b.SPI_SA01), self.state(b.SPI_SA11)), (b.SA_STATE_KEYED,) * 2)
        self.assertEqual(int.from_bytes(bytes(self.sdls.sa_get(b.SPI_SA01).iv), "big"), 1)  # fresh counter
        self.sdls.ep_start_sessions()
        frame = self.sdls.tc_build_frame(b.SPI_SA01, make_spp(0x18, b"y"))
        self.assertEqual(sat_tc_extract_packet(frame, tc_key=new_ktc)[6:], b"y")
        with self.assertRaises(SatTcDrop):
            sat_tc_extract_packet(frame, tc_key=old_ktc)

    # --- failures -----------------------------------------------------------------------

    def test_tampered_ciphertext_gives_the_satellite_other_keys(self):
        """ML-KEM implicit rejection: no error on decaps, but the first frame fails its MAC."""
        ek, sk = self.sat.kem_keygen()
        ct = bytearray(self.sdls.ep_accept_kem_public_key(ek))
        ct[0] ^= 1
        sat_ktc, _ = self.sat.kem_accept(sk, bytes(ct))
        self.sdls.ep_start_sessions()
        frame = self.sdls.tc_build_frame(b.SPI_SA01, make_spp(0x18, b"x"))
        with self.assertRaises(SatTcDrop):
            sat_tc_extract_packet(frame, tc_key=sat_ktc)

    def test_wrong_ek_length_is_refused_and_changes_nothing(self):
        ek, _ = self.sat.kem_keygen()
        self.assertSaError(b.SA_INVALID_ARGUMENT, self.sdls.ep_accept_kem_public_key, ek[:-1])
        self.assertEqual(self.state(b.SPI_SA01), b.SA_STATE_UNKEYED)
        self.assertSaError(b.EP_NO_PENDING, self.sdls.ep_pending_ciphertext)

    def test_malformed_ek_is_crypto_error(self):
        """FIPS 203 input check: every coefficient of a valid ek is below q = 3329."""
        self.assertSaError(b.EP_CRYPTO_ERROR, self.sdls.ep_accept_kem_public_key, b"\xff" * b.KEM_PK_LEN)
        self.assertEqual(self.state(b.SPI_SA01), b.SA_STATE_UNKEYED)

    def test_start_before_any_exchange_is_invalid_state(self):
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.ep_start_sessions)


class EpSignatureTest(SaShmTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sat = sat_crypto()
        cls.pk, cls.sk = cls.sat.dsa_keygen()

    def test_satellite_verifies_a_ground_signature(self):
        self.sdls.sa_set_dsa_key(self.pk, self.sk)
        pdu = b"StartSA SA01" + bytes(range(64))
        sig = self.sdls.ep_sign(pdu)
        self.assertEqual(len(sig), b.DSA_SIG_LEN)
        self.assertTrue(self.sat.dsa_verify(self.pk, pdu, sig))

    def test_modified_pdu_or_signature_fails(self):
        self.sdls.sa_set_dsa_key(self.pk, self.sk)
        pdu = b"StartSA SA01"
        sig = bytearray(self.sdls.ep_sign(pdu))
        self.assertFalse(self.sat.dsa_verify(self.pk, b"StartSA SA02", bytes(sig)))
        sig[100] ^= 1
        self.assertFalse(self.sat.dsa_verify(self.pk, pdu, bytes(sig)))

    def test_other_public_key_fails(self):
        self.sdls.sa_set_dsa_key(self.pk, self.sk)
        other_pk, _ = self.sat.dsa_keygen()
        self.assertFalse(self.sat.dsa_verify(other_pk, b"pdu", self.sdls.ep_sign(b"pdu")))

    def test_key_loaded_by_one_process_signs_in_another(self):
        self.sdls.sa_set_dsa_key(self.pk, self.sk)
        with self.ctx.Pool(1) as pool:
            sig = pool.apply(_worker_sign, (self.name, b"from the sender"))
        self.assertTrue(self.sat.dsa_verify(self.pk, b"from the sender", sig))

    def test_sign_without_a_key_is_unknown_key(self):
        self.assertSaError(b.SA_UNKNOWN_KEY, self.sdls.ep_sign, b"pdu")

    def test_wrong_key_lengths_are_refused(self):
        self.assertSaError(b.SA_INVALID_ARGUMENT, self.sdls.sa_set_dsa_key, self.pk[:-1], self.sk)
        self.assertSaError(b.SA_INVALID_ARGUMENT, self.sdls.sa_set_dsa_key, self.pk, self.sk[:-1])


if __name__ == "__main__":
    unittest.main()
