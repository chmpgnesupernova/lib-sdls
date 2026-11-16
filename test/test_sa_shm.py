"""SA / Key DB in shared memory (SA_my*) tests.

The ground system runs the sender and the receiver as separate processes, so the
cross-process tests start real child processes (spawn) that load their own copy of
libsdls.so and attach to the same segment.
"""

import itertools
import multiprocessing
import os
import unittest

import sdls_binding as b

KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))

_names = itertools.count()


def iv_int(iv):
    return int.from_bytes(iv, "big")


def iv_bytes(n):
    return n.to_bytes(b.GCM_IV_LEN, "big")


# --- child process workers (module level so spawn can import them) ----------------------


def _worker_read_sa(name, spi):
    sdls = b.Sdls()
    sdls.sa_open(name)
    sa = sdls.sa_get(spi)
    return sa.state, sa.auth_key_id, iv_int(bytes(sa.iv))


def _worker_next_ivs(name, spi, count):
    sdls = b.Sdls()
    sdls.sa_open(name)
    return [iv_int(sdls.sa_next_iv(spi)) for _ in range(count)]


def _worker_bring_up_tm(name):
    """Receiver side style worker: loads the TM key and starts SA11."""
    sdls = b.Sdls()
    sdls.sa_open(name)
    sdls.sa_set_key(b.KEYID_SESS_TM, KEY_B)
    sdls.sa_rekey(b.SPI_SA11, b.KEYID_SESS_TM)
    sdls.sa_start(b.SPI_SA11)


def _worker_get_without_open(spi):
    sdls = b.Sdls()
    return sdls.lib.SA_myGetSa(spi, b.ctypes.byref(b.CommonSa()))


class SaShmTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdls = b.Sdls()
        cls.ctx = multiprocessing.get_context("spawn")

    def setUp(self):
        # A unique segment per test keeps tests independent of each other and of a
        # ground system that may be running with the default name.
        self.name = f"/sdls_test_{os.getpid()}_{next(_names)}"
        self.sdls.sa_open(self.name)

    def tearDown(self):
        self.sdls.sa_close()
        self.sdls.sa_unlink(self.name)

    def assertSaError(self, code, func, *args):
        with self.assertRaises(b.SdlsError) as cm:
            func(*args)
        self.assertEqual(cm.exception.code, code, str(cm.exception))

    def bring_up_tc(self, key=KEY_A):
        self.sdls.sa_set_key(b.KEYID_SESS_TC, key)
        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)
        self.sdls.sa_start(b.SPI_SA01)

    def bring_up_tm(self, key=KEY_B):
        self.sdls.sa_set_key(b.KEYID_SESS_TM, key)
        self.sdls.sa_rekey(b.SPI_SA11, b.KEYID_SESS_TM)
        self.sdls.sa_start(b.SPI_SA11)


class SaShmSingleProcessTest(SaShmTestBase):
    # --- segment ------------------------------------------------------------------------

    def test_fresh_segment_holds_defaults(self):
        expected = {
            b.SPI_SA00: b.SA_STATE_OPERATIONAL,
            b.SPI_SA01: b.SA_STATE_UNKEYED,
            b.SPI_SA10: b.SA_STATE_OPERATIONAL,
            b.SPI_SA11: b.SA_STATE_UNKEYED,
        }
        for spi, state in expected.items():
            with self.subTest(spi=spi):
                sa = self.sdls.sa_get(spi)
                self.assertEqual(sa.spi, spi)
                self.assertEqual(sa.state, state)
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA01).iv)), 1)
        self.assertEqual(self.sdls.sa_get(b.SPI_SA01).arsn_window, 64)

    def test_open_twice_is_harmless(self):
        self.sdls.sa_open(self.name)

    def test_state_survives_close_and_reopen(self):
        self.bring_up_tc()
        self.sdls.sa_close()
        self.sdls.sa_open(self.name)
        self.assertEqual(self.sdls.sa_get(b.SPI_SA01).state, b.SA_STATE_OPERATIONAL)

    def test_unlink_resets_to_defaults(self):
        self.bring_up_tc()
        self.sdls.sa_close()
        self.sdls.sa_unlink(self.name)
        self.sdls.sa_open(self.name)
        self.assertEqual(self.sdls.sa_get(b.SPI_SA01).state, b.SA_STATE_UNKEYED)

    def test_invalid_names_are_rejected(self):
        for name in ("no_slash", "/", "/a/b"):
            with self.subTest(name=name):
                self.assertEqual(self.sdls.lib.SA_myUnlink(name.encode()), b.SA_INVALID_ARGUMENT)

    def test_unknown_spi(self):
        self.assertSaError(b.SA_UNKNOWN_SPI, self.sdls.sa_get, 0x1234)
        self.assertSaError(b.SA_UNKNOWN_SPI, self.sdls.sa_start, 0x1234)

    # --- state transitions --------------------------------------------------------------

    def test_full_lifecycle(self):
        self.sdls.sa_set_key(b.KEYID_SESS_TC, KEY_A)

        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)
        sa = self.sdls.sa_get(b.SPI_SA01)
        self.assertEqual((sa.state, sa.last_pid), (b.SA_STATE_KEYED, b.PID_REKEY_SA))
        self.assertEqual((sa.auth_key_id, sa.enc_key_id), (b.KEYID_SESS_TC, b.KEYID_SESS_TC))

        self.sdls.sa_start(b.SPI_SA01)
        sa = self.sdls.sa_get(b.SPI_SA01)
        self.assertEqual((sa.state, sa.last_pid), (b.SA_STATE_OPERATIONAL, b.PID_START_SA))

        self.sdls.sa_stop(b.SPI_SA01)
        sa = self.sdls.sa_get(b.SPI_SA01)
        self.assertEqual((sa.state, sa.last_pid), (b.SA_STATE_KEYED, b.PID_STOP_SA))

        self.sdls.sa_expire(b.SPI_SA01)
        sa = self.sdls.sa_get(b.SPI_SA01)
        self.assertEqual((sa.state, sa.last_pid), (b.SA_STATE_UNKEYED, b.PID_EXPIRE_SA))
        self.assertEqual((sa.auth_key_id, sa.enc_key_id), (b.KEYID_NONE, b.KEYID_NONE))

    def test_transitions_from_wrong_state_are_refused(self):
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_start, b.SPI_SA01)  # Unkeyed
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_stop, b.SPI_SA01)
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_expire, b.SPI_SA01)
        self.bring_up_tc()
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_rekey, b.SPI_SA01, b.KEYID_SESS_TC)
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_expire, b.SPI_SA01)  # Operational

    def test_key_exchange_sas_refuse_transitions(self):
        for spi in (b.SPI_SA00, b.SPI_SA10):
            with self.subTest(spi=spi):
                self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_stop, spi)

    # --- keys -----------------------------------------------------------------------------

    def test_rekey_needs_a_loaded_key(self):
        self.assertSaError(b.SA_UNKNOWN_KEY, self.sdls.sa_rekey, b.SPI_SA01, b.KEYID_SESS_TC)
        self.assertSaError(b.SA_UNKNOWN_KEY, self.sdls.sa_rekey, b.SPI_SA01, 0x0002)

    def test_set_key_arguments(self):
        self.assertSaError(b.SA_INVALID_ARGUMENT, self.sdls.sa_set_key, b.KEYID_SESS_TC, KEY_A[:16])
        self.assertSaError(b.SA_UNKNOWN_KEY, self.sdls.sa_set_key, 0x0002, KEY_A)

    def test_key_in_use_cannot_be_replaced(self):
        self.bring_up_tc()
        self.assertSaError(b.SA_KEY_IN_USE, self.sdls.sa_set_key, b.KEYID_SESS_TC, KEY_B)

    def test_key_cannot_be_bound_to_two_sas(self):
        self.sdls.sa_set_key(b.KEYID_SESS_TC, KEY_A)
        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)
        self.assertSaError(b.SA_KEY_IN_USE, self.sdls.sa_rekey, b.SPI_SA11, b.KEYID_SESS_TC)

    def test_expire_destroys_the_key(self):
        """A rekey resets the IV, so binding the old key again would reuse IVs."""
        self.bring_up_tc()
        self.sdls.sa_stop(b.SPI_SA01)
        self.sdls.sa_expire(b.SPI_SA01)
        self.assertSaError(b.SA_UNKNOWN_KEY, self.sdls.sa_rekey, b.SPI_SA01, b.KEYID_SESS_TC)
        self.sdls.sa_set_key(b.KEYID_SESS_TC, KEY_B)
        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)

    def test_key_value_is_not_exported(self):
        self.assertFalse(hasattr(self.sdls.lib, "SA_myCopySaKey"))

    # --- send side IV -----------------------------------------------------------------

    def test_next_iv_counts_up_from_one(self):
        self.bring_up_tc()
        ivs = [iv_int(self.sdls.sa_next_iv(b.SPI_SA01)) for _ in range(300)]
        self.assertEqual(ivs, list(range(1, 301)))
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA01).iv)), 301)

    def test_rekey_restarts_the_iv(self):
        self.bring_up_tc()
        self.sdls.sa_next_iv(b.SPI_SA01)
        self.sdls.sa_stop(b.SPI_SA01)
        self.sdls.sa_expire(b.SPI_SA01)
        self.bring_up_tc(KEY_B)
        self.assertEqual(iv_int(self.sdls.sa_next_iv(b.SPI_SA01)), 1)

    def test_next_iv_needs_an_operational_tc_sa(self):
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_next_iv, b.SPI_SA01)  # Unkeyed
        self.sdls.sa_set_key(b.KEYID_SESS_TC, KEY_A)
        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_next_iv, b.SPI_SA01)  # Keyed
        self.bring_up_tm()
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_next_iv, b.SPI_SA11)  # TM SA
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_next_iv, b.SPI_SA00)  # no protection

    # --- receive side ARSN ------------------------------------------------------------

    def test_arsn_window(self):
        self.bring_up_tm()  # last accepted ARSN = 0, window 64
        self.sdls.sa_check_arsn(b.SPI_SA11, iv_bytes(1))  # the satellite's first IV
        self.sdls.sa_check_arsn(b.SPI_SA11, iv_bytes(64))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(0))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(65))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(1 << 64))

    def test_rekey_starts_tc_at_1_and_tm_at_0(self):
        self.sdls.sa_set_key(b.KEYID_SESS_TC, KEY_A)
        self.sdls.sa_set_key(b.KEYID_SESS_TM, KEY_B)
        self.sdls.sa_rekey(b.SPI_SA01, b.KEYID_SESS_TC)
        self.sdls.sa_rekey(b.SPI_SA11, b.KEYID_SESS_TM)
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA01).iv)), 1)  # next IV to send
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA11).iv)), 0)  # last accepted

    def test_check_does_not_change_the_sa(self):
        self.bring_up_tm()
        self.sdls.sa_check_arsn(b.SPI_SA11, iv_bytes(10))
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA11).iv)), 0)

    def test_commit_moves_the_window(self):
        self.bring_up_tm()
        self.sdls.sa_commit_arsn(b.SPI_SA11, iv_bytes(5))
        self.assertEqual(iv_int(bytes(self.sdls.sa_get(b.SPI_SA11).iv)), 5)
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(5))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_commit_arsn, b.SPI_SA11, iv_bytes(4))
        self.sdls.sa_check_arsn(b.SPI_SA11, iv_bytes(69))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(70))

    def test_arsn_carries_across_bytes(self):
        self.bring_up_tm()
        for arsn in (64, 128, 192, 0xF0):  # walk up within the window to 0xF0
            self.sdls.sa_commit_arsn(b.SPI_SA11, iv_bytes(arsn))
        self.sdls.sa_check_arsn(b.SPI_SA11, iv_bytes(0x130))  # diff 64, borrows across a byte
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(0x131))
        self.assertSaError(b.SA_REPLAY, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(0xEF))

    def test_arsn_needs_an_operational_tm_sa(self):
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_check_arsn, b.SPI_SA11, iv_bytes(2))
        self.bring_up_tc()
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_check_arsn, b.SPI_SA01, iv_bytes(2))
        self.assertSaError(b.SA_INVALID_STATE, self.sdls.sa_commit_arsn, b.SPI_SA10, iv_bytes(2))


class SaShmMultiProcessTest(SaShmTestBase):
    def run_in_child(self, func, *args):
        with self.ctx.Pool(1) as pool:
            return pool.apply(func, args)

    def test_call_before_open_fails_in_a_fresh_process(self):
        self.assertEqual(self.run_in_child(_worker_get_without_open, b.SPI_SA01), b.SA_NOT_OPEN)

    def test_child_sees_state_set_by_parent(self):
        self.bring_up_tc()
        state, key_id, iv = self.run_in_child(_worker_read_sa, self.name, b.SPI_SA01)
        self.assertEqual((state, key_id, iv), (b.SA_STATE_OPERATIONAL, b.KEYID_SESS_TC, 1))

    def test_parent_sees_state_set_by_child(self):
        self.run_in_child(_worker_bring_up_tm, self.name)
        sa = self.sdls.sa_get(b.SPI_SA11)
        self.assertEqual((sa.state, sa.auth_key_id), (b.SA_STATE_OPERATIONAL, b.KEYID_SESS_TM))

    def test_iv_counter_continues_across_processes(self):
        self.bring_up_tc()
        self.assertEqual(iv_int(self.sdls.sa_next_iv(b.SPI_SA01)), 1)
        self.assertEqual(self.run_in_child(_worker_next_ivs, self.name, b.SPI_SA01, 3), [2, 3, 4])
        self.assertEqual(iv_int(self.sdls.sa_next_iv(b.SPI_SA01)), 5)

    def test_concurrent_senders_never_share_an_iv(self):
        self.bring_up_tc()
        workers, per_worker = 4, 500
        with self.ctx.Pool(workers) as pool:
            results = pool.starmap(_worker_next_ivs, [(self.name, b.SPI_SA01, per_worker)] * workers)
        ivs = [iv for result in results for iv in result]
        self.assertEqual(sorted(ivs), list(range(1, workers * per_worker + 1)))
        for result in results:
            self.assertEqual(result, sorted(result), "each process sees increasing IVs")

    def test_segments_with_different_names_are_independent(self):
        other = self.name + "_other"
        try:
            self.bring_up_tc()
            state, _, _ = self.run_in_child(_worker_read_sa, other, b.SPI_SA01)
            self.assertEqual(state, b.SA_STATE_UNKEYED)
        finally:
            self.sdls.sa_unlink(other)


if __name__ == "__main__":
    unittest.main()
