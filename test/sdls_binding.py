"""ctypes binding for libsdls.so (ground side SDLP / SDLS / EP).

The ground system can use this module as is, or as a reference for its own binding.

ctypes cannot read #define values, so the constants below are copied from the headers
in include/ (tc_sdlp_my.h, tm_sdlp_my.h, sa/, sdls/, ep/). Keep them in sync.
"""

import ctypes
import os
import pathlib

# --- Constants mirrored from the C headers -------------------------------------------

# TC (include/tc_sdlp_my.h, include/tf/tctf_my.h)
TCTF_PRIHDR_LENGTH = 5
TCTF_MAX_FRAME_LENGTH = 1024
TC_SPP_HDR_LENGTH = 6
TC_SPP_MIN_LENGTH = 7
TC_SDLS_HDR_LENGTH = 14  # Security Header: SPI 2 + IV 12
TC_SDLS_TRL_LENGTH = 16  # Security Trailer: MAC (zero filled on SA00)
TC_FECF_LENGTH = 0
TC_MAX_PACKET_LENGTH = (
    TCTF_MAX_FRAME_LENGTH - TCTF_PRIHDR_LENGTH - TC_SDLS_HDR_LENGTH - TC_SDLS_TRL_LENGTH - TC_FECF_LENGTH
)
TC_DUMMY_TFVN = 0
TC_DUMMY_SCID = 0x003
TC_DUMMY_VCID = 0
TC_BYPASS_FLG = 1
TC_CTLCMD_FLG = 0

TC_SUCCESS = 0
TC_INVALID_ARGUMENT = -2
TC_INVALID_LENGTH = -3
TC_INVALID_PACKET = -4
TC_SECURITY_ERROR = -6
TC_BUFFER_TOO_SMALL = -7
TC_NOT_INITIALIZED = -8

TC_ERROR_NAMES = {
    TC_INVALID_ARGUMENT: "TC_SDLP_MY_INVALID_ARGUMENT",
    TC_INVALID_LENGTH: "TC_SDLP_MY_INVALID_LENGTH",
    TC_INVALID_PACKET: "TC_SDLP_MY_INVALID_PACKET",
    TC_SECURITY_ERROR: "TC_SDLP_MY_SECURITY_ERROR",
    TC_BUFFER_TOO_SMALL: "TC_SDLP_MY_BUFFER_TOO_SMALL",
    TC_NOT_INITIALIZED: "TC_SDLP_MY_NOT_INITIALIZED",
}

# TM (include/tm_sdlp_my.h, include/tf/tmtf_my.h)
TMTF_PRIHDR_LENGTH = 6
TMTF_SEGLENGTHID_PKT = 3
TM_FRAME_SIZE = 1786
TM_SDLS_HDR_LENGTH = 14
TM_SDLS_TRL_LENGTH = 16  # Security Trailer: MAC (zero filled on SA10)
TM_DATA_OFFSET = TMTF_PRIHDR_LENGTH + TM_SDLS_HDR_LENGTH
TM_DATA_END = TM_FRAME_SIZE - TM_SDLS_TRL_LENGTH
TM_DATA_LENGTH = TM_DATA_END - TM_DATA_OFFSET
TM_SPP_MIN_LENGTH = 7
TM_IDLE_MIN_LENGTH = 7
TM_IDLE_APID = 0x7FF
TM_DUMMY_TFVN = 0
TM_DUMMY_SCID = 0x003
TM_DUMMY_VCID = 1

TM_SUCCESS = 0
TM_INVALID_ARGUMENT = -2
TM_INVALID_LENGTH = -3
TM_INVALID_PACKET = -4
TM_INVALID_HEADER = -5
TM_SECURITY_ERROR = -6

TM_ERROR_NAMES = {
    TM_INVALID_ARGUMENT: "TM_SDLP_MY_INVALID_ARGUMENT",
    TM_INVALID_LENGTH: "TM_SDLP_MY_INVALID_LENGTH",
    TM_INVALID_PACKET: "TM_SDLP_MY_INVALID_PACKET",
    TM_INVALID_HEADER: "TM_SDLP_MY_INVALID_HEADER",
    TM_SECURITY_ERROR: "TM_SDLP_MY_SECURITY_ERROR",
}

# SDLS frame protection (include/sdls/sdls_my.h)
SDLS_TRAILER_LENGTH = 16
SDLS_CRYPTO_ERROR = -20
SDLS_AUTH_FAIL = -21
SDLS_UNSUPPORTED = -22

# Key exchange (include/ep/ep_my.h, include/sa/sa_my.h)
KEM_PK_LEN = 1184  # ML-KEM-768 ek
KEM_SK_LEN = 2400
KEM_CT_LEN = 1088
DSA_PK_LEN = 1952  # ML-DSA-65
DSA_SK_LEN = 4032
DSA_SIG_LEN = 3309
EP_DSA_CONTEXT = b"lib-sdls EP v1"
EP_KDF_INFO_TC = b"lib-sdls SESS_TC v1"
EP_KDF_INFO_TM = b"lib-sdls SESS_TM v1"
EP_CRYPTO_ERROR = -30
EP_NO_PENDING = -31
EP_UNSUPPORTED = -32

# SA / Key DB in shared memory (include/sa/sa_shm_my.h, include/sa/sa_my.h)
SA_SHM_DEFAULT_NAME = "/sdls_sa_db"

SPI_SA00 = 0x0000  # PQC key exchange, TC
SPI_SA01 = 0x0001  # session, TC (ground sends)
SPI_SA10 = 0xFFFF  # PQC key exchange, TM
SPI_SA11 = 0x0002  # session, TM (ground receives)

KEYID_SESS_TC = 0x0080
KEYID_SESS_TM = 0x0081
KEYID_NONE = 0xFFFF
AES256_KEY_LEN = 32
GCM_IV_LEN = 12

SA_STATE_NULL = 0
SA_STATE_UNKEYED = 1
SA_STATE_KEYED = 2
SA_STATE_OPERATIONAL = 3

PID_CREATE_SA = 0x1
PID_DELETE_SA = 0x4
PID_REKEY_SA = 0x6
PID_EXPIRE_SA = 0x9
PID_START_SA = 0xB
PID_STOP_SA = 0xE

SA_SUCCESS = 0
SA_INVALID_ARGUMENT = -2
SA_NOT_OPEN = -8
SA_SHM_ERROR = -9
SA_LAYOUT_MISMATCH = -10
SA_LOCK_ERROR = -11
SA_UNKNOWN_SPI = -12
SA_INVALID_STATE = -13
SA_UNKNOWN_KEY = -14
SA_KEY_IN_USE = -15
SA_IV_EXHAUSTED = -16
SA_REPLAY = -17

SA_ERROR_NAMES = {
    SA_INVALID_ARGUMENT: "SA_MY_INVALID_ARGUMENT",
    SA_NOT_OPEN: "SA_MY_NOT_OPEN",
    SA_SHM_ERROR: "SA_MY_SHM_ERROR",
    SA_LAYOUT_MISMATCH: "SA_MY_LAYOUT_MISMATCH",
    SA_LOCK_ERROR: "SA_MY_LOCK_ERROR",
    SA_UNKNOWN_SPI: "SA_MY_UNKNOWN_SPI",
    SA_INVALID_STATE: "SA_MY_INVALID_STATE",
    SA_UNKNOWN_KEY: "SA_MY_UNKNOWN_KEY",
    SA_KEY_IN_USE: "SA_MY_KEY_IN_USE",
    SA_IV_EXHAUSTED: "SA_MY_IV_EXHAUSTED",
    SA_REPLAY: "SA_MY_REPLAY",
    SDLS_CRYPTO_ERROR: "SDLS_MY_CRYPTO_ERROR",
    SDLS_AUTH_FAIL: "SDLS_MY_AUTH_FAIL",
    SDLS_UNSUPPORTED: "SDLS_MY_UNSUPPORTED",
    EP_CRYPTO_ERROR: "EP_MY_CRYPTO_ERROR",
    EP_NO_PENDING: "EP_MY_NO_PENDING",
    EP_UNSUPPORTED: "EP_MY_UNSUPPORTED",
}


# SDLS Security Header (include/sdls/sechdr_my.h): SPI 2 + IV 12, big endian
SECHDR_SPI_LENGTH = 2
SECHDR_IV_LENGTH = 12
SECHDR_LENGTH = SECHDR_SPI_LENGTH + SECHDR_IV_LENGTH


class CommonSa(ctypes.Structure):
    """Mirror of common_sa_t (include/sa/sa_my.h). ctypes applies the same natural
    alignment as the C compiler; Sdls() checks the size against SA_mySaSize()."""

    _fields_ = [
        ("spi", ctypes.c_uint16),
        ("dir", ctypes.c_uint8),
        ("gvcid", ctypes.c_uint32),
        ("service_type", ctypes.c_uint8),
        ("len_iv", ctypes.c_uint8),
        ("len_sn", ctypes.c_uint8),
        ("len_pl", ctypes.c_uint8),
        ("len_mac", ctypes.c_uint8),
        ("auth_alg", ctypes.c_uint8),
        ("enc_alg", ctypes.c_uint8),
        ("auth_mask_prihdr", ctypes.c_uint8 * 6),
        ("auth_mask_len", ctypes.c_uint8),
        ("arsn_window", ctypes.c_uint32),
        ("auth_key_id", ctypes.c_uint16),
        ("enc_key_id", ctypes.c_uint16),
        ("iv", ctypes.c_uint8 * GCM_IV_LEN),
        ("state", ctypes.c_uint8),
        ("last_pid", ctypes.c_uint8),
    ]

# --- Library loading ------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_LIB_PATHS = (REPO_ROOT / "build" / "libsdls.so",)


class SdlsError(Exception):
    """A libsdls.so function returned a negative error code."""

    def __init__(self, func, code, names):
        self.func = func
        self.code = code
        super().__init__(f"{func} failed: {names.get(code, 'UNKNOWN')} ({code})")


def find_library():
    """Returns the libsdls.so path: $SDLS_LIB first, then build/libsdls.so."""
    env_path = os.environ.get("SDLS_LIB")
    if env_path:
        return env_path
    for path in DEFAULT_LIB_PATHS:
        if path.exists():
            return str(path)
    raise FileNotFoundError(
        "libsdls.so not found. Build it with 'cmake -S . -B build && cmake --build build' "
        "or set SDLS_LIB to the library path."
    )


class Sdls:
    """Loads libsdls.so and wraps its functions.

    `lib` exposes the raw C functions (with argtypes/restype set) for callers that want
    the return codes. The methods raise SdlsError instead.
    """

    def __init__(self, path=None):
        self.path = path or find_library()
        lib = ctypes.CDLL(self.path)

        lib.TC_SDLP_myInit.argtypes = []
        lib.TC_SDLP_myInit.restype = ctypes.c_int32

        lib.TC_SDLP_myBuildFrame.argtypes = [ctypes.c_uint16, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        lib.TC_SDLP_myBuildFrame.restype = ctypes.c_int32

        lib.TM_SDLP_myExtractPacket.argtypes = [
            ctypes.c_void_p,  # writable frame buffer: SA11 frames are decrypted in place
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        lib.TM_SDLP_myExtractPacket.restype = ctypes.c_int32

        u16, i32, p = ctypes.c_uint16, ctypes.c_int32, ctypes.c_void_p
        for name, argtypes in (
            ("SA_myOpen", [ctypes.c_char_p]),
            ("SA_myClose", []),
            ("SA_myUnlink", [ctypes.c_char_p]),
            ("SA_myGetSa", [u16, ctypes.POINTER(CommonSa)]),
            ("SA_myRekey", [u16, u16]),
            ("SA_myStart", [u16]),
            ("SA_myStop", [u16]),
            ("SA_myExpire", [u16]),
            ("SA_mySetKey", [u16, p, ctypes.c_size_t]),
            ("SA_myNextIv", [u16, p]),
            ("SA_myCheckArsn", [u16, p]),
            ("SA_myCommitArsn", [u16, p]),
            ("SECHDR_myApplyTc", [u16, p, ctypes.c_size_t, p]),
            ("SECHDR_myProcessTm", [p, ctypes.c_size_t, ctypes.POINTER(u16), p]),
            ("SA_mySetDsaKey", [p, ctypes.c_size_t, p, ctypes.c_size_t]),
            ("SDLS_myApplySecurityTc", [u16, p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t]),
            ("SDLS_myProcessSecurityTm", [p, ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(u16)]),
            ("EP_myAcceptKemPublicKey", [p, ctypes.c_size_t, p, ctypes.c_size_t]),
            ("EP_myGetPendingCiphertext", [p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
            ("EP_mySign", [p, ctypes.c_size_t, p, ctypes.POINTER(ctypes.c_size_t)]),
            ("EP_myStartSessions", []),
        ):
            func = getattr(lib, name)
            func.argtypes = argtypes
            func.restype = i32
        lib.SA_mySaSize.argtypes = []
        lib.SA_mySaSize.restype = ctypes.c_size_t
        if lib.SA_mySaSize() != ctypes.sizeof(CommonSa):
            raise RuntimeError("CommonSa does not match common_sa_t; update sdls_binding.py")

        self.lib = lib

    def tc_init(self):
        status = self.lib.TC_SDLP_myInit()
        if status != TC_SUCCESS:
            raise SdlsError("TC_SDLP_myInit", status, TC_ERROR_NAMES)

    def tc_build_frame(self, spi, packet):
        """Wraps one Space Packet into a TC frame on the SA spi and returns the frame
        bytes. Needs sa_open() first. SPI_SA00 for EP PDUs, SPI_SA01 for session traffic."""
        packet = bytes(packet)
        buf = ctypes.create_string_buffer(TCTF_MAX_FRAME_LENGTH)
        status = self.lib.TC_SDLP_myBuildFrame(spi, packet, len(packet), buf, len(buf))
        if status < 0:
            raise SdlsError("TC_SDLP_myBuildFrame", status, TC_ERROR_NAMES)
        return buf.raw[:status]

    def tm_extract(self, frame):
        """Processes one TM frame. Returns (spi, packets): the SA it came on and every
        Space Packet in it, in order (decrypted for SA11). Needs sa_open() first.

        Route by spi: SPI_SA10 packets are unauthenticated EP PDUs (key exchange handler
        only), SPI_SA11 packets are protected telemetry."""
        frame = bytes(frame)
        buf = ctypes.create_string_buffer(frame, len(frame))  # writable: decrypted in place
        cursor = ctypes.c_size_t(0)
        offset = ctypes.c_size_t(0)
        spi = ctypes.c_uint16(0)
        packets = []
        while True:
            status = self.lib.TM_SDLP_myExtractPacket(
                buf, len(frame), ctypes.byref(cursor), ctypes.byref(offset), ctypes.byref(spi)
            )
            if status < 0:
                raise SdlsError("TM_SDLP_myExtractPacket", status, TM_ERROR_NAMES)
            if status == 0:
                return spi.value, packets
            packets.append(buf.raw[offset.value : offset.value + status])

    def tm_extract_packets(self, frame):
        """Every Space Packet in one TM frame, in order (see tm_extract)."""
        return self.tm_extract(frame)[1]

    # --- SA / Key DB (shared memory) -------------------------------------------------
    # The sender and receiver processes both call sa_open() with the same name and then
    # see one SA DB. State changes made by one process are visible to the other at once.

    def _sa_call(self, name, *args):
        status = getattr(self.lib, name)(*args)
        if status != SA_SUCCESS:
            raise SdlsError(name, status, SA_ERROR_NAMES)

    @staticmethod
    def _shm_name(name):
        return None if name is None else name.encode()

    def sa_open(self, name=None):
        """Creates or attaches the shared SA DB (default SA_SHM_DEFAULT_NAME)."""
        self._sa_call("SA_myOpen", self._shm_name(name))

    def sa_close(self):
        self._sa_call("SA_myClose")

    def sa_unlink(self, name=None):
        """Removes the segment; the next sa_open() starts again from the defaults."""
        self._sa_call("SA_myUnlink", self._shm_name(name))

    def sa_get(self, spi):
        sa = CommonSa()
        self._sa_call("SA_myGetSa", spi, ctypes.byref(sa))
        return sa

    def sa_rekey(self, spi, key_id):
        self._sa_call("SA_myRekey", spi, key_id)

    def sa_start(self, spi):
        self._sa_call("SA_myStart", spi)

    def sa_stop(self, spi):
        self._sa_call("SA_myStop", spi)

    def sa_expire(self, spi):
        self._sa_call("SA_myExpire", spi)

    def sa_set_key(self, key_id, key):
        key = bytes(key)
        self._sa_call("SA_mySetKey", key_id, key, len(key))

    def sa_set_dsa_key(self, pk, sk):
        """Loads the ground ML-DSA-65 key pair that signs EP PDUs."""
        pk, sk = bytes(pk), bytes(sk)
        self._sa_call("SA_mySetDsaKey", pk, len(pk), sk, len(sk))

    def sa_next_iv(self, spi):
        iv = ctypes.create_string_buffer(GCM_IV_LEN)
        self._sa_call("SA_myNextIv", spi, iv)
        return iv.raw

    def sa_check_arsn(self, spi, iv):
        self._sa_call("SA_myCheckArsn", spi, bytes(iv))

    def sa_commit_arsn(self, spi, iv):
        self._sa_call("SA_myCommitArsn", spi, bytes(iv))

    # --- SDLS Security Header ---------------------------------------------------------
    # Return codes are SA_MY_* codes.

    def sechdr_apply_tc(self, spi):
        """Builds the TC Security Header for one frame. Returns (header bytes, iv)."""
        hdr = ctypes.create_string_buffer(SECHDR_LENGTH)
        iv = ctypes.create_string_buffer(SECHDR_IV_LENGTH)
        self._sa_call("SECHDR_myApplyTc", spi, hdr, len(hdr), iv)
        return hdr.raw, iv.raw

    def sechdr_process_tm(self, hdr):
        """Checks a TM Security Header. Returns (spi, iv); the ARSN is not committed."""
        hdr = bytes(hdr)
        spi = ctypes.c_uint16()
        iv = ctypes.create_string_buffer(SECHDR_IV_LENGTH)
        self._sa_call("SECHDR_myProcessTm", hdr, len(hdr), ctypes.byref(spi), iv)
        return spi.value, iv.raw

    # --- SDLS frame protection ----------------------------------------------------------

    def sdls_process_tm(self, frame):
        """Runs SDLS ProcessSecurity on a whole TM frame. Returns (spi, processed frame):
        a protected frame comes back with its data field decrypted."""
        buf = ctypes.create_string_buffer(bytes(frame), len(frame))
        spi = ctypes.c_uint16()
        self._sa_call("SDLS_myProcessSecurityTm", buf, len(frame), TMTF_PRIHDR_LENGTH, ctypes.byref(spi))
        return spi.value, buf.raw

    # --- Key exchange (EP) --------------------------------------------------------------

    def ep_accept_kem_public_key(self, ek):
        """Ground side of the key exchange: encapsulates to the satellite ek, loads the
        derived session keys (SA01/SA11 Keyed) and returns the ciphertext for StartSA."""
        ek = bytes(ek)
        ct = ctypes.create_string_buffer(KEM_CT_LEN)
        self._sa_call("EP_myAcceptKemPublicKey", ek, len(ek), ct, len(ct))
        return ct.raw

    def ep_pending_ciphertext(self):
        """The ciphertext of the exchange in progress (any process). SdlsError
        EP_NO_PENDING when there is none."""
        ct = ctypes.create_string_buffer(KEM_CT_LEN)
        n = ctypes.c_size_t(0)
        self._sa_call("EP_myGetPendingCiphertext", ct, len(ct), ctypes.byref(n))
        return ct.raw[: n.value]

    def ep_sign(self, msg):
        """ML-DSA-65 signature of an EP PDU with the ground key and EP_DSA_CONTEXT."""
        msg = bytes(msg)
        sig = ctypes.create_string_buffer(DSA_SIG_LEN)
        n = ctypes.c_size_t(len(sig))
        self._sa_call("EP_mySign", msg, len(msg), sig, ctypes.byref(n))
        return sig.raw[: n.value]

    def ep_start_sessions(self):
        """After the satellite confirmed StartSA: SA01 / SA11 -> Operational."""
        self._sa_call("EP_myStartSessions")
