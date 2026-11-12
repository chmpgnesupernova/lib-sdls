"""ctypes binding for libsdls.so (ground side SDLP).

The ground system can use this module as is, or as a reference for its own binding.

ctypes cannot read #define values, so the constants below are copied from
include/tc_sdlp_my.h and include/tm_sdlp_my.h. Keep them in sync with the headers.
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
TC_SDLS_HDR_LENGTH = 0
TC_SDLS_TRL_LENGTH = 0
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
TC_BUFFER_TOO_SMALL = -7
TC_NOT_INITIALIZED = -8

TC_ERROR_NAMES = {
    TC_INVALID_ARGUMENT: "TC_SDLP_MY_INVALID_ARGUMENT",
    TC_INVALID_LENGTH: "TC_SDLP_MY_INVALID_LENGTH",
    TC_INVALID_PACKET: "TC_SDLP_MY_INVALID_PACKET",
    TC_BUFFER_TOO_SMALL: "TC_SDLP_MY_BUFFER_TOO_SMALL",
    TC_NOT_INITIALIZED: "TC_SDLP_MY_NOT_INITIALIZED",
}

# TM (include/tm_sdlp_my.h, include/tf/tmtf_my.h)
TMTF_PRIHDR_LENGTH = 6
TMTF_SEGLENGTHID_PKT = 3
TM_FRAME_SIZE = 1786
TM_SDLS_HDR_LENGTH = 14
TM_SDLS_TRL_LENGTH = 0
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

TM_ERROR_NAMES = {
    TM_INVALID_ARGUMENT: "TM_SDLP_MY_INVALID_ARGUMENT",
    TM_INVALID_LENGTH: "TM_SDLP_MY_INVALID_LENGTH",
    TM_INVALID_PACKET: "TM_SDLP_MY_INVALID_PACKET",
    TM_INVALID_HEADER: "TM_SDLP_MY_INVALID_HEADER",
}

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

        lib.TC_SDLP_myBuildFrame.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        lib.TC_SDLP_myBuildFrame.restype = ctypes.c_int32

        lib.TM_SDLP_myExtractPacket.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.TM_SDLP_myExtractPacket.restype = ctypes.c_int32

        self.lib = lib

    def tc_init(self):
        status = self.lib.TC_SDLP_myInit()
        if status != TC_SUCCESS:
            raise SdlsError("TC_SDLP_myInit", status, TC_ERROR_NAMES)

    def tc_build_frame(self, packet):
        """Wraps one Space Packet into a TC frame and returns the frame bytes."""
        packet = bytes(packet)
        buf = ctypes.create_string_buffer(TCTF_MAX_FRAME_LENGTH)
        status = self.lib.TC_SDLP_myBuildFrame(packet, len(packet), buf, len(buf))
        if status < 0:
            raise SdlsError("TC_SDLP_myBuildFrame", status, TC_ERROR_NAMES)
        return buf.raw[:status]

    def tm_extract_packets(self, frame):
        """Returns every Space Packet in one TM frame, in order."""
        frame = bytes(frame)
        cursor = ctypes.c_size_t(0)
        offset = ctypes.c_size_t(0)
        packets = []
        while True:
            status = self.lib.TM_SDLP_myExtractPacket(frame, len(frame), ctypes.byref(cursor), ctypes.byref(offset))
            if status < 0:
                raise SdlsError("TM_SDLP_myExtractPacket", status, TM_ERROR_NAMES)
            if status == 0:
                return packets
            packets.append(frame[offset.value : offset.value + status])
