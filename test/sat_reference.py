"""Python port of the satellite (cFS) side SDLP code, used as the test reference.

- sat_tc_extract_packet mirrors TC_SDLP_myExtractPacket (CI side, TC receive).
- SatTmFramer mirrors TM_SDLP_myInit / TM_SDLP_myForwardPacket / TM_SDLP_mySendFrame
  (TO side, TM send).

The Security Header (SPI 2 + IV 12, big endian) follows the Primary Header and the
Security Trailer (16 byte MAC) ends the frame, in both directions. Session SAs (SA01 TC,
SA11 TM) encrypt the data field with AES-256-GCM:

    AAD = (Primary Header AND mask) || Security Header (SPI + IV)   nonce = IV   MAC = GCM tag
    TC mask: all 5 bytes      TM mask: all 6 bytes except the MC Frame Count (byte 2)

EP SAs (SA00, SA10) zero fill the IV and the MAC. The frame layout and the AAD rule here
are written from the agreement, independently of the C library; only the AES-GCM, ML-KEM
and ML-DSA primitives come from libsdls_satsim.so (SatCrypto), the same wolfCrypt code the
satellite is expected to build.

The ground side library must interoperate with this code byte for byte.
"""

import ctypes
import os
import pathlib

import sdls_binding as b

TC_AUTH_MASK = b"\xff" * b.TCTF_PRIHDR_LENGTH
TM_AUTH_MASK = bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF])


def masked(header, mask):
    return bytes(h & m for h, m in zip(header, mask))


# --- satellite crypto primitives (libsdls_satsim.so) --------------------------------------


class SatAuthFail(Exception):
    """A MAC or signature did not verify on the satellite side."""


class SatCrypto:
    """ctypes wrapper of libsdls_satsim.so: the satellite end of AES-GCM, ML-KEM, ML-DSA."""

    def __init__(self, path=None):
        lib = ctypes.CDLL(path or find_satsim_library())
        p, n, i32 = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int32
        for name, argtypes in (
            ("SATSIM_myKemKeygen", [p, p]),
            ("SATSIM_myKemAccept", [p, p, p, p]),
            ("SATSIM_myDsaKeygen", [p, p]),
            ("SATSIM_myDsaVerify", [p, p, n, p, n]),
            ("SATSIM_myGcmEncrypt", [p, p, p, n, p, n, p]),
            ("SATSIM_myGcmDecrypt", [p, p, p, n, p, n, p]),
        ):
            func = getattr(lib, name)
            func.argtypes = argtypes
            func.restype = i32
        self.lib = lib

    def kem_keygen(self):
        pk, sk = ctypes.create_string_buffer(b.KEM_PK_LEN), ctypes.create_string_buffer(b.KEM_SK_LEN)
        assert self.lib.SATSIM_myKemKeygen(pk, sk) == 0
        return pk.raw, sk.raw

    def kem_accept(self, sk, ct):
        """Decaps + the agreed HKDF. Returns (K_TC, K_TM)."""
        ktc, ktm = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
        assert self.lib.SATSIM_myKemAccept(bytes(sk), bytes(ct), ktc, ktm) == 0
        return ktc.raw, ktm.raw

    def dsa_keygen(self):
        pk, sk = ctypes.create_string_buffer(b.DSA_PK_LEN), ctypes.create_string_buffer(b.DSA_SK_LEN)
        assert self.lib.SATSIM_myDsaKeygen(pk, sk) == 0
        return pk.raw, sk.raw

    def dsa_verify(self, pk, msg, sig):
        return self.lib.SATSIM_myDsaVerify(bytes(pk), bytes(msg), len(msg), bytes(sig), len(sig)) == 0

    def gcm_encrypt(self, key, iv, aad, data):
        buf, tag = ctypes.create_string_buffer(bytes(data), len(data)), ctypes.create_string_buffer(16)
        assert self.lib.SATSIM_myGcmEncrypt(bytes(key), bytes(iv), bytes(aad), len(aad), buf, len(data), tag) == 0
        return buf.raw, tag.raw

    def gcm_decrypt(self, key, iv, aad, data, tag):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        rc = self.lib.SATSIM_myGcmDecrypt(bytes(key), bytes(iv), bytes(aad), len(aad), buf, len(data), bytes(tag))
        if rc != 0:
            raise SatAuthFail(f"GCM tag did not verify ({rc})")
        return buf.raw


def find_satsim_library():
    """$SDLS_SATSIM_LIB, else libsdls_satsim.so next to libsdls.so."""
    env_path = os.environ.get("SDLS_SATSIM_LIB")
    if env_path:
        return env_path
    path = pathlib.Path(b.find_library()).resolve().parent / "libsdls_satsim.so"
    if path.exists():
        return str(path)
    raise FileNotFoundError("libsdls_satsim.so not found: build with SDLS_BUILD_TESTS=ON or set SDLS_SATSIM_LIB")


_sat_crypto = None


def sat_crypto():
    global _sat_crypto
    if _sat_crypto is None:
        _sat_crypto = SatCrypto()
    return _sat_crypto


def make_spp(apid, data, seq_flags=0x3, seq_count=0):
    """Builds one CCSDS Space Packet (telecommand/telemetry type bits left 0)."""
    if not data:
        raise ValueError("a Space Packet needs at least 1 data byte")
    length_field = len(data) - 1
    return (
        bytes(
            [
                (apid >> 8) & 0x07,
                apid & 0xFF,
                ((seq_flags & 0x3) << 6) | ((seq_count >> 8) & 0x3F),
                seq_count & 0xFF,
                (length_field >> 8) & 0xFF,
                length_field & 0xFF,
            ]
        )
        + bytes(data)
    )


# --- TC: satellite receive side ------------------------------------------------------


class SatTcDrop(Exception):
    """The satellite side would drop this TC frame."""


def tc_header_fields(frame):
    """Reads the TC primary header with the satellite side TCTF_MY_RD_* layout."""
    return {
        "tfvn": (frame[0] >> 6) & 0x03,
        "bypass": (frame[0] >> 5) & 0x01,
        "ctlcmd": (frame[0] >> 4) & 0x01,
        "scid": ((frame[0] & 0x03) << 8) | frame[1],
        "vcid": (frame[2] >> 2) & 0x3F,
        "framelen": ((frame[2] & 0x03) << 8) | frame[3],
        "seq": frame[4],
    }


def sat_tc_extract_packet(frame, tc_key=None):
    """Mirrors TC_SDLP_myExtractPacket. Returns the packet or raises SatTcDrop.

    A frame on the session SA (SA01) is MAC checked and decrypted with tc_key; a frame on
    the EP SA (SA00) carries its packet in clear."""
    frame_size = len(frame)
    data_offset = b.TCTF_PRIHDR_LENGTH + b.TC_SDLS_HDR_LENGTH
    packet_size = frame_size - data_offset - b.TC_SDLS_TRL_LENGTH - b.TC_FECF_LENGTH

    if packet_size < b.TC_SPP_MIN_LENGTH:
        raise SatTcDrop(f"too short ({frame_size})")

    hdr = tc_header_fields(frame)
    if hdr["framelen"] + 1 != frame_size:
        raise SatTcDrop(f"length field {hdr['framelen'] + 1} != received {frame_size}")

    data = frame[data_offset : data_offset + packet_size]
    sec = tc_sechdr_fields(frame)
    if sec["spi"] == b.SPI_SA01:
        if tc_key is None:
            raise SatTcDrop("session frame but no TC key")
        hdr_end = b.TCTF_PRIHDR_LENGTH
        aad = masked(frame[:hdr_end], TC_AUTH_MASK) + frame[hdr_end : hdr_end + b.SECHDR_LENGTH]
        tag = frame[data_offset + packet_size : data_offset + packet_size + b.TC_SDLS_TRL_LENGTH]
        try:
            data = sat_crypto().gcm_decrypt(tc_key, sec["iv"].to_bytes(12, "big"), aad, data, tag)
        except SatAuthFail as exc:
            raise SatTcDrop(str(exc)) from exc
    elif sec["spi"] != b.SPI_SA00:
        raise SatTcDrop(f"unknown SPI {sec['spi']:#06x}")

    packet_length_field = (data[4] << 8) | data[5]
    if packet_length_field + b.TC_SPP_MIN_LENGTH != packet_size:
        raise SatTcDrop(f"packet size {packet_length_field + b.TC_SPP_MIN_LENGTH} != data field {packet_size}")

    return data


def tc_sechdr_fields(frame):
    """Reads the Security Header that follows the TC primary header."""
    start = b.TCTF_PRIHDR_LENGTH
    return {
        "spi": int.from_bytes(frame[start : start + b.SECHDR_SPI_LENGTH], "big"),
        "iv": int.from_bytes(frame[start + b.SECHDR_SPI_LENGTH : start + b.SECHDR_LENGTH], "big"),
    }


# --- TM: satellite send side ---------------------------------------------------------


class SatTmFramer:
    """Mirrors the satellite TM_SDLP_my* functions. Sent frames collect in `sent`.

    spi: SA written into every Security Header. SPI_SA10 (EP PDUs) zero fills the IV and
    the MAC; any other SA sends first_iv, first_iv + 1, ... (one per frame, like the
    satellite SA11 send side), and with key set encrypts the data field (AES-256-GCM).
    """

    def __init__(
        self,
        scid=b.TM_DUMMY_SCID,
        vcid=b.TM_DUMMY_VCID,
        tfvn=b.TM_DUMMY_TFVN,
        spi=b.SPI_SA10,
        first_iv=1,
        key=None,
    ):
        # TM_SDLP_myInit
        self.data_field_offset = b.TMTF_PRIHDR_LENGTH + b.TM_SDLS_HDR_LENGTH
        self.data_field_length = b.TM_FRAME_SIZE - self.data_field_offset - b.TM_SDLS_TRL_LENGTH
        self.free_octets = self.data_field_length
        self.mc_frame_count = 0
        self.frame = bytearray(b.TM_FRAME_SIZE)
        self.current_data_offset = self.data_field_offset
        self.sent = []
        self.spi = spi
        self.next_iv = first_iv
        self.key = key

        # TMTF_MY_WR_TF_VERSION / SCID / VCID / SEGLENGTHID / FIRSTHDRPTR(0)
        self.frame[0] = ((tfvn & 0x03) << 6) | ((scid >> 4) & 0x3F)
        self.frame[1] = ((scid & 0x0F) << 4) | ((vcid & 0x07) << 1)
        self.frame[4] = (b.TMTF_SEGLENGTHID_PKT << 3) & 0x18
        self.frame[5] = 0

    @staticmethod
    def _fits(packet_size, free_octets):
        return packet_size == free_octets or packet_size + b.TM_IDLE_MIN_LENGTH <= free_octets

    def _add_idle_packet(self):
        if self.free_octets == 0:
            return
        start = self.current_data_offset
        idle_length_field = self.free_octets - b.TM_IDLE_MIN_LENGTH
        self.frame[start : start + self.free_octets] = bytes(self.free_octets)
        self.frame[start + 0] = 0x07
        self.frame[start + 1] = 0xFF
        self.frame[start + 2] = 0xC0
        self.frame[start + 4] = (idle_length_field >> 8) & 0xFF
        self.frame[start + 5] = idle_length_field & 0xFF
        self.current_data_offset += self.free_octets
        self.free_octets = 0

    def _write_sechdr(self):
        if self.spi == b.SPI_SA10:
            iv = 0
        else:
            iv = self.next_iv
            self.next_iv += 1
        start = b.TMTF_PRIHDR_LENGTH
        self.frame[start : start + b.SECHDR_LENGTH] = self.spi.to_bytes(
            b.SECHDR_SPI_LENGTH, "big"
        ) + iv.to_bytes(b.SECHDR_IV_LENGTH, "big")
        return iv

    def _protect(self, iv):
        """Security Trailer: GCM over the data field for a keyed session SA, else zeros."""
        end = b.TM_DATA_END
        if self.spi == b.SPI_SA10 or self.key is None:
            self.frame[end:] = bytes(b.TM_SDLS_TRL_LENGTH)
            return
        hdr_end = b.TMTF_PRIHDR_LENGTH
        aad = masked(self.frame[:hdr_end], TM_AUTH_MASK) + bytes(self.frame[hdr_end : hdr_end + b.SECHDR_LENGTH])
        ct, tag = sat_crypto().gcm_encrypt(
            self.key, iv.to_bytes(12, "big"), aad, self.frame[self.data_field_offset : end]
        )
        self.frame[self.data_field_offset : end] = ct
        self.frame[end:] = tag

    def _complete_frame(self):
        self.mc_frame_count = (self.mc_frame_count + 1) & 0xFF
        self.frame[2] = self.mc_frame_count
        self._protect(self._write_sechdr())
        self.free_octets = self.data_field_length
        self.current_data_offset = self.data_field_offset

    def send_frame(self):
        """TM_SDLP_mySendFrame: an empty frame is not sent."""
        if self.free_octets == self.data_field_length:
            return
        self._add_idle_packet()
        self._complete_frame()
        self.sent.append(bytes(self.frame))

    def forward_packet(self, packet):
        """TM_SDLP_myForwardPacket: returns False if the packet is dropped as oversized."""
        size = len(packet)
        if not self._fits(size, self.data_field_length):
            return False
        if not self._fits(size, self.free_octets):
            self.send_frame()
        start = self.current_data_offset
        self.frame[start : start + size] = packet
        self.current_data_offset += size
        self.free_octets -= size
        if self.free_octets == 0:
            self.send_frame()
        return True
