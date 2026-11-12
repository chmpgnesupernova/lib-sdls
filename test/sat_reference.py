"""Python port of the satellite (cFS) side SDLP code, used as the test reference.

- sat_tc_extract_packet mirrors TC_SDLP_myExtractPacket (CI side, TC receive).
- SatTmFramer mirrors TM_SDLP_myInit / TM_SDLP_myForwardPacket / TM_SDLP_mySendFrame
  (TO side, TM send).

The ground side library must interoperate with this code byte for byte.
"""

import sdls_binding as b


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


def sat_tc_extract_packet(frame):
    """Mirrors TC_SDLP_myExtractPacket. Returns the packet or raises SatTcDrop."""
    frame_size = len(frame)
    data_offset = b.TCTF_PRIHDR_LENGTH + b.TC_SDLS_HDR_LENGTH
    packet_size = frame_size - data_offset - b.TC_SDLS_TRL_LENGTH - b.TC_FECF_LENGTH

    if packet_size < b.TC_SPP_MIN_LENGTH:
        raise SatTcDrop(f"too short ({frame_size})")

    hdr = tc_header_fields(frame)
    if hdr["framelen"] + 1 != frame_size:
        raise SatTcDrop(f"length field {hdr['framelen'] + 1} != received {frame_size}")

    packet_length_field = (frame[data_offset + 4] << 8) | frame[data_offset + 5]
    if packet_length_field + b.TC_SPP_MIN_LENGTH != packet_size:
        raise SatTcDrop(f"packet size {packet_length_field + b.TC_SPP_MIN_LENGTH} != data field {packet_size}")

    return frame[data_offset : data_offset + packet_size]


# --- TM: satellite send side ---------------------------------------------------------


class SatTmFramer:
    """Mirrors the satellite TM_SDLP_my* functions. Sent frames collect in `sent`."""

    def __init__(self, scid=b.TM_DUMMY_SCID, vcid=b.TM_DUMMY_VCID, tfvn=b.TM_DUMMY_TFVN):
        # TM_SDLP_myInit
        self.data_field_offset = b.TMTF_PRIHDR_LENGTH + b.TM_SDLS_HDR_LENGTH
        self.data_field_length = b.TM_FRAME_SIZE - self.data_field_offset - b.TM_SDLS_TRL_LENGTH
        self.free_octets = self.data_field_length
        self.mc_frame_count = 0
        self.frame = bytearray(b.TM_FRAME_SIZE)
        self.current_data_offset = self.data_field_offset
        self.sent = []

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

    def _complete_frame(self):
        self.mc_frame_count = (self.mc_frame_count + 1) & 0xFF
        self.frame[2] = self.mc_frame_count
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
