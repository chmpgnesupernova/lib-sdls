"""Builds complete frames with libsdls.so and prints them field by field.

    python3 test/frame_view.py            # every example frame
    python3 test/frame_view.py --hex      # also a full offset hex dump of each frame

Frames:
    TC: [Primary Header 5][Security Header 14: SPI 2 + IV 12][Space Packet][MAC 16]
    TM: [Primary Header 6][Security Header 14: SPI 2 + IV 12][Space Packets + idle][MAC 16]

TC frames come from the ground library (TC_SDLP_myBuildFrame): an SA01 frame is shown as
sent (data field encrypted). TM frames come from the satellite reference (SatTmFramer)
and are shown after the ground library processed them (SDLS_myProcessSecurityTm): an
SA11 frame is shown decrypted, with the MAC that verified.
The SA DB is a private shared memory segment, removed at the end.
"""

import os
import sys

import sdls_binding as b
from sat_reference import SatTmFramer, make_spp

SPI_NAMES = {
    b.SPI_SA00: "SA00 PQC key exchange TC",
    b.SPI_SA01: "SA01 session TC",
    b.SPI_SA10: "SA10 PQC key exchange TM",
    b.SPI_SA11: "SA11 session TM",
}

HEX_PREVIEW = 24  # bytes shown per data field line before "..."


# --- decoders (pure functions, checked by test_frame_view.py) ---------------------------


def decode_tc_prihdr(frame):
    return {
        "TFVN": (frame[0] >> 6) & 0x03,
        "Bypass": (frame[0] >> 5) & 0x01,
        "CtrlCmd": (frame[0] >> 4) & 0x01,
        "Spare": (frame[0] >> 2) & 0x03,
        "SCID": ((frame[0] & 0x03) << 8) | frame[1],
        "VCID": (frame[2] >> 2) & 0x3F,
        "FrameLen": ((frame[2] & 0x03) << 8) | frame[3],
        "Seq": frame[4],
    }


def decode_tm_prihdr(frame):
    return {
        "TFVN": (frame[0] >> 6) & 0x03,
        "SCID": ((frame[0] & 0x3F) << 4) | (frame[1] >> 4),
        "VCID": (frame[1] >> 1) & 0x07,
        "OCF": frame[1] & 0x01,
        "MCFrameCnt": frame[2],
        "VCFrameCnt": frame[3],
        "SegLenID": (frame[4] >> 3) & 0x03,
        "FirstHdrPtr": ((frame[4] & 0x07) << 8) | frame[5],
    }


def decode_sechdr(hdr):
    return {
        "SPI": int.from_bytes(hdr[: b.SECHDR_SPI_LENGTH], "big"),
        "IV": int.from_bytes(hdr[b.SECHDR_SPI_LENGTH : b.SECHDR_LENGTH], "big"),
    }


def decode_spp(packet):
    return {
        "APID": ((packet[0] & 0x07) << 8) | packet[1],
        "SeqFlags": (packet[2] >> 6) & 0x03,
        "SeqCount": ((packet[2] & 0x3F) << 8) | packet[3],
        "Length": (packet[4] << 8) | packet[5],
    }


def split_spps(data):
    """Splits a TM data field into (offset, packet) pairs, idle packet included."""
    out, offset = [], 0
    while offset + b.TM_SPP_MIN_LENGTH <= len(data):
        size = decode_spp(data[offset:])["Length"] + b.TM_SPP_MIN_LENGTH
        out.append((offset, data[offset : offset + size]))
        offset += size
    return out


# --- printing ---------------------------------------------------------------------------


def hexs(data, limit=None):
    data = bytes(data)
    if limit is not None and len(data) > limit:
        return data[:limit].hex(" ") + f" ... (+{len(data) - limit} B)"
    return data.hex(" ")


def fields(d):
    return "  ".join(f"{k}={v:#05x}" if k in ("SCID", "APID", "SPI") else f"{k}={v}" for k, v in d.items())


def section(title, start, data, detail=None, limit=None):
    end = start + len(data)
    print(f"  [{start:4d}..{end:4d}) {title} ({len(data)} B)")
    if data:
        print(f"      {hexs(data, limit)}")
    if detail:
        print(f"      {detail}")


def iv_note(sec):
    if sec["SPI"] in (b.SPI_SA00, b.SPI_SA10):
        return "(no frame protection: IV zero filled / ignored)"
    return f"(GCM nonce = ARSN {sec['IV']})"


def hexdump(frame):
    for off in range(0, len(frame), 16):
        print(f"      {off:04x}  {frame[off : off + 16].hex(' ')}")


def show_tc(title, frame, show_hex=False):
    pri_end = b.TCTF_PRIHDR_LENGTH
    sec_end = pri_end + b.TC_SDLS_HDR_LENGTH
    data_end = len(frame) - b.TC_SDLS_TRL_LENGTH - b.TC_FECF_LENGTH
    pri, sec = decode_tc_prihdr(frame), decode_sechdr(frame[pri_end:sec_end])

    print(f"=== TC frame: {title} ({len(frame)} B) ===")
    section("TC Primary Header", 0, frame[:pri_end],
            fields(pri) + f"  -> frame size {pri['FrameLen'] + 1} B")
    section("SDLS Security Header", pri_end, frame[pri_end:sec_end],
            f"SPI={sec['SPI']:#06x} [{SPI_NAMES.get(sec['SPI'], 'unknown')}]  IV={sec['IV']} {iv_note(sec)}")
    packet = frame[sec_end:data_end]
    if sec["SPI"] in (b.SPI_SA00, b.SPI_SA10):
        section("Data Field: Space Packet", sec_end, packet, fields(decode_spp(packet)), HEX_PREVIEW)
        section("SDLS Security Trailer (MAC zero filled: unprotected SA)", data_end, frame[data_end:])
    else:
        section("Data Field: Space Packet (AES-256-GCM ciphertext)", sec_end, packet, "", HEX_PREVIEW)
        section("SDLS Security Trailer (MAC = GCM tag)", data_end, frame[data_end:])
    if show_hex:
        hexdump(frame)
    print()


def show_tm(title, frame, show_hex=False):
    pri_end = b.TMTF_PRIHDR_LENGTH
    sec_end = pri_end + b.TM_SDLS_HDR_LENGTH
    data_end = b.TM_DATA_END
    pri, sec = decode_tm_prihdr(frame), decode_sechdr(frame[pri_end:sec_end])

    print(f"=== TM frame: {title} ({len(frame)} B) ===")
    section("TM Primary Header", 0, frame[:pri_end], fields(pri))
    section("SDLS Security Header", pri_end, frame[pri_end:sec_end],
            f"SPI={sec['SPI']:#06x} [{SPI_NAMES.get(sec['SPI'], 'unknown')}]  IV={sec['IV']} {iv_note(sec)}")
    for offset, packet in split_spps(frame[sec_end:data_end]):
        spp = decode_spp(packet)
        name = "idle packet" if spp["APID"] == b.TM_IDLE_APID else "Space Packet"
        section(f"Data Field: {name}", sec_end + offset, packet, fields(spp), HEX_PREVIEW)
    if sec["SPI"] in (b.SPI_SA00, b.SPI_SA10):
        section("SDLS Security Trailer (MAC zero filled: unprotected SA)", data_end, frame[data_end:])
    else:
        section("SDLS Security Trailer (MAC = GCM tag, verified)", data_end, frame[data_end:])
    if show_hex:
        hexdump(frame)
    print()


# --- example frames -----------------------------------------------------------------------


TC_KEY = bytes(range(32))
TM_KEY = bytes(range(32, 64))


def bring_up(sdls):
    """Simulates a finished key exchange: session keys loaded, SA01/SA11 Operational."""
    sdls.sa_set_key(b.KEYID_SESS_TC, TC_KEY)
    sdls.sa_set_key(b.KEYID_SESS_TM, TM_KEY)
    for spi, key_id in ((b.SPI_SA01, b.KEYID_SESS_TC), (b.SPI_SA11, b.KEYID_SESS_TM)):
        sdls.sa_rekey(spi, key_id)
        sdls.sa_start(spi)


def main(show_hex=False):
    sdls = b.Sdls()
    name = f"/sdls_frame_view_{os.getpid()}"
    sdls.sa_open(name)
    try:
        sdls.tc_init()
        bring_up(sdls)

        cmd = make_spp(0x018, b"\x01\x02\x03\x04", seq_count=7)
        show_tc("EP PDU on SA00", sdls.tc_build_frame(b.SPI_SA00, cmd), show_hex)
        for _ in range(2):  # IV 1 then 2
            show_tc("command on SA01", sdls.tc_build_frame(b.SPI_SA01, cmd), show_hex)

        tlm = [make_spp(0x100, b"\xAA" * 10, seq_count=1), make_spp(0x101, b"\xBB" * 20, seq_count=2)]
        for spi in (b.SPI_SA10, b.SPI_SA11):
            framer = SatTmFramer(spi=spi, key=TM_KEY)
            for packet in tlm:
                framer.forward_packet(packet)
            framer.send_frame()
            (frame,) = framer.sent
            # Ground processing: SPI, SA, ARSN, MAC, decryption.
            _, processed = sdls.sdls_process_tm(frame)
            show_tm(f"telemetry on {SPI_NAMES[spi][:4]}", processed, show_hex)
    finally:
        sdls.sa_close()
        sdls.sa_unlink(name)


if __name__ == "__main__":
    main(show_hex="--hex" in sys.argv[1:])
