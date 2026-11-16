"""Checks frame_view.py: its decoders must read frames the way the satellite does,
otherwise the printed view is misleading. Also runs the viewer once end to end."""

import contextlib
import io
import os
import unittest

import frame_view as fv
import sdls_binding as b
from sat_reference import SatTmFramer, make_spp, tc_header_fields


class DecoderTest(unittest.TestCase):
    def test_tc_prihdr_matches_satellite_reader(self):
        # TFVN 1, Bypass 1, CtrlCmd 0, SCID 0x2AB, VCID 0x15, FrameLen 0x3C7, Seq 0x9E
        frame = bytes([0x62, 0xAB, 0x57, 0xC7, 0x9E])
        pri = fv.decode_tc_prihdr(frame)
        self.assertEqual(
            pri,
            {"TFVN": 1, "Bypass": 1, "CtrlCmd": 0, "Spare": 0, "SCID": 0x2AB, "VCID": 0x15, "FrameLen": 0x3C7, "Seq": 0x9E},
        )
        sat = tc_header_fields(frame)
        for key_fv, key_sat in (("TFVN", "tfvn"), ("Bypass", "bypass"), ("CtrlCmd", "ctlcmd"),
                                ("SCID", "scid"), ("VCID", "vcid"), ("FrameLen", "framelen"), ("Seq", "seq")):
            self.assertEqual(pri[key_fv], sat[key_sat], key_fv)

    def test_tm_prihdr_reads_what_the_satellite_writes(self):
        framer = SatTmFramer(scid=0x2AB, vcid=5, tfvn=1)
        framer.forward_packet(make_spp(0x100, b"\x00"))
        framer.send_frame()
        pri = fv.decode_tm_prihdr(framer.sent[0])
        self.assertEqual((pri["TFVN"], pri["SCID"], pri["VCID"]), (1, 0x2AB, 5))
        self.assertEqual((pri["MCFrameCnt"], pri["SegLenID"], pri["FirstHdrPtr"]), (1, b.TMTF_SEGLENGTHID_PKT, 0))

    def test_sechdr_is_big_endian(self):
        hdr = bytes([0x12, 0x34]) + bytes(range(1, 13))
        self.assertEqual(fv.decode_sechdr(hdr), {"SPI": 0x1234, "IV": int.from_bytes(bytes(range(1, 13)), "big")})

    def test_spp_fields(self):
        packet = make_spp(0x5A5, b"\x00" * 300, seq_flags=1, seq_count=0x1234)
        self.assertEqual(fv.decode_spp(packet), {"APID": 0x5A5, "SeqFlags": 1, "SeqCount": 0x1234, "Length": 299})

    def test_split_spps_covers_the_whole_data_field(self):
        packets = [make_spp(0x100 + i, bytes([i]) * (5 + i)) for i in range(4)]
        framer = SatTmFramer()
        for packet in packets:
            framer.forward_packet(packet)
        framer.send_frame()
        data = framer.sent[0][b.TM_DATA_OFFSET : b.TM_DATA_END]
        parts = fv.split_spps(data)
        self.assertEqual([p for _, p in parts[:-1]], packets)
        self.assertEqual(fv.decode_spp(parts[-1][1])["APID"], b.TM_IDLE_APID)
        self.assertEqual(sum(len(p) for _, p in parts), len(data))


class ViewerRunTest(unittest.TestCase):
    def test_viewer_prints_every_section(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fv.main(show_hex=True)
        text = out.getvalue()
        self.assertEqual(text.count("=== TC frame"), 3)
        self.assertEqual(text.count("=== TM frame"), 2)
        self.assertIn("SPI=0x0001 [SA01 session TC]  IV=2", text)
        self.assertIn("SPI=0x0002 [SA11 session TM]  IV=1", text)
        self.assertNotIn(f"sdls_frame_view_{os.getpid()}", os.listdir("/dev/shm"))


if __name__ == "__main__":
    unittest.main()
