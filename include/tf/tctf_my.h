/* TC Transfer Frame primary header, reduced from io_lib tctf.h and tctf.c.
 * Field layout follows CCSDS 232.0 Figure 4-2 (5 octets). */
#ifndef _tctf_my_h_
#define _tctf_my_h_

#include <stdint.h>

#define TCTF_MY_PRIHDR_LENGTH    5
#define TCTF_MY_MAX_FRAME_LENGTH 1024 /* Frame Length field is 10 bits */

typedef struct
{
    uint8_t Octet[4]; /* TFVN, flags, SCID, VCID, Frame Length */
    uint8_t Sequence; /* Frame Sequence Number */
} TCTF_my_PriHdr_t;

/*SAT side code*/
/* Read macros take the header itself, not a pointer to it. */
#define TCTF_MY_RD_TF_VERSION(hdr) (((hdr).Octet[0] >> 6) & 0x03)
#define TCTF_MY_RD_BYPASS_FLG(hdr) (((hdr).Octet[0] >> 5) & 0x01)
#define TCTF_MY_RD_CTLCMD_FLG(hdr) (((hdr).Octet[0] >> 4) & 0x01)
#define TCTF_MY_RD_SCID(hdr)       ((((hdr).Octet[0] & 0x03) << 8) | (hdr).Octet[1])
#define TCTF_MY_RD_VCID(hdr)       (((hdr).Octet[2] >> 2) & 0x3F)
#define TCTF_MY_RD_SEQNUM(hdr)     ((hdr).Sequence)

/* Frame Length field holds the total frame octets minus one. */
#define TCTF_MY_RD_FRAMELEN(hdr) ((((hdr).Octet[2] & 0x03) << 8) | (hdr).Octet[3])

/*GROUND side code*/
/* Write macros mirror the read macros above bit for bit.
 * Octet[0]: TFVN(7-6) Bypass(5) CtrlCmd(4) Spare(3-2) SCID high(1-0)
 * Octet[1]: SCID low
 * Octet[2]: VCID(7-2) Frame Length high(1-0)
 * Octet[3]: Frame Length low */
#define TCTF_MY_WR_TF_VERSION(hdr, val) ((hdr).Octet[0] = (uint8_t)(((hdr).Octet[0] & 0x3F) | (((val)&0x03) << 6)))
#define TCTF_MY_WR_BYPASS_FLG(hdr, val) ((hdr).Octet[0] = (uint8_t)(((hdr).Octet[0] & 0xDF) | (((val)&0x01) << 5)))
#define TCTF_MY_WR_CTLCMD_FLG(hdr, val) ((hdr).Octet[0] = (uint8_t)(((hdr).Octet[0] & 0xEF) | (((val)&0x01) << 4)))

#define TCTF_MY_WR_SCID(hdr, val)                                                         \
    ((hdr).Octet[0] = (uint8_t)(((hdr).Octet[0] & 0xFC) | (((val) >> 8) & 0x03))),       \
        ((hdr).Octet[1] = (uint8_t)((val)&0xFF))

#define TCTF_MY_WR_VCID(hdr, val) ((hdr).Octet[2] = (uint8_t)(((hdr).Octet[2] & 0x03) | (((val)&0x3F) << 2)))

#define TCTF_MY_WR_SEQNUM(hdr, val) ((hdr).Sequence = (uint8_t)((val)&0xFF))

/* Write the total frame octets minus one. */
#define TCTF_MY_WR_FRAMELEN(hdr, val)                                                     \
    ((hdr).Octet[2] = (uint8_t)(((hdr).Octet[2] & 0xFC) | (((val) >> 8) & 0x03))),       \
        ((hdr).Octet[3] = (uint8_t)((val)&0xFF))

#endif /* _tctf_my_h_ */
