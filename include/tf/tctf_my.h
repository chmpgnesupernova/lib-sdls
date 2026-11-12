/* TC Transfer Frame primary header, reduced from io_lib tctf.h and tctf.c.
 * Field layout follows CCSDS 232.0 Figure 4-2 (5 octets). */
#ifndef _tctf_my_h_
#define _tctf_my_h_

#include "common_types.h"

#define TCTF_MY_PRIHDR_LENGTH    5
#define TCTF_MY_MAX_FRAME_LENGTH 1024 /* Frame Length field is 10 bits */

typedef struct
{
    uint8 Octet[4]; /* TFVN, flags, SCID, VCID, Frame Length */
    uint8 Sequence; /* Frame Sequence Number */
} TCTF_my_PriHdr_t;

/* Read macros take the header itself, not a pointer to it. */
#define TCTF_MY_RD_TF_VERSION(hdr) (((hdr).Octet[0] >> 6) & 0x03)
#define TCTF_MY_RD_BYPASS_FLG(hdr) (((hdr).Octet[0] >> 5) & 0x01)
#define TCTF_MY_RD_CTLCMD_FLG(hdr) (((hdr).Octet[0] >> 4) & 0x01)
#define TCTF_MY_RD_SCID(hdr)       ((((hdr).Octet[0] & 0x03) << 8) | (hdr).Octet[1])
#define TCTF_MY_RD_VCID(hdr)       (((hdr).Octet[2] >> 2) & 0x3F)
#define TCTF_MY_RD_SEQNUM(hdr)     ((hdr).Sequence)

/* Frame Length field holds the total frame octets minus one. */
#define TCTF_MY_RD_FRAMELEN(hdr) ((((hdr).Octet[2] & 0x03) << 8) | (hdr).Octet[3])

#endif /* _tctf_my_h_ */
