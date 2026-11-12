/* TM Transfer Frame primary header, reduced from io_lib tmtf.h. */
#ifndef _tmtf_my_h_
#define _tmtf_my_h_

#include <stdint.h>

#define TMTF_MY_PRIHDR_LENGTH   6
#define TMTF_MY_SEGLENGTHID_PKT 3 /* Binary 11 is required for the packet service */

typedef struct
{
    uint8_t Id[2];              /* TFVN, SCID, VCID, OCF flag */
    uint8_t McFrameCount;       /* Master Channel Frame Count */
    uint8_t VcFrameCount;       /* Virtual Channel Frame Count */
    uint8_t DataFieldStatus[2]; /* Flags and First Header Pointer */
} TMTF_my_PriHdr_t;

/*SAT side code*/
#define TMTF_MY_WR_TF_VERSION(hdr, val) ((hdr).Id[0] = ((hdr).Id[0] & 0x3F) | (((val)&0x03) << 6))

#define TMTF_MY_WR_SCID(hdr, val)                                 \
    ((hdr).Id[0] = (((hdr).Id[0] & 0xC0) | (((val) >> 4) & 0x3F))), \
        ((hdr).Id[1] = (((hdr).Id[1] & 0x0F) | (((val)&0x0F) << 4)))

#define TMTF_MY_WR_VCID(hdr, val) ((hdr).Id[1] = (((hdr).Id[1] & 0xF1) | (((val)&0x07) << 1)))

#define TMTF_MY_WR_MCFRMCNT(hdr, val) ((hdr).McFrameCount = ((val)&0xFF))

#define TMTF_MY_WR_SEGLENGTHID(hdr, val) \
    ((hdr).DataFieldStatus[0] = ((((val) << 3) & 0x18) | ((hdr).DataFieldStatus[0] & 0xE7)))

#define TMTF_MY_WR_FIRSTHDRPTR(hdr, val)                                                  \
    ((hdr).DataFieldStatus[0] = ((((val) >> 8) & 0x07) | ((hdr).DataFieldStatus[0] & 0xF8))), \
        ((hdr).DataFieldStatus[1] = (val)&0xFF)

/*GROUND side code*/
/* Read macros mirror the SAT side write macros above bit for bit.
 * Read macros take the header itself, not a pointer to it.
 * Id[0]: TFVN(7-6) SCID high 6 bits(5-0)
 * Id[1]: SCID low 4 bits(7-4) VCID(3-1) OCF flag(0)
 * DataFieldStatus[0]: flags(7-5) Segment Length ID(4-3) First Header Pointer high(2-0)
 * DataFieldStatus[1]: First Header Pointer low */
#define TMTF_MY_RD_TF_VERSION(hdr) (((hdr).Id[0] >> 6) & 0x03)

#define TMTF_MY_RD_SCID(hdr) ((((hdr).Id[0] & 0x3F) << 4) | (((hdr).Id[1] >> 4) & 0x0F))

#define TMTF_MY_RD_VCID(hdr) (((hdr).Id[1] >> 1) & 0x07)

#define TMTF_MY_RD_MCFRMCNT(hdr) ((hdr).McFrameCount)
#define TMTF_MY_RD_VCFRMCNT(hdr) ((hdr).VcFrameCount)

#define TMTF_MY_RD_SEGLENGTHID(hdr) (((hdr).DataFieldStatus[0] >> 3) & 0x03)

#define TMTF_MY_RD_FIRSTHDRPTR(hdr) ((((hdr).DataFieldStatus[0] & 0x07) << 8) | (hdr).DataFieldStatus[1])

#endif /* _tmtf_my_h_ */
