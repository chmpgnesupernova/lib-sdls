/* TM Transfer Frame primary header, reduced from io_lib tmtf.h. */
#ifndef _tmtf_my_h_
#define _tmtf_my_h_

#include "common_types.h"

#define TMTF_MY_PRIHDR_LENGTH   6
#define TMTF_MY_SEGLENGTHID_PKT 3 /* Binary 11 is required for the packet service */

typedef struct
{
    uint8 Id[2];              /* TFVN, SCID, VCID, OCF flag */
    uint8 McFrameCount;       /* Master Channel Frame Count */
    uint8 VcFrameCount;       /* Virtual Channel Frame Count */
    uint8 DataFieldStatus[2]; /* Flags and First Header Pointer */
} TMTF_my_PriHdr_t;

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

#endif /* _tmtf_my_h_ */
