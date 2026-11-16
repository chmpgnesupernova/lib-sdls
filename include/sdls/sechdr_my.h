/* SDLS Security Header (CCSDS 355.0-B-2 §4.1.1, §4.2.2.2).
 * Fixed mission format, the same for TC and TM:
 *
 *   +--------+---------------------------+
 *   | SPI 2B | IV 12B (= ARSN, §4.1.1.4) |    14 octets, big endian
 *   +--------+---------------------------+
 *
 * Sequence Number and Pad Length fields are 0 bytes in every SA (len_sn = len_pl = 0):
 * the 96 bit GCM IV doubles as the anti-replay sequence number.
 * The header follows the TF Primary Header directly (TC: no Segment Header). */
#ifndef _sechdr_my_h_
#define _sechdr_my_h_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sa/sa_shm_my.h"

#define SECHDR_MY_SPI_LENGTH 2
#define SECHDR_MY_IV_LENGTH  12
#define SECHDR_MY_LENGTH     (SECHDR_MY_SPI_LENGTH + SECHDR_MY_IV_LENGTH)

typedef struct
{
    uint8_t Spi[SECHDR_MY_SPI_LENGTH]; /* Security Parameter Index */
    uint8_t Iv[SECHDR_MY_IV_LENGTH];   /* Initialization Vector, big endian counter */
} SECHDR_my_SecHdr_t;

/* The struct is overlaid on frame bytes, so it must have no padding, and its
 * layout must match the SA DB constants. */
typedef char SECHDR_my_SizeCheck_t[(sizeof(SECHDR_my_SecHdr_t) == SECHDR_MY_LENGTH) ? 1 : -1];
typedef char SECHDR_my_SaCheck_t[((SECHDR_MY_LENGTH == COMMON_SEC_HDR_LEN) &&
                                  (SECHDR_MY_IV_LENGTH == COMMON_GCM_IV_LEN)) ? 1 : -1];

/* Read macros take the header itself, not a pointer to it (same as tctf_my.h). */
#define SECHDR_MY_RD_SPI(hdr)      ((uint16_t)(((hdr).Spi[0] << 8) | (hdr).Spi[1]))
#define SECHDR_MY_RD_IV(hdr, pDst) memcpy((pDst), (hdr).Iv, SECHDR_MY_IV_LENGTH)

#define SECHDR_MY_WR_SPI(hdr, val) \
    ((hdr).Spi[0] = (uint8_t)(((val) >> 8) & 0xFF)), ((hdr).Spi[1] = (uint8_t)((val)&0xFF))
#define SECHDR_MY_WR_IV(hdr, pSrc) memcpy((hdr).Iv, (pSrc), SECHDR_MY_IV_LENGTH)
#define SECHDR_MY_CLR_IV(hdr)      memset((hdr).Iv, 0, SECHDR_MY_IV_LENGTH)

/* GROUND side code. Both functions need SA_myOpen first and return SA_MY_* codes. */

/* TC send side: fills the Security Header for one frame on the SA spi.
 * pBuf     : where the header goes (frame + TCTF_MY_PRIHDR_LENGTH)
 * bufSize  : bytes available at pBuf (at least SECHDR_MY_LENGTH)
 * pIv      : optional out (may be NULL). The IV written into the header, i.e. the GCM
 *            nonce the frame must be protected with.
 * Protected SA (SA01): needs a TC SA in Operational; takes a fresh IV with SA_myNextIv,
 *                      so every call consumes one IV.
 * Unprotected SA (SA00, EP PDUs): IV field is zero filled, no IV is consumed.
 * Errors: SA_MY_INVALID_ARGUMENT (NULL, bufSize too small), SA_MY_UNKNOWN_SPI,
 *         SA_MY_INVALID_STATE (TM SA, not Operational), SA_MY_IV_EXHAUSTED. */
int32_t SECHDR_myApplyTc(uint16_t spi, void *pBuf, size_t bufSize, uint8_t *pIv);

/* TM receive side: reads and checks the Security Header of one frame.
 * pBuf     : the header (frame + TMTF_MY_PRIHDR_LENGTH)
 * bufSize  : bytes available at pBuf (at least SECHDR_MY_LENGTH)
 * pSpi     : out, the SPI
 * pIv      : out, the IV (SECHDR_MY_IV_LENGTH bytes)
 * Checks: SPI is known, the SA is a TM SA and Operational, and for a protected SA (SA11)
 * the IV is a new ARSN within the window. The ARSN is NOT recorded: after the MAC
 * verifies, call SA_myCommitArsn(*pSpi, pIv).
 * Errors: SA_MY_INVALID_ARGUMENT, SA_MY_UNKNOWN_SPI, SA_MY_INVALID_STATE, SA_MY_REPLAY. */
int32_t SECHDR_myProcessTm(const void *pBuf, size_t bufSize, uint16_t *pSpi, uint8_t *pIv);

#endif /* _sechdr_my_h_ */
