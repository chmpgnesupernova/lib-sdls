/* SDLS frame protection: ApplySecurity (TC send) and ProcessSecurity (TM receive),
 * CCSDS 355.0-B-2 §4.2.2 / §4.2.3, reduced to this mission's fixed layout.
 *
 * Frame layout (TC and TM):
 *   [Primary Header][Security Header 14: SPI 2 + IV 12][Frame Data][Security Trailer 16: MAC]
 *
 * What happens to a frame is decided by its SA (sa/sa_my.h):
 *   service_type NONE     (SA00, SA10: EP PDUs)  IV and MAC fields zero filled, nothing checked
 *   service_type AUTH_ENC (SA01, SA11: sessions) Frame Data encrypted, MAC = GCM tag
 *   service_type AUTH                            Frame Data in clear, MAC = GMAC over it
 * and which algorithm does it by the SA's enc_alg / auth_alg (crypto registry).
 *
 * Additional Authenticated Data (must match the satellite byte for byte):
 *   AAD = (Primary Header AND auth_mask_prihdr) || Security Header              (AUTH_ENC)
 *   AAD = (Primary Header AND auth_mask_prihdr) || Security Header || Frame Data (AUTH)
 * Security Header = SPI 2 + IV 12, as on the wire. The IV is also the GCM nonce.
 * TC masks nothing (5 bytes), TM masks the MC Frame Count (byte 2), per the SA defaults.
 * So every header byte is authenticated except the TM MC Frame Count.
 *
 * Return codes: SA_MY_* (sa/sa_shm_my.h) or the SDLS_MY_* codes below.
 */
#ifndef _sdls_my_h_
#define _sdls_my_h_

#include <stddef.h>
#include <stdint.h>

#include "sa/sa_my.h"
#include "sdls/sechdr_my.h"

#define SDLS_MY_TRAILER_LENGTH COMMON_GCM_MAC_LEN /* every SA, zero filled when unprotected */

#define SDLS_MY_CRYPTO_ERROR   (-20) /* backend failure */
#define SDLS_MY_AUTH_FAIL      (-21) /* MAC did not verify: forged, corrupted or wrong key */
#define SDLS_MY_UNSUPPORTED    (-22) /* SA service type / algorithm not built in */

/* TC send side. The frame must already hold the Primary Header (all fields final:
 * the header is authenticated) and the Frame Data:
 *   pFrame    : frame start
 *   priHdrLen : TF Primary Header length (5)
 *   dataLen   : Frame Data length (the Space Packet)
 *   bufSize   : bytes available at pFrame (at least priHdrLen + 14 + dataLen + 16)
 * Writes the Security Header (taking one IV from a protected SA), encrypts the Frame Data
 * in place and writes the Security Trailer.
 * Every check that can refuse the frame runs before an IV is taken, so a refused frame
 * never consumes one. */
int32_t SDLS_myApplySecurityTc(uint16_t spi, void *pFrame, size_t priHdrLen, size_t dataLen, size_t bufSize);

/* TM receive side, one whole frame:
 *   pFrame    : frame start; for a protected SA the Frame Data is decrypted in place
 *   frameSize : whole frame length
 *   priHdrLen : TF Primary Header length (6)
 *   pSpi      : out (may be NULL), the SA the frame came on
 * Order: SA lookup and state, anti-replay pre-check, MAC verify and decrypt, and only then
 * the ARSN is recorded. A frame that fails verification leaves the SA untouched and its
 * Frame Data zeroized. */
int32_t SDLS_myProcessSecurityTm(void *pFrame, size_t frameSize, size_t priHdrLen, uint16_t *pSpi);

#endif /* _sdls_my_h_ */
