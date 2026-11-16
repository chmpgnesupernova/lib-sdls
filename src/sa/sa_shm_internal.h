/* Library internal SA/Key DB access. Not exported from libsdls.so. */
#ifndef _sa_shm_internal_h_
#define _sa_shm_internal_h_

#include "sa/sa_shm_my.h"

#define SA_MY_INTERNAL __attribute__((visibility("hidden")))

/* Copies the session key bound to the SA as its auth key into pKey (COMMON_AES256_KEY_LEN
 * bytes). For the frame protection code only; the caller must zeroize pKey after use. */
SA_MY_INTERNAL int32_t SA_myCopySaKey(uint16_t spi, uint8_t *pKey);

/* Copies the ground ML-DSA secret key (COMMON_DSA_SK_LEN bytes) for EP signing.
 * The caller must zeroize pSk after use. SA_MY_UNKNOWN_KEY if none is loaded. */
SA_MY_INTERNAL int32_t SA_myCopyDsaSecretKey(uint8_t *pSk);

/* Key exchange ciphertext shared between the receiving and the sending process.
 * Store with ctLen 0 clears it. Load returns SA_MY_INVALID_STATE when nothing is pending. */
SA_MY_INTERNAL int32_t SA_myStorePendingCt(const uint8_t *pCt, size_t ctLen);
SA_MY_INTERNAL int32_t SA_myLoadPendingCt(uint8_t *pCt, size_t ctSize, size_t *pCtLen);

#endif /* _sa_shm_internal_h_ */
