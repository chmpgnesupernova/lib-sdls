/* Library internal SA/Key DB access. Not exported from libsdls.so. */
#ifndef _sa_shm_internal_h_
#define _sa_shm_internal_h_

#include "sa/sa_shm_my.h"

#define SA_MY_INTERNAL __attribute__((visibility("hidden")))

/* Copies the session key bound to the SA as its auth key into pKey (COMMON_AES256_KEY_LEN
 * bytes). For the frame protection code only; the caller must zeroize pKey after use. */
SA_MY_INTERNAL int32_t SA_myCopySaKey(uint16_t spi, uint8_t *pKey);

#endif /* _sa_shm_internal_h_ */
