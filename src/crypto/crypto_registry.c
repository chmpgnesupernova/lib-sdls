/* Algorithm ID -> backend ops. See crypto_my.h.
 *
 * To add a partner algorithm: give it an ID in common_alg_e (sa/sa_my.h), implement its
 * ops in the backend file, and add one case below. The SDLS and EP layers pick it up
 * from the SA's auth_alg / enc_alg without any other change. */
#include "crypto_my.h"

#include "sa/sa_my.h"

const CRYPTO_my_Aead_t *CRYPTO_myGetAead(uint8_t alg)
{
    switch (alg)
    {
        case COMMON_ALG_AES256_GCM:
            return &CRYPTO_myBackendAes256Gcm;
        default:
            return NULL;
    }
}

const CRYPTO_my_Kem_t *CRYPTO_myGetKem(uint8_t alg)
{
    switch (alg)
    {
        case COMMON_ALG_ML_KEM_768:
            return &CRYPTO_myBackendMlKem768;
        default:
            return NULL;
    }
}

const CRYPTO_my_Sig_t *CRYPTO_myGetSig(uint8_t alg)
{
    switch (alg)
    {
        case COMMON_ALG_ML_DSA_65:
            return &CRYPTO_myBackendMlDsa65;
        default:
            return NULL;
    }
}

const CRYPTO_my_Kdf_t *CRYPTO_myGetKdf(void)
{
    return &CRYPTO_myBackendHkdfSha256;
}

void CRYPTO_myZeroize(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
    {
        *v++ = 0;
    }
}
