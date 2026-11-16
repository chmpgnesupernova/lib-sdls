/* Crypto provider interface (library internal, not exported from libsdls.so).
 *
 * The SDLS layer (sdls/), the key exchange (ep/) and nothing else call this interface.
 * Only the backend file (crypto_wolfssl.c today) includes the crypto library headers, so
 * a partner implementation replaces that one file:
 *
 *   sdls_my.c / ep_my.c ──> crypto_registry.c ──> crypto_<backend>.c ──> wolfSSL / partner
 *                           (algorithm ID -> ops)  (defines CRYPTO_myBackend*)
 *
 * Rules every backend must follow:
 * - Plain bytes in, plain bytes out. No SA, SPI or frame knowledge.
 * - AEAD works in place. Decrypt verifies the tag in constant time and zeroizes the data
 *   on failure, so a forged frame never leaves plaintext behind.
 * - Secret keys are passed in raw for each call and never kept by the backend; the
 *   caller zeroizes its copy afterwards.
 * - Sizes are fixed per algorithm and published in the ops struct, so callers do not
 *   hard code them.
 * - Return CRYPTO_MY_* codes only; backend specific error codes never leak out.
 */
#ifndef _crypto_my_h_
#define _crypto_my_h_

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_MY_INTERNAL __attribute__((visibility("hidden")))

#define CRYPTO_MY_SUCCESS          (0)
#define CRYPTO_MY_ERROR            (-1) /* backend failure (init, RNG, bad key format, ...) */
#define CRYPTO_MY_AUTH_FAIL        (-2) /* AEAD tag or signature did not verify */
#define CRYPTO_MY_INVALID_ARGUMENT (-3)

/* --- AEAD (AES-256-GCM) ------------------------------------------------------------------ */

typedef struct
{
    const char *name;
    size_t      keyLen;
    size_t      ivLen;
    size_t      tagLen;
    /* data: plaintext in, ciphertext out (len bytes, in place). tag: tagLen bytes out. */
    int32_t (*encrypt)(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aadLen, uint8_t *data,
                       size_t len, uint8_t *tag);
    /* data: ciphertext in, plaintext out (in place) only if tag verifies; zeroized otherwise. */
    int32_t (*decrypt)(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aadLen, uint8_t *data,
                       size_t len, const uint8_t *tag);
} CRYPTO_my_Aead_t;

/* --- KEM (ML-KEM-768) -------------------------------------------------------------------- */

typedef struct
{
    const char *name;
    size_t      pkLen; /* encapsulation key (ek) */
    size_t      skLen; /* decapsulation key (dk) */
    size_t      ctLen;
    size_t      ssLen;
    /* Ground side. */
    int32_t (*encaps)(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
    /* Satellite side (and the test satellite). May be NULL in a ground only backend. */
    int32_t (*keygen)(uint8_t *pk, uint8_t *sk);
    int32_t (*decaps)(const uint8_t *sk, const uint8_t *ct, uint8_t *ss);
} CRYPTO_my_Kem_t;

/* --- Signature (ML-DSA-65, pure, with a context string) -------------------------------- */

typedef struct
{
    const char *name;
    size_t      pkLen;
    size_t      skLen;
    size_t      sigLen; /* maximum (ML-DSA signatures are fixed size) */
    /* Ground side. *sigLen: in buffer size, out signature size. */
    int32_t (*sign)(const uint8_t *sk, const uint8_t *ctx, size_t ctxLen, const uint8_t *msg, size_t msgLen,
                    uint8_t *sig, size_t *sigLen);
    /* Satellite side. CRYPTO_MY_AUTH_FAIL for a bad signature. */
    int32_t (*verify)(const uint8_t *pk, const uint8_t *ctx, size_t ctxLen, const uint8_t *msg, size_t msgLen,
                      const uint8_t *sig, size_t sigLen);
    /* Key provisioning and tests. May be NULL. */
    int32_t (*keygen)(uint8_t *pk, uint8_t *sk);
} CRYPTO_my_Sig_t;

/* --- KDF (HKDF-SHA256) ------------------------------------------------------------------- */

typedef struct
{
    const char *name;
    int32_t (*derive)(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen, const uint8_t *info,
                      size_t infoLen, uint8_t *out, size_t outLen);
} CRYPTO_my_Kdf_t;

/* --- Registry (crypto_registry.c) --------------------------------------------------------
 * Maps the SA/key algorithm IDs (common_alg_e in sa/sa_my.h) to the backend ops.
 * Returns NULL when the algorithm is unknown or not built in. */

CRYPTO_MY_INTERNAL const CRYPTO_my_Aead_t *CRYPTO_myGetAead(uint8_t alg);
CRYPTO_MY_INTERNAL const CRYPTO_my_Kem_t  *CRYPTO_myGetKem(uint8_t alg);
CRYPTO_MY_INTERNAL const CRYPTO_my_Sig_t  *CRYPTO_myGetSig(uint8_t alg);
CRYPTO_MY_INTERNAL const CRYPTO_my_Kdf_t  *CRYPTO_myGetKdf(void);

/* Zeroizes secrets; not removed by the optimizer. */
CRYPTO_MY_INTERNAL void CRYPTO_myZeroize(void *p, size_t n);

/* --- Backend symbols ---------------------------------------------------------------------
 * Every backend file defines these objects (any it cannot provide may be left out
 * together with its registry entry). */

CRYPTO_MY_INTERNAL extern const CRYPTO_my_Aead_t CRYPTO_myBackendAes256Gcm;
CRYPTO_MY_INTERNAL extern const CRYPTO_my_Kem_t  CRYPTO_myBackendMlKem768;
CRYPTO_MY_INTERNAL extern const CRYPTO_my_Sig_t  CRYPTO_myBackendMlDsa65;
CRYPTO_MY_INTERNAL extern const CRYPTO_my_Kdf_t  CRYPTO_myBackendHkdfSha256;

#endif /* _crypto_my_h_ */
