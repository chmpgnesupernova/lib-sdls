/* wolfCrypt backend for the crypto provider interface (crypto_my.h).
 *
 * The only file in the library that includes wolfSSL headers. The same file is meant to
 * build on the satellite (STM32) with a user_settings.h that turns on the same features:
 *   AES-GCM, ML-KEM (WOLFSSL_HAVE_MLKEM), ML-DSA (WOLFSSL_HAVE_MLDSA / HAVE_DILITHIUM),
 *   HKDF (HAVE_HKDF), SHA-256, and a hardware seeded RNG.
 * Linux (configure): --enable-aesgcm --enable-mlkem --enable-mldsa  (HKDF is on by default)
 */
#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h> /* the build's feature macros; must come before any wolfSSL header */
#endif
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#include <pthread.h>

#include "crypto_my.h"

/* FIPS 203 / FIPS 204 sizes. The checks catch a wolfSSL build with other parameter sets. */
#define KEM_PK_LEN 1184
#define KEM_SK_LEN 2400
#define KEM_CT_LEN 1088
#define KEM_SS_LEN 32
#define DSA_PK_LEN 1952
#define DSA_SK_LEN 4032
#define DSA_SIG_LEN 3309

typedef char CRYPTO_myKemCheck_t[(WC_ML_KEM_768_PUBLIC_KEY_SIZE == KEM_PK_LEN &&
                                  WC_ML_KEM_768_PRIVATE_KEY_SIZE == KEM_SK_LEN &&
                                  WC_ML_KEM_768_CIPHER_TEXT_SIZE == KEM_CT_LEN) ? 1 : -1];
typedef char CRYPTO_myDsaCheck_t[(ML_DSA_LEVEL3_PUB_KEY_SIZE == DSA_PK_LEN && ML_DSA_LEVEL3_KEY_SIZE == DSA_SK_LEN &&
                                  ML_DSA_LEVEL3_SIG_SIZE == DSA_SIG_LEN) ? 1 : -1];

/* --- library and RNG setup ---------------------------------------------------------------
 * Initialized on first use, so callers (and Python) need no init call. WC_RNG is not
 * thread safe, so every use holds rngLock. */

static pthread_once_t  CRYPTO_myOnce    = PTHREAD_ONCE_INIT;
static pthread_mutex_t CRYPTO_myRngLock = PTHREAD_MUTEX_INITIALIZER;
static WC_RNG          CRYPTO_myRng;
static int             CRYPTO_myReady;

static void CRYPTO_myInitOnce(void)
{
    CRYPTO_myReady = (wolfCrypt_Init() == 0) && (wc_InitRng(&CRYPTO_myRng) == 0);
}

static int CRYPTO_myRngLock_(void)
{
    pthread_once(&CRYPTO_myOnce, CRYPTO_myInitOnce);
    if (!CRYPTO_myReady)
    {
        return -1;
    }
    pthread_mutex_lock(&CRYPTO_myRngLock);
    return 0;
}

static void CRYPTO_myRngUnlock_(void)
{
    pthread_mutex_unlock(&CRYPTO_myRngLock);
}

static int CRYPTO_myEnsureInit(void)
{
    pthread_once(&CRYPTO_myOnce, CRYPTO_myInitOnce);
    return CRYPTO_myReady ? 0 : -1;
}

/* --- AES-256-GCM ------------------------------------------------------------------------- */

static int32_t CRYPTO_myGcmEncrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aadLen,
                                   uint8_t *data, size_t len, uint8_t *tag)
{
    Aes aes;
    int ret;

    if ((key == NULL) || (iv == NULL) || (tag == NULL) || ((data == NULL) && (len != 0)) ||
        ((aad == NULL) && (aadLen != 0)))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if ((CRYPTO_myEnsureInit() != 0) || (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0))
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_AesGcmSetKey(&aes, key, 32);
    if (ret == 0)
    {
        ret = wc_AesGcmEncrypt(&aes, data, data, (word32)len, iv, 12, tag, 16, aad, (word32)aadLen);
    }
    wc_AesFree(&aes);
    CRYPTO_myZeroize(&aes, sizeof(aes)); /* the key schedule lives in the struct */
    return (ret == 0) ? CRYPTO_MY_SUCCESS : CRYPTO_MY_ERROR;
}

static int32_t CRYPTO_myGcmDecrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aadLen,
                                   uint8_t *data, size_t len, const uint8_t *tag)
{
    Aes aes;
    int ret;

    if ((key == NULL) || (iv == NULL) || (tag == NULL) || ((data == NULL) && (len != 0)) ||
        ((aad == NULL) && (aadLen != 0)))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if ((CRYPTO_myEnsureInit() != 0) || (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0))
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_AesGcmSetKey(&aes, key, 32);
    if (ret == 0)
    {
        ret = wc_AesGcmDecrypt(&aes, data, data, (word32)len, iv, 12, tag, 16, aad, (word32)aadLen);
    }
    wc_AesFree(&aes);
    CRYPTO_myZeroize(&aes, sizeof(aes));

    if (ret != 0)
    {
        /* Whatever order the implementation used internally, no plaintext survives. */
        CRYPTO_myZeroize(data, len);
        return (ret == AES_GCM_AUTH_E) ? CRYPTO_MY_AUTH_FAIL : CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

const CRYPTO_my_Aead_t CRYPTO_myBackendAes256Gcm = {
    .name    = "AES-256-GCM (wolfCrypt)",
    .keyLen  = 32,
    .ivLen   = 12,
    .tagLen  = 16,
    .encrypt = CRYPTO_myGcmEncrypt,
    .decrypt = CRYPTO_myGcmDecrypt,
};

/* --- ML-KEM-768 -------------------------------------------------------------------------- */

static int32_t CRYPTO_myKemEncaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    MlKemKey key;
    int      ret;

    if ((pk == NULL) || (ct == NULL) || (ss == NULL))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if ((CRYPTO_myEnsureInit() != 0) || (wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID) != 0))
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_MlKemKey_DecodePublicKey(&key, pk, KEM_PK_LEN); /* also checks the ek format */
    if (ret == 0)
    {
        if (CRYPTO_myRngLock_() != 0)
        {
            ret = -1;
        }
        else
        {
            ret = wc_MlKemKey_Encapsulate(&key, ct, ss, &CRYPTO_myRng);
            CRYPTO_myRngUnlock_();
        }
    }
    wc_MlKemKey_Free(&key);
    if (ret != 0)
    {
        CRYPTO_myZeroize(ss, KEM_SS_LEN);
        return CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

static int32_t CRYPTO_myKemKeygen(uint8_t *pk, uint8_t *sk)
{
    MlKemKey key;
    int      ret;

    if ((pk == NULL) || (sk == NULL))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if ((CRYPTO_myEnsureInit() != 0) || (wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID) != 0))
    {
        return CRYPTO_MY_ERROR;
    }
    if (CRYPTO_myRngLock_() != 0)
    {
        ret = -1;
    }
    else
    {
        ret = wc_MlKemKey_MakeKey(&key, &CRYPTO_myRng);
        CRYPTO_myRngUnlock_();
    }
    if (ret == 0)
    {
        ret = wc_MlKemKey_EncodePublicKey(&key, pk, KEM_PK_LEN);
    }
    if (ret == 0)
    {
        ret = wc_MlKemKey_EncodePrivateKey(&key, sk, KEM_SK_LEN);
    }
    wc_MlKemKey_Free(&key);
    if (ret != 0)
    {
        CRYPTO_myZeroize(sk, KEM_SK_LEN);
        return CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

/* ML-KEM uses implicit rejection: a tampered ct still decapsulates, to a different
 * secret. The mismatch surfaces later as a failed MAC under the derived session key. */
static int32_t CRYPTO_myKemDecaps(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    MlKemKey key;
    int      ret;

    if ((sk == NULL) || (ct == NULL) || (ss == NULL))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if ((CRYPTO_myEnsureInit() != 0) || (wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID) != 0))
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_MlKemKey_DecodePrivateKey(&key, sk, KEM_SK_LEN);
    if (ret == 0)
    {
        ret = wc_MlKemKey_Decapsulate(&key, ss, ct, KEM_CT_LEN);
    }
    wc_MlKemKey_Free(&key);
    if (ret != 0)
    {
        CRYPTO_myZeroize(ss, KEM_SS_LEN);
        return CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

const CRYPTO_my_Kem_t CRYPTO_myBackendMlKem768 = {
    .name   = "ML-KEM-768 (wolfCrypt)",
    .pkLen  = KEM_PK_LEN,
    .skLen  = KEM_SK_LEN,
    .ctLen  = KEM_CT_LEN,
    .ssLen  = KEM_SS_LEN,
    .encaps = CRYPTO_myKemEncaps,
    .keygen = CRYPTO_myKemKeygen,
    .decaps = CRYPTO_myKemDecaps,
};

/* --- ML-DSA-65 --------------------------------------------------------------------------- */

static int CRYPTO_myDsaInit(dilithium_key *pKey)
{
    if (CRYPTO_myEnsureInit() != 0 || wc_dilithium_init(pKey) != 0)
    {
        return -1;
    }
    if (wc_dilithium_set_level(pKey, WC_ML_DSA_65) != 0)
    {
        wc_dilithium_free(pKey);
        return -1;
    }
    return 0;
}

static int32_t CRYPTO_myDsaSign(const uint8_t *sk, const uint8_t *ctx, size_t ctxLen, const uint8_t *msg,
                                size_t msgLen, uint8_t *sig, size_t *sigLen)
{
    dilithium_key key;
    word32        outLen;
    int           ret;

    if ((sk == NULL) || (sig == NULL) || (sigLen == NULL) || ((msg == NULL) && (msgLen != 0)) ||
        ((ctx == NULL) && (ctxLen != 0)) || (ctxLen > 255) || (*sigLen < DSA_SIG_LEN))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if (CRYPTO_myDsaInit(&key) != 0)
    {
        return CRYPTO_MY_ERROR;
    }
    outLen = (word32)*sigLen;
    ret    = wc_dilithium_import_private(sk, DSA_SK_LEN, &key);
    if (ret == 0)
    {
        if (CRYPTO_myRngLock_() != 0)
        {
            ret = -1;
        }
        else
        {
            /* Hedged (randomized) signing; the satellite verifies it the same way. */
            ret = wc_dilithium_sign_ctx_msg(ctx, (byte)ctxLen, msg, (word32)msgLen, sig, &outLen, &key,
                                            &CRYPTO_myRng);
            CRYPTO_myRngUnlock_();
        }
    }
    wc_dilithium_free(&key); /* zeroizes the private key material */
    if (ret != 0)
    {
        return CRYPTO_MY_ERROR;
    }
    *sigLen = outLen;
    return CRYPTO_MY_SUCCESS;
}

static int32_t CRYPTO_myDsaVerify(const uint8_t *pk, const uint8_t *ctx, size_t ctxLen, const uint8_t *msg,
                                  size_t msgLen, const uint8_t *sig, size_t sigLen)
{
    dilithium_key key;
    int           res = 0; /* 1 only for a valid signature */
    int           ret;

    if ((pk == NULL) || (sig == NULL) || ((msg == NULL) && (msgLen != 0)) || ((ctx == NULL) && (ctxLen != 0)) ||
        (ctxLen > 255))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if (CRYPTO_myDsaInit(&key) != 0)
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_dilithium_import_public(pk, DSA_PK_LEN, &key);
    if (ret == 0)
    {
        ret = wc_dilithium_verify_ctx_msg(sig, (word32)sigLen, ctx, (byte)ctxLen, msg, (word32)msgLen, &res, &key);
    }
    wc_dilithium_free(&key);

    /* A bad signature can come back as ret == 0 with res == 0, or as a verify error
     * code (wrong length); both are a failed verification, not a backend failure. */
    if ((ret == 0) && (res == 1))
    {
        return CRYPTO_MY_SUCCESS;
    }
    return CRYPTO_MY_AUTH_FAIL;
}

static int32_t CRYPTO_myDsaKeygen(uint8_t *pk, uint8_t *sk)
{
    dilithium_key key;
    word32        pkLen = DSA_PK_LEN;
    word32        skLen = DSA_SK_LEN;
    int           ret;

    if ((pk == NULL) || (sk == NULL))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if (CRYPTO_myDsaInit(&key) != 0)
    {
        return CRYPTO_MY_ERROR;
    }
    if (CRYPTO_myRngLock_() != 0)
    {
        ret = -1;
    }
    else
    {
        ret = wc_dilithium_make_key(&key, &CRYPTO_myRng);
        CRYPTO_myRngUnlock_();
    }
    if (ret == 0)
    {
        ret = wc_dilithium_export_public(&key, pk, &pkLen);
    }
    if (ret == 0)
    {
        ret = wc_dilithium_export_private(&key, sk, &skLen);
    }
    wc_dilithium_free(&key);
    if ((ret != 0) || (pkLen != DSA_PK_LEN) || (skLen != DSA_SK_LEN))
    {
        CRYPTO_myZeroize(sk, DSA_SK_LEN);
        return CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

const CRYPTO_my_Sig_t CRYPTO_myBackendMlDsa65 = {
    .name   = "ML-DSA-65 (wolfCrypt)",
    .pkLen  = DSA_PK_LEN,
    .skLen  = DSA_SK_LEN,
    .sigLen = DSA_SIG_LEN,
    .sign   = CRYPTO_myDsaSign,
    .verify = CRYPTO_myDsaVerify,
    .keygen = CRYPTO_myDsaKeygen,
};

/* --- HKDF-SHA256 ------------------------------------------------------------------------- */

static int32_t CRYPTO_myHkdf(const uint8_t *ikm, size_t ikmLen, const uint8_t *salt, size_t saltLen,
                             const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen)
{
    int ret;

    if ((ikm == NULL) || (out == NULL) || ((salt == NULL) && (saltLen != 0)) || ((info == NULL) && (infoLen != 0)))
    {
        return CRYPTO_MY_INVALID_ARGUMENT;
    }
    if (CRYPTO_myEnsureInit() != 0)
    {
        return CRYPTO_MY_ERROR;
    }
    ret = wc_HKDF(WC_SHA256, ikm, (word32)ikmLen, salt, (word32)saltLen, info, (word32)infoLen, out, (word32)outLen);
    if (ret != 0)
    {
        CRYPTO_myZeroize(out, outLen);
        return CRYPTO_MY_ERROR;
    }
    return CRYPTO_MY_SUCCESS;
}

const CRYPTO_my_Kdf_t CRYPTO_myBackendHkdfSha256 = {
    .name   = "HKDF-SHA256 (wolfCrypt)",
    .derive = CRYPTO_myHkdf,
};
