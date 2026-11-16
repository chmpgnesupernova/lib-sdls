/* libsdls_satsim.so: test only stand-in for the satellite side crypto.
 *
 * Built from the same crypto backend as libsdls.so (the satellite is expected to compile
 * the same wolfCrypt code), so the Python tests can play the satellite end of the key
 * exchange and of AES-GCM frame protection. The frame layout, AAD rule and IV handling
 * stay in Python (test/sat_reference.py), written independently of the C library.
 *
 * Not part of the ground library. Keys pass through in the clear on purpose. */
#include <stddef.h>
#include <stdint.h>

#include "crypto/crypto_my.h"
#include "ep/ep_my.h"
#include "sa/sa_my.h"

#define SATSIM_API __attribute__((visibility("default")))

/* ML-KEM-768 key pair: pk COMMON_KEM_PK_LEN, sk COMMON_KEM_SK_LEN bytes. */
SATSIM_API int32_t SATSIM_myKemKeygen(uint8_t *pPk, uint8_t *pSk)
{
    return CRYPTO_myGetKem(COMMON_ALG_ML_KEM_768)->keygen(pPk, pSk);
}

/* Satellite end of the exchange: decaps, then the same HKDF as EP_myAcceptKemPublicKey. */
SATSIM_API int32_t SATSIM_myKemAccept(const uint8_t *pSk, const uint8_t *pCt, uint8_t *pKeyTc, uint8_t *pKeyTm)
{
    const CRYPTO_my_Kdf_t *pKdf = CRYPTO_myGetKdf();
    uint8_t                ss[COMMON_KEM_SS_LEN];
    int32_t                rc;

    rc = CRYPTO_myGetKem(COMMON_ALG_ML_KEM_768)->decaps(pSk, pCt, ss);
    if (rc == CRYPTO_MY_SUCCESS)
    {
        rc = pKdf->derive(ss, sizeof(ss), pCt, COMMON_KEM_CT_LEN, (const uint8_t *)EP_MY_KDF_INFO_TC,
                          sizeof(EP_MY_KDF_INFO_TC) - 1, pKeyTc, COMMON_AES256_KEY_LEN);
    }
    if (rc == CRYPTO_MY_SUCCESS)
    {
        rc = pKdf->derive(ss, sizeof(ss), pCt, COMMON_KEM_CT_LEN, (const uint8_t *)EP_MY_KDF_INFO_TM,
                          sizeof(EP_MY_KDF_INFO_TM) - 1, pKeyTm, COMMON_AES256_KEY_LEN);
    }
    CRYPTO_myZeroize(ss, sizeof(ss));
    return rc;
}

/* Ground ML-DSA-65 key pair for tests (on a real mission it is provisioned). */
SATSIM_API int32_t SATSIM_myDsaKeygen(uint8_t *pPk, uint8_t *pSk)
{
    return CRYPTO_myGetSig(COMMON_ALG_ML_DSA_65)->keygen(pPk, pSk);
}

/* Satellite check of a ground signature, with the EP context string. */
SATSIM_API int32_t SATSIM_myDsaVerify(const uint8_t *pPk, const uint8_t *pMsg, size_t msgLen, const uint8_t *pSig,
                                      size_t sigLen)
{
    return CRYPTO_myGetSig(COMMON_ALG_ML_DSA_65)->verify(pPk, (const uint8_t *)EP_MY_DSA_CONTEXT,
                                                         sizeof(EP_MY_DSA_CONTEXT) - 1, pMsg, msgLen, pSig, sigLen);
}

/* AES-256-GCM in place, the same contract as the provider interface. */
SATSIM_API int32_t SATSIM_myGcmEncrypt(const uint8_t *pKey, const uint8_t *pIv, const uint8_t *pAad, size_t aadLen,
                                       uint8_t *pData, size_t len, uint8_t *pTag)
{
    return CRYPTO_myGetAead(COMMON_ALG_AES256_GCM)->encrypt(pKey, pIv, pAad, aadLen, pData, len, pTag);
}

SATSIM_API int32_t SATSIM_myGcmDecrypt(const uint8_t *pKey, const uint8_t *pIv, const uint8_t *pAad, size_t aadLen,
                                       uint8_t *pData, size_t len, const uint8_t *pTag)
{
    return CRYPTO_myGetAead(COMMON_ALG_AES256_GCM)->decrypt(pKey, pIv, pAad, aadLen, pData, len, pTag);
}
