/* Ground side PQC key exchange. See include/ep/ep_my.h. */
#include <string.h>

#include "ep/ep_my.h"
#include "sa/sa_shm_my.h"

#include "../crypto/crypto_my.h"
#include "../sa/sa_shm_internal.h"

/* Takes a session SA back to Unkeyed (destroying its key) so new keys can be loaded. */
static int32_t EP_myResetSa(uint16_t spi)
{
    common_sa_t sa;
    int32_t     status;

    status = SA_myGetSa(spi, &sa);
    if ((status == SA_MY_SUCCESS) && (sa.state == COMMON_SA_OPERATIONAL))
    {
        status = SA_myStop(spi);
        sa.state = COMMON_SA_KEYED;
    }
    if ((status == SA_MY_SUCCESS) && (sa.state == COMMON_SA_KEYED))
    {
        status = SA_myExpire(spi);
    }
    return status;
}

static int32_t EP_myLoadSessionKey(uint16_t spi, uint16_t keyId, const uint8_t *pKey)
{
    int32_t status = EP_myResetSa(spi);
    if (status == SA_MY_SUCCESS)
    {
        status = SA_mySetKey(keyId, pKey, COMMON_AES256_KEY_LEN);
    }
    if (status == SA_MY_SUCCESS)
    {
        status = SA_myRekey(spi, keyId);
    }
    return status;
}

int32_t EP_myAcceptKemPublicKey(const uint8_t *pEk, size_t ekLen, uint8_t *pCt, size_t ctSize)
{
    const CRYPTO_my_Kem_t *pKem = CRYPTO_myGetKem(COMMON_ALG_ML_KEM_768);
    const CRYPTO_my_Kdf_t *pKdf = CRYPTO_myGetKdf();
    uint8_t                ct[COMMON_KEM_CT_LEN];
    uint8_t                ss[COMMON_KEM_SS_LEN];
    uint8_t                kTc[COMMON_AES256_KEY_LEN];
    uint8_t                kTm[COMMON_AES256_KEY_LEN];
    int32_t                status;

    if ((pEk == NULL) || (pCt == NULL) || (ekLen != COMMON_KEM_PK_LEN) || (ctSize < COMMON_KEM_CT_LEN))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((pKem == NULL) || (pKem->encaps == NULL) || (pKdf == NULL) || (pKem->pkLen != COMMON_KEM_PK_LEN) ||
        (pKem->ctLen != COMMON_KEM_CT_LEN) || (pKem->ssLen != COMMON_KEM_SS_LEN))
    {
        return EP_MY_UNSUPPORTED;
    }

    if (pKem->encaps(pEk, ct, ss) != CRYPTO_MY_SUCCESS)
    {
        return EP_MY_CRYPTO_ERROR;
    }
    status = SA_MY_SUCCESS;
    if ((pKdf->derive(ss, sizeof(ss), ct, sizeof(ct), (const uint8_t *)EP_MY_KDF_INFO_TC,
                      sizeof(EP_MY_KDF_INFO_TC) - 1, kTc, sizeof(kTc)) != CRYPTO_MY_SUCCESS) ||
        (pKdf->derive(ss, sizeof(ss), ct, sizeof(ct), (const uint8_t *)EP_MY_KDF_INFO_TM,
                      sizeof(EP_MY_KDF_INFO_TM) - 1, kTm, sizeof(kTm)) != CRYPTO_MY_SUCCESS))
    {
        status = EP_MY_CRYPTO_ERROR;
    }
    CRYPTO_myZeroize(ss, sizeof(ss));

    /* A failure part way leaves the SAs Unkeyed (old keys gone, new ones not bound),
     * never Operational on a key the satellite does not have. */
    if (status == SA_MY_SUCCESS)
    {
        status = EP_myLoadSessionKey(COMMON_SPI_SA01, COMMON_KEYID_SESS_TC, kTc);
    }
    if (status == SA_MY_SUCCESS)
    {
        status = EP_myLoadSessionKey(COMMON_SPI_SA11, COMMON_KEYID_SESS_TM, kTm);
    }
    CRYPTO_myZeroize(kTc, sizeof(kTc));
    CRYPTO_myZeroize(kTm, sizeof(kTm));

    if (status == SA_MY_SUCCESS)
    {
        status = SA_myStorePendingCt(ct, sizeof(ct));
    }
    if (status == SA_MY_SUCCESS)
    {
        memcpy(pCt, ct, sizeof(ct));
    }
    return status;
}

int32_t EP_myGetPendingCiphertext(uint8_t *pCt, size_t ctSize, size_t *pCtLen)
{
    int32_t status;

    if ((pCt == NULL) || (pCtLen == NULL))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    status = SA_myLoadPendingCt(pCt, ctSize, pCtLen);
    return (status == SA_MY_INVALID_STATE) ? EP_MY_NO_PENDING : status;
}

int32_t EP_mySign(const uint8_t *pMsg, size_t msgLen, uint8_t *pSig, size_t *pSigLen)
{
    const CRYPTO_my_Sig_t *pDsa = CRYPTO_myGetSig(COMMON_ALG_ML_DSA_65);
    uint8_t                sk[COMMON_DSA_SK_LEN];
    int32_t                status;
    int32_t                rc;

    if (((pMsg == NULL) && (msgLen != 0)) || (pSig == NULL) || (pSigLen == NULL) ||
        (*pSigLen < COMMON_DSA_SIG_LEN))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((pDsa == NULL) || (pDsa->sign == NULL) || (pDsa->skLen != COMMON_DSA_SK_LEN) ||
        (pDsa->sigLen != COMMON_DSA_SIG_LEN))
    {
        return EP_MY_UNSUPPORTED;
    }

    status = SA_myCopyDsaSecretKey(sk);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    rc = pDsa->sign(sk, (const uint8_t *)EP_MY_DSA_CONTEXT, sizeof(EP_MY_DSA_CONTEXT) - 1, pMsg, msgLen, pSig,
                     pSigLen);
    CRYPTO_myZeroize(sk, sizeof(sk));
    return (rc == CRYPTO_MY_SUCCESS) ? SA_MY_SUCCESS : EP_MY_CRYPTO_ERROR;
}

int32_t EP_myStartSessions(void)
{
    int32_t status = SA_myStart(COMMON_SPI_SA01);
    if (status == SA_MY_SUCCESS)
    {
        status = SA_myStart(COMMON_SPI_SA11);
    }
    if (status == SA_MY_SUCCESS)
    {
        status = SA_myStorePendingCt(NULL, 0);
    }
    return status;
}
