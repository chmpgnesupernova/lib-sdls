/* SDLS ApplySecurity (TC) / ProcessSecurity (TM). See include/sdls/sdls_my.h.
 *
 * The two-axis decision lives here:
 *   - WHAT to do with a frame comes from the SA service type (NONE / AUTH / AUTH_ENC);
 *   - WHICH implementation does it comes from the SA algorithm ID, through the crypto
 *     registry (src/crypto). This file never names a crypto library. */
#include <string.h>

#include "sdls/sdls_my.h"

#include "../crypto/crypto_my.h"
#include "../sa/sa_shm_internal.h"

/* AAD upper bound: masked Primary Header + SPI + (AUTH only) the TM Frame Data. */
#define SDLS_MY_AAD_MAX 2048

/* Checks that the SA's protection is something this build can do and finds the AEAD.
 * *ppAead is NULL for an unprotected SA (service type NONE). Runs before any IV is taken. */
static int32_t SDLS_myResolve(const common_sa_t *pSa, size_t priHdrLen, const CRYPTO_my_Aead_t **ppAead)
{
    const CRYPTO_my_Aead_t *pAead;
    uint8_t                 alg;

    *ppAead = NULL;
    switch (pSa->service_type)
    {
        case COMMON_SVC_NONE:
            return SA_MY_SUCCESS;
        case COMMON_SVC_AUTH_ENC:
            alg = pSa->enc_alg; /* GCM: one algorithm, one key for both */
            if (pSa->auth_alg != alg)
            {
                return SDLS_MY_UNSUPPORTED;
            }
            break;
        case COMMON_SVC_AUTH:
            alg = pSa->auth_alg;
            break;
        default: /* encryption without authentication is not offered */
            return SDLS_MY_UNSUPPORTED;
    }

    pAead = CRYPTO_myGetAead(alg);
    if ((pAead == NULL) || (pAead->ivLen != SECHDR_MY_IV_LENGTH) || (pAead->tagLen != SDLS_MY_TRAILER_LENGTH) ||
        (pAead->keyLen != COMMON_AES256_KEY_LEN) || (pSa->len_mac != SDLS_MY_TRAILER_LENGTH) ||
        (pSa->len_iv != SECHDR_MY_IV_LENGTH))
    {
        return SDLS_MY_UNSUPPORTED;
    }
    /* The authentication mask must describe exactly this frame type's Primary Header. */
    if (pSa->auth_mask_len != priHdrLen)
    {
        return SA_MY_INVALID_STATE;
    }

    *ppAead = pAead;
    return SA_MY_SUCCESS;
}

/* AAD = (Primary Header AND mask) || SPI [|| Frame Data for AUTH]. */
static size_t SDLS_myBuildAad(const common_sa_t *pSa, const uint8_t *pFrame, size_t priHdrLen, const uint8_t *pData,
                              size_t dataLen, uint8_t *pAad)
{
    size_t len = 0;
    size_t i;

    for (i = 0; i < priHdrLen; i++)
    {
        pAad[len++] = pFrame[i] & pSa->auth_mask_prihdr[i];
    }
    memcpy(&pAad[len], pFrame + priHdrLen, SECHDR_MY_SPI_LENGTH); /* SPI, as on the wire */
    len += SECHDR_MY_SPI_LENGTH;

    if (pSa->service_type == COMMON_SVC_AUTH)
    {
        memcpy(&pAad[len], pData, dataLen);
        len += dataLen;
    }
    return len;
}

int32_t SDLS_myApplySecurityTc(uint16_t spi, void *pFrame, size_t priHdrLen, size_t dataLen, size_t bufSize)
{
    uint8_t                *pBytes = (uint8_t *)pFrame;
    const CRYPTO_my_Aead_t *pAead;
    common_sa_t             sa;
    uint8_t                 iv[SECHDR_MY_IV_LENGTH];
    uint8_t                 key[COMMON_AES256_KEY_LEN];
    uint8_t                 aad[SDLS_MY_AAD_MAX];
    uint8_t                *pData;
    uint8_t                *pTrailer;
    size_t                  aadLen;
    int32_t                 status;
    int32_t                 rc;

    if ((pFrame == NULL) || (priHdrLen == 0) || (priHdrLen > COMMON_PRIHDR_MAX_LEN) ||
        (dataLen > SDLS_MY_AAD_MAX - COMMON_PRIHDR_MAX_LEN - SECHDR_MY_SPI_LENGTH) ||
        (bufSize < priHdrLen + SECHDR_MY_LENGTH + dataLen + SDLS_MY_TRAILER_LENGTH))
    {
        return SA_MY_INVALID_ARGUMENT;
    }

    /* Everything that can refuse the frame, before an IV is taken. */
    status = SA_myGetSa(spi, &sa);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    if ((sa.dir != COMMON_DIR_TC) || (sa.state != COMMON_SA_OPERATIONAL))
    {
        return SA_MY_INVALID_STATE;
    }
    status = SDLS_myResolve(&sa, priHdrLen, &pAead);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }

    /* Security Header: SPI and, for a protected SA, a fresh IV (zero for SA00). */
    status = SECHDR_myApplyTc(spi, pBytes + priHdrLen, bufSize - priHdrLen, iv);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }

    pData    = pBytes + priHdrLen + SECHDR_MY_LENGTH;
    pTrailer = pData + dataLen;
    memset(pTrailer, 0, SDLS_MY_TRAILER_LENGTH);

    if (pAead == NULL)
    {
        return SA_MY_SUCCESS; /* SA00: IV and MAC zero filled (docs §6-7) */
    }

    /* From here the IV is spent: on an error it is simply never used again. */
    status = SA_myCopySaKey(spi, key);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    aadLen = SDLS_myBuildAad(&sa, pBytes, priHdrLen, pData, dataLen, aad);
    if (sa.service_type == COMMON_SVC_AUTH_ENC)
    {
        rc = pAead->encrypt(key, iv, aad, aadLen, pData, dataLen, pTrailer);
    }
    else
    {
        rc = pAead->encrypt(key, iv, aad, aadLen, NULL, 0, pTrailer); /* GMAC */
    }
    CRYPTO_myZeroize(key, sizeof(key));

    if (rc != CRYPTO_MY_SUCCESS)
    {
        memset(pTrailer, 0, SDLS_MY_TRAILER_LENGTH);
        return SDLS_MY_CRYPTO_ERROR;
    }
    return SA_MY_SUCCESS;
}

int32_t SDLS_myProcessSecurityTm(void *pFrame, size_t frameSize, size_t priHdrLen, uint16_t *pSpi)
{
    uint8_t                *pBytes = (uint8_t *)pFrame;
    const CRYPTO_my_Aead_t *pAead;
    common_sa_t             sa;
    uint8_t                 iv[SECHDR_MY_IV_LENGTH];
    uint8_t                 key[COMMON_AES256_KEY_LEN];
    uint8_t                 aad[SDLS_MY_AAD_MAX];
    uint8_t                *pData;
    const uint8_t          *pTrailer;
    uint16_t                spi;
    size_t                  dataLen;
    size_t                  aadLen;
    int32_t                 status;
    int32_t                 rc;

    if ((pFrame == NULL) || (priHdrLen == 0) || (priHdrLen > COMMON_PRIHDR_MAX_LEN) ||
        (frameSize < priHdrLen + SECHDR_MY_LENGTH + SDLS_MY_TRAILER_LENGTH))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    dataLen = frameSize - priHdrLen - SECHDR_MY_LENGTH - SDLS_MY_TRAILER_LENGTH;
    if (dataLen > SDLS_MY_AAD_MAX - COMMON_PRIHDR_MAX_LEN - SECHDR_MY_SPI_LENGTH)
    {
        return SA_MY_INVALID_ARGUMENT;
    }

    /* §4.2.3: SPI known, TM SA, Operational, and (protected SA) the IV is a new ARSN
     * within the window. Nothing is recorded yet. */
    status = SECHDR_myProcessTm(pBytes + priHdrLen, frameSize - priHdrLen, &spi, iv);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    status = SA_myGetSa(spi, &sa);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    status = SDLS_myResolve(&sa, priHdrLen, &pAead);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }

    if (pAead != NULL)
    {
        pData    = pBytes + priHdrLen + SECHDR_MY_LENGTH;
        pTrailer = pData + dataLen;

        status = SA_myCopySaKey(spi, key);
        if (status != SA_MY_SUCCESS)
        {
            return status;
        }
        aadLen = SDLS_myBuildAad(&sa, pBytes, priHdrLen, pData, dataLen, aad);
        if (sa.service_type == COMMON_SVC_AUTH_ENC)
        {
            rc = pAead->decrypt(key, iv, aad, aadLen, pData, dataLen, pTrailer); /* zeroizes on failure */
        }
        else
        {
            rc = pAead->decrypt(key, iv, aad, aadLen, NULL, 0, pTrailer);
            if (rc != CRYPTO_MY_SUCCESS)
            {
                CRYPTO_myZeroize(pData, dataLen); /* no unauthenticated data left behind */
            }
        }
        CRYPTO_myZeroize(key, sizeof(key));
        CRYPTO_myZeroize(aad, aadLen);

        if (rc == CRYPTO_MY_AUTH_FAIL)
        {
            return SDLS_MY_AUTH_FAIL;
        }
        if (rc != CRYPTO_MY_SUCCESS)
        {
            return SDLS_MY_CRYPTO_ERROR;
        }

        /* Only an authentic frame moves the window. The commit re-checks under the lock,
         * so a newer frame committed meanwhile by another process is never rolled back. */
        status = SA_myCommitArsn(spi, iv);
        if (status != SA_MY_SUCCESS)
        {
            CRYPTO_myZeroize(pData, dataLen);
            return status;
        }
    }
    /* SA10 (no frame protection, docs §6-4): IV and MAC fields are ignored. */

    if (pSpi != NULL)
    {
        *pSpi = spi;
    }
    return SA_MY_SUCCESS;
}
