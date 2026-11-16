/* SDLS Security Header build (TC) and check (TM) against the shared SA DB.
 * See include/sdls/sechdr_my.h. */
#include "sdls/sechdr_my.h"

int32_t SECHDR_myApplyTc(uint16_t spi, void *pBuf, size_t bufSize, uint8_t *pIv)
{
    SECHDR_my_SecHdr_t *pHdr = (SECHDR_my_SecHdr_t *)pBuf;
    uint8_t             iv[SECHDR_MY_IV_LENGTH];
    common_sa_t         sa;
    int32_t             status;

    if ((pBuf == NULL) || (bufSize < SECHDR_MY_LENGTH))
    {
        return SA_MY_INVALID_ARGUMENT;
    }

    status = SA_myGetSa(spi, &sa);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    if ((sa.dir != COMMON_DIR_TC) || (sa.state != COMMON_SA_OPERATIONAL))
    {
        return SA_MY_INVALID_STATE;
    }

    if (sa.service_type == COMMON_SVC_NONE)
    {
        /* SA00 carries EP PDUs signed at PDU level: the IV field is present but
         * zero filled (docs §6-7), and there is no counter to advance. */
        memset(iv, 0, sizeof(iv));
    }
    else
    {
        /* NextIv re-checks direction and state under the SA DB lock, so an SA stopped
         * between GetSa and here is still refused. */
        status = SA_myNextIv(spi, iv);
        if (status != SA_MY_SUCCESS)
        {
            return status;
        }
    }

    SECHDR_MY_WR_SPI(*pHdr, spi);
    SECHDR_MY_WR_IV(*pHdr, iv);
    if (pIv != NULL)
    {
        memcpy(pIv, iv, SECHDR_MY_IV_LENGTH);
    }

    return SA_MY_SUCCESS;
}

int32_t SECHDR_myProcessTm(const void *pBuf, size_t bufSize, uint16_t *pSpi, uint8_t *pIv)
{
    const SECHDR_my_SecHdr_t *pHdr = (const SECHDR_my_SecHdr_t *)pBuf;
    uint8_t                   iv[SECHDR_MY_IV_LENGTH];
    common_sa_t               sa;
    uint16_t                  spi;
    int32_t                   status;

    if ((pBuf == NULL) || (bufSize < SECHDR_MY_LENGTH) || (pSpi == NULL) || (pIv == NULL))
    {
        return SA_MY_INVALID_ARGUMENT;
    }

    spi = SECHDR_MY_RD_SPI(*pHdr);
    SECHDR_MY_RD_IV(*pHdr, iv);

    /* §4.2.3: an unknown SPI or an SA that is not Operational drops the frame. */
    status = SA_myGetSa(spi, &sa);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }
    if ((sa.dir != COMMON_DIR_TM) || (sa.state != COMMON_SA_OPERATIONAL))
    {
        return SA_MY_INVALID_STATE;
    }

    /* SA10 (no frame protection, docs §6-4) has no ARSN; the IV field is ignored. */
    if (sa.service_type != COMMON_SVC_NONE)
    {
        status = SA_myCheckArsn(spi, iv);
        if (status != SA_MY_SUCCESS)
        {
            return status;
        }
    }

    *pSpi = spi;
    memcpy(pIv, iv, SECHDR_MY_IV_LENGTH);

    return SA_MY_SUCCESS;
}
