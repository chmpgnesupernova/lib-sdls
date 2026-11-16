/* Minimal TM-SDLP frame decoding for one fixed channel, mirrored from the SAT side
 * TM_SDLP_myForwardPacket (reduced from io_lib tm_sdlp.c). */
#include "tm_sdlp_my.h"

/* Checks the frame level fields the SAT side always writes, then hands the frame to SDLS. */
static int32_t TM_SDLP_myCheckFrame(uint8_t *pFrame, size_t frameSize, uint16_t *pSpi)
{
    const TMTF_my_PriHdr_t *pHdr = (const TMTF_my_PriHdr_t *)pFrame;

    /* The SAT side always sends the whole fixed size frame. */
    if (frameSize != TM_SDLP_MY_FRAME_SIZE)
    {
        return TM_SDLP_MY_INVALID_LENGTH;
    }

    /* Channel IDs are not checked because the prototype has only one channel. */
    // if ((TMTF_MY_RD_TF_VERSION(*pHdr) != TM_SDLP_MY_DUMMY_TFVN) || (TMTF_MY_RD_SCID(*pHdr) != TM_SDLP_MY_DUMMY_SCID) ||
    //     (TMTF_MY_RD_VCID(*pHdr) != TM_SDLP_MY_DUMMY_VCID))
    // {
    //     return TM_SDLP_MY_INVALID_CHANNEL;
    // }

    /* Packets are never segmented, so every frame uses the packet service and starts
     * with a packet (First Header Pointer 0). */
    if ((TMTF_MY_RD_SEGLENGTHID(*pHdr) != TMTF_MY_SEGLENGTHID_PKT) || (TMTF_MY_RD_FIRSTHDRPTR(*pHdr) != 0))
    {
        return TM_SDLP_MY_INVALID_HEADER;
    }

    /* SDLS: SPI names an Operational TM SA; a session frame must be a new ARSN within the
     * window and pass the MAC, and is decrypted in place. GVCID is not matched against
     * the SA (dummy channel IDs). */
    if (SDLS_myProcessSecurityTm(pFrame, frameSize, TMTF_MY_PRIHDR_LENGTH, pSpi) != SA_MY_SUCCESS)
    {
        return TM_SDLP_MY_SECURITY_ERROR;
    }

    return TM_SDLP_MY_SUCCESS;
}

int32_t TM_SDLP_myExtractPacket(void *pFrame, size_t frameSize, size_t *pCursor, size_t *pPacketOffset,
                                uint16_t *pSpi)
{
    uint8_t       *pBytes = (uint8_t *)pFrame;
    uint16_t       spi;
    size_t         offset;
    size_t         remaining;
    size_t         packetSize;
    uint16_t       apid;
    int32_t        status;

    if ((pFrame == NULL) || (pCursor == NULL) || (pPacketOffset == NULL))
    {
        return TM_SDLP_MY_INVALID_ARGUMENT;
    }

    /* Cursor 0 starts a new frame: check the header once and jump to the data field. */
    if (*pCursor == 0)
    {
        status = TM_SDLP_myCheckFrame(pBytes, frameSize, &spi);
        if (status != TM_SDLP_MY_SUCCESS)
        {
            return status;
        }
        if (pSpi != NULL)
        {
            *pSpi = spi;
        }
        *pCursor = TM_SDLP_MY_DATA_OFFSET;
    }
    else if (frameSize != TM_SDLP_MY_FRAME_SIZE)
    {
        return TM_SDLP_MY_INVALID_LENGTH;
    }

    offset = *pCursor;
    if ((offset < TM_SDLP_MY_DATA_OFFSET) || (offset > TM_SDLP_MY_DATA_END))
    {
        return TM_SDLP_MY_INVALID_ARGUMENT;
    }

    /* The data field is full: no more packets. */
    if (offset == TM_SDLP_MY_DATA_END)
    {
        return 0;
    }

    /* The SAT side leaves either 0 bytes or room for a whole idle packet,
     * so a remainder smaller than one packet means the frame is broken. */
    remaining = TM_SDLP_MY_DATA_END - offset;
    if (remaining < TM_SDLP_MY_SPP_MIN_LENGTH)
    {
        return TM_SDLP_MY_INVALID_PACKET;
    }

    apid       = (uint16_t)(((pBytes[offset] & 0x07) << 8) | pBytes[offset + 1]);
    packetSize = (((size_t)pBytes[offset + 4] << 8) | pBytes[offset + 5]) + TM_SDLP_MY_SPP_MIN_LENGTH;

    if (packetSize > remaining)
    {
        return TM_SDLP_MY_INVALID_PACKET;
    }

    /* The idle packet always fills the rest of the data field. */
    if (apid == TM_SDLP_MY_IDLE_APID)
    {
        *pCursor = TM_SDLP_MY_DATA_END;
        return 0;
    }

    *pPacketOffset = offset;
    *pCursor       = offset + packetSize;

    return (int32_t)packetSize;
}
