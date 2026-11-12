/* Minimal TM-SDLP framing for one fixed channel, reduced from io_lib tm_sdlp.c. */
#include "tm_sdlp_my.h"
#include "to_lab_events.h"

typedef struct
{
    uint16            dataFieldLength;   /* Length of the data field */
    uint16            dataFieldOffset;   /* Data field offset from the frame start */
    uint16            freeOctets;        /* Free octets left in the data field */
    uint16            currentDataOffset; /* Next free data octet from the frame start */
    uint8             mcFrameCount;      /* Master Channel Frame Count */
    TMTF_my_PriHdr_t *frame;             /* Transfer Frame buffer */
} TM_SDLP_myFrameInfo_t;

static TM_SDLP_myFrameInfo_t TM_SDLP_myFrameInfo;
static uint8                 TM_SDLP_myFrameBuffer[TM_SDLP_MY_FRAME_SIZE];

/* The remainder must be 0 or large enough for an idle packet. */
static bool TM_SDLP_myFits(size_t packetSize, size_t freeOctets)
{
    return (packetSize == freeOctets) || (packetSize + TM_SDLP_MY_IDLE_MIN_LENGTH <= freeOctets);
}

/* Fills the remaining data field with one idle packet. */
static void TM_SDLP_myAddIdlePacket(TM_SDLP_myFrameInfo_t *pFrameInfo)
{
    uint8 *pIdle;
    uint16 idleLengthField;

    if (pFrameInfo->freeOctets == 0)
    {
        return;
    }

    pIdle           = (uint8 *)pFrameInfo->frame + pFrameInfo->currentDataOffset;
    idleLengthField = pFrameInfo->freeOctets - TM_SDLP_MY_IDLE_MIN_LENGTH;

    /* Zero the area first so data from the previous frame is not sent again. */
    CFE_PSP_MemSet(pIdle, 0, pFrameInfo->freeOctets);

    /* CCSDS header: idle APID 0x7FF, unsegmented sequence flags and data length. */
    pIdle[0] = 0x07;
    pIdle[1] = 0xFF;
    pIdle[2] = 0xC0;
    pIdle[4] = (uint8)(idleLengthField >> 8);
    pIdle[5] = (uint8)(idleLengthField & 0xFF);

    pFrameInfo->currentDataOffset += pFrameInfo->freeOctets;
    pFrameInfo->freeOctets = 0;
}

/* Writes the Master Channel Frame Count and rewinds the frame for the next packets. */
static void TM_SDLP_myCompleteFrame(TM_SDLP_myFrameInfo_t *pFrameInfo)
{
    pFrameInfo->mcFrameCount++;
    TMTF_MY_WR_MCFRMCNT(*pFrameInfo->frame, pFrameInfo->mcFrameCount);

    pFrameInfo->freeOctets        = pFrameInfo->dataFieldLength;
    pFrameInfo->currentDataOffset = pFrameInfo->dataFieldOffset;
}

int32 TM_SDLP_myInit(void)
{
    TM_SDLP_myFrameInfo_t *pFrameInfo = &TM_SDLP_myFrameInfo;
    int32                  dataFieldLength;
    uint16                 dataFieldOffset;
    uint8                  sdlsSecurityHeaderLength;
    uint8                  sdlsSecurityTrailerLength;
    // SecurityAssociation_t *sa_ptr = NULL;

    /* Encryption is disabled, so fixed lengths replace the SA lookup. */
    // iStatus = sa_if->sa_get_operational_sa_from_gvcid(0, TM_SDLP_MY_DUMMY_SCID, TM_SDLP_MY_DUMMY_VCID, 0, &sa_ptr);
    // if (iStatus != CRYPTO_LIB_SUCCESS)
    // {
    //     return iStatus;
    // }
    // sdlsSecurityHeaderLength  = Crypto_Get_Security_Header_Length(sa_ptr);
    // sdlsSecurityTrailerLength = Crypto_Get_Security_Trailer_Length(sa_ptr);
    sdlsSecurityHeaderLength  = TM_SDLP_MY_SDLS_HDR_LENGTH;
    sdlsSecurityTrailerLength = TM_SDLP_MY_SDLS_TRL_LENGTH;

    dataFieldOffset = TMTF_MY_PRIHDR_LENGTH + sdlsSecurityHeaderLength;
    dataFieldLength = (int32)TM_SDLP_MY_FRAME_SIZE - dataFieldOffset - sdlsSecurityTrailerLength;

    if (dataFieldLength < TM_SDLP_MY_IDLE_MIN_LENGTH)
    {
        CFE_EVS_SendEvent(TO_FRAMEINIT_ERR_EID, CFE_EVS_EventType_ERROR, "TO invalid TM frame data length %d",
                          (int)dataFieldLength);
        return TM_SDLP_MY_INVALID_LENGTH;
    }

    pFrameInfo->dataFieldLength   = (uint16)dataFieldLength;
    pFrameInfo->dataFieldOffset   = dataFieldOffset;
    pFrameInfo->freeOctets        = pFrameInfo->dataFieldLength;
    pFrameInfo->currentDataOffset = dataFieldOffset;
    pFrameInfo->mcFrameCount      = 0;
    pFrameInfo->frame             = (TMTF_my_PriHdr_t *)TM_SDLP_myFrameBuffer;

    CFE_PSP_MemSet(TM_SDLP_myFrameBuffer, 0, sizeof(TM_SDLP_myFrameBuffer));

    TMTF_MY_WR_TF_VERSION(*pFrameInfo->frame, TM_SDLP_MY_DUMMY_TFVN);
    TMTF_MY_WR_SCID(*pFrameInfo->frame, TM_SDLP_MY_DUMMY_SCID);
    TMTF_MY_WR_VCID(*pFrameInfo->frame, TM_SDLP_MY_DUMMY_VCID);
    TMTF_MY_WR_SEGLENGTHID(*pFrameInfo->frame, TMTF_MY_SEGLENGTHID_PKT);

    /* Packets are never segmented, so every sent frame starts with a packet. */
    TMTF_MY_WR_FIRSTHDRPTR(*pFrameInfo->frame, 0);

    return TM_SDLP_MY_SUCCESS;
}

int32 TM_SDLP_mySendFrame(osal_id_t sockId, const OS_SockAddr_t *pAddr)
{
    TM_SDLP_myFrameInfo_t *pFrameInfo = &TM_SDLP_myFrameInfo;

    if (pFrameInfo->freeOctets == pFrameInfo->dataFieldLength)
    {
        return TM_SDLP_MY_SUCCESS;
    }

    TM_SDLP_myAddIdlePacket(pFrameInfo);
    TM_SDLP_myCompleteFrame(pFrameInfo);

    /* Encryption is disabled for now. */
    // iStatus = Crypto_TM_ApplySecurity((uint8_t *)pFrameInfo->frame, TM_SDLP_MY_FRAME_SIZE);
    // if (iStatus != CRYPTO_LIB_SUCCESS)
    // {
    //     return iStatus;
    // }

    return OS_SocketSendTo(sockId, TM_SDLP_myFrameBuffer, sizeof(TM_SDLP_myFrameBuffer), pAddr);
}

int32 TM_SDLP_myForwardPacket(const void *pPacket, size_t packetSize, osal_id_t sockId, const OS_SockAddr_t *pAddr)
{
    TM_SDLP_myFrameInfo_t *pFrameInfo = &TM_SDLP_myFrameInfo;
    int32                  status     = TM_SDLP_MY_SUCCESS;

    //if SPP packet do not fit into 1786 byte, then Drop the packet 
    if (!TM_SDLP_myFits(packetSize, pFrameInfo->dataFieldLength))
    {
        CFE_EVS_SendEvent(TO_PKTSIZE_ERR_EID, CFE_EVS_EventType_ERROR, "TO dropped packet of %u bytes",
                          (unsigned int)packetSize);
        return TM_SDLP_MY_SUCCESS;
    }
    

    //if SPP packet do not fit into remaining buffer in the frame previously filled,
    //then fill it with idle packet and send it 
    if (!TM_SDLP_myFits(packetSize, pFrameInfo->freeOctets))
    {
        status = TM_SDLP_mySendFrame(sockId, pAddr);
        if (status < 0)
        {
            return status;
        }
    }


    //if SPP packet < freeOctets < dataFieldLength, 
    //then copy the SPP packet to remaining buffer of premade Frame 
    CFE_PSP_MemCpy((uint8 *)pFrameInfo->frame + pFrameInfo->currentDataOffset, pPacket, packetSize);
    pFrameInfo->currentDataOffset += packetSize;
    pFrameInfo->freeOctets -= packetSize;

    //if the SPP packet is fits perfectly into remainig size, then send it 
    if (pFrameInfo->freeOctets == 0)
    {
        status = TM_SDLP_mySendFrame(sockId, pAddr);
    }
    //return the status and loop 
    //if there is no message to foward in TLM pipe, then the mySendFrame() will be called 
    return status;
}
