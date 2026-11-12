/* Minimal TC-SDLP frame encoding for one fixed channel, mirrored from the SAT side
 * TC_SDLP_myExtractPacket (based on NOS3 CI udp_tf). */
#include <stdbool.h>
#include <string.h>

#include "tc_sdlp_my.h"

typedef struct
{
    bool     initialized;     /* TC_SDLP_myInit has been called */
    uint16_t dataFieldOffset; /* Data field offset from the frame start */
    uint16_t maxPacketSize;   /* Largest packet that fits into one frame */
    uint8_t  frameSeqNum;     /* Frame Sequence Number, not checked by the SAT side (no COP-1) */
} TC_SDLP_myFrameInfo_t;

static TC_SDLP_myFrameInfo_t TC_SDLP_myFrameInfo;

int32_t TC_SDLP_myInit(void)
{
    TC_SDLP_myFrameInfo_t *pFrameInfo = &TC_SDLP_myFrameInfo;

    /* SDLS is disabled, so fixed lengths replace the SA lookup.
     * Later the Security Header/Trailer lengths come from the SA here. */
    pFrameInfo->dataFieldOffset = TCTF_MY_PRIHDR_LENGTH + TC_SDLP_MY_SDLS_HDR_LENGTH;
    pFrameInfo->maxPacketSize   = TC_SDLP_MY_MAX_PACKET_LENGTH;
    pFrameInfo->frameSeqNum     = 0;
    pFrameInfo->initialized     = true;

    return TC_SDLP_MY_SUCCESS;
}

int32_t TC_SDLP_myBuildFrame(const void *pPacket, size_t packetSize, void *pBuf, size_t bufSize)
{
    TC_SDLP_myFrameInfo_t *pFrameInfo = &TC_SDLP_myFrameInfo;
    const uint8_t         *pSpp       = (const uint8_t *)pPacket;
    uint8_t               *pFrame     = (uint8_t *)pBuf;
    TCTF_my_PriHdr_t      *pHdr       = (TCTF_my_PriHdr_t *)pBuf;
    size_t                 frameSize;
    size_t                 packetLengthField;

    if (!pFrameInfo->initialized)
    {
        return TC_SDLP_MY_NOT_INITIALIZED;
    }

    if ((pPacket == NULL) || (pBuf == NULL))
    {
        return TC_SDLP_MY_INVALID_ARGUMENT;
    }

    /* SPP Header Size 6 Byte + Payload 1 Byte = minimum SPP packet size 7 Byte.
     * The frame Length field is 10 bits, so one frame holds at most 1024 bytes. */
    if ((packetSize < TC_SDLP_MY_SPP_MIN_LENGTH) || (packetSize > pFrameInfo->maxPacketSize))
    {
        return TC_SDLP_MY_INVALID_LENGTH;
    }

    /* The SAT side drops the frame unless the SPP length field matches the data field. */
    packetLengthField = ((size_t)pSpp[4] << 8) | pSpp[5];
    if (packetLengthField + TC_SDLP_MY_SPP_MIN_LENGTH != packetSize)
    {
        return TC_SDLP_MY_INVALID_PACKET;
    }

    frameSize = pFrameInfo->dataFieldOffset + packetSize + TC_SDLP_MY_SDLS_TRL_LENGTH + TC_SDLP_MY_FECF_LENGTH;
    if (bufSize < frameSize)
    {
        return TC_SDLP_MY_BUFFER_TOO_SMALL;
    }

    /* Primary Header: the same fields the SAT side reads. */
    memset(pFrame, 0, pFrameInfo->dataFieldOffset);
    TCTF_MY_WR_TF_VERSION(*pHdr, TC_SDLP_MY_DUMMY_TFVN);
    TCTF_MY_WR_BYPASS_FLG(*pHdr, TC_SDLP_MY_BYPASS_FLG);
    TCTF_MY_WR_CTLCMD_FLG(*pHdr, TC_SDLP_MY_CTLCMD_FLG);
    TCTF_MY_WR_SCID(*pHdr, TC_SDLP_MY_DUMMY_SCID);
    TCTF_MY_WR_VCID(*pHdr, TC_SDLP_MY_DUMMY_VCID);
    TCTF_MY_WR_FRAMELEN(*pHdr, frameSize - 1);
    TCTF_MY_WR_SEQNUM(*pHdr, pFrameInfo->frameSeqNum);

    /* SDLS is disabled: the Security Header area (0 bytes now) stays zeroed. */

    /* The data field holds exactly one Space Packet. */
    memcpy(pFrame + pFrameInfo->dataFieldOffset, pSpp, packetSize);

    /* SDLS is disabled: the Security Trailer area (0 bytes now) stays zeroed.
     * Later the SA adds the Security Header/Trailer and the MAC here. */
    memset(pFrame + pFrameInfo->dataFieldOffset + packetSize, 0, TC_SDLP_MY_SDLS_TRL_LENGTH);
    // iStatus = Crypto_TC_ApplySecurity(...);
    // if (iStatus != CRYPTO_LIB_SUCCESS)
    // {
    //     return TC_SDLP_MY_SECURITY_ERROR;
    // }

    /* The optional FECF is not used, so no CRC is appended. */

    pFrameInfo->frameSeqNum++;

    return (int32_t)frameSize;
}
