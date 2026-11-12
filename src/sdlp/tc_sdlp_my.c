/* Minimal TC-SDLP frame decoding for one fixed channel, based on NOS3 CI udp_tf. */
#include <string.h>

#include "tc_sdlp_my.h"
#include "ci_lab_events.h"

int32 TC_SDLP_myExtractPacket(CFE_SB_Buffer_t *pBuf, int32 frameSize)
{
    uint8                  *pFrame     = pBuf->Msg.Byte;
    const TCTF_my_PriHdr_t *pHdr       = (const TCTF_my_PriHdr_t *)pFrame;
    //TC_SDLP_MY_SDLS_HDR_LENGTH = 0 for now 
    const int32             dataOffset = TCTF_MY_PRIHDR_LENGTH + TC_SDLP_MY_SDLS_HDR_LENGTH;
    int32                   packetSize;
    int32                   packetLengthField;
    // int32 iStatus;
    // TC_t  crypto_tc_frame;

    /* The frame must hold the headers, the trailers and the smallest packet. */
    //FECF length = 0 for now 
    packetSize = frameSize - dataOffset - TC_SDLP_MY_SDLS_TRL_LENGTH - TC_SDLP_MY_FECF_LENGTH;
    
    // SPP Header Size 6 Byte + Payload 1 Byte = minimum SPP packet size 7 Byte
    if (packetSize < TC_SDLP_MY_SPP_MIN_LENGTH)
    {
        CFE_EVS_SendEvent(CI_LAB_TCFRAME_ERR_EID, CFE_EVS_EventType_ERROR, "CI: TC frame dropped, too short (%d)",
                          (int)frameSize);
        return TC_SDLP_MY_INVALID_LENGTH; // return (-3) 
    }

    // The Frame Length field must match the received datagram size. 
    if (TCTF_MY_RD_FRAMELEN(*pHdr) + 1 != frameSize)
    {
        CFE_EVS_SendEvent(CI_LAB_TCFRAME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: TC frame dropped, length field %d != received %d", (int)TCTF_MY_RD_FRAMELEN(*pHdr) + 1,
                          (int)frameSize);
        return TC_SDLP_MY_INVALID_LENGTH; // return (-3) 
    }

    /* Channel IDs are not checked because the prototype has only one channel. */
    // if ((TCTF_MY_RD_TF_VERSION(*pHdr) != TC_SDLP_MY_DUMMY_TFVN) || (TCTF_MY_RD_SCID(*pHdr) != TC_SDLP_MY_DUMMY_SCID) ||
    //     (TCTF_MY_RD_VCID(*pHdr) != TC_SDLP_MY_DUMMY_VCID))
    // {
    //     return TC_SDLP_MY_INVALID_CHANNEL;
    // }

    /* Bypass, Control Command and Sequence Number are for COP-1, which is not used. */
    // if ((TCTF_MY_RD_CTLCMD_FLG(*pHdr) != 0) || (TCTF_MY_RD_BYPASS_FLG(*pHdr) != 1))
    // {
    //     return TC_SDLP_MY_INVALID_CHANNEL;
    // }

    /* The optional FECF is not used, so there is no CRC check. */
    // if (FECF in the last 2 bytes != CRC-16 of the rest of the frame)
    // {
    //     return TC_SDLP_MY_INVALID_LENGTH;
    // }

    /* SDLS is disabled: the Security Header and Trailer are skipped unchecked.
     * Later, the SA is found by SPI and the MAC and Sequence Number are verified here. */
    // iStatus = Crypto_TC_ProcessSecurity(pFrame, (int *)&frameSize, &crypto_tc_frame);
    // if (iStatus != CRYPTO_LIB_SUCCESS)
    // {
    //     return TC_SDLP_MY_SECURITY_ERROR;
    // }

    /* The data field holds exactly one Space Packet. */
    packetLengthField = ((int32)pFrame[dataOffset + 4] << 8) | pFrame[dataOffset + 5];
    if (packetLengthField + TC_SDLP_MY_SPP_MIN_LENGTH != packetSize)
    {
        CFE_EVS_SendEvent(CI_LAB_TCFRAME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: TC frame dropped, packet size %d != data field %d",
                          (int)(packetLengthField + TC_SDLP_MY_SPP_MIN_LENGTH), (int)packetSize);
        return TC_SDLP_MY_INVALID_PACKET;
    }

    // The areas transmitted to SoftwareBus overlaps, so the memmove to same memory address 

    memmove(pFrame, pFrame + dataOffset, (size_t)packetSize);

    return packetSize;
}
