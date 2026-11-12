/* Minimal TC-SDLP frame decoding for one fixed channel, based on NOS3 CI udp_tf. */
#include <string.h>

#include "../../incldue/tc_sdlp_my.h"
//#include "ci_lab_events.h"

typedef struct
{
} TC_SDLP_myFrameInfo_t;

static TC_SDLP_myFrameInfo_t TC_SDLP_myFrameInfo;
static uint8                 TC_SDLP_myFrameBuffer[TC_SDLP_MY_FRAME_SIZE];

int32 TC_SDLP_myInit(void)
{

}

int32 TC_SDLP_mySendFrame(void* pPacket, size_t packetSize, void* pBuf)
{

}


