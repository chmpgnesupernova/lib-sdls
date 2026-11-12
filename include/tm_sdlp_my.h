/* Minimal TM-SDLP framing for one fixed channel, reduced from io_lib tm_sdlp.h.
 * SPP packets are copied into a premade frame and are never segmented. */
#ifndef _tm_sdlp_my_h_
#define _tm_sdlp_my_h_

#include "cfe.h"
#include "tmtf_my.h"
// #include "crypto.h"

#define TM_SDLP_MY_SUCCESS         (0)
#define TM_SDLP_MY_INVALID_LENGTH  (-3)

/* Fixed dummy channel IDs written into the premade frame header. */
#define TM_SDLP_MY_DUMMY_TFVN 0
#define TM_SDLP_MY_DUMMY_SCID 0x003
#define TM_SDLP_MY_DUMMY_VCID 1

#define TM_SDLP_MY_FRAME_SIZE 1786

/* Fixed SDLS layout: SPI 2 + IV 12 bytes and no trailer.
 * The area stays reserved and zeroed while encryption is disabled. */
#define TM_SDLP_MY_SDLS_HDR_LENGTH 14
#define TM_SDLP_MY_SDLS_TRL_LENGTH 0

/* An idle packet needs a 6 byte header and at least 1 data byte. */
#define TM_SDLP_MY_IDLE_MIN_LENGTH 7

/* Builds the premade frame. Call once during application init. */
int32 TM_SDLP_myInit(void);

/* Adds one packet to the frame and sends every frame that gets completed.
 * Returns a negative value on a send error; an oversized packet is dropped. */
int32 TM_SDLP_myForwardPacket(const void *pPacket, size_t packetSize, osal_id_t sockId, const OS_SockAddr_t *pAddr);

/* Fills the current frame with idle data and sends it. An empty frame is not sent. */
int32 TM_SDLP_mySendFrame(osal_id_t sockId, const OS_SockAddr_t *pAddr);

#endif /* _tm_sdlp_my_h_ */
