/* Minimal TM-SDLP frame decoding for one fixed channel, mirrored from the SAT side
 * TM_SDLP_myForwardPacket (reduced from io_lib tm_sdlp.h).
 * The SAT side copies one or more SPP packets into a fixed size frame, never segments
 * them, and fills the rest with one idle packet. */
#ifndef _tm_sdlp_my_h_
#define _tm_sdlp_my_h_

#include <stddef.h>
#include <stdint.h>

#include "tf/tmtf_my.h"
// #include "crypto.h"

#define TM_SDLP_MY_SUCCESS          (0)
#define TM_SDLP_MY_INVALID_ARGUMENT (-2)
#define TM_SDLP_MY_INVALID_LENGTH   (-3)
#define TM_SDLP_MY_INVALID_PACKET   (-4)
#define TM_SDLP_MY_INVALID_HEADER   (-5)
// #define TM_SDLP_MY_SECURITY_ERROR  (-6)

/* Fixed dummy channel IDs written into the premade frame header by the SAT side. */
#define TM_SDLP_MY_DUMMY_TFVN 0
#define TM_SDLP_MY_DUMMY_SCID 0x003
#define TM_SDLP_MY_DUMMY_VCID 1

#define TM_SDLP_MY_FRAME_SIZE 1786

/* Fixed SDLS layout: SPI 2 + IV 12 bytes and no trailer.
 * The area stays reserved and zeroed while encryption is disabled. */
#define TM_SDLP_MY_SDLS_HDR_LENGTH 14
#define TM_SDLP_MY_SDLS_TRL_LENGTH 0

/* Data field position inside the frame. */
#define TM_SDLP_MY_DATA_OFFSET (TMTF_MY_PRIHDR_LENGTH + TM_SDLP_MY_SDLS_HDR_LENGTH)
#define TM_SDLP_MY_DATA_END    (TM_SDLP_MY_FRAME_SIZE - TM_SDLP_MY_SDLS_TRL_LENGTH)

/* A Space Packet needs a 6 byte header and at least 1 data byte. */
#define TM_SDLP_MY_SPP_HDR_LENGTH 6
#define TM_SDLP_MY_SPP_MIN_LENGTH 7

/* An idle packet needs a 6 byte header and at least 1 data byte. */
#define TM_SDLP_MY_IDLE_MIN_LENGTH 7
#define TM_SDLP_MY_IDLE_APID       0x7FF

/* SAT side code */

/* Builds the premade frame. Call once during application init. */
//int32 TM_SDLP_myInit(void);
/* Adds one packet to the frame and sends every frame that gets completed.
 * Returns a negative value on a send error; an oversized packet is dropped. */
//int32 TM_SDLP_myForwardPacket(const void *pPacket, size_t packetSize, osal_id_t sockId, const OS_SockAddr_t *pAddr);
/* Fills the current frame with idle data and sends it. An empty frame is not sent. */
//int32 TM_SDLP_mySendFrame(osal_id_t sockId, const OS_SockAddr_t *pAddr);

/* GROUND side code */

/* Finds the next Space Packet in one received TM frame (offset iteration).
 * pFrame        : received frame
 * frameSize     : size of pFrame in bytes (must be TM_SDLP_MY_FRAME_SIZE)
 * pCursor       : in/out. Set to 0 before the first call for a frame; the frame
 *                 header is checked on that call. Advanced past the returned packet.
 * pPacketOffset : out. Offset of the returned packet from the frame start.
 * Returns the packet size (> 0), 0 when the frame has no more packets
 * (the idle packet or the data field end was reached), or a negative error code.
 *
 * Python (ctypes) usage:
 *   cursor, off = c_size_t(0), c_size_t(0)
 *   while (n := lib.TM_SDLP_myExtractPacket(frame, len(frame), byref(cursor), byref(off))) > 0:
 *       packet = frame[off.value : off.value + n]                                      */
int32_t TM_SDLP_myExtractPacket(const void *pFrame, size_t frameSize, size_t *pCursor, size_t *pPacketOffset);

#endif /* _tm_sdlp_my_h_ */
