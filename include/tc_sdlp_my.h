/* Minimal TC-SDLP frame encoding for one fixed channel, mirrored from the SAT side
 * TC_SDLP_myExtractPacket (based on NOS3 CI udp_tf).
 * Frame: [Primary Header 5][Security Header][Space Packet][Security Trailer].
 * Security Header/Trailer are 0 bytes while SDLS is disabled.
 * No Segment Header (Type-D frame) and no FECF. */
#ifndef _tc_sdlp_my_h_
#define _tc_sdlp_my_h_

#include <stddef.h>
#include <stdint.h>

#include "tf/tctf_my.h"
// #include "crypto.h"

#define TC_SDLP_MY_SUCCESS          (0)
#define TC_SDLP_MY_INVALID_ARGUMENT (-2)
#define TC_SDLP_MY_INVALID_LENGTH   (-3)
#define TC_SDLP_MY_INVALID_PACKET   (-4)
// #define TC_SDLP_MY_INVALID_CHANNEL (-5)
// #define TC_SDLP_MY_SECURITY_ERROR  (-6)
#define TC_SDLP_MY_BUFFER_TOO_SMALL (-7)
#define TC_SDLP_MY_NOT_INITIALIZED  (-8)

/* Channel IDs written into every frame. They match the SAT side expected IDs. */
#define TC_SDLP_MY_DUMMY_TFVN 0
#define TC_SDLP_MY_DUMMY_SCID 0x003
#define TC_SDLP_MY_DUMMY_VCID 0

/* COP-1 is not used: Type-BD frame (Bypass = 1, Control Command = 0).
 * These match the SAT side flag check. */
#define TC_SDLP_MY_BYPASS_FLG 1
#define TC_SDLP_MY_CTLCMD_FLG 0

/* SDLS TC baseline: SPI 2 + Sequence Number 4 bytes, and a 16 byte MAC.
 * The fields stay reserved and are skipped while SDLS is disabled. */
#define TC_SDLP_MY_SDLS_HDR_LENGTH 0
#define TC_SDLP_MY_SDLS_TRL_LENGTH 0

/* The Frame Error Control Field is optional and not used. */
#define TC_SDLP_MY_FECF_LENGTH 0

/* A Space Packet needs a 6 byte header and at least 1 data byte. */
#define TC_SDLP_MY_SPP_HDR_LENGTH  6
#define TC_SDLP_MY_SPP_MIN_LENGTH  7

/* Largest Space Packet that fits into one TC frame. */
#define TC_SDLP_MY_MAX_PACKET_LENGTH                                                       \
    (TCTF_MY_MAX_FRAME_LENGTH - TCTF_MY_PRIHDR_LENGTH - TC_SDLP_MY_SDLS_HDR_LENGTH - \
     TC_SDLP_MY_SDLS_TRL_LENGTH - TC_SDLP_MY_FECF_LENGTH)

/* SAT side code */
// int32 TC_SDLP_myExtractPacket(CFE_SB_Buffer_t *pBuf, int32 frameSize);

/* GROUND side code */

/* Sets up the frame layout and resets the Frame Sequence Number.
 * Call once before TC_SDLP_myBuildFrame. Returns TC_SDLP_MY_SUCCESS. */
int32_t TC_SDLP_myInit(void);

/* Wraps one Space Packet into a TC frame written to pBuf.
 * pPacket    : one complete Space Packet (header + data)
 * packetSize : size of pPacket in bytes
 * pBuf       : output buffer for the frame; must not overlap pPacket
 * bufSize    : size of pBuf in bytes (TCTF_MY_MAX_FRAME_LENGTH is always enough)
 * Returns the frame size in bytes, or a negative error code. */
int32_t TC_SDLP_myBuildFrame(const void *pPacket, size_t packetSize, void *pBuf, size_t bufSize);

#endif /* _tc_sdlp_my_h_ */
