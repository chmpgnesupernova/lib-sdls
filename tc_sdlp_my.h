/* Minimal TC-SDLP frame decoding for one fixed channel, based on NOS3 CI udp_tf.
 * Frame: [Primary Header 5][Security Header 6][Space Packet][Security Trailer 16].
 * No Segment Header (Type-D frame) and no FECF. */
#ifndef _tc_sdlp_my_h_
#define _tc_sdlp_my_h_

#include "cfe.h"
#include "tctf_my.h"
// #include "crypto.h"

#define TC_SDLP_MY_SUCCESS          (0)
#define TC_SDLP_MY_INVALID_LENGTH   (-3)
#define TC_SDLP_MY_INVALID_PACKET   (-4)
// #define TC_SDLP_MY_INVALID_CHANNEL (-5)
// #define TC_SDLP_MY_SECURITY_ERROR  (-6)

/* Expected channel IDs. The prototype has one channel, so they are not checked. */
#define TC_SDLP_MY_DUMMY_TFVN 0
#define TC_SDLP_MY_DUMMY_SCID 0x003
#define TC_SDLP_MY_DUMMY_VCID 0

/* SDLS TC baseline: SPI 2 + Sequence Number 4 bytes, and a 16 byte MAC.
 * The fields stay reserved and are skipped while SDLS is disabled. */
#define TC_SDLP_MY_SDLS_HDR_LENGTH 0
#define TC_SDLP_MY_SDLS_TRL_LENGTH 0

/* The Frame Error Control Field is optional and not used. */
#define TC_SDLP_MY_FECF_LENGTH 0

/* A Space Packet needs a 6 byte header and at least 1 data byte. */
#define TC_SDLP_MY_SPP_HDR_LENGTH  6
#define TC_SDLP_MY_SPP_MIN_LENGTH  7

/* Checks one received TC frame and moves its Space Packet to the buffer start.
 * Returns the packet size, or a negative value if the frame is dropped. */
int32 TC_SDLP_myExtractPacket(CFE_SB_Buffer_t *pBuf, int32 frameSize);

#endif /* _tc_sdlp_my_h_ */
