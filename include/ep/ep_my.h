/* Ground side PQC key exchange (EP), called from the Python ground system.
 *
 * Flow (project decision; SDLS-EP names kept, the standard is not followed strictly):
 *
 *   satellite                                   ground
 *   ML-KEM key pair, ek ── TM on SA10 ──────▶   RoutingService: EP_myAcceptKemPublicKey(ek)
 *                                                 encaps -> ct, ss
 *                                                 HKDF(ss) -> SESS_TC, SESS_TM keys
 *                                                 SA01 / SA11: (Stop, Expire,) SetKey, Rekey -> Keyed
 *                                                 ct kept in the SA DB for the sender
 *   verify, decaps, HKDF ◀── TC on SA00 ─────   MiniCmdUtil: StartSA PDU = ... ct ...
 *   Rekey + Start                                 signed with EP_mySign (ML-DSA-65)
 *   ack ── TM on SA10 ──────────────────────▶   EP_myStartSessions(): SA01 / SA11 -> Operational
 *
 * What the library owns: the shared secret, the session keys and the ground ML-DSA secret
 * key. None of them is ever returned to the caller. The ciphertext and signatures are
 * public data and are returned.
 *
 * NOT decided yet (agree with the satellite side before relying on it):
 *   - the EP PDU byte format (tag, length, where ct and the signature go);
 *   - how a StartSA PDU is split over TC frames: ct (1088 B) + signature (3309 B) does
 *     not fit one TC frame (max packet 989 B);
 *   - whether the ek is pinned (preloaded) or trusted as received (SA10 is unauthenticated,
 *     docs §6-4: a substituted ek lets an attacker learn the ground's session keys and
 *     forge TM, though not reach the satellite, which checks the ground signature).
 * Until then the caller builds the PDU bytes and signs them with EP_mySign.
 *
 * Every function needs SA_myOpen (sa/sa_shm_my.h) in this process first.
 * Return codes: SA_MY_* (sa/sa_shm_my.h) or the EP_MY_* codes below.
 */
#ifndef _ep_my_h_
#define _ep_my_h_

#include <stddef.h>
#include <stdint.h>

#include "sa/sa_my.h"

#define EP_MY_KEM_PK_LENGTH  COMMON_KEM_PK_LEN  /* 1184, ML-KEM-768 ek */
#define EP_MY_KEM_CT_LENGTH  COMMON_KEM_CT_LEN  /* 1088 */
#define EP_MY_DSA_SIG_LENGTH COMMON_DSA_SIG_LEN /* 3309, ML-DSA-65 */

/* ML-DSA context string (FIPS 204 pure ML-DSA). The satellite verifies with the same one. */
#define EP_MY_DSA_CONTEXT "lib-sdls EP v1"

/* Session key derivation, the satellite does the same after decaps:
 *   K_TC = HKDF-SHA256(ikm = ss, salt = ct, info = EP_MY_KDF_INFO_TC, 32 bytes)
 *   K_TM = HKDF-SHA256(ikm = ss, salt = ct, info = EP_MY_KDF_INFO_TM, 32 bytes)
 * Two labels give independent keys per direction; the salt binds them to this exchange. */
#define EP_MY_KDF_INFO_TC "lib-sdls SESS_TC v1"
#define EP_MY_KDF_INFO_TM "lib-sdls SESS_TM v1"

#define EP_MY_CRYPTO_ERROR  (-30) /* KEM, KDF or signature backend failure (bad ek format, ...) */
#define EP_MY_NO_PENDING    (-31) /* no key exchange in progress */
#define EP_MY_UNSUPPORTED   (-32) /* algorithm not built in */

/* Ground side of the key exchange, called when the satellite ek arrives (on SA10).
 *   pEk    : ML-KEM-768 encapsulation key, ekLen must be EP_MY_KEM_PK_LENGTH
 *   pCt    : out, the ciphertext for the StartSA PDU (EP_MY_KEM_CT_LENGTH bytes)
 *   ctSize : bytes available at pCt
 * Encapsulates, derives the two session keys and loads them: SA01 and SA11 are first
 * taken back to Unkeyed if needed (Stop, Expire: the old keys are destroyed), then
 * SetKey and Rekey leave them Keyed, with fresh IV counters. The ciphertext is also kept
 * in the SA DB (EP_myGetPendingCiphertext) for the process that sends StartSA.
 * A second call starts over with new keys. */
int32_t EP_myAcceptKemPublicKey(const uint8_t *pEk, size_t ekLen, uint8_t *pCt, size_t ctSize);

/* The ciphertext of the exchange in progress, for the sending process.
 * EP_MY_NO_PENDING when there is none. *pCtLen: out, bytes written. */
int32_t EP_myGetPendingCiphertext(uint8_t *pCt, size_t ctSize, size_t *pCtLen);

/* Signs an EP PDU with the ground ML-DSA-65 key (loaded with SA_mySetDsaKey) and
 * EP_MY_DSA_CONTEXT. *pSigLen: in, bytes available at pSig (EP_MY_DSA_SIG_LENGTH is
 * enough); out, signature size. */
int32_t EP_mySign(const uint8_t *pMsg, size_t msgLen, uint8_t *pSig, size_t *pSigLen);

/* Call after the satellite confirmed StartSA: SA01 and SA11 Keyed -> Operational, and
 * the pending ciphertext is cleared. Starting earlier would send TC the satellite cannot
 * decrypt yet. */
int32_t EP_myStartSessions(void);

#endif /* _ep_my_h_ */
