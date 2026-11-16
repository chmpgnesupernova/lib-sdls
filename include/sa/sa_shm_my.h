/* Ground side SA / Key DB in POSIX shared memory.
 *
 * The ground system runs the sender and the receiver as separate Python processes, and
 * each one loads its own copy of libsdls.so. Library globals are therefore per process,
 * so the SA DB and the Key DB live in one shared memory segment that every process maps.
 *
 *   sender   process ──┐
 *                      ├── /dev/shm/<name> : { header, robust mutex, SA DB, Key DB }
 *   receiver process ──┘
 *
 * - The first SA_myOpen creates the segment and copies common_sa_db_default into it.
 *   Later SA_myOpen calls (any process) attach to the existing segment.
 * - Every access holds a process-shared robust mutex. If a process dies while holding
 *   it, the next process recovers the lock.
 * - The segment lives in RAM only. After a host reboot the session keys are gone and
 *   SA01/SA11 start Unkeyed again (docs §6-5), so IV counters never need to persist:
 *   a new key exchange is required before any IV is used again.
 * - Session key values never leave the library: there is no exported getter.
 *
 * Ground roles: SA01 (TC) is the send direction and uses SA_myNextIv.
 *               SA11 (TM) is the receive direction and uses SA_myCheckArsn/CommitArsn.
 */
#ifndef _sa_shm_my_h_
#define _sa_shm_my_h_

#include <stddef.h>
#include <stdint.h>

#include "sa/sa_my.h"

#define SA_MY_SUCCESS          (0)
#define SA_MY_INVALID_ARGUMENT (-2)
#define SA_MY_NOT_OPEN         (-8)
#define SA_MY_SHM_ERROR        (-9)  /* shm_open, mmap, flock, ... failed (see errno) */
#define SA_MY_LAYOUT_MISMATCH  (-10) /* segment was made by an incompatible library build */
#define SA_MY_LOCK_ERROR       (-11) /* the shared mutex is unrecoverable */
#define SA_MY_UNKNOWN_SPI      (-12)
#define SA_MY_INVALID_STATE    (-13) /* SA state or direction does not allow the call */
#define SA_MY_UNKNOWN_KEY      (-14)
#define SA_MY_KEY_IN_USE       (-15) /* key is referenced by a Keyed/Operational SA */
#define SA_MY_IV_EXHAUSTED     (-16) /* 96 bit IV space used up, rekey required */
#define SA_MY_REPLAY           (-17) /* ARSN not newer than the last one or outside the window */

/* Default segment name. Sender and receiver must use the same name. */
#define SA_MY_SHM_DEFAULT_NAME "/sdls_sa_db"

/* --- Segment lifecycle ------------------------------------------------------------- */

/* Creates or attaches the shared SA/Key DB.
 * name : POSIX shm name starting with '/', or NULL for SA_MY_SHM_DEFAULT_NAME.
 * The segment is created with mode 0600 (same user only).
 * Calling it again while already open returns SA_MY_SUCCESS without changes. */
int32_t SA_myOpen(const char *name);

/* Unmaps the segment from this process. The segment and its contents stay. */
int32_t SA_myClose(void);

/* Removes the segment name. Processes that still have it mapped keep their mapping;
 * the next SA_myOpen creates a fresh segment from the defaults.
 * Use it to reset the DB (tests, ground system restart without reboot). */
int32_t SA_myUnlink(const char *name);

/* sizeof(common_sa_t), so a binding can check its struct mirror. */
size_t SA_mySaSize(void);

/* --- SA read -------------------------------------------------------------------------- */

/* Copies the SA with the given SPI into *pSa. */
int32_t SA_myGetSa(uint16_t spi, common_sa_t *pSa);

/* --- SA state transitions (EP 2.3.3) -------------------------------------------------- */

/* Unkeyed -> Keyed. Binds the session key keyId (loaded with SA_mySetKey) to the SA and
 * resets the counter: a TC SA's next IV to send becomes 1 (default), a TM SA's last
 * accepted ARSN becomes 0, so the satellite's first frame with IV 1 is accepted.
 * The key must be ACTIVE, match the SA algorithm and not be bound to another SA. */
int32_t SA_myRekey(uint16_t spi, uint16_t keyId);

/* Keyed -> Operational. */
int32_t SA_myStart(uint16_t spi);

/* Operational -> Keyed. */
int32_t SA_myStop(uint16_t spi);

/* Keyed -> Unkeyed. Unbinds and destroys (zeroizes) the session key, so the same key
 * can never be bound again with a reset IV. */
int32_t SA_myExpire(uint16_t spi);

/* --- Session keys ----------------------------------------------------------------------- */

/* Loads a 32 byte AES-256 session key (COMMON_KEYID_SESS_TC or COMMON_KEYID_SESS_TM)
 * and marks it ACTIVE. Refused with SA_MY_KEY_IN_USE while a Keyed or Operational SA
 * uses that key ID. The caller must supply a fresh key every time (key exchange output). */
int32_t SA_mySetKey(uint16_t keyId, const uint8_t *pKey, size_t keyLen);

/* Loads the ground ML-DSA key pair used to sign EP PDUs (FIPS 204 raw formats:
 * pk COMMON_DSA_PK_LEN, sk COMMON_DSA_SK_LEN bytes) and marks it ACTIVE. The secret key
 * never leaves the library afterwards: there is no exported getter. */
int32_t SA_mySetDsaKey(const uint8_t *pPk, size_t pkLen, const uint8_t *pSk, size_t skLen);

/* --- Per frame counters ----------------------------------------------------------------- */

/* Send side (TC SA, Operational). Writes the IV for the next frame to pIv
 * (COMMON_GCM_IV_LEN bytes) and advances the counter, atomically across processes,
 * so no two frames ever get the same IV. */
int32_t SA_myNextIv(uint16_t spi, uint8_t *pIv);

/* Receive side (TM SA, Operational). Checks that the received IV/ARSN is newer than the
 * last accepted one and within the SA window. Does not change the SA. */
int32_t SA_myCheckArsn(uint16_t spi, const uint8_t *pIv);

/* Receive side. Call only after the frame MAC verified: records pIv as the last accepted
 * ARSN (re-checked under the lock, so a concurrent newer commit is never rolled back). */
int32_t SA_myCommitArsn(uint16_t spi, const uint8_t *pIv);

#endif /* _sa_shm_my_h_ */
