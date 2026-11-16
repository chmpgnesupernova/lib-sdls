/* Ground side SA / Key DB in POSIX shared memory. See include/sa/sa_shm_my.h. */
#define _GNU_SOURCE /* shm_open, flock, robust mutex, explicit_bzero */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sa_shm_internal.h"

#define SA_MY_SHM_MAGIC   0x534C4453u /* "SDLS" */
#define SA_MY_SHM_VERSION 2u /* 2: EP pending ciphertext */

/* Layout of the shared segment. Every process must use the same library build;
 * the header check in SA_myOpen rejects a segment made by a different layout. */
typedef struct
{
    uint32_t        magic;   /* written last, so 0 means initialization never finished */
    uint32_t        version;
    uint32_t        size;    /* sizeof(SA_myShm_t) */
    uint32_t        reserved;
    pthread_mutex_t lock;    /* process-shared, robust */
    common_sa_db_t  saDb;
    common_key_db_t keyDb;
    /* Key exchange in progress (ep/ep_my.c): the ML-KEM ciphertext made by the process
     * that received the satellite ek, kept for the process that sends StartSA. Public
     * data, but cleared once the sessions start. */
    uint32_t epCtLen; /* 0: nothing pending */
    uint8_t  epCt[COMMON_KEM_CT_LEN];
} SA_myShm_t;

/* This process's mapping. openLock only guards SA_myOpen/SA_myClose against other
 * threads of the same process; the DB itself is guarded by pShm->lock. */
static SA_myShm_t     *SA_myShm      = NULL;
static pthread_mutex_t SA_myOpenLock = PTHREAD_MUTEX_INITIALIZER;

/* --- helpers ------------------------------------------------------------------------- */

static bool SA_myValidName(const char *name)
{
    size_t len = strlen(name);
    return (len >= 2) && (len <= NAME_MAX) && (name[0] == '/') && (strchr(name + 1, '/') == NULL);
}

static int32_t SA_myInitRegion(SA_myShm_t *pShm)
{
    pthread_mutexattr_t attr;
    int32_t             status = SA_MY_SUCCESS;

    memset(pShm, 0, sizeof(*pShm));

    if (pthread_mutexattr_init(&attr) != 0)
    {
        return SA_MY_SHM_ERROR;
    }
    if ((pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) ||
        (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0) ||
        (pthread_mutex_init(&pShm->lock, &attr) != 0))
    {
        status = SA_MY_SHM_ERROR;
    }
    pthread_mutexattr_destroy(&attr);
    if (status != SA_MY_SUCCESS)
    {
        return status;
    }

    pShm->saDb = common_sa_db_default;

    pShm->keyDb.kem.key_id     = COMMON_KEYID_KEM;
    pShm->keyDb.kem.alg        = COMMON_ALG_ML_KEM_768;
    pShm->keyDb.kem.state      = COMMON_KEY_EMPTY;
    pShm->keyDb.gs_dsa.key_id  = COMMON_KEYID_GS_DSA;
    pShm->keyDb.gs_dsa.alg     = COMMON_ALG_ML_DSA_65;
    pShm->keyDb.gs_dsa.state   = COMMON_KEY_EMPTY;
    pShm->keyDb.sess_tc.key_id = COMMON_KEYID_SESS_TC;
    pShm->keyDb.sess_tc.alg    = COMMON_ALG_AES256_GCM;
    pShm->keyDb.sess_tc.state  = COMMON_KEY_EMPTY;
    pShm->keyDb.sess_tm.key_id = COMMON_KEYID_SESS_TM;
    pShm->keyDb.sess_tm.alg    = COMMON_ALG_AES256_GCM;
    pShm->keyDb.sess_tm.state  = COMMON_KEY_EMPTY;

    pShm->version = SA_MY_SHM_VERSION;
    pShm->size    = (uint32_t)sizeof(SA_myShm_t);
    __atomic_store_n(&pShm->magic, SA_MY_SHM_MAGIC, __ATOMIC_RELEASE);

    return SA_MY_SUCCESS;
}

static int32_t SA_myLock(void)
{
    int rc;

    if (SA_myShm == NULL)
    {
        return SA_MY_NOT_OPEN;
    }

    rc = pthread_mutex_lock(&SA_myShm->lock);
    if (rc == EOWNERDEAD)
    {
        /* The previous owner died inside a critical section. Every critical section
         * here only copies a few fields, so the DB is still usable. */
        pthread_mutex_consistent(&SA_myShm->lock);
        rc = 0;
    }
    return (rc == 0) ? SA_MY_SUCCESS : SA_MY_LOCK_ERROR;
}

static void SA_myUnlock(void)
{
    pthread_mutex_unlock(&SA_myShm->lock);
}

/* Lock must be held for the find functions and everything below them. */
static int SA_myFindSa(uint16_t spi)
{
    int i;
    for (i = 0; i < COMMON_SA_COUNT; i++)
    {
        if (SA_myShm->saDb.sa[i].spi == spi)
        {
            return i;
        }
    }
    return -1;
}

static common_sym_key_t *SA_myFindSymKey(uint16_t keyId)
{
    if (keyId == COMMON_KEYID_SESS_TC)
    {
        return &SA_myShm->keyDb.sess_tc;
    }
    if (keyId == COMMON_KEYID_SESS_TM)
    {
        return &SA_myShm->keyDb.sess_tm;
    }
    return NULL;
}

/* True when an SA other than skipIdx holds keyId while Keyed or Operational. */
static bool SA_myKeyBound(uint16_t keyId, int skipIdx)
{
    int i;
    for (i = 0; i < COMMON_SA_COUNT; i++)
    {
        const common_sa_t *pSa = &SA_myShm->saDb.sa[i];
        if ((i != skipIdx) && ((pSa->state == COMMON_SA_KEYED) || (pSa->state == COMMON_SA_OPERATIONAL)) &&
            ((pSa->auth_key_id == keyId) || (pSa->enc_key_id == keyId)))
        {
            return true;
        }
    }
    return false;
}

/* Accepts pIv when 0 < pIv - last <= arsn_window (96 bit big endian arithmetic). */
static int32_t SA_myArsnInWindow(const common_sa_t *pSa, const uint8_t *pIv)
{
    uint8_t  diff[COMMON_GCM_IV_LEN];
    unsigned borrow = 0;
    uint32_t low;
    bool     zero = true;
    int      i;

    for (i = COMMON_GCM_IV_LEN - 1; i >= 0; i--)
    {
        unsigned d = (unsigned)pIv[i] - (unsigned)pSa->iv[i] - borrow;
        diff[i]    = (uint8_t)d;
        borrow     = (d >> 8) & 1u;
        zero       = zero && (diff[i] == 0);
    }
    if ((borrow != 0) || zero)
    {
        return SA_MY_REPLAY; /* older than or equal to the last accepted ARSN */
    }
    for (i = 0; i < (int)COMMON_GCM_IV_LEN - 4; i++)
    {
        if (diff[i] != 0)
        {
            return SA_MY_REPLAY;
        }
    }
    low = ((uint32_t)diff[8] << 24) | ((uint32_t)diff[9] << 16) | ((uint32_t)diff[10] << 8) | diff[11];
    return (low <= pSa->arsn_window) ? SA_MY_SUCCESS : SA_MY_REPLAY;
}

/* Common checks for the per frame counter calls. */
static int32_t SA_myOperationalSa(uint16_t spi, uint8_t dir, common_sa_t **ppSa)
{
    int idx = SA_myFindSa(spi);
    if (idx < 0)
    {
        return SA_MY_UNKNOWN_SPI;
    }
    *ppSa = &SA_myShm->saDb.sa[idx];
    if (((*ppSa)->service_type == COMMON_SVC_NONE) || ((*ppSa)->dir != dir) ||
        ((*ppSa)->state != COMMON_SA_OPERATIONAL))
    {
        return SA_MY_INVALID_STATE;
    }
    return SA_MY_SUCCESS;
}

/* --- segment lifecycle --------------------------------------------------------------- */

int32_t SA_myOpen(const char *name)
{
    SA_myShm_t *pShm   = MAP_FAILED;
    int32_t     status = SA_MY_SUCCESS;
    struct stat st;
    bool        fresh = false;
    int         fd;

    if (name == NULL)
    {
        name = SA_MY_SHM_DEFAULT_NAME;
    }
    if (!SA_myValidName(name))
    {
        return SA_MY_INVALID_ARGUMENT;
    }

    pthread_mutex_lock(&SA_myOpenLock);
    if (SA_myShm != NULL)
    {
        pthread_mutex_unlock(&SA_myOpenLock);
        return SA_MY_SUCCESS;
    }

    fd = shm_open(name, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        pthread_mutex_unlock(&SA_myOpenLock);
        return SA_MY_SHM_ERROR;
    }

    /* flock serializes creation: two processes starting together cannot both
     * initialize, and nobody maps a half initialized segment. */
    if ((flock(fd, LOCK_EX) != 0) || (fstat(fd, &st) != 0))
    {
        status = SA_MY_SHM_ERROR;
    }
    else if (st.st_size == 0)
    {
        fresh = true;
        if (ftruncate(fd, (off_t)sizeof(SA_myShm_t)) != 0)
        {
            status = SA_MY_SHM_ERROR;
        }
    }
    else if ((size_t)st.st_size != sizeof(SA_myShm_t))
    {
        status = SA_MY_LAYOUT_MISMATCH;
    }

    if (status == SA_MY_SUCCESS)
    {
        pShm = mmap(NULL, sizeof(SA_myShm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (pShm == MAP_FAILED)
        {
            status = SA_MY_SHM_ERROR;
        }
    }

    if (status == SA_MY_SUCCESS)
    {
        uint32_t magic = __atomic_load_n(&pShm->magic, __ATOMIC_ACQUIRE);

        if (fresh || (magic == 0))
        {
            /* magic 0 on an existing segment: its creator died during init. */
            status = SA_myInitRegion(pShm);
        }
        else if ((magic != SA_MY_SHM_MAGIC) || (pShm->version != SA_MY_SHM_VERSION) ||
                 (pShm->size != sizeof(SA_myShm_t)))
        {
            status = SA_MY_LAYOUT_MISMATCH;
        }
    }

    if ((status != SA_MY_SUCCESS) && (pShm != MAP_FAILED))
    {
        munmap(pShm, sizeof(SA_myShm_t));
    }
    if (status == SA_MY_SUCCESS)
    {
        SA_myShm = pShm;
    }

    flock(fd, LOCK_UN);
    close(fd); /* the mapping stays valid without the descriptor */
    pthread_mutex_unlock(&SA_myOpenLock);
    return status;
}

int32_t SA_myClose(void)
{
    pthread_mutex_lock(&SA_myOpenLock);
    if (SA_myShm != NULL)
    {
        munmap(SA_myShm, sizeof(SA_myShm_t));
        SA_myShm = NULL;
    }
    pthread_mutex_unlock(&SA_myOpenLock);
    return SA_MY_SUCCESS;
}

int32_t SA_myUnlink(const char *name)
{
    if (name == NULL)
    {
        name = SA_MY_SHM_DEFAULT_NAME;
    }
    if (!SA_myValidName(name))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((shm_unlink(name) != 0) && (errno != ENOENT))
    {
        return SA_MY_SHM_ERROR;
    }
    return SA_MY_SUCCESS;
}

size_t SA_mySaSize(void)
{
    return sizeof(common_sa_t);
}

/* --- SA read ------------------------------------------------------------------------- */

int32_t SA_myGetSa(uint16_t spi, common_sa_t *pSa)
{
    int32_t status;
    int     idx;

    if (pSa == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    idx = SA_myFindSa(spi);
    if (idx < 0)
    {
        status = SA_MY_UNKNOWN_SPI;
    }
    else
    {
        *pSa = SA_myShm->saDb.sa[idx];
    }

    SA_myUnlock();
    return status;
}

/* --- SA state transitions ------------------------------------------------------------ */

/* Shared front part of the transitions: finds the SA and checks its current state.
 * SA00/SA10 (no frame protection) stay Operational and refuse every transition. */
static int32_t SA_myTransitionSa(uint16_t spi, uint8_t fromState, common_sa_t **ppSa, int *pIdx)
{
    int idx = SA_myFindSa(spi);
    if (idx < 0)
    {
        return SA_MY_UNKNOWN_SPI;
    }
    *ppSa = &SA_myShm->saDb.sa[idx];
    if (pIdx != NULL)
    {
        *pIdx = idx;
    }
    if (((*ppSa)->service_type == COMMON_SVC_NONE) || ((*ppSa)->state != fromState))
    {
        return SA_MY_INVALID_STATE;
    }
    return SA_MY_SUCCESS;
}

int32_t SA_myRekey(uint16_t spi, uint16_t keyId)
{
    common_sym_key_t *pKey;
    common_sa_t      *pSa;
    int32_t           status;
    int               idx;

    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myTransitionSa(spi, COMMON_SA_UNKEYED, &pSa, &idx);
    if (status == SA_MY_SUCCESS)
    {
        pKey = SA_myFindSymKey(keyId);
        if ((pKey == NULL) || (pKey->state != COMMON_KEY_ACTIVE) || (pKey->alg != pSa->auth_alg))
        {
            status = SA_MY_UNKNOWN_KEY;
        }
        else if (SA_myKeyBound(keyId, idx))
        {
            status = SA_MY_KEY_IN_USE;
        }
    }
    if (status == SA_MY_SUCCESS)
    {
        /* GCM: one key does both, so enc uses the auth key when encryption is on. */
        pSa->auth_key_id = keyId;
        pSa->enc_key_id  = (pSa->service_type & COMMON_SVC_ENC) ? keyId : COMMON_KEYID_NONE;
        /* common_sa_db_default is shared with the satellite, where its IV (1) means
         * "next IV to send". On the ground only the send direction (TC) uses it that
         * way. The receive direction (TM) stores the last accepted ARSN, which starts
         * at 0 so that the satellite's first frame (IV 1) is accepted. */
        if (pSa->dir == COMMON_DIR_TC)
        {
            memcpy(pSa->iv, common_sa_db_default.sa[idx].iv, sizeof(pSa->iv));
        }
        else
        {
            memset(pSa->iv, 0, sizeof(pSa->iv));
        }
        pSa->state    = COMMON_SA_KEYED;
        pSa->last_pid = COMMON_PID_REKEY_SA;
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myStart(uint16_t spi)
{
    common_sym_key_t *pKey;
    common_sa_t      *pSa;
    int32_t           status;

    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myTransitionSa(spi, COMMON_SA_KEYED, &pSa, NULL);
    if (status == SA_MY_SUCCESS)
    {
        pKey = SA_myFindSymKey(pSa->auth_key_id);
        if ((pKey == NULL) || (pKey->state != COMMON_KEY_ACTIVE))
        {
            status = SA_MY_UNKNOWN_KEY;
        }
    }
    if (status == SA_MY_SUCCESS)
    {
        pSa->state    = COMMON_SA_OPERATIONAL;
        pSa->last_pid = COMMON_PID_START_SA;
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myStop(uint16_t spi)
{
    common_sa_t *pSa;
    int32_t      status;

    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myTransitionSa(spi, COMMON_SA_OPERATIONAL, &pSa, NULL);
    if (status == SA_MY_SUCCESS)
    {
        pSa->state    = COMMON_SA_KEYED;
        pSa->last_pid = COMMON_PID_STOP_SA;
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myExpire(uint16_t spi)
{
    common_sym_key_t *pKey;
    common_sa_t      *pSa;
    int32_t           status;

    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myTransitionSa(spi, COMMON_SA_KEYED, &pSa, NULL);
    if (status == SA_MY_SUCCESS)
    {
        pKey = SA_myFindSymKey(pSa->auth_key_id);
        if (pKey != NULL)
        {
            explicit_bzero(pKey->value, sizeof(pKey->value));
            pKey->state = COMMON_KEY_DESTROYED;
        }
        pSa->auth_key_id = COMMON_KEYID_NONE;
        pSa->enc_key_id  = COMMON_KEYID_NONE;
        pSa->state       = COMMON_SA_UNKEYED;
        pSa->last_pid    = COMMON_PID_EXPIRE_SA;
    }

    SA_myUnlock();
    return status;
}

/* --- session keys -------------------------------------------------------------------- */

int32_t SA_mySetKey(uint16_t keyId, const uint8_t *pKeyValue, size_t keyLen)
{
    common_sym_key_t *pKey;
    int32_t           status;

    if ((pKeyValue == NULL) || (keyLen != COMMON_AES256_KEY_LEN))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    pKey = SA_myFindSymKey(keyId);
    if (pKey == NULL)
    {
        status = SA_MY_UNKNOWN_KEY;
    }
    else if (SA_myKeyBound(keyId, -1))
    {
        status = SA_MY_KEY_IN_USE;
    }
    else
    {
        memcpy(pKey->value, pKeyValue, COMMON_AES256_KEY_LEN);
        pKey->alg   = COMMON_ALG_AES256_GCM;
        pKey->state = COMMON_KEY_ACTIVE;
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myCopySaKey(uint16_t spi, uint8_t *pKeyValue)
{
    common_sym_key_t *pKey;
    int32_t           status;
    int               idx;

    if (pKeyValue == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    idx = SA_myFindSa(spi);
    if (idx < 0)
    {
        status = SA_MY_UNKNOWN_SPI;
    }
    else
    {
        const common_sa_t *pSa = &SA_myShm->saDb.sa[idx];
        pKey                   = SA_myFindSymKey(pSa->auth_key_id);
        if ((pSa->state != COMMON_SA_KEYED) && (pSa->state != COMMON_SA_OPERATIONAL))
        {
            status = SA_MY_INVALID_STATE;
        }
        else if ((pKey == NULL) || (pKey->state != COMMON_KEY_ACTIVE))
        {
            status = SA_MY_UNKNOWN_KEY;
        }
        else
        {
            memcpy(pKeyValue, pKey->value, COMMON_AES256_KEY_LEN);
        }
    }

    SA_myUnlock();
    return status;
}

/* --- per frame counters -------------------------------------------------------------- */

int32_t SA_myNextIv(uint16_t spi, uint8_t *pIv)
{
    common_sa_t *pSa;
    int32_t      status;
    int          i;

    if (pIv == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myOperationalSa(spi, COMMON_DIR_TC, &pSa);
    if (status == SA_MY_SUCCESS)
    {
        /* All ones is never handed out: the increment after it would wrap to values
         * already used with this key. */
        status = SA_MY_IV_EXHAUSTED;
        for (i = 0; i < (int)COMMON_GCM_IV_LEN; i++)
        {
            if (pSa->iv[i] != 0xFF)
            {
                status = SA_MY_SUCCESS;
                break;
            }
        }
    }
    if (status == SA_MY_SUCCESS)
    {
        memcpy(pIv, pSa->iv, COMMON_GCM_IV_LEN);
        for (i = COMMON_GCM_IV_LEN - 1; (i >= 0) && (++pSa->iv[i] == 0); i--)
        {
        }
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myCheckArsn(uint16_t spi, const uint8_t *pIv)
{
    common_sa_t *pSa;
    int32_t      status;

    if (pIv == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myOperationalSa(spi, COMMON_DIR_TM, &pSa);
    if (status == SA_MY_SUCCESS)
    {
        status = SA_myArsnInWindow(pSa, pIv);
    }

    SA_myUnlock();
    return status;
}

int32_t SA_myCommitArsn(uint16_t spi, const uint8_t *pIv)
{
    common_sa_t *pSa;
    int32_t      status;

    if (pIv == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    status = SA_myOperationalSa(spi, COMMON_DIR_TM, &pSa);
    if (status == SA_MY_SUCCESS)
    {
        status = SA_myArsnInWindow(pSa, pIv);
    }
    if (status == SA_MY_SUCCESS)
    {
        memcpy(pSa->iv, pIv, COMMON_GCM_IV_LEN);
    }

    SA_myUnlock();
    return status;
}

/* --- ground ML-DSA key (EP PDU signing) ---------------------------------------------- */

int32_t SA_mySetDsaKey(const uint8_t *pPk, size_t pkLen, const uint8_t *pSk, size_t skLen)
{
    common_dsa_key_t *pKey;
    int32_t           status;

    if ((pPk == NULL) || (pSk == NULL) || (pkLen != COMMON_DSA_PK_LEN) || (skLen != COMMON_DSA_SK_LEN))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    pKey = &SA_myShm->keyDb.gs_dsa;
    memcpy(pKey->pk, pPk, COMMON_DSA_PK_LEN);
    memcpy(pKey->sk, pSk, COMMON_DSA_SK_LEN);
    pKey->has_sk = 1;
    pKey->alg    = COMMON_ALG_ML_DSA_65;
    pKey->state  = COMMON_KEY_ACTIVE;

    SA_myUnlock();
    return status;
}

int32_t SA_myCopyDsaSecretKey(uint8_t *pSk)
{
    const common_dsa_key_t *pKey;
    int32_t                 status;

    if (pSk == NULL)
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    pKey = &SA_myShm->keyDb.gs_dsa;
    if ((pKey->state != COMMON_KEY_ACTIVE) || !pKey->has_sk)
    {
        status = SA_MY_UNKNOWN_KEY;
    }
    else
    {
        memcpy(pSk, pKey->sk, COMMON_DSA_SK_LEN);
    }

    SA_myUnlock();
    return status;
}

/* --- key exchange ciphertext ----------------------------------------------------------- */

int32_t SA_myStorePendingCt(const uint8_t *pCt, size_t ctLen)
{
    int32_t status;

    if ((ctLen > COMMON_KEM_CT_LEN) || ((pCt == NULL) && (ctLen != 0)))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    memset(SA_myShm->epCt, 0, sizeof(SA_myShm->epCt));
    if (ctLen != 0)
    {
        memcpy(SA_myShm->epCt, pCt, ctLen);
    }
    SA_myShm->epCtLen = (uint32_t)ctLen;

    SA_myUnlock();
    return status;
}

int32_t SA_myLoadPendingCt(uint8_t *pCt, size_t ctSize, size_t *pCtLen)
{
    int32_t status;

    if ((pCt == NULL) || (pCtLen == NULL))
    {
        return SA_MY_INVALID_ARGUMENT;
    }
    if ((status = SA_myLock()) != SA_MY_SUCCESS)
    {
        return status;
    }

    if (SA_myShm->epCtLen == 0)
    {
        status = SA_MY_INVALID_STATE;
    }
    else if (ctSize < SA_myShm->epCtLen)
    {
        status = SA_MY_INVALID_ARGUMENT;
    }
    else
    {
        memcpy(pCt, SA_myShm->epCt, SA_myShm->epCtLen);
        *pCtLen = SA_myShm->epCtLen;
    }

    SA_myUnlock();
    return status;
}
