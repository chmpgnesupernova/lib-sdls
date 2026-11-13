/*
 * pqc_struct.h — SA / Key DB 구조체 정의 (지상국·위성 공용)
 *
 * 기준: CCSDS 355.0-B-2 (SDLS) §3.4.2, 표 6-1 / CCSDS 355.1-B-1 (SDLS-EP) §2.3, §5.5, Annex D
 * 설계 문서: docs/sa-database.md
 *
 * 규칙: 모든 길이는 바이트 단위, 다중 바이트 값은 BE로 직렬화(구조체 메모리 표현과는 별개)
 *       구조체를 그대로 캐스팅해 송신하지 않는다 (직렬화 함수 사용).
 */
#ifndef PQC_STRUCT_H
#define PQC_STRUCT_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 1. 크기 상수                                                        */
/* ------------------------------------------------------------------ */

/* AES-256-GCM (SA01, SA11) */
#define COMMON_AES256_KEY_LEN     32u   /* 256 b */
#define COMMON_GCM_IV_LEN         12u   /* 96 b, Security Header IV 필드 = ARSN 겸용 */
#define COMMON_GCM_MAC_LEN        16u   /* 128 b, Security Trailer */

/* ML-KEM-768 (FIPS 203) — 파라미터 세트 미확정, docs §7 */
#define COMMON_KEM_PK_LEN       1184u
#define COMMON_KEM_SK_LEN       2400u
#define COMMON_KEM_CT_LEN       1088u
#define COMMON_KEM_SS_LEN         32u

/* ML-DSA-65 (FIPS 204) — 파라미터 세트 미확정, docs §7 */
#define COMMON_DSA_PK_LEN       1952u
#define COMMON_DSA_SK_LEN       4032u
#define COMMON_DSA_SIG_LEN      3309u

/* Security Header: SPI(2) + IV(12) 고정 형식 */
#define COMMON_SPI_LEN             2u
#define COMMON_SEC_HDR_LEN        (COMMON_SPI_LEN + COMMON_GCM_IV_LEN)

/* TF Primary Header 길이 (인증 마스크 범위) */
#define COMMON_TC_PRIHDR_LEN       5u
#define COMMON_TM_PRIHDR_LEN       6u
#define COMMON_PRIHDR_MAX_LEN      6u

/* ------------------------------------------------------------------ */
/* 2. 식별자 상수                                                      */
/* ------------------------------------------------------------------ */

/* SPI (355.0 §4.1.1.2 / EP 4.3.1.2: 0, 65535는 EP PDU 전송에 사용 가능) */
#define COMMON_SPI_SA00        0x0000u  /* PQC 키교환, TC */
#define COMMON_SPI_SA01        0x0001u  /* 세션, TC      */
#define COMMON_SPI_SA10        0xFFFFu  /* PQC 키교환, TM */
#define COMMON_SPI_SA11        0x0002u  /* 세션, TM      */

/* Key ID (EP D4.3.4: 0~127은 세션키에 사용하지 않음) */
#define COMMON_KEYID_KEM       0x0001u  /* ML-KEM 키쌍 (위성 생성)   */
#define COMMON_KEYID_GS_DSA    0x0002u  /* 지상 ML-DSA 키쌍           */
#define COMMON_KEYID_SESS_TC   0x0080u  /* AES-256 세션키, TC (SA01) */
#define COMMON_KEYID_SESS_TM   0x0081u  /* AES-256 세션키, TM (SA11) */
#define COMMON_KEYID_NONE      0xFFFFu  /* 키 없음                    */

/*
 * GVCID (EP D5.2.2): TFVN(4) | SCID(16) | VCID(6) | MAPID(6) = 32 b
 * TC: TFVN 0, SCID 1, VCID 1, MAP 0  → 0x00001040
 * TM: VCID 미정 (docs §7) — 임시로 1
 */
#define COMMON_GVCID(tfvn, scid, vcid, mapid)                    \
    ( ((uint32_t)((tfvn)  & 0x0Fu)   << 28) |                     \
      ((uint32_t)((scid)  & 0xFFFFu) << 12) |                     \
      ((uint32_t)((vcid)  & 0x3Fu)   <<  6) |                     \
      ((uint32_t)((mapid) & 0x3Fu)) )

#define COMMON_GVCID_TC        COMMON_GVCID(0u, 1u, 1u, 0u)
#define COMMON_GVCID_TM        COMMON_GVCID(0u, 1u, 1u, 0u)   /* TODO: TM VCID 확정 */

/* ------------------------------------------------------------------ */
/* 3. 열거형                                                           */
/*    구조체 안에서는 크기 고정을 위해 uint8_t로 저장한다.               */
/* ------------------------------------------------------------------ */

/* SA 상태 — EP Figure 5-11의 2비트 코드와 동일 */
typedef enum {
    COMMON_SA_NULL        = 0x0,   /* 00 */
    COMMON_SA_UNKEYED     = 0x1,   /* 01 */
    COMMON_SA_KEYED       = 0x2,   /* 10 */
    COMMON_SA_OPERATIONAL = 0x3    /* 11 */
} common_sa_state_e;

/* SA 상태전이 Procedure ID — EP 표 5-1 (SA Status 응답값) */
typedef enum {
    COMMON_PID_CREATE_SA = 0x1,    /* 0001: Null      → Unkeyed     */
    COMMON_PID_DELETE_SA = 0x4,    /* 0100: Unkeyed   → Null        */
    COMMON_PID_REKEY_SA  = 0x6,    /* 0110: Unkeyed   → Keyed       */
    COMMON_PID_EXPIRE_SA = 0x9,    /* 1001: Keyed     → Unkeyed     */
    COMMON_PID_START_SA  = 0xB,    /* 1011: Keyed     → Operational */
    COMMON_PID_STOP_SA   = 0xE     /* 1110: Operational → Keyed     */
} common_sa_pid_e;

/*
 * SA Service Type (355.0 §3.4.2.2.4)
 * 비트 배치는 EP Create SA PDU의 플래그와 맞춤: bit1 = 암호화, bit0 = 인증
 * NONE은 표준에 없는 값 — SA00/SA10용 (프레임 레벨 보호 없음, PDU 서명). docs §6-1
 */
typedef enum {
    COMMON_SVC_NONE     = 0x0,     /* 표준 이탈 */
    COMMON_SVC_AUTH     = 0x1,
    COMMON_SVC_ENC      = 0x2,
    COMMON_SVC_AUTH_ENC = 0x3
} common_sa_service_e;

/* 알고리즘 식별자 — 표준은 mission-specific (EP 5.5.1.6.2.12 NOTE) */
typedef enum {
    COMMON_ALG_NONE       = 0x00,
    COMMON_ALG_AES256_GCM = 0x01,
    COMMON_ALG_ML_KEM_768 = 0x10,
    COMMON_ALG_ML_DSA_65  = 0x20
} common_alg_e;

/* SA가 보호하는 링크 방향 = EP Service Group (5.3.2.2.2.3) */
typedef enum {
    COMMON_DIR_TC = 0x1,           /* 01: 지상 → 위성 */
    COMMON_DIR_TM = 0x2            /* 10: 위성 → 지상 */
} common_dir_e;

/* 키 상태 — EP 2.3.2 / 5.4.1.2. 인코딩 값은 mission-specific (위성 측과 합의 필요) */
typedef enum {
    COMMON_KEY_PRE_ACTIVE  = 0x0,
    COMMON_KEY_ACTIVE      = 0x1,
    COMMON_KEY_DEACTIVATED = 0x2,
    COMMON_KEY_DESTROYED   = 0x3,
    COMMON_KEY_EMPTY       = 0xF   /* 슬롯 비어 있음 (구현용, 표준 외) */
} common_key_state_e;

/* SA DB 인덱스 */
typedef enum {
    COMMON_SA_IDX_SA00 = 0,
    COMMON_SA_IDX_SA01 = 1,
    COMMON_SA_IDX_SA10 = 2,
    COMMON_SA_IDX_SA11 = 3,
    COMMON_SA_COUNT    = 4
} common_sa_idx_e;

/* ------------------------------------------------------------------ */
/* 4. 키 DB  (SA는 키 값을 갖지 않고 Key ID로 참조, 355.0 §3.4.2.3.2)   */
/* ------------------------------------------------------------------ */

/* 대칭 세션키 */
typedef struct {
    uint16_t key_id;
    uint8_t  alg;                              /* common_alg_e        */
    uint8_t  state;                            /* common_key_state_e  */
    uint8_t  value[COMMON_AES256_KEY_LEN];
} common_sym_key_t;

/* ML-KEM 키쌍. 지상은 pk만, 위성은 pk+sk 보유 */
typedef struct {
    uint16_t key_id;
    uint8_t  alg;
    uint8_t  state;
    uint8_t  has_sk;                           /* 1: sk 유효 */
    uint8_t  pk[COMMON_KEM_PK_LEN];
    uint8_t  sk[COMMON_KEM_SK_LEN];
} common_kem_key_t;

/* ML-DSA 키쌍. 지상은 pk+sk, 위성은 pk만 (사전 주입) */
typedef struct {
    uint16_t key_id;
    uint8_t  alg;
    uint8_t  state;
    uint8_t  has_sk;
    uint8_t  pk[COMMON_DSA_PK_LEN];
    uint8_t  sk[COMMON_DSA_SK_LEN];
} common_dsa_key_t;

/*
 * 키 DB — 세션키는 RAM에만 둔다. 재부팅하면 세션키가 사라지고 SA01·SA11은 Unkeyed로 돌아간다 (docs §6-5).
 * 참고: 약 9.6 KB. 위성 쪽에서 메모리가 부족하면 쓰지 않는 sk 필드를 역할별로 제외할 수 있다.
 */
typedef struct {
    common_kem_key_t kem;                      /* COMMON_KEYID_KEM     */
    common_dsa_key_t gs_dsa;                   /* COMMON_KEYID_GS_DSA  */
    common_sym_key_t sess_tc;                  /* COMMON_KEYID_SESS_TC */
    common_sym_key_t sess_tm;                  /* COMMON_KEYID_SESS_TM */
} common_key_db_t;

/* ------------------------------------------------------------------ */
/* 5. SA  (355.0 §3.4.2 + 표 6-1, EP 추가 항목)                         */
/* ------------------------------------------------------------------ */

typedef struct {
    /* --- SA 수명 동안 고정 (표 6-1 첫째 그룹) --- */
    uint16_t spi;                              /* §3.4.2.2.3                        */
    uint8_t  dir;                              /* common_dir_e (= EP Service Group) */
    uint32_t gvcid;                            /* §3.4.2.2.1, TC는 SA당 VC 1개      */
    uint8_t  service_type;                     /* common_sa_service_e §3.4.2.2.4    */

    uint8_t  len_iv;                           /* §3.4.2.2.6  Security Header IV    */
    uint8_t  len_sn;                           /* §3.4.2.2.5  0: IV가 ARSN 겸용     */
    uint8_t  len_pl;                           /* §3.4.2.2.7  0: GCM 패딩 없음      */
    uint8_t  len_mac;                          /* §3.4.2.2.8  Security Trailer      */

    uint8_t  auth_alg;                         /* common_alg_e §3.4.2.3.1           */
    uint8_t  enc_alg;                          /* common_alg_e §3.4.2.4.1           */

    /*
     * 인증 마스크 (§4.2.2.6.2) — TF Primary Header 부분만 저장한다.
     * 표준 규칙상 Security Header의 SPI(h)와 Frame Data(i)는 항상 1이고,
     * IV는 GCM nonce로 별도 입력되므로 고정 규칙으로 처리한다.
     * TM은 MC Frame Count(오프셋 2) 바이트가 반드시 0 (d).
     */
    uint8_t  auth_mask_prihdr[COMMON_PRIHDR_MAX_LEN];
    uint8_t  auth_mask_len;                    /* 5(TC) 또는 6(TM)                  */

    uint32_t arsn_window;                      /* §3.4.2.3.5, 수신 측이 사용        */

    /* --- Operational 동안 고정 (표 6-1 둘째 그룹): 키 참조 --- */
    uint16_t auth_key_id;                      /* §3.4.2.3.2                        */
    uint16_t enc_key_id;                       /* §3.4.2.4.2  GCM은 auth와 같은 키  */

    /* --- 동적 (표 6-1 셋째 그룹) --- */
    /*
     * IV = ARSN (§4.1.1.4.2 NOTE). BE 96비트 카운터.
     * 송신 측: 다음에 보낼 값 / 수신 측: 마지막으로 수락한 값.
     * 지상국 기준 SA01=송신, SA11=수신 (위성은 반대).
     */
    uint8_t  iv[COMMON_GCM_IV_LEN];

    /* --- EP 상태 --- */
    uint8_t  state;                            /* common_sa_state_e  EP 2.3.3       */
    uint8_t  last_pid;                         /* common_sa_pid_e    EP 5.5.1.10.3  */
} common_sa_t;

/* SA DB — 지상·위성이 각자 사본을 가진다 */
typedef struct {
    common_sa_t sa[COMMON_SA_COUNT];           /* common_sa_idx_e로 인덱싱 */
} common_sa_db_t;

/* 초기값 (pqc_sa_default.c) — SA가 미리 생성된 상태 */
extern const common_sa_db_t common_sa_db_default;

#endif /* PQC_STRUCT_H */
