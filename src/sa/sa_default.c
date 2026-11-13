/*
 * pqc_sa_default.c — SA00 · SA01 · SA10 · SA11 초기값 (미리 생성된 상태)
 * 근거: docs/sa-database.md §2
 *
 * 부팅 시 이 값을 각 노드의 SA DB로 복사해서 쓴다 (const 원본은 수정하지 않는다).
 */
#include "pqc_struct.h"

/* TC Primary Header 5 B 전체 인증 (설계 결정: AAD에 헤더 포함) */
#define TC_MASK  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 }
/* TM Primary Header 6 B, MC Frame Count(오프셋 2) 제외 (355.0 §4.2.2.6.2 d) */
#define TM_MASK  { 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF }

#define IV_ZERO  { 0 }
#define IV_ONE   { 0,0,0,0, 0,0,0,0, 0,0,0,1 }

const common_sa_db_t common_sa_db_default = {
    .sa = {
        /* SA00: PQC 키교환, TC. 프레임 보호 없음, EP PDU 내부 ML-DSA 서명 */
        [COMMON_SA_IDX_SA00] = {
            .spi              = COMMON_SPI_SA00,
            .dir              = COMMON_DIR_TC,
            .gvcid            = COMMON_GVCID_TC,
            .service_type     = COMMON_SVC_NONE,          /* 표준 이탈, docs §6-1 */
            .len_iv           = COMMON_GCM_IV_LEN,        /* 0 채움, docs §6-7 */
            .len_sn           = 0,
            .len_pl           = 0,
            .len_mac          = COMMON_GCM_MAC_LEN,       /* 0 채움 */
            .auth_alg         = COMMON_ALG_ML_DSA_65,     /* PDU 레벨 서명 */
            .enc_alg          = COMMON_ALG_NONE,
            .auth_mask_prihdr = { 0 },
            .auth_mask_len    = 0,
            .arsn_window      = 0,
            .auth_key_id      = COMMON_KEYID_GS_DSA,
            .enc_key_id       = COMMON_KEYID_NONE,
            .iv               = IV_ZERO,
            .state            = COMMON_SA_OPERATIONAL,
            .last_pid         = COMMON_PID_START_SA,
        },

        /* SA01: 세션, TC. AES-256-GCM. 키교환 후 Keyed → Operational */
        [COMMON_SA_IDX_SA01] = {
            .spi              = COMMON_SPI_SA01,
            .dir              = COMMON_DIR_TC,
            .gvcid            = COMMON_GVCID_TC,
            .service_type     = COMMON_SVC_AUTH_ENC,
            .len_iv           = COMMON_GCM_IV_LEN,
            .len_sn           = 0,                        /* IV가 ARSN 겸용 */
            .len_pl           = 0,
            .len_mac          = COMMON_GCM_MAC_LEN,
            .auth_alg         = COMMON_ALG_AES256_GCM,
            .enc_alg          = COMMON_ALG_AES256_GCM,
            .auth_mask_prihdr = TC_MASK,
            .auth_mask_len    = COMMON_TC_PRIHDR_LEN,
            .arsn_window      = 64,                       /* PoC 제안값 */
            .auth_key_id      = COMMON_KEYID_NONE,        /* Unkeyed: 키교환 후 SESS_TC */
            .enc_key_id       = COMMON_KEYID_NONE,
            .iv               = IV_ONE,
            .state            = COMMON_SA_UNKEYED,
            .last_pid         = COMMON_PID_CREATE_SA,     /* 미리 생성됨 */
        },

        /* SA10: PQC 키교환, TM. 프레임 보호 없음, 위성 인증 없음 (docs §6-4) */
        [COMMON_SA_IDX_SA10] = {
            .spi              = COMMON_SPI_SA10,
            .dir              = COMMON_DIR_TM,
            .gvcid            = COMMON_GVCID_TM,
            .service_type     = COMMON_SVC_NONE,
            .len_iv           = COMMON_GCM_IV_LEN,
            .len_sn           = 0,
            .len_pl           = 0,
            .len_mac          = COMMON_GCM_MAC_LEN,
            .auth_alg         = COMMON_ALG_NONE,
            .enc_alg          = COMMON_ALG_NONE,
            .auth_mask_prihdr = { 0 },
            .auth_mask_len    = 0,
            .arsn_window      = 0,
            .auth_key_id      = COMMON_KEYID_NONE,
            .enc_key_id       = COMMON_KEYID_NONE,
            .iv               = IV_ZERO,
            .state            = COMMON_SA_OPERATIONAL,
            .last_pid         = COMMON_PID_START_SA,
        },

        /* SA11: 세션, TM. AES-256-GCM */
        [COMMON_SA_IDX_SA11] = {
            .spi              = COMMON_SPI_SA11,
            .dir              = COMMON_DIR_TM,
            .gvcid            = COMMON_GVCID_TM,
            .service_type     = COMMON_SVC_AUTH_ENC,
            .len_iv           = COMMON_GCM_IV_LEN,
            .len_sn           = 0,
            .len_pl           = 0,
            .len_mac          = COMMON_GCM_MAC_LEN,
            .auth_alg         = COMMON_ALG_AES256_GCM,
            .enc_alg          = COMMON_ALG_AES256_GCM,
            .auth_mask_prihdr = TM_MASK,
            .auth_mask_len    = COMMON_TM_PRIHDR_LEN,
            .arsn_window      = 64,
            .auth_key_id      = COMMON_KEYID_NONE,        /* Unkeyed: 키교환 후 SESS_TM */
            .enc_key_id       = COMMON_KEYID_NONE,
            .iv               = IV_ONE,
            .state            = COMMON_SA_UNKEYED,
            .last_pid         = COMMON_PID_CREATE_SA,
        },
    },
};
