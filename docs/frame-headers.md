# 프레임 헤더 구현 현황 (지상국 libsdls)

지상국 `libsdls.so`가 만들고 해석하는 프레임 헤더를 정리한 문서입니다.
헤더마다 필드 구성, 구현 여부, 그리고 필드를 쓰거나 읽는 매크로·함수를 적었습니다.

- 기준 코드: 현재 작업 트리 (커밋 `b44546c` 이후 미커밋 변경 포함)
- 기준 표준: CCSDS 232.0 (TC SDLP), 132.0 (TM SDLP), 355.0 (SDLS), 355.1 (SDLS-EP)
- 범례: ✅ 구현 · ⚠️ 부분 구현 또는 고정값 · ❌ 미구현

---

## 1. 프레임 구성

```
TC (지상 → 위성), 가변 길이, 최대 1024 B
+------------------+-------------------------------+--------------+------------------+
| Primary Header   | Security Header               | Data Field   | Security Trailer |
| 5 B              | 14 B  (SPI 2 + IV 12)         | Space Packet | 0 B (MAC 미구현)  |
+------------------+-------------------------------+--------------+------------------+
  0                  5                               19

TM (위성 → 지상), 고정 길이 1786 B
+------------------+-------------------------------+--------------------------+------------------+
| Primary Header   | Security Header               | Data Field               | Security Trailer |
| 6 B              | 14 B  (SPI 2 + IV 12)         | Space Packet들 + idle    | 0 B (MAC 미구현)  |
+------------------+-------------------------------+--------------------------+------------------+
  0                  6                               20                         1786
```

| 헤더 | 길이 | 상태 | 정의 파일 |
|---|---|---|---|
| TC Primary Header | 5 B | ✅ | [include/tf/tctf_my.h](../include/tf/tctf_my.h) |
| TM Primary Header | 6 B | ✅ | [include/tf/tmtf_my.h](../include/tf/tmtf_my.h) |
| SDLS Security Header (TC/TM 공통) | 14 B | ✅ | [include/sdls/sechdr_my.h](../include/sdls/sechdr_my.h) |
| SDLS Security Trailer (MAC) | 0 B (계획 16 B) | ❌ | — |
| TC Segment Header | 없음 | ❌ (Type-D 프레임, 쓰지 않음) | — |
| FECF (CRC) | 없음 | ❌ (선택 항목, 쓰지 않음) | — |

프레임 전체를 필드별로 보려면 `python3 test/frame_view.py [--hex]`를 실행합니다.

---

## 2. TC Primary Header (5 B, CCSDS 232.0 Figure 4-2)

구조체 `TCTF_my_PriHdr_t { uint8_t Octet[4]; uint8_t Sequence; }`

| 필드 | 비트 | 위치 | 지상 송신 값 | 상태 | 쓰기 매크로 | 읽기 매크로 |
|---|---|---|---|---|---|---|
| Transfer Frame Version Number | 2 | Octet[0] 7-6 | `0` (`TC_SDLP_MY_DUMMY_TFVN`) | ⚠️ 더미 고정값 | `TCTF_MY_WR_TF_VERSION` | `TCTF_MY_RD_TF_VERSION` |
| Bypass Flag | 1 | Octet[0] 5 | `1` (Type-B, COP-1 미사용) | ⚠️ 고정값 | `TCTF_MY_WR_BYPASS_FLG` | `TCTF_MY_RD_BYPASS_FLG` |
| Control Command Flag | 1 | Octet[0] 4 | `0` (Type-D, 데이터) | ⚠️ 고정값 | `TCTF_MY_WR_CTLCMD_FLG` | `TCTF_MY_RD_CTLCMD_FLG` |
| Spare | 2 | Octet[0] 3-2 | `0` | ✅ (memset, 매크로 없음) | — | — |
| Spacecraft ID | 10 | Octet[0] 1-0, Octet[1] | `0x003` (`TC_SDLP_MY_DUMMY_SCID`) | ⚠️ 더미 고정값 | `TCTF_MY_WR_SCID` | `TCTF_MY_RD_SCID` |
| Virtual Channel ID | 6 | Octet[2] 7-2 | `0` (`TC_SDLP_MY_DUMMY_VCID`) | ⚠️ 더미 고정값 | `TCTF_MY_WR_VCID` | `TCTF_MY_RD_VCID` |
| Frame Length | 10 | Octet[2] 1-0, Octet[3] | 전체 프레임 길이 − 1 | ✅ 계산값 | `TCTF_MY_WR_FRAMELEN` | `TCTF_MY_RD_FRAMELEN` |
| Frame Sequence Number | 8 | Sequence | 0부터 프레임마다 +1, 255 다음 0 | ✅ (COP-1이 없어 위성은 검사하지 않음) | `TCTF_MY_WR_SEQNUM` | `TCTF_MY_RD_SEQNUM` |

- 지상은 쓰기 매크로만 사용합니다(`TC_SDLP_myBuildFrame`). 읽기 매크로는 위성 쪽 코드용입니다.
- 미구현: COP-1(FARM/FOP), Type-A(AD) 프레임, Control Command(BC) 프레임, 다중 채널. Bypass/CtrlCmd를 바꿀 API는 없습니다.

### 관련 함수

| C 함수 | Python (`sdls_binding.Sdls`) | 하는 일 |
|---|---|---|
| `TC_SDLP_myInit(void)` | `tc_init()` | 프레임 배치 설정, Frame Sequence Number를 0으로 초기화 |
| `TC_SDLP_myBuildFrame(spi, pPacket, packetSize, pBuf, bufSize)` | `tc_build_frame(spi, packet)` | Primary Header 전 필드와 Security Header를 쓰고 Space Packet을 붙임. 성공하면 프레임 길이를 반환 |

`TC_SDLP_myBuildFrame` 처리 순서:
1. 인자 검사 → Space Packet 길이 검사(7 B 이상, 1005 B 이하) → SPP Length 필드와 실제 크기 일치 검사 → 버퍼 크기 검사
2. Primary Header 기록
3. `SECHDR_myApplyTc`로 Security Header 기록. 실패하면 `TC_SDLP_MY_SECURITY_ERROR`
4. Space Packet 복사, Frame Sequence Number +1

1~3단계에서 실패하면 IV를 소비하지 않고 Frame Sequence Number도 올라가지 않습니다.

---

## 3. TM Primary Header (6 B, CCSDS 132.0 §4.1.2)

구조체 `TMTF_my_PriHdr_t { uint8_t Id[2]; uint8_t McFrameCount; uint8_t VcFrameCount; uint8_t DataFieldStatus[2]; }`

| 필드 | 비트 | 위치 | 위성 송신 값 | 지상 처리 | 상태 | 쓰기 매크로 (위성) | 읽기 매크로 (지상) |
|---|---|---|---|---|---|---|---|
| Transfer Frame Version Number | 2 | Id[0] 7-6 | `0` | 검사 안 함 | ⚠️ 검사 코드는 주석 처리됨 | `TMTF_MY_WR_TF_VERSION` | `TMTF_MY_RD_TF_VERSION` |
| Spacecraft ID | 10 | Id[0] 5-0, Id[1] 7-4 | `0x003` | 검사 안 함 | ⚠️ 검사 코드는 주석 처리됨 | `TMTF_MY_WR_SCID` | `TMTF_MY_RD_SCID` |
| Virtual Channel ID | 3 | Id[1] 3-1 | `1` | 검사 안 함 | ⚠️ 검사 코드는 주석 처리됨 | `TMTF_MY_WR_VCID` | `TMTF_MY_RD_VCID` |
| OCF Flag | 1 | Id[1] 0 | `0` | 읽지 않음 | ❌ 매크로 없음 | — | — |
| Master Channel Frame Count | 8 | McFrameCount | 프레임마다 +1 | 읽지 않음 | ⚠️ 매크로만 있음 | `TMTF_MY_WR_MCFRMCNT` | `TMTF_MY_RD_MCFRMCNT` |
| Virtual Channel Frame Count | 8 | VcFrameCount | `0` (위성이 쓰지 않음) | 읽지 않음 | ⚠️ 읽기 매크로만 있음 | — | `TMTF_MY_RD_VCFRMCNT` |
| Secondary Header Flag | 1 | DataFieldStatus[0] 7 | `0` | 읽지 않음 | ❌ 매크로 없음 | — | — |
| Synchronization Flag | 1 | DataFieldStatus[0] 6 | `0` | 읽지 않음 | ❌ 매크로 없음 | — | — |
| Packet Order Flag | 1 | DataFieldStatus[0] 5 | `0` | 읽지 않음 | ❌ 매크로 없음 | — | — |
| Segment Length ID | 2 | DataFieldStatus[0] 4-3 | `3` (`TMTF_MY_SEGLENGTHID_PKT`) | `3`이 아니면 `TM_SDLP_MY_INVALID_HEADER` | ✅ | `TMTF_MY_WR_SEGLENGTHID` | `TMTF_MY_RD_SEGLENGTHID` |
| First Header Pointer | 11 | DataFieldStatus[0] 2-0, [1] | `0` (패킷을 쪼개지 않음) | `0`이 아니면 `TM_SDLP_MY_INVALID_HEADER` | ✅ | `TMTF_MY_WR_FIRSTHDRPTR` | `TMTF_MY_RD_FIRSTHDRPTR` |

- 미구현: TM Secondary Header, OCF(CLCW), 패킷 분할(FHP ≠ 0), 프레임 카운트 연속성 검사, 다중 채널.

### 관련 함수

| C 함수 | Python | 하는 일 |
|---|---|---|
| `TM_SDLP_myExtractPacket(pFrame, frameSize, pCursor, pPacketOffset)` | `tm_extract_packets(frame)` | 커서 0 호출에서 Primary Header와 Security Header를 검사하고, 이후 호출마다 Space Packet을 하나씩 돌려줌. idle 패킷이나 데이터 필드 끝을 만나면 0을 반환 |

커서 0 호출의 검사 순서 (`TM_SDLP_myCheckFrame`):
1. 프레임 길이가 1786 B인지 → 아니면 `TM_SDLP_MY_INVALID_LENGTH`
2. Segment Length ID = 3, FHP = 0 → 아니면 `TM_SDLP_MY_INVALID_HEADER`
3. `SECHDR_myProcessTm`으로 Security Header 검사 → 실패하면 `TM_SDLP_MY_SECURITY_ERROR`
4. 보호 SA(SA11)이면 `SA_myCommitArsn`으로 ARSN 기록 (MAC 구현 후 MAC 검증 뒤로 옮겨야 함)

---

## 4. SDLS Security Header (14 B, CCSDS 355.0 §4.1.1)

구조체 `SECHDR_my_SecHdr_t { uint8_t Spi[2]; uint8_t Iv[12]; }`. 다중 바이트 값은 모두 Big Endian이고, TC와 TM이 같은 형식을 씁니다.

| 필드 | 길이 | 위치 (헤더 기준) | 상태 | 쓰기 매크로 | 읽기 매크로 |
|---|---|---|---|---|---|
| Security Parameter Index (SPI) | 2 B | 0-1 | ✅ | `SECHDR_MY_WR_SPI` | `SECHDR_MY_RD_SPI` |
| Initialization Vector (IV) | 12 B | 2-13 | ✅ | `SECHDR_MY_WR_IV`, `SECHDR_MY_CLR_IV`(0 채움, 현재 미사용) | `SECHDR_MY_RD_IV` |
| Sequence Number | 0 B | — | ❌ 의도적으로 없음 (`len_sn = 0`). IV가 ARSN을 겸함 | — | — |
| Pad Length | 0 B | — | ❌ 의도적으로 없음 (`len_pl = 0`). GCM은 패딩이 필요 없음 | — | — |

### SPI 값

| SPI | SA | 방향 | 프레임 보호 | IV 필드 |
|---|---|---|---|---|
| `0x0000` | SA00 | TC | 없음 (EP PDU를 ML-DSA로 서명) | 0으로 채움, 카운터를 쓰지 않음 |
| `0x0001` | SA01 | TC | AES-256-GCM (Trailer 미구현) | 1부터 프레임마다 +1 |
| `0xFFFF` | SA10 | TM | 없음 | 검사하지 않음 |
| `0x0002` | SA11 | TM | AES-256-GCM (Trailer 미구현) | ARSN 윈도우 검사 |

### IV의 의미

- **송신(지상 TC, SA01):** SA의 `iv`는 "다음에 보낼 값"입니다. Rekey하면 1로 돌아가고, 프레임마다 1씩 증가합니다. 모든 바이트가 0xFF가 되면 `SA_MY_IV_EXHAUSTED`로 더 발급하지 않습니다.
- **수신(지상 TM, SA11):** SA의 `iv`는 "마지막으로 수락한 ARSN"입니다. Rekey하면 0으로 돌아갑니다. `0 < 받은 IV − 마지막 값 ≤ arsn_window(64)`일 때만 받습니다.

### 관련 함수 ([include/sdls/sechdr_my.h](../include/sdls/sechdr_my.h))

| C 함수 | Python | 하는 일 | 반환 |
|---|---|---|---|
| `SECHDR_myApplyTc(spi, pBuf, bufSize, pIv)` | `sechdr_apply_tc(spi)` → `(header, iv)` | TC SA가 Operational인지 확인하고 SPI와 IV를 씀. 보호 SA는 `SA_myNextIv`로 IV를 하나 소비 | `SA_MY_*` |
| `SECHDR_myProcessTm(pBuf, bufSize, pSpi, pIv)` | `sechdr_process_tm(header)` → `(spi, iv)` | SPI를 읽어 TM SA가 Operational인지 확인하고, 보호 SA는 ARSN 윈도우를 검사. **ARSN은 기록하지 않음** | `SA_MY_*` |

GVCID(TFVN·SCID·VCID)와 SA의 `gvcid`가 일치하는지는 검사하지 않습니다. 채널 ID가 아직 더미이기 때문입니다.

---

## 5. Security Trailer, FECF (미구현)

| 항목 | 현재 | 계획 |
|---|---|---|
| Security Trailer (MAC) | 0 B (`TC/TM_SDLP_MY_SDLS_TRL_LENGTH`) | 16 B GCM 태그. 인증 범위는 SA `auth_mask_prihdr`(Primary Header) + SPI + 데이터. IV는 GCM nonce로 별도 입력 |
| 데이터 필드 암호화 | 평문 | SA01/SA11에서 AES-256-GCM |
| FECF | 0 B | 계획 없음 |

암호화와 MAC이 없으므로 **SA01/SA11 프레임도 현재는 평문이고 인증되지 않습니다.**

---

## 6. 참고: 처리 중에 읽는 Space Packet 헤더 필드

Space Packet은 데이터 필드의 내용이지만, SDLP 처리 과정에서 아래 필드를 읽습니다.

| 필드 | 위치 | TC (`TC_SDLP_myBuildFrame`) | TM (`TM_SDLP_myExtractPacket`) |
|---|---|---|---|
| APID | 0-1 바이트, 11비트 | 읽지 않음 | `0x7FF`(idle)이면 프레임 끝으로 처리 |
| Packet Data Length | 4-5 바이트 | `Length + 7 == packetSize`인지 검사 | 패킷 경계 계산 |

---

## 7. SA 필드 사용 현황 (`common_sa_t`, [include/sa/sa_my.h](../include/sa/sa_my.h))

SA DB는 공유메모리 `/dev/shm/sdls_sa_db`에 있고([include/sa/sa_shm_my.h](../include/sa/sa_shm_my.h)), 송신·수신 프로세스가 함께 씁니다.

| 필드 | 사용 | 읽는 곳 | 바꾸는 곳 |
|---|---|---|---|
| `spi` | ✅ | SA 조회 (모든 `SA_my*`) | 바꾸지 않음 (기본값 고정) |
| `dir` | ✅ | `SECHDR_myApplyTc/ProcessTm`, `SA_myNextIv`(TC만), `SA_myCheck/CommitArsn`(TM만), `SA_myRekey`(IV 초기값 결정) | 바꾸지 않음 |
| `gvcid` | ❌ | — (채널 ID 더미) | — |
| `service_type` | ✅ | 보호 여부 판단 (NONE이면 IV 0/무시, 상태 전이 거부) | 바꾸지 않음 |
| `len_iv`, `len_sn`, `len_pl`, `len_mac` | ❌ | — (고정 상수 14 B / 0 B 사용) | — |
| `auth_alg` | ⚠️ | `SA_myRekey`에서 키 알고리즘이 맞는지 확인 | 바꾸지 않음 |
| `enc_alg` | ❌ | — | — |
| `auth_mask_prihdr`, `auth_mask_len` | ❌ | — (MAC 미구현) | — |
| `arsn_window` | ✅ | `SA_myCheckArsn`, `SA_myCommitArsn` | 바꾸지 않음 |
| `auth_key_id` | ✅ | `SA_myStart`, `SA_myExpire`, 키 중복 사용 검사 | `SA_myRekey`(키 연결), `SA_myExpire`(NONE) |
| `enc_key_id` | ✅ | 키 중복 사용 검사 | `SA_myRekey`, `SA_myExpire` |
| `iv` | ✅ | `SA_myNextIv`, `SA_myCheckArsn`, `SA_myGetSa` | `SA_myNextIv`(+1), `SA_myCommitArsn`(갱신), `SA_myRekey`(TC 1 / TM 0) |
| `state` | ✅ | 모든 처리 함수 | `SA_myRekey/Start/Stop/Expire` |
| `last_pid` | ✅ | `SA_myGetSa` | `SA_myRekey/Start/Stop/Expire` |

### SA 상태 전이 (EP 2.3.3)

```
          SA_myRekey(spi, keyId)          SA_myStart(spi)
Unkeyed ─────────────────────────▶ Keyed ─────────────────▶ Operational
   ▲                                 │  ◀─────────────────
   └──────── SA_myExpire(spi) ───────┘     SA_myStop(spi)
             (세션키 0으로 지우고 폐기)
```

SA00/SA10은 항상 Operational이고, 모든 전이를 거부합니다(`SA_MY_INVALID_STATE`).

### SA / Key DB 함수 전체 ([include/sa/sa_shm_my.h](../include/sa/sa_shm_my.h))

| 분류 | C 함수 | Python | 하는 일 |
|---|---|---|---|
| 수명 | `SA_myOpen(name)` | `sa_open(name=None)` | 공유메모리를 만들거나 붙음. 처음이면 `common_sa_db_default`로 초기화 |
| | `SA_myClose()` | `sa_close()` | 이 프로세스에서 매핑 해제 (내용은 유지) |
| | `SA_myUnlink(name)` | `sa_unlink(name=None)` | 세그먼트 이름 삭제. 다음 Open은 기본값으로 새로 시작 |
| | `SA_mySaSize()` | (바인딩이 로드 시 확인) | `sizeof(common_sa_t)` |
| 조회 | `SA_myGetSa(spi, pSa)` | `sa_get(spi)` → `CommonSa` | SA 전체 복사 |
| 상태 전이 | `SA_myRekey(spi, keyId)` | `sa_rekey(spi, key_id)` | Unkeyed → Keyed, 키 연결, IV 초기화 |
| | `SA_myStart(spi)` | `sa_start(spi)` | Keyed → Operational |
| | `SA_myStop(spi)` | `sa_stop(spi)` | Operational → Keyed |
| | `SA_myExpire(spi)` | `sa_expire(spi)` | Keyed → Unkeyed, 세션키 폐기 |
| 키 | `SA_mySetKey(keyId, pKey, len)` | `sa_set_key(key_id, key)` | AES-256 세션키(32 B) 로드. 사용 중인 키는 교체 불가 |
| | `SA_myCopySaKey(spi, pKey)` | 없음 (라이브러리 내부 전용, export 안 함) | SA에 연결된 세션키 복사. 암호화 코드용 |
| 프레임 카운터 | `SA_myNextIv(spi, pIv)` | `sa_next_iv(spi)` | TC: IV 발급 후 +1 (프로세스 간 원자적) |
| | `SA_myCheckArsn(spi, pIv)` | `sa_check_arsn(spi, iv)` | TM: ARSN 윈도우 검사만 함 |
| | `SA_myCommitArsn(spi, pIv)` | `sa_commit_arsn(spi, iv)` | TM: 마지막 수락 ARSN 갱신 (MAC 검증 뒤에 호출해야 함) |

---

## 8. 반환 코드

| 값 | TC (`TC_SDLP_MY_*`) | TM (`TM_SDLP_MY_*`) | SA / SECHDR (`SA_MY_*`) |
|---|---|---|---|
| 0 | `SUCCESS` | `SUCCESS` | `SUCCESS` |
| -2 | `INVALID_ARGUMENT` | `INVALID_ARGUMENT` | `INVALID_ARGUMENT` |
| -3 | `INVALID_LENGTH` | `INVALID_LENGTH` | — |
| -4 | `INVALID_PACKET` | `INVALID_PACKET` | — |
| -5 | — | `INVALID_HEADER` | — |
| -6 | `SECURITY_ERROR` | `SECURITY_ERROR` | — |
| -7 | `BUFFER_TOO_SMALL` | — | — |
| -8 | `NOT_INITIALIZED` | — | `NOT_OPEN` |
| -9 | — | — | `SHM_ERROR` |
| -10 | — | — | `LAYOUT_MISMATCH` |
| -11 | — | — | `LOCK_ERROR` |
| -12 | — | — | `UNKNOWN_SPI` |
| -13 | — | — | `INVALID_STATE` |
| -14 | — | — | `UNKNOWN_KEY` |
| -15 | — | — | `KEY_IN_USE` |
| -16 | — | — | `IV_EXHAUSTED` |
| -17 | — | — | `REPLAY` |

`SECURITY_ERROR`(-6)는 SA 쪽 실패 원인을 하나로 묶은 코드입니다. 원인을 알고 싶으면 `SA_myGetSa`로 SA 상태를 직접 확인합니다.

---

## 9. 미구현 요약

| 항목 | 영향 |
|---|---|
| Security Trailer(MAC)와 데이터 암호화 | SA01/SA11 프레임이 평문이고 인증되지 않음 |
| ARSN 기록을 MAC 검증 뒤로 이동 | 지금은 위조 프레임으로 수신 윈도우를 밀 수 있음 |
| GVCID 검사 | 채널 ID가 더미라 보류 |
| SA의 `len_*`, `auth_mask_*`, `enc_alg` 사용 | 고정 길이 상수로 대신함 |
| 키교환(ML-KEM/ML-DSA, EP PDU) | `SA_mySetKey`로 키를 직접 넣어 대신함 |
| TM에서 패킷이 어느 SA로 왔는지 반환 | Python이 프레임 6-7 바이트를 직접 읽어야 함 |
| TM OCF / Secondary Header / 패킷 분할, TC COP-1 | 범위 밖 |

위성 쪽에서 맞춰야 할 것:
- TC Security Header를 14 B로 반영
- 수신 SA(SA01)의 마지막 수락 ARSN을 0에서 시작
