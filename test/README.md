# libsdls.so Python 테스트

Python ground system이 ctypes로 `libsdls.so`를 불러 쓰는 방식 그대로 지상국 SDLP/SDLS/EP를 검증합니다.
위성(cFS) 쪽 코드를 Python으로 옮긴 참조 구현과 바이트 단위로 왕복이 맞는지 확인합니다.
위성 쪽 암호 연산(AES-GCM, ML-KEM, ML-DSA)은 같은 wolfCrypt 백엔드로 빌드한 테스트 전용
`libsdls_satsim.so`가 맡고, 프레임 레이아웃과 AAD 규칙은 Python 참조 구현이 독립적으로 만듭니다.

## 파일

| 파일 | 내용 |
|---|---|
| `sdls_binding.py` | ctypes 바인딩 (함수 시그니처, C 헤더 상수 사본, 예외 래퍼). ground system에서 그대로 가져다 써도 됨 |
| `sat_reference.py` | 위성 쪽 `TC_SDLP_myExtractPacket`, `TM_SDLP_myForwardPacket` 등의 Python 포팅. SA01/SA11 암호화 포함 (`SatCrypto`로 satsim 호출) |
| `satsim/satsim.c` | 테스트 전용 위성 암호 라이브러리 `libsdls_satsim.so` 소스 |
| `test_sdls.py` | SDLS 프레임 보호: TC 암호화를 위성이 복호화, 바이트 변조 거절, MC Frame Count 비인증, 위조 프레임이 ARSN을 못 미는지, 실패 시 데이터 소거. `cryptography`가 있으면 독립 구현으로 교차 검증 |
| `test_ep.py` | 키 교환: 위성 ek → 지상 캡슐화 → 위성 역캡슐화 → 양방향 보호 통신, 키 재교환, 변조된 ct, 잘못된 ek, ML-DSA 서명 검증, 프로세스 간 ct·서명키 공유 |
| `test_tc_sdlp.py` | `TC_SDLP_myInit`, `TC_SDLP_myBuildFrame` 테스트 |
| `test_tm_sdlp.py` | `TM_SDLP_myExtractPacket` 테스트 |
| `frame_view.py` | 완성된 TC/TM 프레임(Primary + Security Header + Data + Trailer)을 필드별로 출력. `python3 test/frame_view.py [--hex]` |
| `test_frame_view.py` | `frame_view.py` 디코더 검증 + 실행 확인 |
| `test_sechdr.py` | SDLS Security Header (`SECHDR_my*`) 테스트. TC 헤더 바이트(SPI BE + IV), TM 헤더 SPI/SA/ARSN 검사 |
| `test_sa_shm.py` | 공유메모리 SA/Key DB (`SA_my*`) 테스트. 상태 전이, IV 발급, ARSN 윈도우, 자식 프로세스(spawn)로 프로세스 간 공유와 동시 IV 발급 검증 |

표준 라이브러리(`unittest`, `ctypes`)만 필요합니다. Python `cryptography` 패키지가 있으면 AES-GCM 독립 교차 검증 테스트도 돌고, 없으면 그 테스트만 건너뜁니다.

## 실행

wolfSSL이 `--enable-aesgcm --enable-mlkem --enable-mldsa`로 빌드돼 있어야 합니다.

```sh
# wolfSSL을 시스템이 아닌 곳에 설치했다면 -DWOLFSSL_ROOT=/opt/wolfssl 또는 PKG_CONFIG_PATH 지정
cmake -S . -B build
cmake --build build

# 방법 1: ctest (빌드한 라이브러리 경로를 자동으로 넘김)
ctest --test-dir build --output-on-failure

# 방법 2: 직접 실행 (기본으로 build/libsdls.so를 찾음)
python3 -m unittest discover -s test -v

# 다른 위치의 라이브러리를 테스트할 때 (satsim은 기본으로 libsdls.so 옆에서 찾음)
SDLS_LIB=/path/to/libsdls.so SDLS_SATSIM_LIB=/path/to/libsdls_satsim.so python3 -m unittest discover -s test -v
```

## 주의

- ctypes는 `#define`을 읽지 못하므로 `sdls_binding.py`의 상수는 `include/` 헤더 값을 복사한 것입니다. 헤더를 바꾸면 같이 고쳐야 합니다.
- `sat_reference.py`는 위성 쪽 코드가 바뀌면 같이 맞춰야 합니다. 이 파일이 지상국 라이브러리의 정답 기준입니다.
- TC 쪽은 라이브러리 안에 정적 상태(초기화 여부, Frame Sequence Number, SA DB 매핑)가 있어서, Init/`SA_myOpen` 전 호출 테스트는 라이브러리 사본을 따로 로드해서 확인합니다.
- TC/TM 프레임 처리는 Security Header(SPI 2 + IV 12)를 공유메모리 SA DB로 처리하므로, TC/TM 테스트도 테스트마다 새 SA DB를 엽니다. `SatTmFramer(spi=..., key=...)`로 위성이 쓸 SA와 세션키를 고릅니다(기본 SA10, 평문).
- TM 프레임은 SA11이면 라이브러리가 제자리에서 복호화하므로, 바인딩(`tm_extract`)은 받은 바이트를 쓰기 가능한 버퍼로 복사해서 넘깁니다. 반환값의 SPI로 SA10(EP PDU)과 SA11(보호된 텔레메트리)을 구분합니다.
- SA 테스트는 테스트마다 `/sdls_test_<pid>_<n>` 이름의 공유메모리를 만들고 끝나면 지웁니다. 기본 이름(`/sdls_sa_db`)을 쓰는 실행 중인 ground system에는 영향을 주지 않습니다.
