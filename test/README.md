# libsdls.so Python 테스트

Python ground system이 ctypes로 `libsdls.so`를 불러 쓰는 방식 그대로 지상국 SDLP를 검증합니다.
위성(cFS) 쪽 SDLP 코드를 Python으로 옮긴 참조 구현과 바이트 단위로 왕복이 맞는지 확인합니다.

## 파일

| 파일 | 내용 |
|---|---|
| `sdls_binding.py` | ctypes 바인딩 (함수 시그니처, C 헤더 상수 사본, 예외 래퍼). ground system에서 그대로 가져다 써도 됨 |
| `sat_reference.py` | 위성 쪽 `TC_SDLP_myExtractPacket`, `TM_SDLP_myForwardPacket` 등의 Python 포팅 |
| `test_tc_sdlp.py` | `TC_SDLP_myInit`, `TC_SDLP_myBuildFrame` 테스트 |
| `test_tm_sdlp.py` | `TM_SDLP_myExtractPacket` 테스트 |
| `frame_view.py` | 완성된 TC/TM 프레임(Primary + Security Header + Data + Trailer)을 필드별로 출력. `python3 test/frame_view.py [--hex]` |
| `test_frame_view.py` | `frame_view.py` 디코더 검증 + 실행 확인 |
| `test_sechdr.py` | SDLS Security Header (`SECHDR_my*`) 테스트. TC 헤더 바이트(SPI BE + IV), TM 헤더 SPI/SA/ARSN 검사 |
| `test_sa_shm.py` | 공유메모리 SA/Key DB (`SA_my*`) 테스트. 상태 전이, IV 발급, ARSN 윈도우, 자식 프로세스(spawn)로 프로세스 간 공유와 동시 IV 발급 검증 |

외부 패키지 없이 표준 라이브러리(`unittest`, `ctypes`)만 사용합니다.

## 실행

```sh
cmake -S . -B build
cmake --build build

# 방법 1: ctest (빌드한 라이브러리 경로를 자동으로 넘김)
ctest --test-dir build --output-on-failure

# 방법 2: 직접 실행 (기본으로 build/libsdls.so를 찾음)
python3 -m unittest discover -s test -v

# 다른 위치의 라이브러리를 테스트할 때
SDLS_LIB=/path/to/libsdls.so python3 -m unittest discover -s test -v
```

## 주의

- ctypes는 `#define`을 읽지 못하므로 `sdls_binding.py`의 상수는 `include/` 헤더 값을 복사한 것입니다. 헤더를 바꾸면 같이 고쳐야 합니다.
- `sat_reference.py`는 위성 쪽 코드가 바뀌면 같이 맞춰야 합니다. 이 파일이 지상국 라이브러리의 정답 기준입니다.
- TC 쪽은 라이브러리 안에 정적 상태(초기화 여부, Frame Sequence Number, SA DB 매핑)가 있어서, Init/`SA_myOpen` 전 호출 테스트는 라이브러리 사본을 따로 로드해서 확인합니다.
- TC/TM 프레임 처리는 Security Header(SPI 2 + IV 12)를 공유메모리 SA DB로 처리하므로, TC/TM 테스트도 테스트마다 새 SA DB를 엽니다. `SatTmFramer(spi=...)`로 위성이 쓸 SA를 고릅니다(기본 SA10).
- SA 테스트는 테스트마다 `/sdls_test_<pid>_<n>` 이름의 공유메모리를 만들고 끝나면 지웁니다. 기본 이름(`/sdls_sa_db`)을 쓰는 실행 중인 ground system에는 영향을 주지 않습니다.
