# 테스트

## 실행

```bash
cargo test --locked           # 전체 (속성 테스트 포함, 약 20초)
cargo test --locked -- --ignored --skip live_relay   # 느린 스트레스 테스트
node --test web/reprotect-ui.test.cjs   # 프런트엔드 (가짜 DOM)
```

CI의 `ci.yml`이 push마다 포맷·clippy·`cargo test`·JS 테스트를 돌리고, `weekly.yml`이 주 1회 `cargo audit`와 느린 테스트를 돌립니다.

## 종류

| 종류 | 위치 | 확인하는 것 |
|---|---|---|
| 단위·통합 테스트 | 각 모듈의 `tests`, `src/send_tests.rs`, `src/history/tests.rs` | 기능, 오류 경로, 장애 주입, 과거 형식 호환 |
| 속성 테스트(proptest) | `hex.rs`, `channel.rs`(`properties`), `parser_tests.rs`, `history/tests.rs`(`mutated_backups`) | 아래 참고 |
| 변이 검사 | 저장소에 남기지 않음. 각 수정의 `docs/security-fixes.md` 항목에 결과 기록 | 테스트가 실제로 그 동작을 막는지 |
| 프런트엔드 | `web/reprotect-ui.test.cjs` | 가짜 DOM에서의 화면 상태 |

변이 검사는 "수정을 일부러 망가뜨렸을 때 해당 테스트만 실패하는가"를 손으로 확인한 것입니다. 자동화하지 않았습니다.

## 속성 테스트가 확인하는 것

- **hex**: 모든 바이트열이 왕복하고, 디코드는 정규 형태(소문자·짝수 길이)만 받으며 임의 문자열에도 패닉하지 않습니다.
- **채널**: 임의 길이 메시지가 패딩을 거쳐 문서화된 크기 중 하나가 되어 왕복하고, **도착 순서가 어떻게 섞여도** 모든 메시지가 한 번씩 순서대로 전달되며, 봉투의 비트 하나를 뒤집으면 메시지가 전달되지 않고, 임의 바이트는 프레임으로 받아들여지지 않습니다.
- **HTTP 요청 머리**: 바이트가 어떻게 쪼개져 도착해도 첫 빈 줄에서 끝나고 결과가 같으며, 한도를 넘으면 거부합니다.
- **초대 코드·접속 코드·릴레이 URL·설정 파일**: 임의 입력과 유효한 코드의 변형이 패닉하지 않고, 받아들인 값은 정규 형태이며(URL은 정규화가 고정점), 설정은 저장 후 다시 읽어도 같습니다.
- **백업**: 변형된 ADBACK(비밀번호 유무), ADBACK7 스트림, ADPACK3 묶음은 항상 거부되고, 거부된 묶음은 대화를 남기지 않습니다.

기본 케이스 수는 테스트마다 정해져 있습니다. `PROPTEST_CASES=20000 cargo test parser_tests`처럼 환경 변수로 늘릴 수 있고, 2026-11-23에 파서 테스트(`parser_tests`)와 hex 테스트를 20,000 케이스로 돌려 실패가 없었습니다(약 1분).

## 하지 않은 것: 커버리지 기반 퍼징

계획에는 `cargo-fuzz` 타깃이 있었지만 **만들지 않았습니다.** 이유:

1. 이 저장소는 바이너리 크레이트만 있고 `lib.rs`가 없어서 `cargo-fuzz` 타깃이 파서를 가져다 쓸 수 없습니다. 쓰려면 `src/lib.rs`로 모듈을 올리는 구조 변경이 먼저 필요합니다.
2. `libFuzzer`는 nightly 툴체인이 필요한데 이 환경에는 stable만 있었습니다.

위의 속성 테스트는 무작위 입력과 변형을 쓰지만 **커버리지 정보로 입력을 진화시키지 않으므로** 깊은 분기까지 닿는다는 보장이 없습니다. "퍼징했다"고 쓸 수 있는 상태가 아닙니다. 다음 단계로 `lib.rs` 분리 후 다음 타깃을 추가하는 것을 권합니다: ADBACK7·ADPACK3 디코더, `read_request_head`, 릴레이 `receive`, `InviteCode::parse`, `load_settings_from_path`.

## 알려진 한계

- `history/tests.rs`(약 3,900줄)와 `send_tests.rs`(약 2,800줄)는 길고, 긴 시나리오 테스트 일부는 한 함수에 여러 단계가 들어 있습니다.
- 실제 relay, 실제 기기 두 대, Tor 회로 분리는 자동 테스트로 확인하지 못했습니다(가짜 relay와 가짜 SOCKS 서버로만 검증).
