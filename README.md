# Another Dimension v2

[![CI](https://github.com/answndud/another-dimension-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/answndud/another-dimension-v2/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A local, serverless 1:1 text chat for Apple Silicon macOS, written in Rust. A small Rust program serves a loopback-only web UI, peers connect through public Nostr relays over a Noise XX session with Ed25519 identity proofs, and history is stored encrypted on the device. There is no account server and no automatic cloud sync. It is a personal project built to practice applied security engineering, and **it has not been independently audited**: read [SECURITY.md](SECURITY.md) for the threat model and the known weaknesses before trusting it with anything.

Apple Silicon Mac에서 실행하는 로컬 1:1 텍스트 채팅 앱입니다. Rust 프로그램이 로컬 웹 화면을 제공하고, 대화는 기기 안에 암호화해 저장합니다. 중앙 계정 서버나 자동 클라우드 동기화는 사용하지 않습니다.

## 핵심 보안 설계

구현을 직접 확인할 수 있도록 근거 파일을 함께 적었습니다. 전체 구조는 [docs/architecture.md](docs/architecture.md)를 보세요.

- **로컬 API 방어** ([src/main.rs](src/main.rs)): 루프백 임의 포트에만 바인딩하고, 모든 요청의 `Host`와 POST의 `Origin`·`Content-Type`을 정확히 비교합니다. 256비트 일회용 연결 코드(TTL 5분, 시도 5회, 상수 시간 비교)로 세션 토큰을 받고, 토큰은 쿠키가 아닌 `sessionStorage`에 두고, 1시간 유휴·12시간 절대 만료이며 새 연결 코드 발급이나 로그아웃 때 모두 폐기합니다. 엄격한 CSP(인라인 스크립트·스타일 없음)와 `Referrer-Policy`·COOP·CORP·`Permissions-Policy`를 모든 응답에 붙이고 CORS 헤더는 보내지 않으며 `Transfer-Encoding`과 중복 헤더는 거부합니다.
- **신원과 통신 키 분리** ([src/channel.rs](src/channel.rs)): Noise의 static 키는 연결마다 새로 만들고, 장기 신원은 별도의 Ed25519 키입니다. 핸드셰이크 해시에 대한 서명을 암호화된 전송 안에서 교환하므로 relay가 신원을 볼 수 없습니다. 양쪽의 증명과 사용자 확인 전에는 채팅 API를 호출할 수 없도록 typestate로 설계했습니다.
- **프레임 순번과 재정렬 창** ([src/channel.rs](src/channel.rs)): 프레임마다 순번이 있고 32개 범위 안의 재정렬을 허용하며 중복은 무시합니다. 인증 실패는 세션을 닫습니다.
- **인증 암호화 저장** ([src/history.rs](src/history.rs)): 대화 로그, 인덱스, 확인된 상대 기록을 ChaCha20-Poly1305로 보호합니다. 파일명은 상대 ID의 HMAC이고, 중간 레코드의 인증 실패는 오류로 처리하며 꼬리의 불완전한 레코드만 복구합니다.
- **스트리밍 백업 결속** ([src/history.rs](src/history.rs)): ADBACK7은 파일별 무작위 ID, 프레임 인덱스, 종료 프레임을 인증 데이터에 묶어 잘라내기·재정렬·파일 간 바꿔치기를 탐지합니다. ADPACK3는 적용 전에 묶음 전체를 HMAC으로 검증합니다. 백업 비밀번호는 Argon2id로 유도합니다.
- **서명된 메시지와 복원 동의** ([src/history.rs](src/history.rs)): 새 메시지는 Ed25519 서명을 가지며, 상대 기록 복원은 전송 동의와 최종 병합 동의를 각각 거칩니다.
- **Tor 모드의 우회 금지** ([src/relay.rs](src/relay.rs)): 모든 relay 연결이 지정한 SOCKS 프록시를 통하고 호스트 이름 해석도 프록시가 처리하며, 프록시가 실패해도 직접 연결로 전환하지 않습니다. 프록시 주소는 루프백만 허용합니다.
- **입력 크기 상한**: HTTP 헤더·본문, 핸드셰이크 메시지, 프레임, relay 이벤트에 상한이 있고 할당 전에 검사합니다.
- **작은 `unsafe` 범위**: `unsafe`는 파일 잠금(`flock`)과 `geteuid` 호출 6곳뿐이며 모두 [src/history.rs](src/history.rs)에 있습니다. 프런트엔드에는 `innerHTML`과 `eval`이 없습니다.
- **재현 가능한 의존성**: 모든 의존성을 정확한 버전으로 고정하고 `Cargo.lock`을 커밋하며, CI에서 `cargo audit`을 실행합니다.

한계도 공개합니다. 알려진 약점 목록은 [SECURITY.md](SECURITY.md#known-weaknesses)에 있고, 고친 문제는 [docs/security-fixes.md](docs/security-fixes.md)에 기록합니다.
## 설치와 실행

1. Xcode Command Line Tools와 Rust stable(Cargo 포함)을 설치합니다. macOS 터미널에서 `xcode-select --install`을 실행하고, [rustup.rs](https://rustup.rs)의 안내에 따라 stable toolchain을 설치할 수 있습니다.
2. 저장소를 내려받고 프로젝트 디렉터리에서 실행합니다.

```sh
git clone https://github.com/answndud/another-dimension-v2.git
cd another-dimension-v2
cargo run --release
```

의존성이 이미 로컬에 준비되어 있으면 `cargo run --offline`을 사용할 수 있습니다. 처음 빌드에는 Cargo 의존성 다운로드가 필요할 수 있습니다.

데이터(신원·대화 기록·앱 설정)는 암호화해 로컬에 저장하고, 시작할 때 터미널에 저장 위치를 표시합니다.

| 빌드 | macOS 저장 위치 |
|---|---|
| 릴리스 (`cargo run --release`) | `~/Library/Application Support/Another Dimension v2/` |
| 디버그 (`cargo run`) | 이 저장소의 `chat-data/` (Git에서 제외) |

`ANOTHER_DIMENSION_DATA_DIR`에 절대 경로를 지정하면 두 빌드 모두 그 위치를 씁니다. 이 폴더는 심볼릭 링크가 아니어야 하고, `..`를 포함하지 않으며, 이미 있다면 내 소유에 `chmod 700`(다른 사용자 접근 불가)이어야 합니다. 조건에 맞지 않으면 권한을 바꾸지 않고 실행을 거부합니다. 없는 폴더는 비공개로 만듭니다.

**이전에 저장소의 `chat-data/`를 쓰던 경우:** 릴리스 빌드는 이제 그 폴더를 읽지 않습니다. 데이터를 자동으로 옮기지는 않으며, 옛 위치에 데이터가 남아 있으면 시작할 때 경고합니다. 계속 그 위치를 쓰려면 폴더를 `chmod 700 chat-data` 한 뒤 아래처럼 실행하세요.

```sh
ANOTHER_DIMENSION_DATA_DIR="$PWD/chat-data" cargo run --release
```

터미널에 표시된 `http://127.0.0.1:포트/` 주소를 지원되는 Chromium 계열 브라우저에서 엽니다. 앱이 터미널에 발급한 일회용 로컬 연결 코드를 화면에 입력합니다. 이 연결 코드는 개인 접속 코드와 다릅니다. 새 신원은 화면에서 개인 접속 코드를 생성해 별도 안전한 곳에 저장한 뒤 로그인합니다. 연결 코드는 만료되거나 한 번 사용된 뒤 다시 쓸 수 없습니다.

## 개인 코드와 대화 연결

- 개인 접속 코드는 본인 신원을 다른 지원 기기에서 복원하는 비밀입니다. 상대에게 보내지 마세요. 분실하면 운영자가 복구할 수 없고, 코드를 가진 사람은 같은 신원을 복원할 수 있습니다. 추가 코드를 발급해도 이미 발급된 코드 사본을 폐기하지는 못합니다.
- 새 대화에서 초대 코드를 만들고 상대에게 별도 연락 수단으로 전달합니다. 양쪽 화면에 표시되는 12자리 확인 코드를 그 별도 경로(전화 등)로 처음부터 끝까지 비교한 후 각자 확인해야 메시지를 주고받을 수 있습니다. 코드를 비교하는 데 최대 5분까지 기다립니다. 두 사람은 같은 버전의 프로그램을 써야 합니다. 앱은 비교가 실제로 안전한 경로에서 이루어졌는지 확인할 수 없으며, 코드는 현실 인물의 신원을 증명하지 않습니다.
- 확인한 상대는 대화 목록에서 다시 연결할 수 있습니다. 상대 또는 본인의 신원이 바뀌면 새 초대와 확인이 필요할 수 있습니다. 기존 대화를 새 신원에 연결할 때는 사용자가 해당 대화를 명시적으로 선택하고 이전 신원을 확인해야 합니다. 신원 계보만으로 같은 사람임을 증명하지 않습니다.

## 기록과 수동 백업

대화 기록과 확인된 상대 관계는 개인 코드에서 유도한 키로 암호화해 로컬에 보관합니다. 관리 메뉴의 대화 기록 관리에서 선택한 대화를 암호화 파일로 내보내고 다른 기기에서 가져올 수 있습니다. 새 단일 대화 백업은 ADBACK7, 여러 대화 묶음은 ADPACK3이며, 단일 백업에는 선택적 백업 비밀번호를 설정할 수 있습니다. 백업 파일과 개인 접속 코드는 별도로 보관해야 하고, 앱은 파일을 자동 업로드하지 않습니다.

- 상대가 가진 누락 기록은 예상량 확인, 전송 동의, 미리 보기, 최종 병합 동의를 각각 거쳐 복원합니다. 서명은 발신 키와 변조 여부를 확인할 뿐 실제 인물이나 기록의 완전성을 증명하지 않습니다.
- 기록은 자동으로 삭제되지 않습니다. 사용자가 대화 전체, 선택한 메시지, 날짜 범위를 삭제할 수 있지만 상대방 기록과 백업 파일은 지워지지 않습니다.
- 보호가 약한 구형 형식(ADBACK2, ADBACK6, ADPACK1, ADPACK2)은 기본적으로 가져오지 않고, 화면의 형식별 경고를 확인한 뒤에만 가져옵니다. 서명이 없는 메시지는 기록 화면에서 "서명 없음 · 미검증"으로 표시됩니다. 형식별 보호 범위, 크기 제한, 가져오기 동작, 임시 파일 정리 절차는 [docs/backup-formats.md](docs/backup-formats.md)에 정리했습니다.

## Relay와 Tor 설정

기본 설정은 일반 연결입니다. 로그인 후 메뉴의 **연결 설정**에서 relay 주소 목록과 연결 모드를 관리할 수 있습니다. 주소 목록은 한 줄에 하나씩 입력하며 `wss://`만 허용됩니다. 목록 변경은 저장 후 서버를 재시작해야 적용됩니다. 앱은 실행 중 설정된 relay 목록에 연결을 시도하지만 서비스 가용성이나 상대와 공통 relay가 항상 있다는 것을 보장하지 않습니다.

Tor 모드를 사용하려면 Tor 서비스를 별도로 설치·실행하고, 그 서비스가 제공하는 로컬 SOCKS 주소를 설정에 입력하세요(예: `127.0.0.1:9050`; 설치 방식에 따라 포트가 다를 수 있음). 앱은 Tor를 설치·실행하지 않고, 지정한 SOCKS 서비스가 실제 Tor인지 확인하지 않습니다. SOCKS 또는 relay 연결이 실패하면 직접 연결로 우회하지 않습니다. 모드를 저장한 뒤 서버를 종료하고 다시 실행해야 적용됩니다.

Tor 모드는 앱의 relay 연결에만 적용됩니다. 메시지 링크를 열 때 표시되는 외부 브라우저는 Tor를 사용하지 않을 수 있으며 앱은 그 브라우저의 네트워크 경로를 제어하지 않습니다. Tor가 완전한 익명성이나 트래픽 상관분석 방지를 보장하지 않습니다.

## 범위와 확인 상태

이 프로젝트는 macOS Apple Silicon을 주요 대상으로 합니다. 실제 브라우저 레이아웃, 사용자 환경의 Tor 경로, 공개 relay의 가용성과 상호운용은 별도 환경에서 확인해야 합니다. 독립 보안 감사는 수행되지 않았으며, 암호화 구현을 보안 보증으로 해석해서는 안 됩니다.

## 문서

| 문서 | 내용 |
|---|---|
| [SECURITY.md](SECURITY.md) | 위협 모델, 보장하는 것과 하지 않는 것, 알려진 약점, 취약점 제보 |
| [docs/architecture.md](docs/architecture.md) | 구성요소, 연결 흐름, 저장 키 구조 (다이어그램 포함) |
| [docs/adr/](docs/adr/) | 설계 결정 기록 (로컬 웹 UI, Noise XX와 Nostr, 접속 코드, 백업 형식 정책) |
| [docs/security-fixes.md](docs/security-fixes.md) | 발견한 문제와 수정, 회귀 테스트 기록 |
| [docs/backup-formats.md](docs/backup-formats.md) | 백업 형식별 보호 범위와 가져오기 동작 |
| [docs/frontend.md](docs/frontend.md) | 프런트엔드 구조와 접근성 원칙 |

## 개발

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
node --check web/app.js
node --test web/reprotect-ui.test.cjs
```

`cargo test`는 약 10초 걸립니다. 64 MiB 초과 파일이나 10만 건 이상의 기록을 다루는 대용량 테스트 6개는 느려서(약 2~3분) 기본으로는 건너뛰며, `cargo test -- --ignored --skip live_relay`로 실행합니다. 이 테스트는 CI에서 주 1회 돌고, 같은 주기로 의존성 권고도 점검합니다. 실제 대화 데이터를 건드리지 않도록 테스트는 임시 디렉터리를 사용합니다. 앱을 직접 실행해 시험할 때는 `ANOTHER_DIMENSION_DATA_DIR`에 임시 절대 경로(`chmod 700`)를 지정하세요.

## 라이선스

[MIT](LICENSE)
