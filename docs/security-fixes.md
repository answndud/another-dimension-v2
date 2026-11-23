# 보안 수정 기록

발견한 문제를 "발견 → 영향 → 수정 → 회귀 테스트" 형식으로 기록합니다. 수정이 끝난 항목만 추가하며, 아직 남아 있는 문제는 [SECURITY.md](../SECURITY.md#known-weaknesses)의 알려진 한계에 있습니다.

## 항목 형식

```markdown
## SF-NNN 제목

- 날짜: YYYY-MM-DD
- 심각도: High / Medium / Low
- 위치: 파일과 함수
- 발견: 무엇이 문제인지, 어떻게 알게 되었는지
- 영향: 공격자가 무엇을 할 수 있었는지 (구체적인 시나리오)
- 수정: 무엇을 바꿨는지, 왜 이 방법을 택했는지
- 회귀 테스트: 테스트 이름과 이 테스트가 막는 동작
- 남은 한계: 수정 후에도 남는 부분
```

## 기록

## SF-002 구형 백업(ADBACK2)으로 위조된 대화 기록을 가져올 수 있음

- 날짜: 2026-11-23
- 심각도: High
- 위치: `src/history.rs`의 `import_backup_file`, `reprotect_backup_file`, ADBACK2 복호화(`derive_password_backup_key`)
- 발견: 코드 리뷰에서 ADBACK2의 키가 백업 비밀번호에서만 유도되고, 인증 데이터(AAD)가 피해자의 **공개** 신원 ID뿐이며, 메시지에 서명이 없다는 점을 발견했습니다. 그다음 실제로 가능한지 테스트로 먼저 재현했습니다. 위조 파일을 만드는 데 비밀이 필요하지 않았고, 수정 전 코드에서는 오류 없이 가져와졌습니다.
- 영향: 비밀번호를 아는 사람(예: 피해자에게 파일과 비밀번호를 함께 건넨 공격자)이 상대가 보낸 것처럼 보이는 메시지를 만들어 피해자의 기록에 병합시킬 수 있었습니다. 경고도, 구분 표시도 없었습니다. 기록 화면은 서명 여부를 아예 보여 주지 않아서 위조 메시지가 진짜와 구분되지 않았습니다.
- 수정:
  1. 서버가 ADBACK2, ADBACK6, ADPACK1, ADPACK2를 기본적으로 거부합니다. 요청에 `allowLegacy: true`가 있을 때만 처리하며, `false`나 잘못된 타입은 거부합니다(`LegacyBackupPolicy`).
  2. 재보호(reprotect)에도 같은 규칙을 적용했습니다. 구형 파일을 신원 키로 인증된 새 컨테이너에 담아 주면 이후 가져오기에서 경고가 사라지는 우회 경로가 되기 때문입니다.
  3. 화면이 형식별 위험을 설명하고 사용자가 확인한 뒤에만 `allowLegacy`를 보냅니다. 확인창은 UX이고 강제는 서버가 합니다.
  4. 서버가 메시지 목록에 `signed`를 내보내고, 기록 화면이 서명 없는 메시지에 "서명 없음 · 미검증"을 글자로 표시합니다. 시스템 메시지는 제외합니다.
- 회귀 테스트:
  - `history::tests::forged_password_only_backup_is_not_imported_by_default`: 위조 파일이 기본 설정에서 거부되고 기록이 바뀌지 않는다.
  - `history::tests::forged_password_only_backup_imports_unsigned_only_after_opt_in`: 허용해도 메시지에는 서명이 없다.
  - `send_tests::backup_transfer_api_enforces_the_legacy_format_opt_in_on_the_server`: HTTP 계층에서 필드 없음·`false`·`"yes"`는 거부되고 대화 파일이 만들어지지 않으며, `true`만 통과한다.
  - `history::tests::only_formats_with_weaker_guarantees_need_confirmation`: 어떤 형식이 확인을 요구하는지 표로 고정한다.
  - `history::tests::current_format_round_trip_keeps_unsigned_messages_unsigned`: ADBACK7로 내보내고 가져와도 서명 없는 메시지는 서명 없이 남는다(그래서 화면이 `proof`만으로 표시해야 한다).
  - `history::tests::legacy_bundle_is_rejected_by_default_and_imports_after_opt_in`, `v6_backup_and_v2_bundle_need_confirmation_but_remain_importable`: 다른 구형 형식과 재보호.
  - 프런트엔드: 확인 없이는 아무것도 전송되지 않고, 확인 후에만 `allowLegacy`가 가며, 현재 형식에는 플래그와 확인창이 없고, 서명 없는 메시지에 표지가 붙는다.
- 남은 한계:
  - 사용자가 확인하면 구형 파일은 여전히 가져와집니다. 출처가 불분명한 ADBACK2 파일에 확인을 누르면 위조된 기록을 받을 수 있고, 그 메시지는 "서명 없음 · 미검증"으로 표시될 뿐입니다.
  - 표시는 기록 관리 화면과 복원 미리보기에 있고, 대화 중인 채팅 화면에는 아직 없습니다.
  - 현재 형식(ADBACK7)도 메시지별 서명 없는 기록을 담을 수 있습니다. 구형 로컬 기록을 내보낸 경우이며 같은 표지로 표시됩니다.

## SF-001 `url` 의존성의 스택 오버플로 (RUSTSEC-2026-0592)

- 날짜: 2026-11-22
- 심각도: Low (이 프로젝트의 도달 가능성 기준)
- 위치: 전이 의존성 `url` 2.5.8 (`nostr`, `tungstenite`가 사용)
- 발견: CI에 `cargo audit`을 추가하기 전에 로컬에서 실행해 발견했습니다. 중첩된 `blob:` URL에서 `Url::origin()`이 스택 오버플로를 일으킵니다.
- 영향: 공격자가 만든 URL이 `origin()`에 전달되면 프로세스가 비정상 종료될 수 있습니다. 이 프로젝트는 `Url::origin()`을 직접 호출하지 않고 relay 주소는 `wss://`만 허용하므로 실제로 도달하기는 어렵습니다.
- 수정: `Cargo.lock`에서 `url`을 2.5.9로 올렸습니다(`cargo update -p url --precise 2.5.9`). `Cargo.toml`은 바뀌지 않았고, 함께 올라간 것은 `form_urlencoded` 1.2.3뿐입니다.
- 회귀 테스트: 전용 테스트는 없습니다. CI의 `cargo audit` 단계가 같은 권고가 다시 나타나는 것을 막습니다.
- 남은 한계: `nostr`가 `faster-hex`를 통해 끌어오는 `heapless` 0.8.0에 unsound 경고 9건이 남아 있습니다. `nostr`를 정확한 버전(`=0.45.7`)으로 고정했기 때문에 직접 고칠 수 없고, `cargo audit`의 실패 조건이 아닌 경고입니다.
