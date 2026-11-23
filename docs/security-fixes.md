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

## SF-019 로컬 대화 로그의 롤백·꼬리 절단을 알아차리지 못함

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/history.rs`(`LogFormat`, `write_log_header`, `History::check_anchor`, `announce_replacement`, `record_anchor`), `src/anchor.rs`(새 파일), `src/main.rs`(경고 문구)
- 발견: 로그 레코드의 AAD가 `ADLOG2 ‖ 신원 ‖ 상대 ‖ 순번`뿐이라, ① `replace`/삭제 뒤에도 같은 키와 같은 순번으로 인증되는 **이전 세대 레코드를 현재 파일에 끼워 넣을 수 있었고** ② 파일 꼬리를 레코드 경계에서 자르거나 이전 파일을 되돌려도 남은 레코드가 모두 인증되어 **알아차릴 방법이 없었습니다**.
- 영향: 로그 파일 하나만 바꿀 수 있는 공격자(백업 동기화 서비스, 다른 사용자 계정의 도구 등)가 지운 메시지를 되살리거나 마지막 대화를 조용히 없앨 수 있었습니다.
- 수정:
  1. **ADLOG3**: 헤더에 무작위 16바이트 세대 id를 두고 모든 레코드의 AAD에 넣습니다. `replace`, 삭제, 복원 병합, 이전 형식 이전은 새 세대를 만듭니다. ADLOG1/2는 계속 읽고, 대화를 열 때 ADLOG3로 다시 씁니다. 헤더가 일부만 쓰이다 끊긴 경우는 다시 씁니다.
  1-b. 레코드는 저장 키에서 용도별로 파생한 키(`history-log-aead`)로 암호화합니다(2.11에서 남겨 둔 마지막 항목). `adlog3_records_use_their_own_key_not_the_storage_key`가 저장 키로는 풀리지 않음을 확인하고, 파생을 빼면 실패합니다.
  2. **앵커 파일** `conversations.anchor`: 각 대화의 (세대 id, 레코드 수, 설치 예정 세대)를 별도 용도 키로 암호화해 저장합니다. 로그가 디스크에 내려간 **뒤에** 갱신하므로 충돌 뒤에는 로그보다 뒤처질 수는 있어도 앞서지는 않습니다. 교체는 이름을 바꾸기 전에 새 세대를 `pending`으로 먼저 기록해, 이름 변경 직후 충돌을 변조로 오인하지 않습니다.
  3. 열 때 비교해 ① 같은 세대인데 레코드가 적으면 "짧아짐", ② 설치된 적 없는 세대면 "다른 버전", ③ 앵커를 읽을 수 없으면 "상태 정보 읽기 실패"를 **한 번** 경고하고 현재 상태를 다시 기록합니다. 대화는 열립니다(경고만 하고 기록을 막지는 않습니다).
- 회귀 테스트: `a_record_from_an_earlier_generation_does_not_authenticate_in_the_current_one`(AAD에서 세대를 빼면 실패), `a_log_cut_at_a_record_boundary_is_reported_once`, `an_older_copy_of_the_log_is_reported_after_a_replace`, `crashes_between_the_steps_of_a_write_are_not_mistaken_for_tampering`, `ordinary_use_never_raises_the_warning`(삭제로 짧아진 경우 포함), `a_conversation_from_before_anchors_existed_is_adopted_without_a_warning`, `an_unreadable_anchor_is_reported_and_then_replaced`, `deleting_a_conversation_forgets_its_anchor`, `an_adlog2_log_still_opens_and_is_rewritten_as_adlog3`, `a_header_cut_short_by_a_crash_is_rewritten`, 앵커 판정 단위 테스트. 변이 검사: 세대 AAD 제거, 추가 시 앵커 갱신 제거, `pending` 허용 제거, 길이 비교 제거가 각각 해당 테스트만 실패시키는 것을 확인했습니다.
- 남은 한계: 데이터 디렉터리의 모든 파일을 함께 되돌리는 공격, 또는 앵커 파일을 지우고 로그를 자르는 공격은 단일 기기에서 막을 수 없습니다(신뢰할 카운터가 없음). 경고는 사라진 메시지를 복구하지 않습니다. 앵커는 메시지를 저장할 때마다 다시 쓰이므로 대화가 아주 많으면 비용이 늘어납니다(측정하지 않았습니다). 프로세스 사이의 앵커 파일 경쟁은 막지 않습니다(기존 인덱스와 같은 한계).

## SF-018 같은 쌍의 재연결이 항상 같은 relay 토픽과 키로 보임

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/relay.rs`(`InviteCode::relay_material_at`, `rendezvous_at`, `RelayRendezvous`의 수신 검증)
- 발견: 재연결 비밀에서 파생된 토픽과 서명 키가 시간과 무관하게 고정이었습니다.
- 영향: relay 운영자는 같은 토픽·키가 반복되는 것으로 한 쌍의 재연결을 몇 달이고 이어서 추적할 수 있었습니다. 또 relay가 저장해 둔 오래된 이벤트를 다시 보내도 수신 측이 시각을 보지 않았습니다.
- 수정(프로토콜 v3에 합류, 버전 올림 없음): 재연결 비밀에서 6시간 epoch마다 다른 토픽과 키를 HKDF로 파생합니다(`EPOCH_INFO`). 이전·현재·다음 epoch 세 곳을 구독하고 현재 epoch에 게시하므로 경계에서 시계가 어긋나도 만납니다. 수신 측은 (작성자 키, 토픽 태그)가 같은 epoch의 쌍인지 확인하고, 생성 시각이 5분 이내인 이벤트만 받습니다. 처음 초대 코드는 한 번만 쓰이므로 epoch를 쓰지 않습니다. 중복 방지 집합이 가득 차면 연결을 끝내던 동작은 오래된 항목을 버리도록 바꿨습니다(채워서 연결을 끊는 공격 방지).
- 회귀 테스트: epoch마다 토픽·키가 다르고 다른 비밀과 겹치지 않는 테스트 3개, 경계 시계 어긋남 테스트(`two_clocks_that_disagree_across_an_epoch_boundary_still_find_each_other`, `clocks_more_than_one_epoch_apart_do_not_meet`), 수신 검증 테스트(`an_event_older_than_the_window_is_ignored_as_a_replay`, `an_event_dated_too_far_ahead_is_ignored_too`, `replayed_events_cannot_fix_the_attempt_or_end_the_rendezvous`, `an_event_mixing_one_epochs_key_with_another_epochs_topic_is_ignored`, `flooding_the_topic_with_valid_events_does_not_end_the_rendezvous`). 변이 검사: 신선도 검사 제거 시 3개, 쌍 검사 완화 시 1개, `seen` 초과 오류 복원 시 1개가 해당 테스트만 실패하는 것을 확인했습니다.
- 남은 한계: 같은 epoch 안에서는 토픽이 같아 연결 가능합니다. 시계가 한 epoch(6시간) 넘게 어긋난 두 기기는 만나지 못합니다. 이벤트 시각의 5분 허용 범위는 재전송을 완전히 막지 못하고 세션 인증이 최종 방어입니다. 실제 relay와 실제 기기는 검증하지 못했습니다.

## SF-017 relay와 구독자에게 메시지 길이와 이 프로그램의 흔적이 그대로 보임

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/channel.rs`(`write_message`, `read_message`, 봉투 구성), `src/relay.rs`(구독 ID, 크기 한도)
- 발견: 서브에이전트의 프로토콜 리뷰가 지적했고 코드로 확인했습니다. (1) 암호문 길이가 메시지 길이를 한 바이트씩 그대로 따라갔습니다(98바이트 더 긴 메시지가 정확히 98바이트 더 긴 이벤트). (2) 모든 이벤트가 평문 고정 표지 `ADV2`로 시작했습니다. (3) 세션 태그 16바이트가 이벤트의 공개 `t` 태그와 봉투 본문에 **같은 값으로 두 번** 실렸습니다(`relay.rs`가 `hex(session_tag)`를 토픽으로 씀). (4) 구독 ID가 고정 접두사 `ad-v2-live`로 시작했습니다.
- 영향: 이 relay의 이벤트를 볼 수 있는 누구나(운영자뿐 아니라 같은 종류를 구독한 모두) ① 이 프로그램의 사용자임을 쉽게 식별하고 ② 메시지의 정확한 길이를 알 수 있었습니다. 짧은 응답("네", "아니오")이나 하트비트가 구별되었습니다.
- 수정(프로토콜 v3에 합류, 버전 올림 없음):
  1. 채팅 평문을 `[종류][역할][길이 u16][메시지][0 패딩]` 구조로 만들어 256, 1024, 4096, 8176바이트 중 하나가 되도록 채웁니다. 수신 측은 길이 필드로 메시지를 꺼내고, **허용된 크기가 아니거나 패딩이 0이 아니거나 길이가 넘치면 거부**합니다. 숨은 채널을 막기 위해서입니다.
  2. 봉투에서 `ADV2` 표지와 세션 태그를 뺐습니다. 봉투는 `[순번 8바이트][암호문]`입니다. 이벤트가 피어의 세션 키로 서명되고 토픽 태그가 맞아야 `receive`에 들어오고, 다른 세션의 프레임은 복호화되지 않으므로 인증은 약해지지 않습니다(테스트로 확인).
  3. 구독 ID를 접두사 없는 무작위 hex 32자로 바꿨습니다.
  4. `MAX_ENVELOPE`와 부트스트랩 프레임 한도를 채널의 상수에서 도출하게 해, 같은 값이 두 곳에 따로 있다가 어긋나지 않도록 했습니다.
- **구현 중 실제 버그를 하나 만들었다가 찾았습니다.** 패딩 후 최소 프레임이 272바이트인데 `MAX_BOOTSTRAP_FRAME`이 256으로 고정되어 있어서, 연락처 제안 단계에서 relay 테스트 6개가 `TimedOut("contact offer")`로 깨졌습니다. 시간 초과는 결과일 뿐 원인이 아니었고, 양쪽 오류를 찍어 보니 한쪽이 `InvalidEvent`(프레임이 한도 초과)였습니다. 한도를 패딩 정책에서 도출하도록 고쳤습니다.
- 회귀 테스트:
  - `messages_of_different_lengths_produce_envelopes_of_the_same_length`: 0~251바이트 메시지가 모두 같은 길이의 봉투가 되고 왕복한다. 패딩을 끄면 12개 테스트가 실패하는 것을 확인했습니다.
  - `padding_classes_are_the_documented_sizes_and_the_largest_message_fits`: 경계값(252→256, 253→1024, 1021→4096, 4093→8176), 최대 메시지가 봉투 한도를 정확히 채워 왕복, 한 바이트 초과는 전송 불가.
  - 수신 검증을 직접 건드리는 테스트(손으로 만든 위조 프레임): `padding_that_is_not_all_zeros_is_rejected`, `a_payload_size_outside_the_padding_classes_is_rejected`, `a_length_field_that_overruns_the_payload_is_rejected`, `a_frame_with_the_wrong_kind_or_the_wrong_sender_role_is_rejected`. 각 검증을 끄면 해당 테스트만 실패하는 것을 확인했습니다.
  - `a_frame_from_another_session_does_not_decrypt_and_ends_the_session`, `out_of_window_frames_are_rejected_without_closing_the_session`, `an_envelope_too_short_or_too_long_is_rejected`.
  - `subscription_ids_are_random_and_carry_no_program_marker`.
- 동작이 바뀐 점: 다른 세션의 프레임을 받으면 예전에는 "잘못된 태그"로 조용히 거부하고 세션이 이어졌지만, 이제는 복호화 실패로 **세션이 닫힙니다**. 그런 프레임을 만들 수 있는 것은 피어의 세션 키를 가진 피어 본인뿐이고 피어가 세션을 끊는 것은 어차피 가능하므로 새 위협은 아닙니다.
- 검토만 하고 하지 않은 것: 이벤트 본문을 hex 대신 base64로 바꾸는 것. 본문이 어차피 패딩된 크기 클래스로 고정되고(최대 약 16 KiB), hex는 디버깅이 쉬우며, 바꾸면 두 곳의 디코드 경로와 크기 한도를 모두 건드려야 해서 얻는 것에 비해 위험이 큽니다.
- 남은 노출(SECURITY.md의 "보장하지 않는 것"에 반영):
  - 길이는 네 크기 클래스까지만 가려집니다. 관찰자는 대략 어느 정도 길이인지는 압니다.
  - 순번이 평문이라 한쪽이 보낸 메시지 수가 보입니다.
  - 이벤트의 시각, 빈도, 방향은 그대로 보입니다.
  - **랑데부 단계의 "준비됐나요" 프레임은 여전히 평문 고정 접두사(`AD2-READY`)로 시작합니다.** Noise 핸드셰이크 이전이라 암호화되어 있지 않고, 이것을 없애려면 연결 흐름 자체를 바꿔야 해서 이번 범위에서 제외했습니다. 이 프레임을 읽을 수 있는 것은 초대 비밀에서 유도된 토픽을 구독한 쪽뿐입니다.
  - 핸드셰이크 메시지의 길이는 Noise 패턴 때문에 고정이라 식별될 수 있습니다.
  - IP 주소와 연결 시각은 Tor를 쓰지 않으면 relay에 보입니다.

## SF-016 메시지 하나가 유실되면 대화가 멈추고 결국 세션이 닫힘, 그리고 한 키로 모든 메시지를 보호

- 날짜: 2026-11-23
- 심각도: Medium (가용성), Low (키 수명)
- 위치: `src/channel.rs`의 `SessionTransport`, `src/relay.rs`의 `RelaySession::poll`, `src/main.rs`의 채팅 워커, 프런트엔드의 시스템 항목 처리
- 발견: 서브에이전트의 프로토콜 리뷰가 지적했고 **먼저 테스트로 재현했습니다.** relay 이벤트(kind 20000)는 휘발성이라 재전송되지 않습니다. 프레임 하나가 도착하지 않으면 `receive_sequence`가 그 자리에서 멈춰서, 그 뒤의 메시지는 한 개도 전달되지 않다가 32개가 쌓이면 `OutsideReorderWindow`로 세션이 닫혔습니다. 또한 한 세션의 모든 메시지가 키 하나로 보호되었습니다.
- 영향: 네트워크가 잠깐 끊기거나 relay가 이벤트 하나를 놓치면 사용자에게는 "상대가 말이 없다"로 보이다가 연결이 끊겼습니다. 어떤 메시지가 사라졌는지 알 길이 없었습니다.
- 수정(계획서의 안 A):
  1. 순번에 구멍이 생기면 이후 프레임을 보관하고, 10초(`GAP_TIMEOUT`) 지나도 안 메워지면 구멍을 건너뜁니다. 건너뛰려면 Noise 수신 nonce를 옮겨야 하는데, `snow`의 `set_receiving_nonce`로 그렇게 합니다. 건너뛴 프레임은 나중에 도착해도 이미 지나간 nonce라 버려서 **같은 (키, nonce)가 두 번 쓰이지 않습니다.**
  2. 건너뛰면 `RelayUpdate::MessagesLost`로 알리고, 앱은 대화 화면에 시스템 안내("상대가 보낸 메시지 N개가 도착하지 않았을 수 있습니다…")를 넣습니다. 이 안내는 연결의 일시적 사실이라 **기록에는 저장하지 않습니다.** 보관돼 있던 메시지를 먼저 전달하고 안내를 그다음에 한 번만 내보냅니다.
  3. 각 방향은 1,000개마다 키를 갱신합니다(Noise Rekey). 어느 키를 쓸지는 순번으로만 정해져서 구멍을 건너뛰어도 양쪽이 일치합니다.
  4. 프런트엔드는 "시스템 발신자" 판정을 한 함수로 모았고, 연결 안내의 접근성 레이블을 "연결 상태 안내"로 따로 둡니다(신원 변경 안내와 구분).
- **조사 중 틀린 가정을 바로잡았습니다.** 처음에는 순번이 곧 Noise nonce라고 가정하고 `set_receiving_nonce(순번)`을 썼는데, 순서가 바뀐 프레임을 받는 기존 테스트가 `Noise(Decrypt)`로 깨졌습니다. 측정해 보니 세션이 시작될 때 Noise 수신 nonce는 **3**이었습니다(핸드셰이크 뒤 신원 증명, 공개, 확인 프레임이 각각 nonce를 씀). 따라서 순번 `n`의 프레임은 nonce `3 + n`으로 암호화됩니다. 이 오프셋은 프로토콜 단계 수에 따라 달라지므로 하드코딩하지 않고 세션 시작 시점의 수신 nonce를 기준(`receive_base_nonce`)으로 저장합니다.
- 회귀 테스트:
  - `a_lost_frame_stops_delivery_only_until_the_gap_times_out`, `a_skipped_frame_that_arrives_late_is_ignored_and_cannot_be_replayed`, `a_gap_that_fills_in_time_is_not_skipped_and_nothing_is_reported_lost`, `several_separate_losses_are_each_counted`.
  - 키 갱신: `frames_keep_flowing_across_many_key_changes`, `a_hole_that_spans_a_key_change_is_crossed_with_the_right_key`, `the_real_key_change_interval_is_crossed_without_a_problem`(실제 간격 1,000을 넘겨 1,005개 송수신), `a_key_change_means_old_ciphertext_does_not_open_with_the_new_key`.
  - 세션 수준: `a_hole_that_never_fills_is_reported_as_lost_messages_after_the_delivered_ones`(메시지가 먼저, 알림이 그다음에 한 번), `a_gap_that_fills_in_time_reports_nothing_lost`.
  - 프런트엔드: 연결 안내가 시스템 항목처럼 보이고 접근성 레이블이 "연결 상태 안내"이며 서명 없음 표지가 붙지 않는다.
  - nonce 기준을 잊게 하거나, 키 갱신을 한쪽이라도 빼거나, 시간 초과를 없애거나, 알림을 빼거나 순서를 바꾸면 각각 해당 테스트가 실패하는 것을 확인했습니다(변이 검사 7건, 프런트엔드 3건).
- 이 작업에서 **테스트 환경의 빈틈도 하나 메웠습니다.** 가짜 DOM의 `setAttribute`가 아무것도 저장하지 않는 빈 함수여서 지금까지 어떤 테스트도 `aria-label`을 검증하지 못했습니다. 속성을 저장하고 읽게 만들어 기존 테스트 137개가 그대로 통과함을 확인한 뒤, 접근성 레이블 테스트를 추가했습니다.
- 남은 한계:
  - **유실된 메시지는 복구되지 않습니다.** 재전송이나 수신 확인(안 B)은 만들지 않았습니다. 사용자에게 알릴 뿐이고, 보낸 사람은 상대가 놓쳤다는 것을 알 수 없습니다.
  - 건너뛸 수 있는 구멍은 32프레임까지입니다. 그보다 크게 건너뛴 프레임이 오면 여전히 세션이 닫힙니다.
  - 10초라는 시간과 1,000개라는 간격은 제가 정한 값입니다(`GAP_TIMEOUT`, `REKEY_INTERVAL`).
  - **실제 relay에서의 유실은 확인하지 못했습니다.** 가짜 relay로 프레임 하나를 발행하지 않는 방식으로 재현했을 뿐입니다.
  - 유실 안내의 문구와 위치(대화 목록 안)는 화면에서 직접 보지 못했고 JS 테스트까지만 확인했습니다.
  - 키 갱신으로 순방향 비밀성이 생기는 것은 아닙니다. 새 키는 이전 키에서 유도되므로, 키 하나가 유출되면 이후 키는 계산할 수 있습니다. 한 키가 보호하는 메시지 수를 줄이는 효과뿐입니다.
  - 상대가 키 갱신을 하지 않는 이전 판이었다면 맞지 않겠지만, 이 판(v3)은 아직 한 번도 배포되지 않았으므로 호환성 문제는 없습니다.

## SF-015 Tor 모드에서 모든 relay 연결이 같은 회로를 공유할 수 있었음

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/relay.rs`의 `connect_socks5`
- 발견: 서브에이전트의 프로토콜 리뷰가 지적했고 코드로 확인했습니다. SOCKS5 협상이 "인증 없음"(메서드 0)만 제안했습니다. Tor는 SOCKS 사용자 이름과 비밀번호가 서로 다른 스트림을 서로 다른 회로에 올리는데(`IsolateSOCKSAuth`), 자격 증명을 보내지 않으니 모든 스트림이 같은 회로를 쓸 수 있었습니다.
- 영향: 여러 relay에 대한 연결과 랑데부, 세션이 같은 회로를 지나면 Tor 출구나 중간 노드가 이들을 한 사용자의 활동으로 묶기 쉽습니다. 더 직접적으로는, 프록시가 인증을 요구하도록 설정되어 있으면 **옛 코드는 아예 연결하지 못했습니다**("no-authentication mode를 거부했다"). 테스트로 확인했습니다.
- 수정: 메서드 목록을 `[0, 2]`(인증 없음, 사용자 이름/비밀번호)로 제안합니다. 프록시가 2를 고르면 RFC 1929에 따라 **연결마다 새로 만든 무작위 자격 증명**(사용자 이름과 비밀번호 각 16바이트 hex)을 보내고, 0을 고르면 그대로 진행합니다. 프록시가 0xff(수용 불가)이거나 제안하지 않은 메서드를 고르면 실패하며 **직접 연결로 우회하지 않습니다**(기존 원칙 유지). 비밀번호 버퍼는 `Zeroizing`입니다.
- 회귀 테스트:
  - `socks_connection_offers_username_authentication_so_tor_can_isolate_circuits`: 메서드 2를 제안하고 무작위 자격 증명을 보낸다. 옛 코드에서 실패하는 것을 먼저 확인했습니다.
  - `every_socks_connection_uses_credentials_of_its_own`: 연결마다 자격 증명이 다르다. 항상 같은 값으로 바꾸면 실패하는 것을 확인했습니다.
  - `a_proxy_that_needs_no_authentication_still_works_and_gets_no_credentials`, `a_proxy_that_accepts_none_of_our_methods_is_an_error_not_a_direct_connection`, `a_proxy_that_rejects_the_credentials_is_an_error`, 기존의 `socks_proxy_failure_never_falls_back_to_direct_relay_connection`(새 협상에 맞게 고침).
- **증명하지 못한 것:** "relay별·세션별로 실제로 다른 회로를 쓴다"는 최종 효과입니다. 그것은 사용자의 Tor가 `IsolateSOCKSAuth`를 켠 상태에서 자격 증명에 따라 회로를 나누는 동작이며, Tor 데몬 없이는 관찰할 수 없습니다. 테스트가 보장하는 것은 "연결마다 서로 다른 무작위 자격 증명을 RFC 1929대로 보낸다"까지입니다.
- 남은 한계:
  - 격리는 사용자의 Tor 설정에 달려 있습니다. 앱은 프록시가 Tor인지도, 격리가 켜져 있는지도 확인하지 않습니다(README에 이미 적은 한계).
  - 같은 연결 안의 모든 트래픽은 당연히 한 회로입니다. 세션 하나가 쓰는 여러 relay는 서로 다른 회로로 가지만, 한 relay와의 연결은 그 세션 내내 같은 회로입니다.
  - 인증을 요구하지 않는 일반 SOCKS 프록시에서는 아무 자격 증명도 보내지 않으므로 격리와 무관합니다.
  - 기존 테스트의 낡은 인사말 단언을 고치다가, 한 번은 같은 블록이 두 테스트에 있어서 스크립트가 아무것도 적용하지 않고 멈췄습니다. 적용되지 않은 것을 확인한 뒤 순서를 바꿔 다시 했습니다.

## SF-014 비밀이 지워지지 않는 임시 문자열로 남던 곳과 relay 수락 문구의 무방비

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/relay.rs`(초대 코드 표시를 만드는 `from_secret`), `src/channel.rs`(공개 전 무작위 값), `web/app.js`(relay 수락 문구)
- 발견: 코드 리뷰와 서브에이전트 리뷰를 코드로 확인했습니다.
  - 초대 코드 표시를 만들 때 이미 `Zeroizing`인 문자열에 `push_str(&hex(시크릿))`로 붙였는데, 그 **임시 `hex(...)` 결과가 지워지지 않고 해제**되었습니다. 이 임시 문자열이 초대 비밀 전체를 담고 있었습니다.
  - 2.12에서 추가한 공개 전 무작위 값의 평문 프레임이 일반 `Vec`이었습니다.
  - 리뷰는 "relay 수락이 UI에서 전달처럼 보인다"고 했지만, **실제 화면 문구는 이미 "relay가 이벤트를 수락했습니다. 상대방의 수신이나 저장을 뜻하지 않습니다."로 정확했습니다.** 다만 그 문구를 지키는 테스트는 하나도 없었습니다.
- 영향: 힙에 남은 비밀은 이후 메모리 덤프나 스왑에서 읽힐 수 있습니다(엔드포인트가 이미 침해된 경우의 이야기). 문구는 영향 없음, 회귀 위험만 있었습니다.
- 수정:
  - `push_secret_hex`로 비밀의 hex를 지워지는 문자열에 직접 씁니다. 임시 문자열을 만들지 않습니다.
  - 공개 전 무작위 값의 평문 프레임을 `Zeroizing`으로 바꿨습니다. 이미 `Zeroizing`이라서 중복이던 `fill(0)`과 불필요한 `mut`을 지웠습니다.
  - 문구는 바꾸지 않고, 네 가지 상태(수락, 대기, 거부, 불명)의 문구가 수신을 뜻하지 않는다는 구분을 지키도록 테스트로 고정했습니다.
  - `random_hex`는 건드리지 않았습니다. 이 값은 이벤트 태그로 **네트워크에 공개되는 값**이라 비밀이 아니고, 지우면 무엇이 비밀인지가 흐려집니다.
- 회귀 테스트:
  - `secret_hex_is_the_same_text_as_the_ordinary_hex`, `an_invite_code_still_round_trips_after_the_display_is_built_without_a_temporary`: 동작이 바뀌지 않았음을 확인한다.
  - JS `a_relay_acceptance_is_never_worded_as_the_peer_having_received_the_message`: 수락 문구를 "전달되었습니다"로 바꾸면 실패하는 것을 확인했습니다.
- **증명하지 못한 것:** 제로화가 실제로 일어났는지는 테스트하지 못했습니다. 해제된 힙 메모리를 안전하게 검사할 방법이 없어서, 위 테스트는 "동작이 같다"만 보장하고 "지워진다"는 코드 구조(임시 문자열이 없다)로만 보장합니다.
- 남은 한계(의도적으로 하지 않은 것):
  - 복호화된 메시지 본문(`Vec<u8>`, `StoredMessage.text`)은 지우지 않습니다. 화면에 표시되고 기록 검색에 쓰이는 데이터라 전부 지우면 비용이 크고 효과가 작습니다.
  - 라이브러리 안의 키(`nostr`의 `Keys` 등)는 지울 수 없습니다.
  - 스택에 복사된 키 값은 지워지지 않을 수 있습니다.
  - 비밀번호는 요청 처리 중 `Zeroizing<String>`으로 들고 있다가 `&str`로 넘기며, 그 안에서 키 유도에 쓰는 복사본은 별도로 지우지 않습니다.

## SF-013 레거시 백업을 읽을 때 파일 크기 상한이 우회되고 파이프에서 멈춤

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/history.rs`의 레거시(메모리 기반) 백업을 읽는 세 곳: 가져오기, 검증, 재보호
- 발견: 코드 리뷰에서 세 곳이 모두 `metadata().len()`으로 크기를 확인한 뒤 그 길이만큼 미리 할당하고 `read_to_end`로 읽는다는 점을 확인했습니다.
- 영향: 메타데이터의 길이는 믿을 수 없습니다. FIFO나 장치 파일은 길이 0으로 보여 검사를 통과하고, 이후 읽기가 데이터가 끝나기를 기다리며 **영원히 멈추거나**(앱의 파일 선택은 사용자가 고르므로 FIFO를 고를 가능성은 낮지만 같은 기기의 다른 프로세스가 만들 수 있음) 쓰는 쪽이 계속 보내면 메모리를 무한히 씁니다. 검사 이후에 커지는 파일도 상한을 넘을 수 있었습니다. 이 가운데 FIFO에서 멈추는 것은 테스트로 확인했습니다.
- 수정: 세 곳을 `read_legacy_backup` 하나로 합쳤습니다. 일반 파일이 아니면 읽기 전에 거부하고, 읽기 자체를 `상한 + 1`바이트로 제한해서 넘으면 이미 읽은 내용을 지우고 거부합니다. 길이를 믿고 미리 할당하지 않습니다.
- 회귀 테스트:
  - `a_legacy_backup_that_is_not_a_regular_file_is_refused_before_it_is_read`: FIFO를 거부한다. 읽기가 멈추면 멈춤이 아니라 5초 뒤 "the read must not block on a pipe"로 실패한다. 옛 방식으로 되돌리면 정확히 그렇게 실패하는 것을 확인했습니다.
  - `a_legacy_backup_is_read_up_to_the_limit_and_not_one_byte_more`: 16 MiB는 읽고 1바이트 초과는 거부한다. **이 테스트는 옛 방식에서도 통과합니다.** 일반 파일은 메타데이터 길이가 정확하기 때문이며, 회귀 방지용으로만 의미가 있습니다.
  - `importing_verifying_and_reprotecting_all_refuse_an_oversized_legacy_file`: 세 경로가 모두 같은 거부를 하고 재보호는 아무것도 쓰지 않는다.
- 계획과 달랐던 점: 계획서의 "메시지 개수 상한도 추가"는 이미 있었습니다. 디코더가 `count > 1_000_000`이거나 페이로드가 그 수를 담을 수 없으면(`count > (길이-36)/13`) 거부하므로 새로 만들지 않았습니다.
- 남은 한계: 상한 이하의 파일이 읽는 도중 같은 크기로 바뀌는 경쟁(TOCTOU)은 막지 않습니다. 스트리밍 형식(ADBACK6·7, ADPACK2·3)은 이 경로를 쓰지 않고 프레임 단위로 검사합니다.

## SF-012 코드를 비교하는 사람의 시간이 프로토콜 타임아웃에 묶여 있음

- 날짜: 2026-11-23
- 심각도: Low-Medium (사용성, 보안 확인을 포기하게 만드는 쪽으로 작용)
- 위치: `src/relay.rs`의 `RelayRendezvous::confirm`, `confirm_with_contact`, `src/main.rs`의 확인 대기 루프
- 발견: 코드를 읽다가 두 가지를 확인했습니다. 첫째, 내가 확인을 누른 뒤 상대의 확인 프레임을 기다리는 제한이 프로토콜 전체의 30초(`RENDEZVOUS_TIMEOUT`)였습니다. 둘째, 사람이 코드를 비교하는 동안 메인 루프가 relay 소켓을 읽지 않아 relay의 ping에 응답하지 않았습니다. **첫째는 테스트로 먼저 재현했습니다.** 가짜 relay에서 한 사람은 즉시, 다른 사람은 프로토콜 타임아웃(4초로 줄임)보다 늦게(6초) 확인하게 하자, 먼저 확인한 쪽이 `TimedOut("peer confirmation")`으로 실패했습니다.
- 영향: 전화로 12자리를 맞춰 보며 각자 누르는 시간이 30초를 넘으면 먼저 누른 쪽 연결이 실패하고 처음부터 다시 해야 했습니다. 확인 절차가 불편하면 사용자는 코드를 대충 비교하게 되므로 보안에도 불리합니다.
- 수정:
  1. 상대의 확인을 기다리는 제한을 프로토콜 타임아웃과 분리해 5분으로 했습니다(`CONFIRMATION_TIMEOUT`).
  2. 내가 코드를 비교하는 동안에도 최대 5분 제한을 두고, 그동안 `keep_alive()`로 relay 연결에 응답합니다. 그 사이 도착한 프레임(예: 상대의 확인)은 버리지 않고 도착 순서대로 보관했다가 `receive_frame`이 먼저 꺼냅니다.
- 회귀 테스트:
  - `a_user_who_confirms_much_later_than_the_peer_does_not_make_the_peer_time_out`: 수정 전 실패, 수정 후 통과.
  - `waiting_for_the_other_person_ends_at_the_confirmation_limit`: 대기는 길지만 무한하지 않고, 프로토콜 타임아웃이 아닌 확인 제한을 쓴다.
  - `frames_that_arrive_while_a_person_decides_are_kept_in_order`, `both_users_taking_a_long_time_to_confirm_still_connect`.
  - 보관함이 프레임을 버리게 하거나, 대기를 다시 프로토콜 타임아웃에 묶으면 해당 테스트가 실패하는 것을 확인했습니다.
- 남은 한계:
  - **`keep_alive`가 실제 relay에서 연결을 유지하는 데 필요한지는 확인하지 못했습니다.** `keep_alive`를 아무것도 안 하게 바꿔도 위 테스트가 통과합니다. 테스트가 쓰는 가짜 relay가 ping을 보내지 않고 응답이 없다고 연결을 끊지도 않기 때문입니다. 비용이 거의 없는 방어라서 유지했지만, 효과는 실제 relay에서만 볼 수 있습니다. 무시된 수동 테스트 `live_relay_two_party_channel_roundtrip`에 `AD_LIVE_CONFIRM_PAUSE_SECS`(확인 전 대기 초)를 줄 수 있게 해 두었습니다.
  - 확인 대기 루프 한 번이 relay 수에 비례해 길어질 수 있습니다(relay 읽기 제한 250ms × relay 수). 3개면 약 1초이며, 이는 측정이 아니라 계산한 값입니다. "확인"이나 "취소"를 누른 뒤 반응이 그만큼 늦을 수 있습니다.
  - 화면에는 "상대를 기다리는 중" 같은 대기 안내가 이전 그대로입니다. 최대 5분이라는 한도를 화면에서 알려 주지는 않습니다.
  - 확인 시간이 지나면 연결을 닫고 새 초대 코드로 다시 시작하게 합니다.

## SF-011 사람이 비교하는 지문을 조작할 수 있었고 64자리 전체를 비교하기도 어려웠음

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/channel.rs`(`fingerprint`, 신원 증명 교환), `src/relay.rs`(`authenticate`), 확인 화면
- 발견: 서브에이전트의 프로토콜 리뷰가 지적했고 코드로 확인했습니다. 두 사람이 비교하는 값은 핸드셰이크 해시와 두 신원 키의 해시였습니다. 이 값을 만드는 데 양쪽이 나중에 고를 수 있는 입력(핸드셰이크 키, 신원 키)이 모두 들어가고 사전에 그 입력을 약속(commit)하는 단계가 없었습니다. 화면에는 64자리 hex 전체가 표시되었습니다.
- 영향: 사람은 64자리를 끝까지 비교하지 않고 앞 몇 글자만 맞춰 보기 쉽습니다. 초대 코드를 아는 중간자는 두 연결의 키를 바꿔 가며 앞 8자리가 같아지는 조합을 찾을 수 있었습니다(약 2^32회). 사람이 비교한 앞부분이 일치해도 실제로는 다른 상대와 연결된 셈입니다.
- 수정(프로토콜 3판):
  1. **무작위 값의 커밋과 공개.** 각 쪽이 16바이트 무작위 값을 만들고 그 값의 해시(커밋)를 신원 증명에 실어 보냅니다. 커밋도 신원 키로 서명하는 입력에 포함되어 전송 중에 바꿀 수 없습니다. 상대의 커밋을 받은 **뒤에야** 자신의 값을 공개하고, 받은 값이 커밋과 다르면 `CommitmentMismatch`로 거부합니다. 중간자는 두 연결에서 자신의 값을 상대 값을 보기 전에 고정해야 하므로 두 코드를 맞출 수 없습니다.
  2. **확인 코드.** 지문에 두 값을 넣고, 거기서 12자리 숫자(6자리 두 그룹, 약 40비트)를 뽑아 크게 보여 줍니다. 안내문은 12자리를 처음부터 끝까지 비교하라고 명시하고, 공개 키와 전체 지문은 접어 두었습니다.
  3. Noise 프롤로그와 서명 도메인을 v3으로 올렸습니다. 이전 판 상대와는 핸드셰이크가 실패합니다.
- 회귀 테스트:
  - `a_value_that_does_not_open_the_commitment_is_rejected`: 커밋과 맞지 않는 공개 값은 거부된다.
  - `the_commitment_is_signed_with_the_identity_so_it_cannot_be_swapped`: 서명한 커밋은 통과하고 바꾼 커밋은 거부된다.
  - `the_code_depends_on_both_random_values_and_on_the_transcript`, `both_users_see_the_same_short_code_in_two_groups_of_six_digits`, `the_code_uses_the_whole_twelve_digit_range_not_a_smaller_one`.
  - `a_reveal_from_the_wrong_role_or_of_the_wrong_size_is_rejected`, `a_peer_on_protocol_version_two_cannot_complete_the_handshake`.
  - 프런트엔드: 코드가 가장 눈에 띄는 값이고 긴 식별자는 접혀 있으며, 서버가 준 코드를 그대로 보여 주고, 코드가 없으면 비워 둔다.
  - 커밋 검사를 끄거나, 한쪽 값을 지문에서 빼거나, 커밋을 서명 입력에서 빼면 해당 테스트가 실패하는 것을 확인했습니다. **코드 범위를 좁히는 변이는 처음에는 테스트를 통과했습니다.** 코드가 실제로 12자리 범위를 쓰는지 보지 않았기 때문이며, 범위 테스트를 추가한 뒤에야 잡힙니다.
- 남은 한계:
  - **코드는 약 40비트의 추측 방지입니다.** 초대 코드를 아는 중간자는 한 번의 시도에서 2^-40의 확률로 성공하고 다시 시도할 수 있습니다. 시도마다 새 연결이 필요하고 사용자는 서로 다른 코드를 보게 됩니다.
  - **초대 코드가 새면 이 보호는 한 층 약해집니다.** 초대 코드 없이는 중간자가 랑데부에 참여할 수 없다는 가정에 기대고 있습니다.
  - 이전 판 상대와의 불일치는 일반적인 핸드셰이크 실패로 보이며 화면은 그 원인을 구분하지 못합니다.
  - 재연결(저장된 상대 키를 고정하는 경우)은 코드를 보여 주지 않고 같은 교환을 거치기만 합니다.
  - 실제 두 기기와 실제 relay에서의 연결은 이 환경에서 확인하지 못했습니다. 가짜 relay 테스트까지만 통과했습니다.

## SF-010 하나의 키를 여러 용도에 겹쳐 쓰던 저장 계층

- 날짜: 2026-11-23
- 심각도: Low-Medium
- 위치: `src/history.rs`(대화 인덱스, 연결 키 저장소), `src/contacts.rs`(연락처 레코드와 백업)
- 발견: 코드 리뷰에서 한 키가 둘 이상의 서로 다른 용도에 쓰이는 곳을 확인했습니다. 대화 인덱스를 암호화하는 키가 대화 파일 이름을 만드는 HMAC 키와 같았고, 연락처의 키는 파일 이름 HMAC, 레코드 암호화, 백업 암호화에 모두 쓰였으며, 연결 키 저장소는 대화 로그와 같은 저장 키를 그대로 썼습니다.
- 영향: 지금 당장 악용 가능한 취약점은 아닙니다. 서로 다른 AAD와 형식이 혼동을 막고 있었지만 그것은 우연히 성립한 보호였고, 한 용도의 약점(예: nonce 재사용, 파일 이름 길이 노출)이 다른 용도에 번질 수 있었습니다. 형식이 늘어날수록 깨지기 쉬운 구조입니다.
- 수정: `identity::purpose_key()`로 용도마다 HKDF 라벨이 다른 키를 만듭니다.
  - 인덱스: `ADIDX2`, 라벨 `history-index-aead/v2`
  - 연결 키 저장소: `ADLKEY2`, 라벨 `linked-keys-aead/v2`
  - 연락처 레코드: `ADPEER2`, 라벨 `verified-contact-record-aead/v2`
  - 연락처 백업: `ADCONB2`, 라벨 `contact-backup-aead/v2`
  **기존 데이터는 그대로 열립니다.** 읽기는 이전 형식(ADIDX1, ADLKEY1, ADPEER1, ADCONB1)을 계속 지원하고, 쓰기는 항상 새 형식이라서 다음에 쓸 때 자연스럽게 새 형식으로 옮겨 갑니다.
  **파일 이름을 만드는 HMAC 키는 일부러 바꾸지 않았습니다.** 바꾸면 기존 파일을 찾을 수 없고, 이름 변경을 전부 마이그레이션해야 합니다. 이 키는 이제 이름 용도로만 쓰입니다.
- 회귀 테스트:
  - 이전 형식 호환: `an_index_from_the_previous_version_still_lists_conversations_and_is_upgraded_on_write`, `a_linked_key_store_from_the_previous_version_still_reads_and_is_upgraded_on_write`, `a_record_written_by_the_previous_version_still_loads_and_is_upgraded_on_rewrite`, `a_backup_from_the_previous_version_still_imports_and_new_backups_use_their_own_key`. 이전 코드가 만들던 바이트를 테스트에서 직접 재현해 읽고, 다시 쓰면 새 형식이 되는지 확인합니다.
  - 키 분리: `a_new_index_is_not_encrypted_with_the_key_that_names_files`, `a_new_record_is_not_encrypted_with_the_filename_key`와 위 백업 테스트. 새 데이터가 이전 키(파일 이름 키, 저장 키, 다른 용도의 키)로 열리지 않음을 확인합니다.
  - 형식을 이전 것으로 되돌리거나, 이전 형식 읽기를 막거나, 키를 겹치게 하면 각각 해당 테스트가 실패하는 것을 확인했습니다(변이 검사 4건).
- 남은 한계:
  - **대화 로그 레코드는 아직 원시 저장 키를 씁니다.** 로그 형식(ADLOG)을 바꾸는 일은 세대 id와 끝 표시를 넣는 로그 변조 탐지 작업과 같은 형식 버전업으로 묶는 편이 낫기 때문입니다(계획의 3.6). 그 전까지 저장 키를 직접 쓰는 곳은 로그 레코드뿐입니다.
  - 백업 키(ADBACK 계열)와 복원 스테이징 키는 이미 용도별 라벨을 쓰고 있어서 이번에 바꾸지 않았습니다.
  - 이전 형식의 파일은 다시 쓰이기 전까지 이전 키로 남아 있습니다. 읽기만 하는 파일은 옮겨지지 않습니다.
  - 이전 형식 읽기를 언제 없앨지는 정하지 않았습니다. 없애면 오래된 데이터를 열 수 없게 됩니다.

## SF-009 접속 코드 설명이 암호화로 보호되는 것처럼 읽힘

- 날짜: 2026-11-23
- 심각도: Low (문서)
- 위치: `src/identity.rs`의 주석, `docs/adr/0003-access-code-format.md`
- 발견: AD2 코드는 래핑 키를 같은 코드 안에 함께 담아서, 암호화가 기밀성을 더하지 않습니다. 그런데 코드 주석은 "encrypted seed envelope"라고만 적어 보호를 주는 것처럼 읽혔습니다.
- 영향: 이 코드를 별도로 안전하게 보관해야 하는 비밀이 아니라 "암호화된 파일"로 오해하면, 코드가 노출됐을 때의 위험을 낮게 볼 수 있습니다.
- 수정: 형식(`AD1-`은 시드를 평문으로, `AD2-`는 코드 안의 키로 감싼 형태)과 효과(코드마다 다른 문자열이 나올 뿐)를 `identity.rs`에 정확히 적고, SECURITY.md와 ADR 0003의 설명과 맞췄습니다. 형식은 기존 코드와의 호환을 위해 바꾸지 않았습니다.
- 회귀 테스트: `a_code_is_the_whole_secret_and_codes_for_one_identity_cannot_be_told_apart_by_it`(코드에 래핑 키가 들어 있고 같은 신원의 코드가 서로 다른 문자열이다)와 `a_legacy_code_holds_the_seed_in_the_clear_and_still_restores_the_identity`. 코드가 다른 비밀을 요구하도록 바뀌면 이 테스트가 실패하므로 문서도 함께 바꿔야 합니다.
- 남은 한계: 코드 노출은 곧 신원 노출입니다. 개별 코드를 폐기할 수 없습니다. 사용자 비밀번호로 코드를 보호하는 기능은 이번 범위에 넣지 않았습니다.

## SF-008 릴리스 빌드가 빌드한 기기의 절대 경로에 데이터를 저장함

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/history.rs`의 `data_directory()`
- 발견: 코드 리뷰에서 macOS 빌드가 `env!("CARGO_MANIFEST_DIR")/chat-data`를 반환한다는 점을 확인했습니다. 이 값은 컴파일 시점에 바이너리에 박힙니다. 환경 변수 `ANOTHER_DIMENSION_DATA_DIR`는 디버그 빌드에서만 읽혔고, 값에 대한 검사는 "절대 경로"뿐이었습니다.
- 영향: 다른 기기에서 빌드한 릴리스 바이너리는 존재하지 않는 경로나 빌더의 소스 트리에 비밀을 쓰려 했고, 그 위치의 소유자와 권한을 확인하지 않았습니다. 환경 변수로 `$HOME` 같은 공유 디렉터리를 가리킬 수도 있었습니다.
- 수정:
  1. macOS 릴리스 빌드는 `~/Library/Application Support/Another Dimension v2/`를 씁니다. 디버그 빌드는 개발 편의를 위해 소스 트리의 `chat-data/`를 그대로 씁니다.
  2. `ANOTHER_DIMENSION_DATA_DIR`는 모든 빌드에서 읽되, 절대 경로이고 `..`가 없고 심볼릭 링크가 아니며, 이미 있다면 내 소유이고 그룹·타인 접근이 불가능한(`chmod 700`) 디렉터리일 때만 받습니다. 맞지 않으면 **권한을 바꾸지 않고** 거부합니다. 공유 디렉터리의 권한을 조용히 바꾸면 사용자를 자기 폴더에서 잠그기 때문입니다.
  3. 시작할 때 데이터 위치를 터미널에 출력하고, 옛 위치(소스 트리의 `chat-data/`)에 데이터가 남아 있으면 경고합니다. 데이터를 자동으로 옮기지는 않습니다.
- 회귀 테스트:
  - `macos_data_directory_depends_on_the_build_and_never_on_the_build_machine`: 릴리스 경로는 빌더의 소스 경로 아래에 있지 않다.
  - `a_user_chosen_data_directory_must_be_safe_for_secrets`: 상대 경로, `..`, 심볼릭 링크, 일반 파일, 0750/0755/0707/0777 디렉터리를 거부하고 거부된 디렉터리의 권한을 바꾸지 않으며, 없는 경로와 0700 디렉터리는 받는다.
  - `legacy_data_is_reported_but_never_moved`: 경고는 보고만 하고 데이터를 옮기지 않는다.
  - 릴리스 경로, 권한 검사, 심볼릭 링크 검사, `..` 검사를 각각 빼면 해당 테스트가 실패하는 것을 확인했습니다.
- 남은 한계:
  - **동작이 바뀝니다.** 이전에 `cargo run --release`로 저장소의 `chat-data/`를 쓰던 사용자는 릴리스 빌드에서 그 데이터가 보이지 않습니다. README에 이전 방법과 한 줄 명령을 적었고, 시작할 때 경고가 나옵니다. 이 기본값은 사용자 확인 없이 계획서의 제안을 적용한 것입니다.
  - 소유자 확인은 다른 사용자 소유 디렉터리를 만들어 테스트하기 어려워(권한이 필요) 코드 검토로만 확인했습니다.
  - 검사와 사용 사이에 디렉터리가 바뀌는 경쟁(TOCTOU)은 막지 않습니다. 같은 사용자 권한의 공격자는 범위 밖입니다.
  - 검사는 Unix에서만 소유자와 권한을 봅니다.

## SF-007 비공개 파일의 생성 시점 권한과 rename 뒤의 디렉터리 동기화

- 날짜: 2026-11-23
- 심각도: Low (권한), Medium (내구성)
- 위치: `src/history.rs`, `src/contacts.rs`, `src/identity.rs`, `src/main.rs`의 파일 생성·교체 지점(`OpenOptions` 30곳, 디렉터리 생성 11곳, rename 13곳)
- 발견: 코드 리뷰에서 두 가지를 확인했습니다. 첫째, 대부분의 파일이 기본 umask로 만들어진 **뒤에** `set_private_file`로 권한을 줄여서, 그 사이에는 다른 사용자가 읽을 수 있는 상태였습니다(연락처와 신원 계보 파일만 생성 시 0600을 줬습니다). 둘째, 임시 파일을 쓰고 `sync_all` 한 다음 `rename` 했지만, 디렉터리 항목을 디스크에 내리지 않았습니다.
- 영향:
  - 권한: 데이터 디렉터리가 0700이라 실제 노출은 작았지만, 디렉터리가 느슨해지는 경우를 가정하면 비밀을 담은 파일이 잠깐 읽힐 수 있었습니다. 데이터 루트(`chat-data/`)는 기본 권한으로 만들어졌습니다.
  - 내구성: 충돌이나 정전이 나면 성공으로 보고된 교체, 삭제, 복원이 사라지거나 인덱스와 대화 파일이 어긋날 수 있었습니다.
- 수정: `src/fsutil.rs`에 공용 도우미를 만들고 운영 코드가 이것만 쓰도록 했습니다.
  1. `private_options()`: 생성 시점에 모드 0600을 줍니다.
  2. `create_private_dir_all()`: 새로 만드는 모든 디렉터리(없는 상위 포함)를 0700으로 만듭니다.
  3. `rename_durable()`: rename 뒤에 바뀐 디렉터리를 동기화합니다. `sync_parent()`는 `hard_link`로 만든 항목에 같은 일을 합니다. macOS에서는 표준 라이브러리의 `sync_all`이 `F_FULLFSYNC`를 사용합니다.
  디렉터리 동기화가 실패하면 로그만 남깁니다. 그 시점에 rename은 이미 일어났으므로, 오류를 돌려주면 호출자가 이미 바뀐 상태를 되돌리려고 해서 더 나빠집니다.
- 회귀 테스트:
  - `fsutil::tests::files_are_private_from_the_moment_they_are_created`: 느슨한 umask에서 일반 `OpenOptions`는 0666이 되고 `private_options`는 0600이다.
  - `fsutil::tests::every_missing_directory_is_private`: 없는 상위 디렉터리까지 모두 0700이다.
  - `fsutil::tests::production_code_creates_and_replaces_files_through_the_helpers`: 운영 코드가 `OpenOptions::new()`, `create_dir_all`, `rename`을 직접 쓰면 실패한다. 한 곳에서 일부러 되돌려 보면 실패하는 것을 확인했습니다.
  - rename 관련 단위 테스트(대상 덮어쓰기, 디렉터리 간 이동, 없는 원본은 오류이고 대상 보존, `sync_parent`는 호출자를 실패시키지 않음).
  - `history::tests::everything_written_for_an_identity_ends_up_owner_only_under_a_permissive_umask`와 설정 파일 테스트: 신원 데이터를 만드는 실제 경로를 느슨한 umask에서 실행하고, 결과 파일은 0600, 디렉터리는 0700임을 확인합니다.
- 남은 한계:
  - 위 통합 테스트는 **최종 상태만** 봅니다. 코드가 생성 직후 `set_private_file`을 다시 호출하는 곳이 남아 있어서, 헬퍼가 망가져도 이 테스트는 통과합니다(일부러 0644로 바꿔 보고 확인했습니다). 생성 시점의 보장은 헬퍼 단위 테스트와 소스 가드 테스트가 맡습니다.
  - 새로 만든 파일이나 디렉터리의 항목 자체(rename이나 hard_link를 거치지 않는 첫 생성)는 동기화하지 않습니다. 충돌이 나면 막 만든 대화 로그와 첫 레코드가 함께 사라질 수 있습니다.
  - 디렉터리 동기화는 Unix에서만 합니다.
  - 이미 존재하던 파일의 권한은 `set_private_file`이 계속 담당합니다.

## SF-006 난수를 장치 파일에서 직접 읽던 18곳

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/` 전반(키, nonce, salt, 토큰, 초대 비밀을 만드는 18곳)
- 발견: 코드 리뷰에서 모든 곳이 `File::open("/dev/urandom")`을 직접 열고 있다는 점을 확인했습니다.
- 영향: 보안 결함이라기보다 견고성 문제입니다. 소스가 Windows 분기를 갖고 있는데도 그곳에서는 모든 키 생성이 실패했고, nonce 하나를 만들 때마다 파일 디스크립터를 열었으며(열기 실패가 곧 암호화 실패), 난수를 얻는 방식이 18곳에 흩어져 있어 한 번에 점검할 수 없었습니다.
- 수정: `src/random.rs`의 `fill()` 하나로 통일하고 운영체제 난수 API(`getrandom`)를 씁니다. `getrandom`은 이미 `snow`가 쓰던 0.3.4와 같은 버전을 정확히 고정했으므로 새 크레이트는 늘지 않았습니다(`Cargo.lock`에 직접 의존성 한 줄).
- 회귀 테스트:
  - `random::tests::no_module_opens_the_random_device_directly`: 어느 모듈에도 장치 파일 경로가 다시 나타나지 않는다. 일부러 넣어 보면 실패하는 것을 확인했습니다.
  - `random::tests`의 나머지 둘: 버퍼 전체가 채워지고 호출마다 다르며, 빈 버퍼도 처리한다.
- 남은 한계: 암호학적으로 안전한 난수의 질은 운영체제에 맡깁니다. 이전과 같은 신뢰 가정입니다.

## SF-005 응답 헤더 보강과 오류 응답의 경로 노출

- 날짜: 2026-11-23
- 심각도: Low
- 위치: `src/main.rs`의 `respond()`, 오류를 응답 본문으로 보내는 약 11곳
- 발견: 코드 리뷰에서 CSP가 `style-src 'unsafe-inline'`을 허용하고, `Referrer-Policy`와 교차 출처 격리 헤더가 없으며, 내부 `io::Error` 문자열(임시 파일의 절대 경로를 담을 수 있음)이 응답에 그대로 실린다는 점을 확인했습니다.
- 영향: 로컬 전용 서버라 영향은 작습니다. 다만 인라인 스타일 허용은 마크업 삽입이 생길 경우 스타일 기반 데이터 유출의 문턱을 낮추고, 오류 문구는 사용자 계정 이름과 디렉터리 구조를 화면과 로그에 드러냅니다.
- 수정:
  1. 모든 응답(거절 포함)에 `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, 쓰지 않는 기능을 막는 `Permissions-Policy`를 붙였습니다.
  2. `<style>` 블록을 `web/app.css`로 옮기고 `/app.css`로 제공하며 CSP를 `style-src 'self'`로 강화했습니다. 인라인 `style` 속성은 이미 없었고 스크립트는 CSSOM만 써서 막히지 않습니다.
  3. 오류 응답의 절대 경로를 `…/파일명`으로 가리고, 전체 오류는 터미널 로그에만 남깁니다. 파일명은 남겨서 사용자가 복구용 임시 파일을 직접 찾을 수 있습니다.
- 회귀 테스트:
  - `every_response_carries_the_security_headers_and_the_page_has_no_inline_style`: 페이지, 스타일시트, 스크립트, 404, 거절 응답 모두에 헤더가 있고 `unsafe-inline`이 없으며 페이지에 `<style>`·`style=`이 없다.
  - `paths_in_error_text_are_reduced_to_the_file_name`, `client_message_hides_the_directory_layout_of_the_machine`: 경로 가림.
  - JS: 페이지가 `/app.css`를 링크하고 인라인 스타일, `setAttribute('style')`, `innerHTML` 대입이 없다.
  - 헤더 한 줄을 빼거나, CSP에 `unsafe-inline`을 되돌리거나, 경로 가림을 끄면 각각 테스트가 실패하는 것을 확인했습니다.
- 남은 한계:
  - 채팅 상태 JSON으로 가는 오류(예: 임시 파일 정리 실패 안내)는 사용자가 직접 정리할 수 있도록 경로를 남깁니다. `client_message`를 거치는 곳만 가려집니다.
  - 가림은 공백으로 구분된 `/`로 시작하는 단어를 기준으로 하는 휴리스틱입니다. 공백이 들어간 경로는 일부가 남을 수 있습니다.
  - 터미널 로그에는 전체 오류(경로 포함)가 남습니다. 같은 기기 사용자의 터미널이므로 의도한 동작입니다.

## SF-004 느린 클라이언트 하나가 로컬 서버 전체를 멈출 수 있음

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/main.rs`의 accept 루프와 `handle()`
- 발견: 코드 리뷰에서 연결을 한 스레드가 하나씩 처리하고, 타임아웃이 읽을 때마다 2초로 초기화된다는 점을 확인했습니다. 그다음 테스트로 재현했습니다. 한 연결이 요청을 중간까지만 보내고 멈추면 다른 요청이 그동안 기다렸습니다.
- 영향: 같은 기기의 다른 프로세스가 바이트를 1.9초마다 하나씩 보내면 헤더 8 KiB, 본문 2 MiB를 채우는 동안 서버가 몇 시간이고 응답하지 못했습니다(slowloris). 오래 걸리는 백업 작업도 전역 락을 쥔 채 실행되어 그동안 모든 요청이 멈췄습니다.
- 수정:
  1. 연결마다 스레드로 처리하고 동시 처리를 16개로 제한합니다. 넘으면 503으로 즉시 거절합니다. 슬롯은 패닉이 나도 반환됩니다.
  2. 헤더는 5초, 본문은 30초라는 **전체** deadline을 둡니다. 초과하면 408입니다. 읽기마다 초기화되는 타임아웃으로는 바이트를 천천히 보내는 공격을 막지 못했습니다.
  3. 헤더 크기 검사 순서를 고쳤습니다. 예전에는 새로 읽은 덩어리를 더하기 전에 한도를 확인해서, 헤더가 한도 안에 끝나도 같은 읽기에 본문이 딸려 오면 거부될 수 있었습니다. 이제 헤더 끝을 먼저 찾고 한도는 헤더에만 적용합니다.
  4. `Content-Length`는 숫자만 허용합니다(`+5`, `0x5`, 빈 값 거부). 헤더 이름에 공백이 있으면(`Host :`) 조용히 무시하지 않고 거부합니다.
  5. 백업 가져오기는 전역 락을 풀고 실행합니다. 대신 "가져오기 진행 중" 표지가 충돌하는 작업(대화 시작, 삭제, 신원 교체, 연락처 가져오기, 다른 가져오기와 내보내기)을 409로 막습니다. 표지는 패닉이 나도 해제됩니다. 내보내기, 검증, 재보호도 락을 풀고 실행합니다.
- 회귀 테스트:
  - `a_stalled_client_does_not_block_other_clients`: 멈춘 연결이 있어도 다른 클라이언트가 즉시 응답을 받는다.
  - `a_client_that_trickles_bytes_is_cut_off_at_the_header_deadline`, `a_stalled_body_is_cut_off_at_the_body_deadline`: 전체 deadline에서 408.
  - `connections_beyond_the_limit_are_refused_and_capacity_recovers`: 상한 초과는 503이고 슬롯이 돌아온다.
  - `a_head_that_fits_is_accepted_even_when_the_read_overshoots_the_limit` 외 3개: 헤더 읽기(경계, 끝 표지가 읽기 경계에 걸리는 경우, 한도).
  - `malformed_framing_headers_are_rejected`: `Content-Length` 형식과 헤더 이름.
  - `a_running_import_does_not_hold_the_state_lock_but_blocks_conflicting_work`: 가져오기가 멈춰 있는 동안 다른 요청은 응답하고 충돌하는 요청은 409이다. 가져오기에서 락 해제를 빼면 이 테스트가 실패하는 것을 확인했습니다.
  - 스레드 처리와 header deadline을 각각 빼는 변이 검사에서도 해당 테스트가 실패했습니다.
- 남은 한계:
  - 느린 클라이언트 16개가 동시에 deadline(최대 5초)까지 연결을 점유하면 그동안 새 연결은 503을 받습니다. 한 연결이 서버 전체를 막는 문제는 없어졌지만 완전한 서비스 거부 방어는 아닙니다.
  - 이 서버는 루프백 전용이라 공격자는 같은 기기의 프로세스입니다.
  - 요청 스레드가 패닉으로 전역 락을 쥔 채 죽으면 락이 오염(poison)되어 이후 요청이 실패합니다. 이전에는 서버 프로세스 전체가 종료됐습니다.
  - 락을 푸는 것은 백업 전송 작업에 한정했습니다. 다른 핸들러는 짧은 작업이라 락을 쥔 채 실행합니다.

## SF-003 세션 토큰이 만료되지 않고 폐기되지도 않음

- 날짜: 2026-11-23
- 심각도: Medium
- 위치: `src/main.rs`의 세션 목록(`State.sessions`), `issue_code`, 로그아웃 핸들러
- 발견: 코드 리뷰에서 세션이 만료 없는 무제한 `Vec`이고, 로그아웃과 새 연결 코드 발급 어느 쪽도 기존 토큰을 폐기하지 않는다는 점을 확인했습니다. 또 "토큰 무효"와 "신원 미로그인"이 모두 401이라 화면이 두 경우를 구분하지 못했습니다.
- 영향: 개발자 도구나 화면 공유로 토큰이 한 번 새어 나가면 프로그램을 재시작할 때까지 유효했습니다. 로그아웃하고 나중에 다른 신원으로 로그인하면, 복사된 토큰이 새 신원의 기록과 연락처를 그대로 읽을 수 있었습니다.
- 수정:
  1. 세션을 `src/session.rs`의 `SessionStore`로 분리했습니다. 1시간 동안 쓰지 않으면 만료되고, 쓰고 있어도 12시간이 지나면 만료되며, 동시 세션은 최대 4개이고 넘으면 가장 오래 쓰지 않은 것을 내보냅니다. 시각을 인자로 받아 실제로 기다리지 않고 테스트합니다.
  2. 새 연결 코드를 발급하면(터미널 Enter) 기존 세션을 모두 끝냅니다.
  3. 로그아웃은 모든 세션을 끝내고 새 연결 코드를 출력합니다. 현재 세션만 끝내는 방식은 선택하지 않았습니다. 복사된 토큰은 현재 세션의 토큰과 같은 문자열일 수 있어서, "다른 세션만 폐기"로는 막지 못하기 때문입니다.
  4. 토큰 무효는 401, 세션은 유효하지만 신원이 없으면 412로 나눴습니다. 화면은 401이면 세션 종료로 보고 연결 코드 화면으로 돌아가며(폴링도 멈춤), 412면 신원 로그인 화면을 보여 주고 세션은 유지합니다. 이전 세션에 대한 늦은 401은 현재 세션을 끝내지 않습니다.
- 회귀 테스트:
  - `session::tests`(8개): 유휴 만료와 경계, 사용하면 연장되지만 절대 수명은 넘지 못함, 개수 상한과 가장 오래 쓰지 않은 세션 제거, 만료된 세션은 개수에 포함되지 않음, 개별·전체 폐기.
  - `send_tests::rejected_session_is_401_but_missing_identity_is_412`: 여러 경로에서 401과 412가 구분된다.
  - `send_tests::a_new_connection_code_ends_every_existing_session`: 새 코드가 기존 세션과 옛 코드를 모두 무효로 한다.
  - `send_tests::logout_ends_every_session_and_offers_a_new_connection_code`: 로그아웃 후 모든 토큰이 무효이고 새 코드로 다시 연결된다.
  - 프런트엔드(6개): 401이면 연결 코드 화면으로 돌아가고, 오래된 세션의 401은 무시하며, 412는 세션을 유지하고, 로그아웃 후 연결 코드 화면으로 가며, 세션 종료 뒤 폴링이 다시 예약되지 않는다.
  - 폐기 코드를 일부러 빼면 해당 테스트가 실패하는 것을 확인했습니다(변이 검사 5건).
- 남은 한계:
  - 새 연결 코드가 모든 세션을 끝내므로 **동시에 연결할 수 있는 브라우저 탭은 사실상 하나**입니다. 탭마다 `sessionStorage`가 따로라서 두 번째 탭을 연결하면 첫 번째 탭의 세션이 끝납니다. 최대 4개 상한은 이 경로로는 거의 닿지 않는 안전장치입니다.
  - 1시간·12시간은 제가 정한 값입니다. 로컬 앱이라 짧게 잡으면 불편하고 길게 잡으면 노출 시간이 늘어납니다.
  - 세션 만료 후에는 터미널에서 새 코드를 입력해야 합니다. 코드가 보이지 않으면 Enter로 발급합니다.
  - 토큰은 여전히 페이지 스크립트가 읽을 수 있는 `sessionStorage`에 있습니다. 스크립트 삽입은 CSP와 안전한 렌더링으로 막고 있습니다.
  - 연결 코드 입력을 5번 틀리면 새 코드가 나올 때까지 연결할 수 없는 점은 그대로입니다.

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
