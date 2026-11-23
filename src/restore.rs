//! Bookkeeping for an accepted history restore: timeouts, staging and the queue of
//! messages that arrive while it merges.

use super::*;

pub(crate) const RESTORE_PREVIEW_RECORDS: usize = 12;

pub(crate) const MAX_MERGE_PENDING_MESSAGES: usize = 256;

pub(crate) const MAX_MERGE_PENDING_BYTES: usize = 1024 * 1024;

pub(crate) const RESTORE_MERGE_SEND_REJECTION: &str =
    "기록 병합 중이라 메시지를 전송하지 않았습니다. 병합 완료 후 다시 보내세요.";

pub(crate) const HISTORY_RESTORE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn history_restore_timed_out(started_at: Option<Instant>, now: Instant) -> bool {
    started_at.is_some_and(|started| now.duration_since(started) > HISTORY_RESTORE_TIMEOUT)
}

pub(crate) fn history_restore_work_timed_out(
    started_at: Option<Instant>,
    request_pending: bool,
    staging_pending: bool,
    now: Instant,
) -> bool {
    (request_pending || staging_pending) && history_restore_timed_out(started_at, now)
}

pub(crate) fn reserve_history_restore_resolution(
    snapshot: &mut ChatSnapshot,
    accept: bool,
) -> Result<&'static str, &'static str> {
    if snapshot.phase != "connected" {
        return Err("restore operation is not available");
    }
    let state = if accept {
        if snapshot.history_restore_in_progress {
            return Err("restore approval is already in progress");
        }
        match snapshot.history_restore_state {
            "awaiting-transfer-consent" => "transfer-queued",
            "awaiting-merge-consent" => "merge-queued",
            _ => return Err("restore approval was already handled"),
        }
    } else if matches!(
        snapshot.history_restore_state,
        "idle" | "failed" | "merging" | "merge-queued" | "cancel-queued" | "completed"
    ) {
        return Err("restore operation cannot be declined in this state");
    } else {
        "cancel-queued"
    };
    snapshot.history_restore_state = state;
    snapshot.history_restore_in_progress = true;
    snapshot.history_restore_status = Some(match state {
        "merge-queued" => {
            "최종 병합 요청을 접수했습니다. 완료 여부는 연결 상태에서 확인합니다.".to_owned()
        }
        "transfer-queued" => "전송 동의 요청을 접수했습니다.".to_owned(),
        _ => "복원 취소 요청을 접수했습니다.".to_owned(),
    });
    Ok(state)
}

pub(crate) fn history_restore_request_allowed(snapshot: &ChatSnapshot) -> bool {
    snapshot.phase == "connected"
        && !snapshot.history_restore_in_progress
        && snapshot.history_restore_offer.is_empty()
        && matches!(
            snapshot.history_restore_state,
            "idle" | "failed" | "completed"
        )
}

pub(crate) fn mark_history_restore_timeout(snapshot: &mut ChatSnapshot) {
    snapshot.history_restore_in_progress = false;
    snapshot.history_restore_state = "failed";
    snapshot.history_restore_received = 0;
    snapshot.history_restore_total = 0;
    snapshot.history_restore_offer.clear();
    snapshot.history_restore_offer_count = 0;
    snapshot.history_restore_legacy_count = 0;
    snapshot.history_restore_estimate_bytes = 0;
    snapshot.history_restore_status = Some(
        "상대 기록 응답 시간이 초과되었습니다. 로컬 기록은 변경하지 않았습니다. 다시 연결되어 있으면 복원을 다시 요청할 수 있습니다."
            .to_owned(),
    );
}

pub(crate) fn reserve_history_restore_timeout(snapshot: &mut ChatSnapshot) -> bool {
    if !matches!(
        snapshot.history_restore_state,
        "estimating" | "awaiting-transfer-consent" | "receiving" | "awaiting-merge-consent"
    ) {
        return false;
    }
    mark_history_restore_timeout(snapshot);
    true
}

pub(crate) fn try_reserve_history_restore_timeout(operation: &ChatOperation) -> bool {
    operation
        .snapshot
        .lock()
        .is_ok_and(|mut snapshot| reserve_history_restore_timeout(&mut snapshot))
}

pub(crate) fn discard_restore_staging(
    staging: &mut Option<history::RestoreStaging>,
    operation: &ChatOperation,
) {
    let mut cleanup_error = None;
    if let Some(staging) = staging.take() {
        if let Err(error) = staging.cleanup() {
            cleanup_error = Some(error.to_string());
            chat_update(operation, |snapshot| {
                snapshot.history_restore_cleanup_error = Some(error.to_string());
                snapshot.history_restore_state = "failed";
                snapshot.history_restore_in_progress = false;
            });
        }
    }
    chat_update(operation, |snapshot| {
        if snapshot.history_restore_state == "merge-queued" {
            snapshot.history_restore_state = "failed";
            snapshot.history_restore_in_progress = false;
            snapshot.history_restore_status = Some(match cleanup_error {
                Some(error) => format!("채팅 종료 전에 병합이 시작되지 않았습니다. 기존 기록은 변경되지 않았습니다. 임시 저장소 정리 실패: {error}"),
                None => "채팅 종료 전에 병합이 시작되지 않았습니다. 기존 기록은 변경되지 않았습니다. 다시 연결해 복원을 다시 요청하세요.".to_owned(),
            });
        }
    });
}

pub(crate) fn restore_merge_active(operation: &ChatOperation) -> bool {
    operation
        .snapshot
        .lock()
        .map(|snapshot| history_restore_is_merging(snapshot.history_restore_state))
        .unwrap_or(true)
}

pub(crate) fn history_restore_is_merging(state: &str) -> bool {
    matches!(state, "merge-queued" | "merging")
}

pub(crate) fn restore_merge_send_error(operation: &ChatOperation) -> Option<&'static str> {
    restore_merge_active(operation).then_some(RESTORE_MERGE_SEND_REJECTION)
}

pub(crate) fn queue_incoming_message(operation: &ChatOperation, queued_len: usize) -> bool {
    queued_len > 0 || restore_merge_active(operation)
}

pub(crate) fn append_pending_restore_messages(
    operation: &ChatOperation,
    history: &mut Option<history::History>,
    messages: &mut VecDeque<history::StoredMessage>,
    queued_bytes: &mut usize,
    max_messages: usize,
) -> io::Result<usize> {
    if messages.is_empty() {
        return Ok(0);
    }
    let _history_state_guard = operation
        .history_state_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut appended = 0usize;
    while appended < max_messages {
        let Some(entry) = messages.pop_front() else {
            break;
        };
        *queued_bytes = queued_bytes.saturating_sub(entry.text.len());
        let Some(current) = history.as_mut() else {
            return Err(io::Error::other("대화 기록 핸들을 사용할 수 없습니다."));
        };
        current.append(&entry)?;
        chat_update(operation, |snapshot| {
            snapshot.message_count = snapshot.message_count.saturating_add(1);
            snapshot.message_epoch = snapshot.message_epoch.wrapping_add(1);
            snapshot.messages.push(chat_entry(entry));
        });
        appended += 1;
    }
    Ok(appended)
}

// The rejected entry is handed back to the caller, so the Err variant is large.
// TODO(PLAN 3.1): revisit (e.g. Box the entry) when handlers are split into modules.
#[allow(clippy::result_large_err)]
pub(crate) fn queue_message_during_restore_merge(
    messages: &mut VecDeque<history::StoredMessage>,
    queued_bytes: &mut usize,
    entry: history::StoredMessage,
) -> Result<(), history::StoredMessage> {
    let bytes = entry.text.len();
    if messages.len() >= MAX_MERGE_PENDING_MESSAGES
        || queued_bytes.saturating_add(bytes) > MAX_MERGE_PENDING_BYTES
    {
        return Err(entry);
    }
    *queued_bytes += bytes;
    messages.push_back(entry);
    Ok(())
}

pub(crate) fn restore_transfer_allowed(operation: &ChatOperation) -> bool {
    operation
        .snapshot
        .lock()
        .map(|snapshot| snapshot.history_restore_state == "receiving")
        .unwrap_or(false)
}
