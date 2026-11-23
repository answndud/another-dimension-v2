//! Chunked transfer of a conversation between two peers (the history restore offer).

use super::*;

pub(crate) const SYNC_CHUNK_RECORDS: usize = 32;

pub(crate) const SYNC_CHUNK_BYTES: usize = 64 * 1024;

pub(crate) struct HistorySyncSender {
    pub(crate) request_id: String,
    pub(crate) reader: history::HistoryReader,
    pub(crate) total_records: usize,
    pub(crate) sent_records: usize,
    pub(crate) next_chunk: usize,
    pub(crate) pending_record: Option<history::StoredMessage>,
    pub(crate) awaiting_chunk: Option<usize>,
    pub(crate) awaiting_count: usize,
    #[cfg(test)]
    pub(crate) test_next_record: usize,
    #[cfg(test)]
    pub(crate) test_generated: Option<(usize, usize)>,
}

impl HistorySyncSender {
    pub(crate) fn new(
        request_id: String,
        reader: history::HistoryReader,
        total_records: usize,
    ) -> Self {
        Self {
            request_id,
            reader,
            total_records,
            sent_records: 0,
            next_chunk: 0,
            pending_record: None,
            awaiting_chunk: None,
            awaiting_count: 0,
            #[cfg(test)]
            test_next_record: 0,
            #[cfg(test)]
            test_generated: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_generated_test(request_id: String, count: usize, text_bytes: usize) -> Self {
        let file = File::open("/dev/null").expect("null file for test reader");
        let reader = history::HistoryReader::empty_for_test(file);
        let mut sender = Self::new(request_id, reader, count);
        sender.test_generated = Some((count, text_bytes));
        sender
    }

    pub(crate) fn next_record(&mut self) -> io::Result<Option<history::StoredMessage>> {
        #[cfg(test)]
        if let Some((count, text_bytes)) = self.test_generated {
            if self.test_next_record >= count {
                return Ok(None);
            }
            let index = self.test_next_record;
            self.test_next_record += 1;
            return Ok(Some(history::StoredMessage {
                unix_time: index as u64,
                sender: history::MessageSender::Me,
                text: "x".repeat(text_bytes),
                proof: None,
            }));
        }
        self.reader.next_record()
    }

    pub(crate) fn next_chunk(&mut self) -> io::Result<Option<(usize, Vec<Vec<u8>>)>> {
        if self.awaiting_chunk.is_some() || self.sent_records >= self.total_records {
            return Ok(None);
        }
        let chunk_index = self.next_chunk;
        let mut frames = Vec::new();
        let mut bytes = 0usize;
        while self.sent_records + frames.len() < self.total_records
            && frames.len() < SYNC_CHUNK_RECORDS
        {
            let message = match self.pending_record.take() {
                Some(message) => message,
                None => self
                    .next_record()?
                    .ok_or_else(|| io::Error::other("history snapshot ended before estimate"))?,
            };
            let frame = history::encode_transfer_chunk(&message, &self.request_id, chunk_index)?;
            if !frames.is_empty() && bytes.saturating_add(frame.len()) > SYNC_CHUNK_BYTES {
                self.pending_record = Some(message);
                break;
            }
            if frame.len() > SYNC_CHUNK_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "history record exceeds chunk limit",
                ));
            }
            bytes += frame.len();
            frames.push(frame);
        }
        self.awaiting_chunk = Some(chunk_index);
        self.awaiting_count = frames.len();
        Ok(Some((chunk_index, frames)))
    }

    pub(crate) fn acknowledge(&mut self, request_id: &str, chunk_index: usize) -> io::Result<bool> {
        if request_id != self.request_id {
            return Ok(false);
        }
        if self.awaiting_chunk != Some(chunk_index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate or out-of-order history chunk acknowledgment",
            ));
        }
        self.awaiting_chunk = None;
        self.sent_records = self.sent_records.saturating_add(self.awaiting_count);
        self.awaiting_count = 0;
        self.next_chunk += 1;
        Ok(self.sent_records == self.total_records)
    }
}

#[derive(Default)]
pub(crate) struct HistorySyncReceiver {
    pub(crate) request_id: Option<String>,
    pub(crate) total_records: usize,
    pub(crate) next_chunk: usize,
    pub(crate) active_chunk: Option<(usize, usize, usize, usize)>,
    pub(crate) received_records: usize,
    pub(crate) received_bytes: usize,
}

impl HistorySyncReceiver {
    pub(crate) fn begin(&mut self, request_id: &str, total_records: usize) -> io::Result<()> {
        if !valid_sync_request_id(request_id) || self.request_id.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid history transfer start",
            ));
        }
        *self = Self {
            request_id: Some(request_id.to_owned()),
            total_records,
            ..Self::default()
        };
        Ok(())
    }

    pub(crate) fn begin_chunk(
        &mut self,
        request_id: &str,
        chunk: usize,
        count: usize,
    ) -> io::Result<()> {
        if self.request_id.as_deref() != Some(request_id)
            || self.active_chunk.is_some()
            || chunk != self.next_chunk
            || count == 0
            || count > SYNC_CHUNK_RECORDS
            || self.received_records.saturating_add(count) > self.total_records
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing, duplicate, or out-of-order history chunk",
            ));
        }
        self.active_chunk = Some((chunk, count, 0, 0));
        Ok(())
    }

    pub(crate) fn record(
        &mut self,
        request_id: &str,
        chunk: usize,
        bytes: usize,
    ) -> io::Result<()> {
        let Some((active_chunk, expected, received, chunk_bytes)) = self.active_chunk else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history record outside a chunk",
            ));
        };
        if self.request_id.as_deref() != Some(request_id)
            || chunk != active_chunk
            || received >= expected
            || chunk_bytes.saturating_add(bytes) > SYNC_CHUNK_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk size or sequence is invalid",
            ));
        }
        self.received_records += 1;
        self.received_bytes += bytes;
        self.active_chunk = Some((chunk, expected, received + 1, chunk_bytes + bytes));
        Ok(())
    }

    pub(crate) fn end_chunk(&mut self, request_id: &str, chunk: usize) -> io::Result<()> {
        let Some((expected_chunk, expected_records, received, _)) = self.active_chunk else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk end without a chunk",
            ));
        };
        if self.request_id.as_deref() != Some(request_id)
            || chunk != expected_chunk
            || received != expected_records
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk end is out of order",
            ));
        }
        self.active_chunk = None;
        self.next_chunk += 1;
        Ok(())
    }

    pub(crate) fn finish(&self, request_id: &str, total_records: usize) -> io::Result<()> {
        if self.request_id.as_deref() != Some(request_id)
            || self.active_chunk.is_some()
            || total_records != self.total_records
            || self.received_records != self.total_records
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history transfer is incomplete",
            ));
        }
        Ok(())
    }
}

pub(crate) fn valid_sync_request_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn send_next_history_chunk(
    session: &mut RelaySession,
    sync: &mut HistorySyncSender,
) -> io::Result<()> {
    let (chunk, frames) = sync.next_chunk()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "history sender is already awaiting acknowledgment",
        )
    })?;
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-chunk-begin",
            "requestId": sync.request_id,
            "chunk": chunk,
            "count": frames.len(),
        })))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    for frame in &frames {
        session
            .send(frame)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
    }
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-chunk-end",
            "requestId": sync.request_id,
            "chunk": chunk,
        })))
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("{error:?}")))
}

pub(crate) fn send_history_sync_done(
    session: &mut RelaySession,
    request_id: &str,
    count: usize,
) -> io::Result<()> {
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-done",
            "requestId": request_id,
            "totalCount": count,
        })))
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("{error:?}")))
}
