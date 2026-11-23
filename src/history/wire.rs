//! Signed messages and the frames used to transfer history between peers.

use super::*;

/// Backups contain snapshots without record IDs. Preserve the greatest count of
/// each exact message found in either copy: this makes re-import idempotent while
/// retaining identical messages already repeated within either snapshot.
pub(crate) fn merge_snapshot(
    existing: Vec<StoredMessage>,
    imported: Vec<StoredMessage>,
) -> io::Result<Vec<StoredMessage>> {
    merge_restored(&existing, &imported)
}

pub(crate) fn validate_peer_id(peer_id: &str) -> io::Result<()> {
    if peer_id.len() != 64 || !peer_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer id",
        ));
    }
    Ok(())
}

pub(crate) fn decode_peer_id(peer_id: &str) -> io::Result<[u8; 32]> {
    validate_peer_id(peer_id)?;
    crate::hex::decode_array::<32>(peer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer id"))
}

pub(crate) fn sign_message(
    identity: &Identity,
    peer_id: &str,
    unix_time: u64,
    text: String,
) -> io::Result<StoredMessage> {
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid message size",
        ));
    }
    let mut id = [0; 16];
    crate::random::fill(&mut id)?;
    let mut proof = MessageProof {
        id,
        signer: identity.public_key(),
        recipient: decode_peer_id(peer_id)?,
        signature: [0; 64],
    };
    proof.signature = identity.sign(&message_signing_payload(unix_time, &text, &proof));
    Ok(StoredMessage {
        unix_time,
        sender: MessageSender::Me,
        text,
        proof: Some(proof),
    })
}

pub(crate) fn encode_transfer(message: &StoredMessage) -> io::Result<Vec<u8>> {
    encode_wire_message(message, TRANSFER_MAGIC)
}

pub(crate) fn encode_transfer_chunk(
    message: &StoredMessage,
    request_id: &str,
    chunk_index: usize,
) -> io::Result<Vec<u8>> {
    if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("invalid history request ID"));
    }
    let chunk_index =
        u32::try_from(chunk_index).map_err(|_| invalid_data("history chunk index is too large"))?;
    let mut frame = Vec::new();
    frame.extend_from_slice(TRANSFER_CHUNK_MAGIC);
    frame.extend_from_slice(request_id.as_bytes());
    frame.extend_from_slice(&chunk_index.to_be_bytes());
    frame.extend_from_slice(&encode_transfer(message)?);
    Ok(frame)
}

pub(crate) fn transfer_chunk_metadata(frame: &[u8]) -> io::Result<(String, usize, &[u8])> {
    let header_len = TRANSFER_CHUNK_MAGIC.len() + 64 + 4;
    if frame.len() < header_len || !frame.starts_with(TRANSFER_CHUNK_MAGIC) {
        return Err(invalid_data("history record has no request and chunk ID"));
    }
    let request_id = std::str::from_utf8(&frame[5..69])
        .map_err(|_| invalid_data("invalid history request ID"))?;
    if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("invalid history request ID"));
    }
    let chunk = u32::from_be_bytes(frame[69..73].try_into().expect("fixed slice")) as usize;
    Ok((request_id.to_owned(), chunk, &frame[header_len..]))
}

pub(crate) fn encode_signed_message(message: &StoredMessage) -> io::Result<Vec<u8>> {
    if message.proof.is_none() || message.sender != MessageSender::Me {
        return Err(invalid_data("outgoing message is not signed"));
    }
    encode_wire_message(message, MESSAGE_MAGIC)
}

pub(crate) fn encode_wire_message(message: &StoredMessage, magic: &[u8; 6]) -> io::Result<Vec<u8>> {
    let text = message.text.as_bytes();
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid message size",
        ));
    }
    let mut frame = Vec::with_capacity(6 + 1 + 8 + 4 + text.len() + 1 + 144);
    frame.extend_from_slice(magic);
    frame.push(match message.sender {
        MessageSender::Me => 0,
        MessageSender::Other => 1,
    });
    frame.extend_from_slice(&message.unix_time.to_be_bytes());
    frame.extend_from_slice(&(text.len() as u32).to_be_bytes());
    frame.extend_from_slice(text);
    match &message.proof {
        Some(proof) => {
            frame.push(1);
            frame.extend_from_slice(&proof.id);
            frame.extend_from_slice(&proof.signer);
            frame.extend_from_slice(&proof.recipient);
            frame.extend_from_slice(&proof.signature);
        }
        None => frame.push(0),
    }
    Ok(frame)
}

#[cfg(test)]
pub(crate) fn decode_transfer(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
) -> io::Result<StoredMessage> {
    decode_transfer_with_linked_keys(identity, peer_id, peer_key, frame, &[], &[])
}

pub(crate) fn decode_transfer_with_linked_keys(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<StoredMessage> {
    decode_wire_message(
        identity,
        peer_id,
        peer_key,
        frame,
        TRANSFER_MAGIC,
        local_aliases,
        peer_aliases,
    )
}

pub(crate) fn decode_signed_message(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
) -> io::Result<StoredMessage> {
    let message = decode_wire_message(identity, peer_id, peer_key, frame, MESSAGE_MAGIC, &[], &[])?;
    if message.proof.is_none() {
        return Err(invalid_data("new message has no signature"));
    }
    if message.sender != MessageSender::Other {
        return Err(invalid_data("new message has an invalid sender"));
    }
    Ok(message)
}

pub(crate) fn decode_wire_message(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
    magic: &[u8; 6],
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<StoredMessage> {
    if frame.len() < magic.len() + 14 || !frame.starts_with(magic) {
        return Err(invalid_data("invalid history transfer frame"));
    }
    let mut cursor = TRANSFER_MAGIC.len();
    let sender = match frame[cursor] {
        0 => MessageSender::Other,
        1 => MessageSender::Me,
        _ => return Err(invalid_data("invalid transferred sender")),
    };
    cursor += 1;
    let unix_time = u64::from_be_bytes(frame[cursor..cursor + 8].try_into().expect("fixed slice"));
    cursor += 8;
    let text_len =
        u32::from_be_bytes(frame[cursor..cursor + 4].try_into().expect("fixed slice")) as usize;
    cursor += 4;
    if text_len == 0 || text_len > MAX_MESSAGE_BYTES || frame.len() < cursor + text_len + 1 {
        return Err(invalid_data("invalid transferred message length"));
    }
    let text = std::str::from_utf8(&frame[cursor..cursor + text_len])
        .map_err(|_| invalid_data("transferred message is not UTF-8"))?
        .to_owned();
    cursor += text_len;
    let proof = match frame[cursor] {
        0 if frame.len() == cursor + 1 => None,
        1 if frame.len() == cursor + 1 + 144 => {
            cursor += 1;
            let id = frame[cursor..cursor + 16].try_into().expect("fixed slice");
            cursor += 16;
            let signer = frame[cursor..cursor + 32].try_into().expect("fixed slice");
            cursor += 32;
            let recipient = frame[cursor..cursor + 32].try_into().expect("fixed slice");
            cursor += 32;
            let signature = frame[cursor..cursor + 64].try_into().expect("fixed slice");
            Some(MessageProof {
                id,
                signer,
                recipient,
                signature,
            })
        }
        _ => return Err(invalid_data("invalid transferred message proof")),
    };
    if let Some(proof) = &proof {
        let (expected_signer, expected_recipient) = match sender {
            MessageSender::Other => (*peer_key, identity.public_key()),
            MessageSender::Me => (identity.public_key(), decode_peer_id(peer_id)?),
        };
        let (signer_aliases, recipient_aliases) = match sender {
            MessageSender::Other => (peer_aliases, local_aliases),
            MessageSender::Me => (local_aliases, peer_aliases),
        };
        let key = VerifyingKey::from_bytes(&proof.signer)
            .map_err(|_| invalid_data("invalid transferred signing key"))?;
        let signature = Signature::from_bytes(&proof.signature);
        key.verify_strict(
            &message_signing_payload(unix_time, &text, proof),
            &signature,
        )
        .map_err(|_| invalid_data("transferred message signature failed"))?;
        if (proof.signer != expected_signer && !signer_aliases.contains(&proof.signer))
            || (proof.recipient != expected_recipient
                && !recipient_aliases.contains(&proof.recipient))
        {
            return Err(invalid_data(
                "transferred message uses an unlinked identity key or recipient",
            ));
        }
    }
    Ok(StoredMessage {
        unix_time,
        sender,
        text,
        proof,
    })
}

pub(crate) fn is_transfer_frame(frame: &[u8]) -> bool {
    frame.starts_with(TRANSFER_MAGIC) || frame.starts_with(TRANSFER_CHUNK_MAGIC)
}

pub(crate) fn is_signed_message_frame(frame: &[u8]) -> bool {
    frame.starts_with(MESSAGE_MAGIC)
}

pub(crate) fn merge_restored(
    existing: &[StoredMessage],
    offered: &[StoredMessage],
) -> io::Result<Vec<StoredMessage>> {
    let mut by_id = HashMap::<[u8; 16], StoredMessage>::new();
    for message in existing.iter().chain(offered) {
        if let Some(proof) = &message.proof {
            if let Some(previous) = by_id.insert(proof.id, message.clone()) {
                if previous != *message {
                    return Err(invalid_data("message ID collision"));
                }
            }
        }
    }
    let mut merged = existing.to_vec();
    let mut legacy_counts = HashMap::<(u64, MessageSender, String), usize>::new();
    for message in existing.iter().filter(|message| message.proof.is_none()) {
        *legacy_counts
            .entry((message.unix_time, message.sender, message.text.clone()))
            .or_default() += 1;
    }
    let mut offered_legacy_counts = HashMap::<(u64, MessageSender, String), usize>::new();
    let mut seen_ids = HashSet::new();
    for message in offered {
        if let Some(proof) = &message.proof {
            if !seen_ids.insert(proof.id) {
                continue;
            }
            if existing
                .iter()
                .any(|old| old.proof.as_ref().is_some_and(|prior| prior.id == proof.id))
            {
                continue;
            }
            merged.push(message.clone());
        } else {
            let key = (message.unix_time, message.sender, message.text.clone());
            let count = offered_legacy_counts.entry(key.clone()).or_default();
            *count += 1;
            if *count > legacy_counts.get(&key).copied().unwrap_or(0) {
                merged.push(message.clone());
            }
        }
    }
    merged.sort_by_key(|message| message.unix_time);
    Ok(merged)
}

pub(crate) fn message_signing_payload(unix_time: u64, text: &str, proof: &MessageProof) -> Vec<u8> {
    let mut payload = Vec::with_capacity(43 + 16 + 32 + 32 + text.len());
    payload.extend_from_slice(b"another-dimension-v2/chat-message/v1");
    payload.extend_from_slice(&proof.id);
    payload.extend_from_slice(&proof.signer);
    payload.extend_from_slice(&proof.recipient);
    payload.extend_from_slice(&unix_time.to_be_bytes());
    payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
    payload.extend_from_slice(text.as_bytes());
    payload
}

pub(crate) fn verify_stored_proof(
    identity: &Identity,
    peer_id: &str,
    message: &StoredMessage,
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<()> {
    let proof = message
        .proof
        .as_ref()
        .ok_or_else(|| invalid_data("message has no signature"))?;
    let (signer, recipient) = match message.sender {
        MessageSender::Me => (identity.public_key(), decode_peer_id(peer_id)?),
        MessageSender::Other => (decode_peer_id(peer_id)?, identity.public_key()),
    };
    let (signer_aliases, recipient_aliases) = match message.sender {
        MessageSender::Me => (local_aliases, peer_aliases),
        MessageSender::Other => (peer_aliases, local_aliases),
    };
    let key = VerifyingKey::from_bytes(&proof.signer)
        .map_err(|_| invalid_data("invalid backup message signer"))?;
    key.verify_strict(
        &message_signing_payload(message.unix_time, &message.text, proof),
        &Signature::from_bytes(&proof.signature),
    )
    .map_err(|_| invalid_data("backup message signature failed"))
    .and_then(|()| {
        if (proof.signer != signer && !signer_aliases.contains(&proof.signer))
            || (proof.recipient != recipient && !recipient_aliases.contains(&proof.recipient))
        {
            Err(invalid_data(
                "backup message uses an unlinked identity key or recipient",
            ))
        } else {
            Ok(())
        }
    })
}
