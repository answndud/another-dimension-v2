//! Chunked backup transfer route.

use super::*;

pub(crate) fn history_backup_transfer(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request {
        body, state_handle, ..
    } = request;
    // Owned, so the heavy actions below can release the State lock while they run.
    let Some(identity_owned) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let identity = &identity_owned;
    let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(fields) = payload.as_object_mut() else {
        return reject(stream, "400 Bad Request");
    };
    let Some(action) = fields
        .remove("action")
        .and_then(|v| v.as_str().map(str::to_owned))
    else {
        return reject(stream, "400 Bad Request");
    };
    let transfer_dir = match history::History::backup_transfer_directory(identity) {
        Ok(path) => path,
        Err(_) => return reject(stream, "500 Internal Server Error"),
    };
    let transfer_owner = match history::History::backup_transfer_workspace_id(identity) {
        Ok(owner) => owner,
        Err(_) => return reject(stream, "500 Internal Server Error"),
    };
    let new_transfer_id = || -> io::Result<String> {
        let entropy = random_token()?;
        Ok(format!(
            "{}{}",
            transfer_owner,
            &entropy[..64 - transfer_owner.len()]
        ))
    };
    let get_transfer_path = |id: &str| -> Option<PathBuf> {
        if id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !id.to_ascii_lowercase().starts_with(&transfer_owner)
        {
            return None;
        }
        Some(transfer_dir.join(format!("{}.backup", id.to_ascii_lowercase())))
    };
    let response_json = |stream: &mut TcpStream, value: serde_json::Value| {
        let text = value.to_string();
        respond(
            stream,
            "200 OK",
            "application/json; charset=utf-8",
            text.as_bytes(),
        )
    };
    match action.as_str() {
        "export" | "bundle-export" => {
            let password = if action == "export" {
                fields.remove("password").and_then(|v| {
                    v.as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| Zeroizing::new(s.to_owned()))
                })
            } else {
                None
            };
            let peer_ids: Vec<String> = if action == "export" {
                let Some(peer) = fields
                    .remove("peerId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(stream, "400 Bad Request");
                };
                vec![peer]
            } else {
                let Some(values) = fields.remove("peerIds").and_then(|v| v.as_array().cloned())
                else {
                    return reject(stream, "400 Bad Request");
                };
                let Some(peers) = values
                    .into_iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                else {
                    return reject(stream, "400 Bad Request");
                };
                peers
            };
            if !fields.is_empty()
                || peer_ids.iter().any(|peer| {
                    peer_chat_active(&state, peer)
                        || history_delete_active(&state, &identity.public_id(), peer)
                })
            {
                return reject(stream, "409 Conflict");
            }
            // Export only reads history, so the State lock is not needed while it runs.
            drop(state);
            let id = match new_transfer_id() {
                Ok(id) => id,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            let mut created = false;
            let result = (|| -> io::Result<()> {
                let (_, mut file) = history::History::create_backup_transfer_file(
                    identity,
                    &format!("{id}.backup"),
                )?;
                created = true;
                if action == "export" {
                    history::History::export_backup_stream(
                        identity,
                        &peer_ids[0],
                        password.as_deref().map(String::as_str),
                        &mut file,
                    )?;
                } else {
                    history::History::export_backup_bundle_stream(identity, &peer_ids, &mut file)?;
                }
                file.flush()?;
                file.sync_all()?;
                Ok(())
            })();
            if let Err(error) = result {
                if created {
                    let _ = std::fs::remove_file(&path);
                }
                let status = if error.kind() == io::ErrorKind::InvalidInput {
                    "400 Bad Request"
                } else {
                    "500 Internal Server Error"
                };
                return respond(
                    stream,
                    status,
                    "text/plain; charset=utf-8",
                    client_message("요청 처리 오류", &error).as_bytes(),
                );
            }
            let size = match std::fs::metadata(&path) {
                Ok(meta) => meta.len(),
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            response_json(stream, serde_json::json!({"transferId": id, "size": size}))
        }
        "upload-start" => {
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            let id = match new_transfer_id() {
                Ok(id) => id,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            let (_, _file) = match history::History::create_backup_transfer_file(
                identity,
                &format!("{id}.backup"),
            ) {
                Ok(file) => file,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            response_json(stream, serde_json::json!({"transferId": id}))
        }
        "upload-chunk" => {
            // An import reads its transfer file while the State lock is released. A
            // chunk appended meanwhile would change what it is reading.
            if state.history_import_active {
                return reject(stream, "409 Conflict");
            }
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            let Some(offset) = fields.remove("offset").and_then(|v| v.as_u64()) else {
                return reject(stream, "400 Bad Request");
            };
            let Some(encoded) = fields
                .remove("data")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            let bytes = match BASE64.decode(encoded) {
                Ok(bytes) if !bytes.is_empty() && bytes.len() <= 256 * 1024 => bytes,
                _ => return reject(stream, "400 Bad Request"),
            };
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            let mut file = match crate::fsutil::private_options()
                .read(true)
                .append(true)
                .open(path)
            {
                Ok(file) => file,
                Err(_) => return reject(stream, "404 Not Found"),
            };
            if file
                .metadata()
                .map_or(true, |metadata| metadata.len() != offset)
            {
                return reject(stream, "409 Conflict");
            }
            if file.write_all(&bytes).and_then(|_| file.flush()).is_err() {
                return reject(stream, "507 Insufficient Storage");
            }
            response_json(
                stream,
                serde_json::json!({"offset": offset + bytes.len() as u64}),
            )
        }
        "read" => {
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            let Some(offset) = fields.remove("offset").and_then(|v| v.as_u64()) else {
                return reject(stream, "400 Bad Request");
            };
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(_) => return reject(stream, "404 Not Found"),
            };
            let size = match file.metadata() {
                Ok(metadata) => metadata.len(),
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            if offset > size {
                return reject(stream, "416 Range Not Satisfiable");
            }
            if file.seek(io::SeekFrom::Start(offset)).is_err() {
                return reject(stream, "500 Internal Server Error");
            }
            let mut chunk = vec![0; 256 * 1024];
            let read = match file.read(&mut chunk) {
                Ok(read) => read,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            chunk.truncate(read);
            response_json(
                stream,
                serde_json::json!({"transferId": id, "offset": offset, "size": size, "data": BASE64.encode(&chunk), "done": offset + read as u64 == size}),
            )
        }
        "import" => {
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            let password = fields
                .remove("password")
                .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                .filter(|v| !v.is_empty());
            let Some(policy) = take_legacy_policy(fields) else {
                return reject(stream, "400 Bad Request");
            };
            if !fields.is_empty()
                || any_chat_active(&state)
                || !state.active_history_deletions.is_empty()
                || state.history_import_active
            {
                return reject(stream, "409 Conflict");
            }
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            // Reserve the import under the lock, then release it: a large import must
            // not freeze every other request. The reservation keeps chats, other
            // imports and deletions out until it ends (the guard also clears it on panic).
            state.history_import_active = true;
            drop(state);
            let _import_guard = ImportGuard(Arc::clone(&state_handle));
            let result = history::History::import_backup_file_with_policy(
                identity,
                &path,
                password.as_deref().map(String::as_str),
                policy,
            );
            let cleanup = std::fs::remove_file(&path);
            let restored = match (result, cleanup) {
                (Ok(restored), Ok(())) => restored,
                (Err(error), Ok(())) => {
                    return respond(
                        stream,
                        "400 Bad Request",
                        "text/plain; charset=utf-8",
                        client_message("백업 가져오기 오류", &error).as_bytes(),
                    )
                }
                (Ok(_), Err(error)) => {
                    return respond(
                        stream,
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        format!(
                            "backup import completed but temporary upload cleanup failed ({})",
                            client_message("백업 업로드 정리 오류", &error)
                        )
                        .as_bytes(),
                    )
                }
                (Err(error), Err(cleanup)) => {
                    return respond(
                        stream,
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        format!(
                            "backup import failed ({}); temporary upload cleanup failed ({})",
                            client_message("백업 가져오기 오류", &error),
                            client_message("백업 업로드 정리 오류", &cleanup)
                        )
                        .as_bytes(),
                    )
                }
            };
            {
                let state = state_handle
                    .lock()
                    .map_err(|_| io::Error::other("state unavailable"))?;
                for (peer_id, message_count, _) in &restored {
                    update_closed_chat_history(
                        &state,
                        &identity.public_id(),
                        peer_id,
                        *message_count as u64,
                    );
                }
            }
            let response = if restored.len() == 1 {
                let (peer_id, count, linked) = &restored[0];
                serde_json::json!({"peerId": peer_id, "messageCount": count, "linkedIdentityRestored": linked})
            } else {
                serde_json::json!({"conversations": restored.iter().map(|(peer_id,count,linked)| serde_json::json!({"peerId":peer_id,"messageCount":count,"linkedIdentityRestored":linked})).collect::<Vec<_>>()})
            };
            response_json(stream, response)
        }
        "verify" => {
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            let password = fields
                .remove("password")
                .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                .filter(|v| !v.is_empty());
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            drop(state);
            match history::History::verify_backup_file(
                identity,
                &path,
                password.as_deref().map(String::as_str),
            ) {
                Ok((peer_id, count)) => response_json(
                    stream,
                    serde_json::json!({"peerId": peer_id, "messageCount": count}),
                ),
                Err(error) => respond(
                    stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    client_message("요청 처리 오류", &error).as_bytes(),
                ),
            }
        }
        "reprotect" => {
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            let Some(previous_code) = fields
                .remove("previousCode")
                .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
            else {
                return reject(stream, "400 Bad Request");
            };
            let previous_password = fields
                .remove("previousPassword")
                .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                .filter(|v| !v.is_empty());
            let replacement_password = fields
                .remove("replacementPassword")
                .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                .filter(|v| !v.is_empty());
            let Some(policy) = take_legacy_policy(fields) else {
                return reject(stream, "400 Bad Request");
            };
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            drop(state);
            let Some(previous_identity) = Identity::from_code(&previous_code) else {
                return reject(stream, "400 Bad Request");
            };
            let Some(source_path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            let output_id = match new_transfer_id() {
                Ok(id) => id,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            let Some(output_path) = get_transfer_path(&output_id) else {
                return reject(stream, "400 Bad Request");
            };
            let (_, mut output) = match history::History::create_backup_transfer_file(
                identity,
                &format!("{output_id}.backup"),
            ) {
                Ok(file) => file,
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            let result = history::History::reprotect_backup_file_with_policy(
                &previous_identity,
                identity,
                &source_path,
                &mut output,
                previous_password.as_deref().map(String::as_str),
                replacement_password.as_deref().map(String::as_str),
                policy,
            );
            let result = result.and_then(|count| {
                output.flush()?;
                output.sync_all()?;
                Ok(count)
            });
            drop(output);
            let cleanup_source = std::fs::remove_file(&source_path);
            let count = match (result, cleanup_source) {
                (Ok(count), Ok(())) => count,
                (Err(error), Ok(())) => {
                    let _ = std::fs::remove_file(&output_path);
                    return respond(
                        stream,
                        "400 Bad Request",
                        "text/plain; charset=utf-8",
                        client_message("요청 처리 오류", &error).as_bytes(),
                    );
                }
                (Ok(_), Err(error)) => {
                    let _ = std::fs::remove_file(&output_path);
                    return respond(
                        stream,
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        format!(
                            "reprotection completed but temporary upload cleanup failed ({})",
                            client_message("재보호 업로드 정리 오류", &error)
                        )
                        .as_bytes(),
                    );
                }
                (Err(error), Err(cleanup)) => {
                    let _ = std::fs::remove_file(&output_path);
                    return respond(
                        stream,
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        format!(
                            "reprotection failed ({}); temporary upload cleanup failed ({})",
                            client_message("재보호 오류", &error),
                            client_message("재보호 업로드 정리 오류", &cleanup)
                        )
                        .as_bytes(),
                    );
                }
            };
            let size = match std::fs::metadata(&output_path) {
                Ok(meta) => meta.len(),
                Err(_) => return reject(stream, "500 Internal Server Error"),
            };
            response_json(
                stream,
                serde_json::json!({"transferId": output_id, "size": size, "messageCount": count}),
            )
        }
        "cleanup" => {
            let Some(id) = fields
                .remove("transferId")
                .and_then(|v| v.as_str().map(str::to_owned))
            else {
                return reject(stream, "400 Bad Request");
            };
            if !fields.is_empty() {
                return reject(stream, "400 Bad Request");
            }
            let Some(path) = get_transfer_path(&id) else {
                return reject(stream, "400 Bad Request");
            };
            match std::fs::remove_file(path) {
                Ok(()) => response_json(stream, serde_json::json!({"ok": true})),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    response_json(stream, serde_json::json!({"ok": true}))
                }
                Err(error) => respond(
                    stream,
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    client_message("요청 처리 오류", &error).as_bytes(),
                ),
            }
        }
        _ => reject(stream, "400 Bad Request"),
    }
}
