//! Restore staging: sorting and merging imported messages into a conversation.

use super::*;

/// Plaintext of a staged record: time 8, sender 1, text length 4, the text, a proof flag 1
/// and, for a signed message, id 16 + signer 32 + recipient 32 + signature 64.
const STAGED_PLAIN_FIXED: usize = 8 + 1 + 4 + 1;
const STAGED_PROOF_BYTES: usize = 16 + 32 + 32 + 64;
const AEAD_TAG_BYTES: usize = 16;
const RESTORE_INDEX_LABEL: &[u8] = b"another-dimension-v2/restore-merge-index-hmac/v1";
/// Smallest and largest encrypted record the reader accepts (nonce excluded). The largest
/// is a signed message of the longest accepted text, tag included.
const STAGED_RECORD_MIN: usize = STAGED_PLAIN_FIXED + 1 + AEAD_TAG_BYTES;
const STAGED_RECORD_MAX: usize =
    STAGED_PLAIN_FIXED + MAX_MESSAGE_BYTES + STAGED_PROOF_BYTES + AEAD_TAG_BYTES;

pub(crate) struct RestoreStaging {
    pub(crate) directory: PathBuf,
    pub(crate) file: File,
    pub(crate) _lock: File,
    pub(crate) identity_id: String,
    pub(crate) peer_id: String,
    pub(crate) request_id: String,
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) count: u64,
    pub(crate) read_index: u64,
    pub(crate) read_end: u64,
    pub(crate) finished: bool,
    pub(crate) cleaned: bool,
}

impl RestoreStaging {
    pub(crate) fn create(identity: &Identity, peer_id: &str, request_id: &str) -> io::Result<Self> {
        validate_peer_id(peer_id)?;
        if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_data("invalid history restore request ID"));
        }
        let identity_id = identity.public_id();
        let root = data_directory()?
            .join(&identity_id)
            .join(".history-restore");
        crate::fsutil::create_private_dir_all(&root)?;
        set_private_directory(&root)?;
        cleanup_stale_restore_staging(&root)?;
        let directory = root.join(crate::hex::encode(&random_nonce()?));
        crate::fsutil::create_private_dir(&directory)?;
        set_private_directory(&directory)?;
        let result = (|| {
            let lock = crate::fsutil::private_options()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.join("owner.lock"))?;
            set_private_file(&lock)?;
            lock_restore_directory(&lock)?;
            let mut file = crate::fsutil::private_options()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.join("records.enc"))?;
            set_private_file(&file)?;
            file.write_all(RESTORE_STAGING_MAGIC)?;
            file.sync_data()?;
            let mut key = Zeroizing::new([0; 32]);
            Hkdf::<Sha256>::new(Some(request_id.as_bytes()), identity.storage_key().as_ref())
                .expand(
                    b"another-dimension-v2/history-restore-staging/v1",
                    key.as_mut(),
                )
                .map_err(|_| io::Error::other("restore staging key derivation failed"))?;
            Ok(Self {
                directory: directory.clone(),
                file,
                _lock: lock,
                identity_id,
                peer_id: peer_id.to_ascii_lowercase(),
                request_id: request_id.to_ascii_lowercase(),
                key,
                count: 0,
                read_index: 0,
                read_end: 0,
                finished: false,
                cleaned: false,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(directory);
        }
        result
    }

    pub(crate) fn append_verified(&mut self, message: &StoredMessage) -> io::Result<()> {
        if self.finished {
            return Err(invalid_data("restore staging is already finished"));
        }
        #[cfg(test)]
        if test_failure(FAIL_RESTORE_STAGE_WRITE) {
            return Err(io::Error::other("injected restore staging write failure"));
        }
        let plaintext = encode_history_plain(message)?;
        let nonce = random_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("restore staging key unavailable"))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &restore_staging_aad(
                        &self.identity_id,
                        &self.peer_id,
                        &self.request_id,
                        self.count,
                    ),
                },
            )
            .map_err(|_| io::Error::other("restore staging encryption failed"))?;
        let length = u32::try_from(encrypted.len())
            .map_err(|_| invalid_data("restore staging record is too large"))?;
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(&nonce)?;
        self.file.write_all(&encrypted)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("restore staging record count overflow"))?;
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut magic = [0; RESTORE_STAGING_MAGIC.len()];
        self.file.read_exact(&mut magic)?;
        if &magic != RESTORE_STAGING_MAGIC {
            return Err(invalid_data("invalid restore staging header"));
        }
        self.read_end = self.file.metadata()?.len();
        self.file
            .seek(SeekFrom::Start(RESTORE_STAGING_MAGIC.len() as u64))?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn next_record(&mut self) -> io::Result<Option<StoredMessage>> {
        if !self.finished {
            return Err(invalid_data("restore staging is not complete"));
        }
        let position = self.file.stream_position()?;
        if position == self.read_end {
            if self.read_index != self.count {
                return Err(invalid_data("restore staging record count mismatch"));
            }
            return Ok(None);
        }
        if position > self.read_end || self.read_end - position < (4 + NONCE_BYTES + 16) as u64 {
            return Err(invalid_data("restore staging is truncated"));
        }
        let mut length = [0; 4];
        self.file.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(STAGED_RECORD_MIN..=STAGED_RECORD_MAX).contains(&length)
            || self.read_end - position < 4 + NONCE_BYTES as u64 + length as u64
        {
            return Err(invalid_data("invalid restore staging record length"));
        }
        let mut nonce = [0; NONCE_BYTES];
        self.file.read_exact(&mut nonce)?;
        let mut encrypted = vec![0; length];
        self.file.read_exact(&mut encrypted)?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| invalid_data("restore staging key unavailable"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &encrypted,
                        aad: &restore_staging_aad(
                            &self.identity_id,
                            &self.peer_id,
                            &self.request_id,
                            self.read_index,
                        ),
                    },
                )
                .map_err(|_| invalid_data("restore staging authentication failed"))?,
        );
        let message = decode_history_plain(&plain, false)?;
        self.read_index += 1;
        Ok(Some(message))
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        if !self.finished {
            return Err(invalid_data("restore staging is not complete"));
        }
        self.file
            .seek(SeekFrom::Start(RESTORE_STAGING_MAGIC.len() as u64))?;
        self.read_index = 0;
        Ok(())
    }

    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    #[cfg(test)]
    pub(crate) fn storage_bytes(&self) -> io::Result<u64> {
        self.file.metadata().map(|metadata| metadata.len())
    }

    pub(crate) fn cleanup(mut self) -> io::Result<()> {
        #[cfg(test)]
        if test_failure_once(FAIL_RESTORE_CLEANUP_ONCE) {
            return Err(io::Error::other("injected restore staging cleanup failure"));
        }
        std::fs::remove_dir_all(&self.directory)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for RestoreStaging {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

pub(crate) fn remove_restore_result_file(path: &std::path::Path) -> io::Result<()> {
    #[cfg(test)]
    if test_failure(FAIL_RESTORE_RESULT_CLEANUP) {
        return Err(io::Error::other("injected restore result cleanup failure"));
    }
    std::fs::remove_file(path)
}

pub(crate) fn restore_staging_aad(
    identity_id: &str,
    peer_id: &str,
    request_id: &str,
    index: u64,
) -> Vec<u8> {
    [
        RESTORE_STAGING_MAGIC.as_slice(),
        identity_id.as_bytes(),
        peer_id.as_bytes(),
        request_id.as_bytes(),
        &index.to_be_bytes(),
    ]
    .concat()
}

pub(crate) fn lock_restore_directory(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only operates on the live descriptor owned by `file`.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn cleanup_stale_restore_staging(root: &std::path::Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory_name = entry.file_name();
        let directory_name = directory_name.to_string_lossy();
        if directory_name.len() != NONCE_BYTES * 2
            || !directory_name.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let records_path = entry.path().join("records.enc");
        if !std::fs::symlink_metadata(&records_path)
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        let mut records = File::open(&records_path)?;
        let mut magic = [0; RESTORE_STAGING_MAGIC.len()];
        if records.read_exact(&mut magic).is_err() || &magic != RESTORE_STAGING_MAGIC {
            continue;
        }
        let lock_path = entry.path().join("owner.lock");
        let lock = match crate::fsutil::private_options()
            .read(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock only operates on the live descriptor owned by `lock`.
            let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(error);
            }
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

pub(crate) fn cleanup_restore_merge_attempt(root: &std::path::Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "merge-index"
            || (entry.file_type()?.is_file()
                && ((name.starts_with("sort-") || name.starts_with("merge-"))
                    && name.ends_with(".adlog")))
        {
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

pub(crate) fn cleanup_orphaned_restore_outputs(
    directory: &std::path::Path,
    history_path: &std::path::Path,
) -> io::Result<()> {
    let filename = history_path
        .file_name()
        .ok_or_else(|| invalid_data("conversation filename unavailable"))?
        .to_string_lossy();
    let prefix = format!(".{filename}.restore-merge-");
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name
            .strip_prefix(&prefix)
            .and_then(|tail| tail.strip_suffix(".tmp"))
        else {
            continue;
        };
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

pub(crate) struct RestoreDiskIndex {
    pub(crate) file: File,
    pub(crate) capacity: u64,
    pub(crate) key: Zeroizing<[u8; 32]>,
}

impl RestoreDiskIndex {
    pub(crate) const SLOT_BYTES: u64 = 82;

    pub(crate) fn new(staging: &RestoreStaging, entries: u64) -> io::Result<Self> {
        let capacity = entries
            .checked_mul(2)
            .and_then(u64::checked_next_power_of_two)
            .unwrap_or(u64::MAX)
            .max(16);
        let file = crate::fsutil::private_options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(staging.directory.join("merge-index"))?;
        set_private_file(&file)?;
        file.set_len(
            capacity
                .checked_mul(Self::SLOT_BYTES)
                .ok_or_else(|| invalid_data("restore index is too large"))?,
        )?;
        Ok(Self {
            file,
            capacity,
            // The staging key encrypts the records, so the index gets a key of its own.
            key: crate::identity::purpose_key(&staging.key, RESTORE_INDEX_LABEL),
        })
    }

    pub(crate) fn index_message(
        &mut self,
        message: &StoredMessage,
        offered: bool,
    ) -> io::Result<bool> {
        #[cfg(test)]
        if test_failure(FAIL_RESTORE_INDEX) {
            return Err(io::Error::other("injected restore index write failure"));
        }
        if let Some(proof) = &message.proof {
            self.index_signed(proof.id, message, offered)
        } else {
            self.index_legacy(message, offered)
        }
    }

    pub(crate) fn index_signed(
        &mut self,
        id: [u8; 16],
        message: &StoredMessage,
        offered: bool,
    ) -> io::Result<bool> {
        let mut id_input = b"signed-id\0".to_vec();
        id_input.extend_from_slice(&id);
        let id_hash = keyed_restore_hash(&self.key, &id_input);
        let mut content_input = b"signed-content\0".to_vec();
        content_input.extend_from_slice(&encode_history_plain(message)?);
        let content_hash = keyed_restore_hash(&self.key, &content_input);
        let slot = self.find_slot(1, &id_hash)?;
        if let Some((_, stored)) = slot {
            if stored[34..66] != content_hash {
                return Err(invalid_data("message ID collision in restore proposal"));
            }
            return Ok(!offered);
        }
        self.write_slot(self.empty_slot(1, &id_hash, &content_hash, 0, 0)?)?;
        Ok(true)
    }

    pub(crate) fn index_legacy(
        &mut self,
        message: &StoredMessage,
        offered: bool,
    ) -> io::Result<bool> {
        let mut key_input = b"legacy-message\0".to_vec();
        key_input.extend_from_slice(&encode_history_plain(message)?);
        let legacy_hash = keyed_restore_hash(&self.key, &key_input);
        let slot = self.find_slot(2, &legacy_hash)?;
        let (existing, seen) = slot
            .as_ref()
            .map(|(_, raw)| {
                (
                    u64::from_be_bytes(raw[66..74].try_into().expect("fixed slot")),
                    u64::from_be_bytes(raw[74..82].try_into().expect("fixed slot")),
                )
            })
            .unwrap_or((0, 0));
        let (next_existing, next_seen, keep) = if offered {
            let next_seen = seen
                .checked_add(1)
                .ok_or_else(|| invalid_data("legacy restore duplicate count overflow"))?;
            (existing, next_seen, next_seen > existing)
        } else {
            (
                existing
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("legacy restore duplicate count overflow"))?,
                seen,
                true,
            )
        };
        let raw = self.empty_slot(2, &legacy_hash, &[0; 32], next_existing, next_seen)?;
        if let Some((position, _)) = slot {
            self.file.seek(SeekFrom::Start(position))?;
            self.file.write_all(&raw)?;
        } else {
            self.write_slot(raw)?;
        }
        Ok(keep)
    }

    pub(crate) fn find_slot(
        &mut self,
        kind: u8,
        digest: &[u8; 32],
    ) -> io::Result<Option<(u64, [u8; 82])>> {
        let start =
            u64::from_be_bytes(digest[..8].try_into().expect("fixed digest")) & (self.capacity - 1);
        for offset in 0..self.capacity {
            let slot = (start + offset) & (self.capacity - 1);
            let position = slot * Self::SLOT_BYTES;
            self.file.seek(SeekFrom::Start(position))?;
            let mut raw = [0; 82];
            self.file.read_exact(&mut raw)?;
            if raw[0] == 0 {
                return Ok(None);
            }
            if raw[0] != 1 || raw[1] != kind {
                continue;
            }
            if &raw[2..34] == digest {
                return Ok(Some((position, raw)));
            }
        }
        Err(invalid_data("restore disk index is full"))
    }

    pub(crate) fn empty_slot(
        &self,
        kind: u8,
        digest: &[u8; 32],
        value: &[u8; 32],
        existing: u64,
        seen: u64,
    ) -> io::Result<[u8; 82]> {
        let mut raw = [0; 82];
        raw[0] = 1;
        raw[1] = kind;
        raw[2..34].copy_from_slice(digest);
        raw[34..66].copy_from_slice(value);
        raw[66..74].copy_from_slice(&existing.to_be_bytes());
        raw[74..82].copy_from_slice(&seen.to_be_bytes());
        Ok(raw)
    }

    pub(crate) fn write_slot(&mut self, raw: [u8; 82]) -> io::Result<()> {
        let digest = &raw[2..34];
        let start =
            u64::from_be_bytes(digest[..8].try_into().expect("fixed digest")) & (self.capacity - 1);
        for offset in 0..self.capacity {
            let position = ((start + offset) & (self.capacity - 1)) * Self::SLOT_BYTES;
            self.file.seek(SeekFrom::Start(position))?;
            let mut existing = [0; 82];
            self.file.read_exact(&mut existing)?;
            if existing[0] == 0 {
                self.file.seek(SeekFrom::Start(position))?;
                self.file.write_all(&raw)?;
                return Ok(());
            }
        }
        Err(invalid_data("restore disk index is full"))
    }
}

pub(crate) fn keyed_restore_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn write_restore_sort_run(
    directory: &std::path::Path,
    serial: &mut u64,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    items: &mut Vec<(u64, StoredMessage)>,
) -> io::Result<PathBuf> {
    items.sort_by_key(|(_, message)| message.unix_time);
    let path = directory.join(format!("sort-{:016x}.adlog", *serial));
    *serial = serial
        .checked_add(1)
        .ok_or_else(|| invalid_data("restore sort run counter overflow"))?;
    let mut file = crate::fsutil::private_options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    set_private_file(&file)?;
    let format = write_log_header(&mut file)?;
    for (index, (_, message)) in items.drain(..).enumerate() {
        file.write_all(&encode_record(
            key,
            identity_id,
            peer_id,
            index as u64,
            &format,
            &message,
        )?)?;
    }
    file.sync_all()?;
    Ok(path)
}

pub(crate) fn merge_encrypted_runs(
    input_paths: &[PathBuf],
    output_path: &std::path::Path,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
) -> io::Result<(u64, LogFormat)> {
    if input_paths.len() > RESTORE_MERGE_FAN_IN {
        return Err(invalid_data("too many restore sort inputs"));
    }
    let mut readers = input_paths
        .iter()
        .map(|path| {
            open_history_reader(
                path.clone(),
                Zeroizing::new(*key),
                identity_id.to_owned(),
                peer_id.to_owned(),
            )
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut current = Vec::<Option<StoredMessage>>::with_capacity(readers.len());
    let mut heap = BinaryHeap::<Reverse<(u64, usize)>>::new();
    for (index, reader) in readers.iter_mut().enumerate() {
        let message = reader.next_record()?;
        if let Some(message) = &message {
            heap.push(Reverse((message.unix_time, index)));
        }
        current.push(message);
    }
    let mut output = crate::fsutil::private_options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(output_path)?;
    set_private_file(&output)?;
    let format = write_log_header(&mut output)?;
    let mut output_index = 0u64;
    while let Some(Reverse((_, source))) = heap.pop() {
        let message = current[source]
            .take()
            .ok_or_else(|| invalid_data("restore sort cursor is unavailable"))?;
        output.write_all(&encode_record(
            key,
            identity_id,
            peer_id,
            output_index,
            &format,
            &message,
        )?)?;
        output_index = output_index
            .checked_add(1)
            .ok_or_else(|| invalid_data("restored history is too large"))?;
        #[cfg(test)]
        if output_index == 1 && test_failure(FAIL_RESTORE_OUTPUT) {
            return Err(io::Error::other("injected restore output write failure"));
        }
        current[source] = readers[source].next_record()?;
        if let Some(next) = &current[source] {
            heap.push(Reverse((next.unix_time, source)));
        }
    }
    output.sync_all()?;
    Ok((output_index, format))
}

pub(crate) fn add_restore_run_level(
    mut path: PathBuf,
    levels: &mut Vec<Vec<PathBuf>>,
    serial: &mut u64,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    directory: &std::path::Path,
) -> io::Result<()> {
    let mut level = 0usize;
    loop {
        if levels.len() <= level {
            levels.push(Vec::new());
        }
        levels[level].push(path);
        if levels[level].len() < RESTORE_MERGE_FAN_IN {
            return Ok(());
        }
        let inputs = std::mem::take(&mut levels[level]);
        let output = directory.join(format!("merge-{:016x}.adlog", *serial));
        *serial = serial
            .checked_add(1)
            .ok_or_else(|| invalid_data("restore merge run counter overflow"))?;
        merge_encrypted_runs(&inputs, &output, key, identity_id, peer_id)?;
        for input in inputs {
            std::fs::remove_file(input)?;
        }
        path = output;
        level += 1;
    }
}

/// Sorts messages by time without holding them all in memory: they are collected in a
/// buffer, written out as sorted runs when it fills, and the runs are merged level by
/// level so the number of open runs stays bounded.
pub(crate) struct RestoreSorter<'a> {
    directory: &'a std::path::Path,
    key: &'a [u8; 32],
    identity_id: &'a str,
    peer_id: &'a str,
    buffer: Vec<(u64, StoredMessage)>,
    buffer_bytes: usize,
    peak_buffer_bytes: usize,
    levels: Vec<Vec<PathBuf>>,
    serial: u64,
}

/// What a finished `RestoreSorter` leaves behind.
pub(crate) struct SortedRuns {
    pub(crate) runs: Vec<PathBuf>,
    /// The next unused file number in the directory, for further merge outputs.
    pub(crate) serial: u64,
    #[cfg(test)]
    pub(crate) peak_buffer_bytes: usize,
}

impl<'a> RestoreSorter<'a> {
    pub(crate) fn new(
        directory: &'a std::path::Path,
        key: &'a [u8; 32],
        identity_id: &'a str,
        peer_id: &'a str,
    ) -> Self {
        Self {
            directory,
            key,
            identity_id,
            peer_id,
            buffer: Vec::new(),
            buffer_bytes: 0,
            peak_buffer_bytes: 0,
            levels: Vec::new(),
            serial: 0,
        }
    }

    fn spill(&mut self) -> io::Result<()> {
        let run = write_restore_sort_run(
            self.directory,
            &mut self.serial,
            self.key,
            self.identity_id,
            self.peer_id,
            &mut self.buffer,
        )?;
        self.buffer_bytes = 0;
        add_restore_run_level(
            run,
            &mut self.levels,
            &mut self.serial,
            self.key,
            self.identity_id,
            self.peer_id,
            self.directory,
        )
    }

    pub(crate) fn push(&mut self, message: StoredMessage) -> io::Result<()> {
        let size = std::mem::size_of::<StoredMessage>()
            + message.text.len()
            + if message.proof.is_some() { 144 } else { 0 };
        if !self.buffer.is_empty()
            && (self.buffer.len() >= RESTORE_SORT_RUN_RECORDS
                || self.buffer_bytes.saturating_add(size) > RESTORE_SORT_RUN_BYTES)
        {
            self.spill()?;
        }
        self.buffer_bytes = self.buffer_bytes.saturating_add(size);
        self.peak_buffer_bytes = self.peak_buffer_bytes.max(self.buffer_bytes);
        self.buffer.push((0, message));
        if self.buffer.len() >= RESTORE_SORT_RUN_RECORDS
            || self.buffer_bytes >= RESTORE_SORT_RUN_BYTES
        {
            self.spill()?;
        }
        Ok(())
    }

    /// Writes out what is still buffered and returns the runs that remain.
    pub(crate) fn finish(mut self) -> io::Result<SortedRuns> {
        if !self.buffer.is_empty() {
            self.spill()?;
        }
        Ok(SortedRuns {
            runs: self.levels.into_iter().flatten().collect(),
            serial: self.serial,
            #[cfg(test)]
            peak_buffer_bytes: self.peak_buffer_bytes,
        })
    }
}

impl History {
    pub(crate) fn merge_restore_staging(
        &mut self,
        identity: &Identity,
        staging: &mut RestoreStaging,
    ) -> io::Result<RestoreMergeSummary> {
        if identity.public_id() != self.identity_id
            || staging.identity_id != self.identity_id
            || staging.peer_id != self.peer_id
            || !staging.finished
        {
            return Err(invalid_data(
                "restore staging does not match this conversation",
            ));
        }
        let operation_lock = Arc::clone(&self.operation_lock);
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock_for_path(
            &self.path,
            &self.identity_id,
            &self.peer_id,
            &self.key,
        )?;
        let mut final_temp = None::<PathBuf>;
        let result = (|| {
            let stage_root = staging.directory.clone();
            cleanup_restore_merge_attempt(&stage_root)?;
            let mut count_reader = open_history_reader(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
            )?;
            let mut existing_count = 0u64;
            while count_reader.next_record()?.is_some() {
                existing_count = existing_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("history record count overflow"))?;
            }
            let total_capacity = existing_count
                .checked_add(staging.count())
                .ok_or_else(|| invalid_data("restore record count overflow"))?;
            let mut index = RestoreDiskIndex::new(staging, total_capacity)?;
            let mut sorter =
                RestoreSorter::new(&stage_root, &self.key, &self.identity_id, &self.peer_id);
            let mut existing = open_history_reader(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
            )?;
            while let Some(message) = existing.next_record()? {
                index.index_message(&message, false)?;
                sorter.push(message)?;
            }
            staging.rewind()?;
            let mut imported_count = 0u64;
            while let Some(message) = staging.next_record()? {
                if index.index_message(&message, true)? {
                    imported_count = imported_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("restore count overflow"))?;
                    sorter.push(message)?;
                }
            }
            let sorted = sorter.finish()?;
            #[cfg(test)]
            let peak_buffer_bytes = sorted.peak_buffer_bytes;
            let mut runs = sorted.runs;
            let mut serial = sorted.serial;
            while runs.len() > RESTORE_MERGE_FAN_IN {
                let mut reduced = Vec::new();
                for group in runs.chunks(RESTORE_MERGE_FAN_IN) {
                    if group.len() == 1 {
                        reduced.push(group[0].clone());
                        continue;
                    }
                    let output = stage_root.join(format!("merge-{:016x}.adlog", serial));
                    serial = serial
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("restore merge run counter overflow"))?;
                    merge_encrypted_runs(
                        group,
                        &output,
                        &self.key,
                        &self.identity_id,
                        &self.peer_id,
                    )?;
                    for input in group {
                        std::fs::remove_file(input)?;
                    }
                    reduced.push(output);
                }
                runs = reduced;
            }
            let suffix = crate::hex::encode(&random_nonce()?);
            let filename = self
                .path
                .file_name()
                .ok_or_else(|| invalid_data("conversation filename unavailable"))?;
            let temporary = self.path.with_file_name(format!(
                ".{}.restore-merge-{suffix}.tmp",
                filename.to_string_lossy()
            ));
            final_temp = Some(temporary.clone());
            let (total_count, final_format) = merge_encrypted_runs(
                &runs,
                &temporary,
                &self.key,
                &self.identity_id,
                &self.peer_id,
            )?;
            let append_file = crate::fsutil::private_options()
                .read(true)
                .append(true)
                .open(&temporary)?;
            set_private_file(&append_file)?;
            #[cfg(test)]
            if test_failure(FAIL_RESTORE_RENAME) {
                return Err(io::Error::other(
                    "injected restore atomic replacement failure",
                ));
            }
            self.announce_replacement(&final_format)?;
            crate::fsutil::rename_durable(&temporary, &self.path)?;
            final_temp = None;
            let file_version = history_file_version(&append_file)?;
            self.file = append_file;
            self.next_index = total_count;
            self.file_version = file_version;
            self.format = final_format;
            self.record_anchor();
            Ok(RestoreMergeSummary {
                total_count,
                imported_count,
                #[cfg(test)]
                peak_sort_buffer_bytes: peak_buffer_bytes,
            })
        })();
        let result = match (result, final_temp) {
            (Err(error), Some(path)) => match remove_restore_result_file(&path) {
                Ok(()) => Err(error),
                Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
                Err(cleanup) => Err(io::Error::other(format!(
                    "restore merge failed ({error}); temporary result cleanup failed ({cleanup}); recoverable file: {}",
                    path.display()
                ))),
            },
            (result, _) => result,
        };
        unlock_conversation_file(file_lock);
        result
    }
}
