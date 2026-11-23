use super::{
    backup_transfer_file_identity, cleanup_stale_transfer_workspace,
    cleanup_stale_transfer_workspaces, decode_peer_id, lock_transfer_owner, set_private_directory,
    set_private_file, History, MessageSender, RestoreStaging, StoredMessage,
    MAX_LEGACY_BACKUP_BYTES, MAX_MESSAGE_BYTES, NONCE_BYTES,
};
use crate::identity::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct IsolatedData(PathBuf);

impl IsolatedData {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ad2-history-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(path.clone()));
        Self(path)
    }
}

impl Drop for IsolatedData {
    fn drop(&mut self) {
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn message(time: u64, text: &str) -> StoredMessage {
    StoredMessage {
        unix_time: time,
        sender: MessageSender::Me,
        text: text.to_owned(),
        proof: None,
    }
}

#[test]
fn backup_transfer_cleanup_only_removes_manifested_files_from_unlocked_workspaces() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let active_workspace = History::backup_transfer_directory(&identity).unwrap();
    let active_name = format!("{}.backup", "b".repeat(64));
    let (active_path, mut active_file) =
        History::create_backup_transfer_file(&identity, &active_name).unwrap();
    active_file.write_all(b"active app transfer").unwrap();
    drop(active_file);
    let active_child_names = [
        format!("bundle-child-{}.tmp", "3".repeat(NONCE_BYTES * 2)),
        format!("bundle-import-child-{}.tmp", "4".repeat(NONCE_BYTES * 2)),
    ];
    for name in &active_child_names {
        let (_, file) = History::create_backup_transfer_file(&identity, name).unwrap();
        drop(file);
    }
    let active_manifest = std::fs::read_to_string(active_workspace.join("manifest")).unwrap();
    assert!(active_child_names.iter().all(|name| active_manifest
        .lines()
        .any(|line| line.starts_with(&format!("{name}\t")))));

    let transfer_root = active_workspace.parent().unwrap().to_path_buf();
    let legacy_name = format!("{}.backup", "c".repeat(64));
    let legacy_path = transfer_root.join(&legacy_name);
    std::fs::write(&legacy_path, b"unowned legacy transfer").unwrap();
    let user_backup = transfer_root.join("user-original.backup");
    std::fs::write(&user_backup, b"user original backup").unwrap();

    let stale_id = "a".repeat(NONCE_BYTES * 2);
    let stale_workspace = transfer_root.join(format!(".process-{stale_id}"));
    std::fs::create_dir(&stale_workspace).unwrap();
    set_private_directory(&stale_workspace).unwrap();
    let lock_path = stale_workspace.join("owner.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .unwrap();
    set_private_file(&lock).unwrap();
    lock_transfer_owner(&lock).unwrap();

    let names = [
        format!("{}.backup", "d".repeat(64)),
        format!("bundle-child-{}.tmp", "e".repeat(NONCE_BYTES * 2)),
        format!("bundle-import-child-{}.tmp", "f".repeat(NONCE_BYTES * 2)),
    ];
    let manifest_path = stale_workspace.join("manifest");
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .unwrap();
    set_private_file(&manifest).unwrap();
    manifest.write_all(b"ADBT1\n").unwrap();
    let mut stale_paths = Vec::new();
    for name in &names {
        let file_path = stale_workspace.join(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .unwrap();
        set_private_file(&file).unwrap();
        let (device, inode) = backup_transfer_file_identity(&file.metadata().unwrap()).unwrap();
        writeln!(manifest, "{name}\t{device}\t{inode}").unwrap();
        stale_paths.push(file_path);
    }
    let unregistered_user_file = stale_workspace.join("keep-this.txt");
    std::fs::write(&unregistered_user_file, b"not in manifest").unwrap();
    drop(manifest);
    drop(lock);

    assert_eq!(
        cleanup_stale_transfer_workspaces(&transfer_root).unwrap(),
        1
    );
    assert!(stale_paths.iter().all(|path| !path.exists()));
    assert!(!stale_workspace.join("owner.lock").exists());
    assert!(unregistered_user_file.exists());
    assert!(stale_workspace.exists());
    assert!(active_path.exists());
    assert!(active_workspace.join("owner.lock").exists());
    assert!(legacy_path.exists());
    assert!(user_backup.exists());
}

#[test]
fn backup_transfer_cleanup_retains_files_when_manifest_cannot_prove_ownership() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let active_workspace = History::backup_transfer_directory(&identity).unwrap();
    let transfer_root = active_workspace.parent().unwrap();
    let stale_workspace = transfer_root.join(format!(".process-{}", "1".repeat(NONCE_BYTES * 2)));
    std::fs::create_dir(&stale_workspace).unwrap();
    set_private_directory(&stale_workspace).unwrap();
    let lock_path = stale_workspace.join("owner.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .unwrap();
    set_private_file(&lock).unwrap();
    lock_transfer_owner(&lock).unwrap();
    let temp_name = format!("{}.backup", "2".repeat(64));
    let temp_path = stale_workspace.join(&temp_name);
    std::fs::write(&temp_path, b"retain if ownership is unclear").unwrap();
    let manifest_path = stale_workspace.join("manifest");
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .unwrap();
    set_private_file(&manifest).unwrap();
    writeln!(manifest, "ADBT1").unwrap();
    writeln!(manifest, "{temp_name}\t0\t0").unwrap();
    writeln!(manifest, "../user-original.backup\t0\t0").unwrap();
    drop(manifest);
    drop(lock);

    let error = cleanup_stale_transfer_workspace(&stale_workspace).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(temp_path.exists());
    assert!(lock_path.exists());
    assert!(manifest_path.exists());
}

fn encode_v6_fixture(identity: &Identity, peer_id: &str, messages: &[StoredMessage]) -> Vec<u8> {
    let peer = super::decode_peer_id(peer_id).unwrap();
    let links = super::backup_links_for(identity, peer_id).unwrap();
    let key = super::derive_backup_key(&identity.storage_key());
    let mut aad = super::backup_aad(identity, super::BACKUP_STREAM_V6_MAGIC, None);
    aad.push(0);
    aad.extend_from_slice(&peer);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let mut output = Vec::new();
    output.extend_from_slice(super::BACKUP_STREAM_V6_MAGIC);
    output.push(0);
    output.extend_from_slice(&peer);
    for (index, stored) in messages.iter().enumerate() {
        write_v6_fixture_frame(
            &mut output,
            &cipher,
            &aad,
            1,
            index as u64,
            &super::encode_history_plain(stored).unwrap(),
        );
    }
    write_v6_fixture_frame(
        &mut output,
        &cipher,
        &aad,
        0,
        messages.len() as u64,
        &super::encode_backup_links(&links).unwrap(),
    );
    output
}

fn write_v6_fixture_frame(
    output: &mut Vec<u8>,
    cipher: &ChaCha20Poly1305,
    aad: &[u8],
    kind: u8,
    index: u64,
    plaintext: &[u8],
) {
    let nonce = super::random_nonce().unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &super::backup_stream_frame_aad(aad, kind, index),
            },
        )
        .unwrap();
    output.push(kind);
    output.extend_from_slice(&index.to_be_bytes());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    output.extend_from_slice(&encrypted);
}

fn bundle3_children(bundle: &[u8]) -> Vec<(usize, usize)> {
    assert!(bundle.starts_with(super::BACKUP_STREAM_BUNDLE_MAGIC));
    let count = u32::from_be_bytes(bundle[24..28].try_into().unwrap()) as usize;
    let mut offset = 28;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        let length = u64::from_be_bytes(bundle[offset..offset + 8].try_into().unwrap()) as usize;
        let start = offset + 8;
        let end = start + length;
        children.push((offset, end));
        offset = end;
    }
    assert_eq!(offset + super::BACKUP_BUNDLE_TAG_BYTES, bundle.len());
    children
}

fn append_bundle3_child(output: &mut Vec<u8>, bundle: &[u8], child: (usize, usize)) {
    output.extend_from_slice(&bundle[child.0..child.0 + 8]);
    output.extend_from_slice(&bundle[child.0 + 8..child.1]);
}

#[test]
fn sequential_history_reader_holds_file_length_snapshot_without_repairing() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "39".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "snapshot one")).unwrap();
    let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
    history.append(&message(2, "appended later")).unwrap();
    assert_eq!(
        reader.next_record().unwrap(),
        Some(message(1, "snapshot one"))
    );
    assert_eq!(reader.next_record().unwrap(), None);
}

#[test]
fn append_uses_cached_index_and_refreshes_stale_handles_safely() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "3f".repeat(32);
    let (mut first, _, _) = History::open(&identity, &peer).unwrap();
    for index in 0..256 {
        first.append(&message(index, "cached append")).unwrap();
    }
    let (mut second, _, _) = History::open(&identity, &peer).unwrap();

    super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
    first.append(&message(257, "fast path")).unwrap();
    super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 0));

    super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
    second
        .append(&message(258, "external append refresh"))
        .unwrap();
    super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 1));

    first
        .replace(&[
            message(300, "replacement one"),
            message(301, "replacement two"),
        ])
        .unwrap();
    super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
    second.append(&message(302, "after replacement")).unwrap();
    super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 2));

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&second.path)
        .unwrap();
    file.seek(SeekFrom::Start(8 + 4 + 12 + 2)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Current(-1)).unwrap();
    file.write_all(&[byte[0] ^ 0x80]).unwrap();
    file.sync_all().unwrap();
    let length = file.metadata().unwrap().len();
    drop(file);
    assert!(second.append(&message(303, "must fail")).is_err());
    assert_eq!(std::fs::metadata(&second.path).unwrap().len(), length);
    let result = History::open(&identity, &peer);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn history_pages_are_bounded_and_stale_selection_is_rejected() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "41".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    for index in 0..237 {
        history.append(&message(index, "page item")).unwrap();
    }
    let first = History::read_page(&identity, &peer, None, 50).unwrap();
    assert_eq!(first.entries.len(), 50);
    let cursor = first.next.clone().unwrap();
    assert_eq!(cursor.index, 50);
    let second = History::read_page(&identity, &peer, Some(&cursor), 50).unwrap();
    assert_eq!(second.entries.len(), 50);
    assert_eq!(second.entries[0].index, 50);

    history
        .append(&message(238, "concurrent update invalidates selection"))
        .unwrap();
    let selected = HashSet::from([0usize]);
    let stale = History::delete_indices_if_version(&identity, &peer, &first.version, &selected);
    assert_eq!(stale.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        History::read_page(&identity, &peer, None, 100)
            .unwrap()
            .entries
            .len(),
        100
    );

    let fresh = History::read_page(&identity, &peer, None, 100).unwrap();
    let kept =
        History::delete_indices_if_version(&identity, &peer, &fresh.version, &selected).unwrap();
    assert_eq!(kept.remaining_count, 237);
    let after = History::read_page(&identity, &peer, None, 100).unwrap();
    assert_eq!(after.entries[0].message.text, "page item");
    assert_eq!(History::list(&identity).unwrap()[0].message_count, 237);
}

#[test]
fn streaming_history_deletion_preserves_boundaries_rejects_bad_indices_and_refreshes_handles() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "42".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    let mut first = message(10, "same timestamp one");
    first.sender = MessageSender::Other;
    first.proof = Some(super::MessageProof {
        id: [9; 16],
        signer: [1; 32],
        recipient: [2; 32],
        signature: [3; 64],
    });
    let second = message(10, "same timestamp two");
    let last = message(20, "inclusive end");
    history
        .replace(&[first.clone(), second.clone(), last.clone()])
        .unwrap();
    let old = History::read_page(&identity, &peer, None, 10).unwrap();
    let out_of_range = HashSet::from([3]);
    assert_eq!(
        History::delete_indices_if_version(&identity, &peer, &old.version, &out_of_range)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let selected_same_time = HashSet::from([1]);
    let selected_result =
        History::delete_indices_if_version(&identity, &peer, &old.version, &selected_same_time)
            .unwrap();
    assert_eq!(selected_result.remaining_count, 2);
    let after_selection = History::read_page(&identity, &peer, None, 10).unwrap();
    assert_eq!(after_selection.entries[0].message, first);
    assert_eq!(
        after_selection.entries[0]
            .message
            .proof
            .as_ref()
            .unwrap()
            .id,
        [9; 16]
    );
    let ranged = History::delete_time_range(&identity, &peer, 10, 10).unwrap();
    assert_eq!(ranged.deleted_count, 1);
    assert_eq!(ranged.remaining_count, 1);
    let page = History::read_page(&identity, &peer, None, 10).unwrap();
    assert_eq!(page.entries[0].message, last);
    history
        .append(&message(30, "append after rewrite"))
        .unwrap();
    let page = History::read_page(&identity, &peer, None, 10).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[1].message.text, "append after rewrite");

    let page = History::read_page(&identity, &peer, None, 10).unwrap();
    let selected = HashSet::from([0]);
    let deleted =
        History::delete_indices_if_version(&identity, &peer, &page.version, &selected).unwrap();
    assert_eq!(deleted.remaining_count, 1);
}

#[test]
fn streaming_history_deletion_failures_preserve_original_and_report_cleanup_path() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "43".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "preserve me")).unwrap();
    history.append(&message(2, "keep this record")).unwrap();
    let before = std::fs::read(&history.path).unwrap();
    let page = History::read_page(&identity, &peer, None, 10).unwrap();
    let selected = HashSet::from([0]);
    for failure in [
        super::FAIL_HISTORY_DELETE_WRITE,
        super::FAIL_HISTORY_DELETE_SYNC,
        super::FAIL_HISTORY_DELETE_RENAME,
    ] {
        super::TEST_FAILURES.with(|failures| failures.set(failure));
        assert!(
            History::delete_indices_if_version(&identity, &peer, &page.version, &selected).is_err()
        );
        assert_eq!(std::fs::read(&history.path).unwrap(), before);
    }
    super::TEST_FAILURES.with(|failures| {
        failures.set(super::FAIL_HISTORY_DELETE_WRITE | super::FAIL_HISTORY_DELETE_CLEANUP)
    });
    let error = History::delete_indices_if_version(&identity, &peer, &page.version, &selected)
        .unwrap_err()
        .to_string();
    assert!(error.contains("recoverable file:"));
    assert_eq!(std::fs::read(&history.path).unwrap(), before);
    let retry =
        History::delete_indices_if_version(&identity, &peer, &page.version, &selected).unwrap();
    assert_eq!(retry.remaining_count, 1);
}

#[test]
fn streaming_history_deletion_rejects_partial_source_without_repairing_it() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "46".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "valid record")).unwrap();
    let mut file = OpenOptions::new().append(true).open(&history.path).unwrap();
    file.write_all(&[0, 0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let original = std::fs::read(&history.path).unwrap();
    assert!(History::delete_time_range(&identity, &peer, 0, 2).is_err());
    assert_eq!(std::fs::read(&history.path).unwrap(), original);
}

fn write_synthetic_history(history: &History, count: u64, text: &str) -> u64 {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&history.path)
        .unwrap();
    let format = super::write_log_header(&mut file).unwrap();
    for index in 0..count {
        let record = super::encode_record(
            &history.key,
            &history.identity_id,
            &history.peer_id,
            index,
            &format,
            &message(index, text),
        )
        .unwrap();
        file.write_all(&record).unwrap();
    }
    file.sync_all().unwrap();
    file.metadata().unwrap().len()
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn streaming_selection_deletion_handles_over_one_hundred_thousand_records() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "44".repeat(32);
    let (history, _, _) = History::open(&identity, &peer).unwrap();
    let _bytes = write_synthetic_history(&history, 100_005, "bounded record");
    let version = History::read_page(&identity, &peer, None, 1)
        .unwrap()
        .version;
    let selected = HashSet::from([0, 50_000, 100_004]);
    let result = History::delete_indices_if_version(&identity, &peer, &version, &selected).unwrap();
    assert_eq!(result.remaining_count, 100_002);
    assert_eq!(result.deleted_count, 3);
    assert!(result.peak_record_bytes < 32 * 1024);
    assert_eq!(History::list(&identity).unwrap()[0].message_count, 100_002);
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn streaming_range_deletion_handles_over_sixty_four_mib_and_inclusive_cutoff() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "45".repeat(32);
    let (history, _, _) = History::open(&identity, &peer).unwrap();
    let source_bytes = write_synthetic_history(&history, 17_000, &"x".repeat(4096));
    assert!(source_bytes > 64 * 1024 * 1024);
    // Keep-recent uses an inclusive end; the exact cutoff second is deleted.
    let result = History::delete_time_range(&identity, &peer, 0, 8_499).unwrap();
    assert_eq!(result.deleted_count, 8_500);
    assert_eq!(result.remaining_count, 8_500);
    assert!(result.peak_record_bytes < 32 * 1024);
    let page = History::read_page(&identity, &peer, None, 1).unwrap();
    assert_eq!(page.entries[0].message.unix_time, 8_500);
    let last = History::read_page(&identity, &peer, page.next.as_ref(), 1).unwrap();
    assert_eq!(last.entries[0].message.unix_time, 8_501);
}

#[test]
fn simultaneous_history_handles_append_without_duplicate_indices() {
    let data = IsolatedData::new();
    let (identity, access_code) = Identity::create().unwrap();
    let code = access_code.to_string();
    let peer = "40".repeat(32);
    let _ = History::open(&identity, &peer).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for (index, text) in [(1u64, "concurrent one"), (2, "concurrent two")] {
        let directory = data.0.clone();
        let peer = peer.clone();
        let code = code.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            super::TEST_DATA_DIRECTORY.with(|slot| *slot.borrow_mut() = Some(directory));
            let identity = Identity::from_code(&code).unwrap();
            let (mut history, _, _) = History::open_for_chat(&identity, &peer).unwrap();
            barrier.wait();
            history.append(&message(index, text)).unwrap();
            super::TEST_DATA_DIRECTORY.with(|slot| *slot.borrow_mut() = None);
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let (mut history, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages.len(), 2);
    history
        .append(&message(3, "after concurrent append"))
        .unwrap();
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages.len(), 3);
    let texts: HashSet<_> = messages.iter().map(|item| item.text.as_str()).collect();
    assert!(texts.contains("concurrent one"));
    assert!(texts.contains("concurrent two"));
}

#[test]
fn chat_history_open_keeps_only_count_and_page_sized_results() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "3a".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    for index in 0..600 {
        history.append(&message(index, "page item")).unwrap();
    }
    drop(history);
    let (history, count, recovered) = History::open_for_chat(&identity, &peer).unwrap();
    assert_eq!(count, 600);
    assert!(!recovered);
    let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
    for _ in 0..500 {
        reader.next_record().unwrap().unwrap();
    }
    assert_eq!(
        (0..256)
            .filter(|_| reader.next_record().unwrap().is_some())
            .count(),
        100
    );
    drop(history);
}

#[test]
fn restore_staging_encrypts_records_and_removes_only_its_owned_directory() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "3a".repeat(32);
    let request = "3b".repeat(32);
    let root = super::data_directory()
        .unwrap()
        .join(identity.public_id())
        .join(".history-restore");
    std::fs::create_dir_all(&root).unwrap();
    let unrelated = root.join("unrelated.keep");
    std::fs::write(&unrelated, b"preserve").unwrap();
    let staged = message(9, "secret staged proposal");
    {
        let mut writer = super::RestoreStaging::create(&identity, &peer, &request).unwrap();
        writer.append_verified(&staged).unwrap();
        writer.finish().unwrap();
        assert_eq!(writer.count(), 1);
        let file = std::fs::read(writer.directory.join("records.enc")).unwrap();
        assert!(!file
            .windows(b"secret staged proposal".len())
            .any(|window| window == b"secret staged proposal"));
        assert_eq!(writer.next_record().unwrap(), Some(staged.clone()));
        assert_eq!(writer.next_record().unwrap(), None);
        let path = writer.directory.join("records.enc");
        let mut tampered = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let end = tampered.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0];
        tampered.read_exact(&mut byte).unwrap();
        tampered.seek(SeekFrom::Start(end)).unwrap();
        byte[0] ^= 1;
        tampered.write_all(&byte).unwrap();
        writer.rewind().unwrap();
        assert!(writer.next_record().is_err());
    }
    assert!(unrelated.exists());
    assert_eq!(std::fs::read(unrelated).unwrap(), b"preserve");
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn stale_restore_cleanup_preserves_active_and_unowned_directories() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "4a".repeat(32);
    let root = super::data_directory()
        .unwrap()
        .join(identity.public_id())
        .join(".history-restore");
    let mut active = RestoreStaging::create(&identity, &peer, &"4b".repeat(32)).unwrap();
    active.append_verified(&message(1, "active")).unwrap();
    let stale = root.join("4c".repeat(12));
    std::fs::create_dir(&stale).unwrap();
    std::fs::write(stale.join("owner.lock"), []).unwrap();
    std::fs::write(stale.join("records.enc"), super::RESTORE_STAGING_MAGIC).unwrap();
    let unowned = root.join("notes");
    std::fs::create_dir(&unowned).unwrap();
    std::fs::write(unowned.join("keep"), b"keep").unwrap();
    super::cleanup_stale_restore_staging(&root).unwrap();
    assert!(active.directory.exists());
    assert!(!stale.exists());
    assert_eq!(std::fs::read(unowned.join("keep")).unwrap(), b"keep");
    active.cleanup().unwrap();
}

#[test]
fn restore_result_cleanup_failure_reports_recoverable_path_and_open_cleans_it() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "4d".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "original")).unwrap();
    let mut staging = RestoreStaging::create(&identity, &peer, &"4e".repeat(32)).unwrap();
    staging.append_verified(&message(2, "proposal")).unwrap();
    staging.finish().unwrap();
    super::TEST_FAILURES.with(|failures| {
        failures.set(super::FAIL_RESTORE_RENAME | super::FAIL_RESTORE_RESULT_CLEANUP)
    });
    let error = history
        .merge_restore_staging(&identity, &mut staging)
        .unwrap_err();
    super::TEST_FAILURES.with(|failures| failures.set(0));
    let text = error.to_string();
    assert!(text.contains("recoverable file:"));
    let path = text.split("recoverable file: ").nth(1).unwrap();
    let path = PathBuf::from(path);
    assert!(path.exists());
    assert_eq!(
        History::read_for_identity_copy(&identity, &peer)
            .unwrap()
            .0
            .len(),
        1
    );
    drop(history);
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages.len(), 1);
    assert!(!path.exists());
}

#[test]
fn streamed_restore_merge_preserves_order_multiplicity_and_reports_bounded_buffer() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "40".repeat(32);
    let request = "41".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history
        .append(&message(2, "same time existing one"))
        .unwrap();
    history
        .append(&message(2, "same time existing two"))
        .unwrap();
    history.append(&message(3, "legacy repeat")).unwrap();
    history.append(&message(3, "legacy repeat")).unwrap();
    let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
    staging
        .append_verified(&message(1, "earlier proposal"))
        .unwrap();
    staging
        .append_verified(&message(2, "same time proposal"))
        .unwrap();
    staging
        .append_verified(&message(3, "legacy repeat"))
        .unwrap();
    staging
        .append_verified(&message(3, "legacy repeat"))
        .unwrap();
    staging
        .append_verified(&message(3, "legacy repeat"))
        .unwrap();
    staging.finish().unwrap();
    let summary = history
        .merge_restore_staging(&identity, &mut staging)
        .unwrap();
    assert_eq!(summary.imported_count, 3);
    assert!(summary.peak_sort_buffer_bytes <= super::RESTORE_SORT_RUN_BYTES);
    let messages = History::read_for_identity_copy(&identity, &peer).unwrap().0;
    assert_eq!(messages.len() as u64, summary.total_count);
    assert_eq!(
        messages
            .iter()
            .map(|item| item.unix_time)
            .collect::<Vec<_>>(),
        vec![1, 2, 2, 2, 3, 3, 3]
    );
    assert_eq!(
        messages
            .iter()
            .filter(|item| item.text == "legacy repeat")
            .count(),
        3
    );
    assert_eq!(
        messages.iter().filter(|item| item.unix_time == 2).count(),
        3
    );
    assert_eq!(
        messages
            .iter()
            .filter(|item| item.unix_time == 2)
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec![
            "same time existing one",
            "same time existing two",
            "same time proposal"
        ]
    );
}

#[test]
fn restore_staging_write_failure_leaves_no_completed_proposal() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let mut staging =
        RestoreStaging::create(&identity, &"4f".repeat(32), &"50".repeat(32)).unwrap();
    super::TEST_FAILURES.with(|failures| failures.set(super::FAIL_RESTORE_STAGE_WRITE));
    assert!(staging.append_verified(&message(1, "not stored")).is_err());
    super::TEST_FAILURES.with(|failures| failures.set(0));
    staging.finish().unwrap();
    assert_eq!(staging.count(), 0);
    assert_eq!(staging.next_record().unwrap(), None);
}

#[test]
fn restore_staging_cleanup_failure_is_returned_to_the_caller() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let staging = RestoreStaging::create(&identity, &"53".repeat(32), &"54".repeat(32)).unwrap();
    let directory = staging.directory.clone();
    super::TEST_FAILURES.with(|failures| failures.set(super::FAIL_RESTORE_CLEANUP_ONCE));
    let error = staging.cleanup().unwrap_err();
    super::TEST_FAILURES.with(|failures| failures.set(0));
    assert!(error.to_string().contains("cleanup failure"));
    assert!(!directory.exists());
}

#[test]
fn streamed_restore_merge_retries_and_preserves_original_on_injected_failures() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "42".repeat(32);
    let request = "43".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "keep original")).unwrap();
    let original = History::read_for_identity_copy(&identity, &peer).unwrap().0;
    let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
    staging.append_verified(&message(2, "offer")).unwrap();
    staging.finish().unwrap();
    for failure in [
        super::FAIL_RESTORE_INDEX,
        super::FAIL_RESTORE_OUTPUT,
        super::FAIL_RESTORE_RENAME,
    ] {
        super::TEST_FAILURES.with(|failures| failures.set(failure));
        assert!(history
            .merge_restore_staging(&identity, &mut staging)
            .is_err());
        super::TEST_FAILURES.with(|failures| failures.set(0));
        assert_eq!(
            History::read_for_identity_copy(&identity, &peer).unwrap().0,
            original
        );
    }
    let merged = history
        .merge_restore_staging(&identity, &mut staging)
        .unwrap();
    assert_eq!(merged.imported_count, 1);
    assert_eq!(
        History::read_for_identity_copy(&identity, &peer)
            .unwrap()
            .0
            .len(),
        2
    );
}

#[test]
fn streamed_restore_merge_rejects_signed_id_collision_without_replacing_history() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "44".repeat(32);
    let request = "45".repeat(32);
    let mut original = super::sign_message(&identity, &peer, 7, "signed original".into()).unwrap();
    let mut conflict = original.clone();
    conflict.text = "same ID with changed content".into();
    let proof = original.proof.as_mut().unwrap();
    proof.id = [9; 16];
    conflict.proof.as_mut().unwrap().id = [9; 16];
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&original).unwrap();
    let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
    staging.append_verified(&conflict).unwrap();
    staging.finish().unwrap();
    assert!(history
        .merge_restore_staging(&identity, &mut staging)
        .is_err());
    assert_eq!(
        History::read_for_identity_copy(&identity, &peer).unwrap().0,
        vec![original]
    );
}

#[test]
fn streamed_restore_merge_skips_identical_signed_ids() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "51".repeat(32);
    let original = super::sign_message(&identity, &peer, 7, "signed duplicate".into()).unwrap();
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&original).unwrap();
    let mut staging = RestoreStaging::create(&identity, &peer, &"52".repeat(32)).unwrap();
    staging.append_verified(&original).unwrap();
    staging.append_verified(&original).unwrap();
    staging.finish().unwrap();
    let summary = history
        .merge_restore_staging(&identity, &mut staging)
        .unwrap();
    assert_eq!(summary.imported_count, 0);
    assert_eq!(summary.total_count, 1);
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn transfer_estimate_scans_over_legacy_count_and_byte_thresholds_sequentially() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer_count = "3c".repeat(32);
    let (mut count_history, _, _) = History::open(&identity, &peer_count).unwrap();
    for index in 0..100_001u64 {
        let item = message(index, "x");
        let record = super::encode_record(
            &count_history.key,
            &count_history.identity_id,
            &count_history.peer_id,
            index,
            &count_history.format,
            &item,
        )
        .unwrap();
        count_history.file.write_all(&record).unwrap();
    }
    count_history.file.sync_all().unwrap();
    let (mut reader, count, estimate) =
        History::estimate_transfer(&identity, &peer_count, &"3d".repeat(32)).unwrap();
    assert_eq!(count, 100_001);
    assert!(estimate > count as u64);
    let summaries = History::list(&identity).unwrap();
    assert_eq!(summaries[0].message_count, 100_001);
    let first_page = History::read_page(&identity, &peer_count, None, 100).unwrap();
    assert_eq!(first_page.entries.len(), 100);
    let next_page =
        History::read_page(&identity, &peer_count, first_page.next.as_ref(), 100).unwrap();
    assert_eq!(next_page.entries.len(), 100);
    assert_eq!(next_page.entries[0].index, 100);
    let mut streamed = 0;
    while reader.next_record().unwrap().is_some() {
        streamed += 1;
    }
    assert_eq!(streamed, count);

    let peer_bytes = "3e".repeat(32);
    let (mut byte_history, _, _) = History::open(&identity, &peer_bytes).unwrap();
    for index in 0..17_000u64 {
        let item = message(index, &"y".repeat(4096));
        let record = super::encode_record(
            &byte_history.key,
            &byte_history.identity_id,
            &byte_history.peer_id,
            index,
            &byte_history.format,
            &item,
        )
        .unwrap();
        byte_history.file.write_all(&record).unwrap();
    }
    byte_history.file.sync_all().unwrap();
    let (_, byte_count, byte_estimate) =
        History::estimate_transfer(&identity, &peer_bytes, &"3f".repeat(32)).unwrap();
    assert_eq!(byte_count, 17_000);
    assert!(byte_estimate > 64 * 1024 * 1024);
}

#[test]
fn restores_only_verified_missing_messages_and_rejects_tampering_and_id_collisions() {
    let _data = IsolatedData::new();
    let (alice, _) = Identity::create().unwrap();
    let (bob, _) = Identity::create().unwrap();
    let peer_id = super::hex_encode(&bob.public_key());
    let local_peer_id = super::hex_encode(&alice.public_key());
    let signed = super::sign_message(&alice, &peer_id, 123, "signed record".into()).unwrap();
    let frame = super::encode_transfer(&signed).unwrap();
    let received =
        super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &frame).unwrap();
    assert_eq!(received.sender, MessageSender::Other);
    assert_eq!(
        super::merge_restored(&[], std::slice::from_ref(&received)).unwrap(),
        vec![received.clone()]
    );
    assert_eq!(
        super::merge_restored(
            std::slice::from_ref(&received),
            std::slice::from_ref(&received),
        )
        .unwrap(),
        vec![received.clone()]
    );

    let mut changed_text = frame.clone();
    let text_at = 6 + 1 + 8 + 4;
    changed_text[text_at] ^= 1;
    assert!(
        super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &changed_text).is_err()
    );
    assert!(super::decode_transfer(&bob, &local_peer_id, &[9; 32], &frame).is_err());
    let mut wrong_sender = frame.clone();
    wrong_sender[6] = 1;
    assert!(
        super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &wrong_sender).is_err()
    );

    let mut collision = received.clone();
    collision.text = "different contents".into();
    assert!(super::merge_restored(&[received], &[collision]).is_err());
}

#[test]
fn new_message_decoder_requires_remote_sender_and_valid_proof() {
    let _data = IsolatedData::new();
    let (alice, _) = Identity::create().unwrap();
    let (bob, _) = Identity::create().unwrap();
    let bob_id = super::hex_encode(&bob.public_key());
    let alice_id = super::hex_encode(&alice.public_key());
    let outgoing = super::sign_message(&alice, &bob_id, 500, "authentic".into()).unwrap();
    let frame = super::encode_signed_message(&outgoing).unwrap();
    let received =
        super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &frame).unwrap();
    assert_eq!(received.sender, MessageSender::Other);

    let proof_at = 6 + 1 + 8 + 4 + outgoing.text.len();
    let mut unsigned = frame.clone();
    unsigned.truncate(proof_at + 1);
    unsigned[proof_at] = 0;
    assert!(super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &unsigned).is_err());

    let mut wrong_sender = frame.clone();
    wrong_sender[6] = 1;
    assert!(
        super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &wrong_sender).is_err()
    );

    let id_at = proof_at + 1;
    let signature_at = id_at + 16 + 32 + 32;
    for offset in [7, id_at, signature_at] {
        let mut altered = frame.clone();
        altered[offset] ^= 1;
        assert!(
            super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &altered).is_err()
        );
    }

    let legacy = StoredMessage {
        proof: None,
        sender: MessageSender::Other,
        ..message(500, "unsigned legacy")
    };
    let legacy_frame = super::encode_transfer(&legacy).unwrap();
    let restored =
        super::decode_transfer(&bob, &alice_id, &alice.public_key(), &legacy_frame).unwrap();
    assert!(restored.proof.is_none());
}

#[test]
fn explicitly_linked_identity_keys_validate_original_signatures_only_after_link() {
    let _data = IsolatedData::new();
    let (alice_old, _) = Identity::create().unwrap();
    let (bob, _) = Identity::create().unwrap();
    let alice_old_id = alice_old.public_id();
    let bob_id = bob.public_id();
    let alice_to_bob =
        super::sign_message(&alice_old, &bob_id, 100, "old Alice proof".into()).unwrap();
    let a_frame = super::encode_signed_message(&alice_to_bob).unwrap();
    let received_a =
        super::decode_signed_message(&bob, &alice_old_id, &alice_old.public_key(), &a_frame)
            .unwrap();
    let bob_to_alice =
        super::sign_message(&bob, &alice_old_id, 101, "old Bob proof".into()).unwrap();
    let b_frame = super::encode_signed_message(&bob_to_alice).unwrap();
    let received_b =
        super::decode_signed_message(&alice_old, &bob_id, &bob.public_key(), &b_frame).unwrap();

    let (mut bob_old_history, _, _) = History::open(&bob, &alice_old_id).unwrap();
    bob_old_history.append(&received_a).unwrap();
    bob_old_history.append(&bob_to_alice).unwrap();
    let (mut alice_old_history, _, _) = History::open(&alice_old, &bob_id).unwrap();
    alice_old_history.append(&received_b).unwrap();

    let (alice_new, _) = Identity::create().unwrap();
    alice_old.copy_local_data_to(&alice_new).unwrap();
    let alice_new_id = alice_new.public_id();
    let (mut bob_current, _, _) = History::open(&bob, &alice_new_id).unwrap();
    let peer_marker = StoredMessage {
        unix_time: 102,
        sender: MessageSender::Me,
        text: format!(
            "{}peer:{alice_old_id}:{alice_new_id}",
            super::IDENTITY_EVENT_PREFIX
        ),
        proof: None,
    };
    bob_current
        .link_prior_identity(&bob, &alice_old_id, peer_marker)
        .unwrap();

    let (mut alice_current, _, _) = History::open(&alice_new, &bob_id).unwrap();
    let self_marker = StoredMessage {
        unix_time: 103,
        sender: MessageSender::Me,
        text: format!(
            "{}self:{alice_old_id}:{alice_new_id}",
            super::IDENTITY_EVENT_PREFIX
        ),
        proof: None,
    };
    alice_current
        .append_system_once(&alice_new, self_marker)
        .unwrap();

    let (alice_messages, incomplete) =
        History::read_for_identity_copy(&alice_new, &bob_id).unwrap();
    assert!(!incomplete);
    let local_origins = crate::identity::previous_public_ids(&alice_new).unwrap();
    let fake_message = StoredMessage {
        unix_time: 104,
        sender: MessageSender::Me,
        text: format!(
            "{}self:{}:{}",
            super::IDENTITY_EVENT_PREFIX,
            "55".repeat(32),
            alice_new_id
        ),
        proof: None,
    };
    let (untrusted_local, untrusted_peer) = super::linked_identity_keys(
        &alice_new,
        &[fake_message],
        &alice_new_id,
        &bob_id,
        &local_origins,
    )
    .unwrap();
    assert!(untrusted_local.is_empty());
    assert!(untrusted_peer.is_empty());
    super::record_linked_local_identity(&alice_new, &bob_id, &alice_old_id).unwrap();
    let (local_aliases, peer_aliases) = super::linked_identity_keys(
        &alice_new,
        &alice_messages,
        &alice_new_id,
        &bob_id,
        &local_origins,
    )
    .unwrap();
    assert!(local_aliases.contains(&super::decode_peer_id(&alice_old_id).unwrap()));
    assert!(peer_aliases.is_empty());
    let alice_backup = History::export_backup(&alice_new, &bob_id, None).unwrap();
    assert_eq!(
        History::verify_backup(&alice_new, &alice_backup, None)
            .unwrap()
            .0,
        bob_id
    );

    let (bob_messages, incomplete) = History::read_for_identity_copy(&bob, &alice_new_id).unwrap();
    assert!(!incomplete);
    let (bob_local_aliases, bob_peer_aliases) =
        super::linked_identity_keys(&bob, &bob_messages, &bob.public_id(), &alice_new_id, &[])
            .unwrap();
    assert!(bob_local_aliases.is_empty());
    assert!(bob_peer_aliases.contains(&super::decode_peer_id(&alice_old_id).unwrap()));
    let bob_backup = History::export_backup(&bob, &alice_new_id, None).unwrap();
    assert_eq!(
        History::verify_backup(&bob, &bob_backup, None).unwrap().0,
        alice_new_id
    );

    for entry in bob_messages.iter().filter(|entry| entry.proof.is_some()) {
        let frame = super::encode_transfer(entry).unwrap();
        assert!(super::decode_transfer_with_linked_keys(
            &alice_new,
            &bob_id,
            &bob.public_key(),
            &frame,
            &[],
            &[]
        )
        .is_err());
        let restored = super::decode_transfer_with_linked_keys(
            &alice_new,
            &bob_id,
            &bob.public_key(),
            &frame,
            &local_aliases,
            &peer_aliases,
        )
        .unwrap();
        assert!(restored.proof.is_some());
    }

    let alice_local_entry = alice_messages
        .iter()
        .find(|entry| entry.proof.is_some())
        .unwrap();
    let frame = super::encode_transfer(alice_local_entry).unwrap();
    let restored = super::decode_transfer_with_linked_keys(
        &bob,
        &alice_new_id,
        &alice_new.public_key(),
        &frame,
        &bob_local_aliases,
        &bob_peer_aliases,
    )
    .unwrap();
    assert!(restored.proof.is_some());

    let mut wrong_recipient = frame.clone();
    let text_len = u32::from_be_bytes(wrong_recipient[15..19].try_into().unwrap()) as usize;
    let proof = 19 + text_len + 1;
    wrong_recipient[proof + 16 + 32] ^= 1;
    assert!(super::decode_transfer_with_linked_keys(
        &bob,
        &alice_new_id,
        &alice_new.public_key(),
        &wrong_recipient,
        &bob_local_aliases,
        &bob_peer_aliases
    )
    .is_err());
}

#[test]
fn linked_backup_restores_original_proofs_and_relations_on_another_store() {
    let _data = IsolatedData::new();
    let root = super::data_directory().unwrap();
    let store_a = root.join("store-a");
    let store_b = root.join("store-b");
    std::fs::create_dir_all(&store_a).unwrap();
    std::fs::create_dir_all(&store_b).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_a.clone()));
    let (old_local, _) = Identity::create().unwrap();
    let (replacement, code) = Identity::create().unwrap();
    old_local.copy_local_data_to(&replacement).unwrap();
    let (peer, _) = Identity::create().unwrap();
    let peer_id = peer.public_id();
    let old_proof =
        super::sign_message(&old_local, &peer_id, 777, "before replacement".into()).unwrap();
    let (mut history, _, _) = History::open(&replacement, &peer_id).unwrap();
    history.append(&old_proof).unwrap();
    super::record_linked_local_identity(&replacement, &peer_id, &old_local.public_id()).unwrap();
    let backup = History::export_backup(&replacement, &peer_id, None).unwrap();
    assert!(backup.starts_with(super::BACKUP_LINKED_MAGIC));

    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_b.clone()));
    let restored_identity = Identity::from_code(&code).unwrap();
    assert_eq!(restored_identity.public_id(), replacement.public_id());
    let (restored_peer, _) = History::import_backup(&restored_identity, &backup, None).unwrap();
    assert_eq!(restored_peer, peer_id);
    let (messages, _) = History::read_for_identity_copy(&restored_identity, &peer_id).unwrap();
    assert_eq!(messages, vec![old_proof.clone()]);
    let (locals, _) = super::linked_identity_keys(
        &restored_identity,
        &messages,
        &restored_identity.public_id(),
        &peer_id,
        &crate::identity::previous_public_ids(&restored_identity).unwrap(),
    )
    .unwrap();
    assert!(locals.contains(&old_local.public_key()));

    let mut tampered = backup.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(History::verify_backup(&restored_identity, &tampered, None).is_err());

    let mut bad_signature = old_proof.clone();
    bad_signature.proof.as_mut().unwrap().signature[0] ^= 1;
    let bad_signature_backup =
        super::encode_backup(&replacement, &peer_id, &[bad_signature], None).unwrap();
    assert!(History::verify_backup(&restored_identity, &bad_signature_backup, None).is_err());

    let bundle =
        History::export_backup_bundle(&replacement, std::slice::from_ref(&peer_id)).unwrap();
    let store_c = root.join("store-c");
    std::fs::create_dir_all(&store_c).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_c.clone()));
    let bundle_identity = Identity::from_code(&code).unwrap();
    History::import_backup_bundle(&bundle_identity, &bundle).unwrap();
    let (bundle_messages, _) = History::read_for_identity_copy(&bundle_identity, &peer_id).unwrap();
    let (bundle_local, _) = super::linked_identity_keys(
        &bundle_identity,
        &bundle_messages,
        &bundle_identity.public_id(),
        &peer_id,
        &crate::identity::previous_public_ids(&bundle_identity).unwrap(),
    )
    .unwrap();
    assert!(bundle_local.contains(&old_local.public_key()));

    let store_d = root.join("store-d");
    std::fs::create_dir_all(&store_d).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_d));
    let failed_identity = Identity::from_code(&code).unwrap();
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
    let failure = History::import_backup(&failed_identity, &backup, None).unwrap_err();
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert!(failure
        .to_string()
        .contains("injected linked identity store failure"));
    assert!(crate::identity::previous_public_ids(&failed_identity)
        .unwrap()
        .is_empty());
    assert!(
        !super::is_linked_local_identity(&failed_identity, &peer_id, &old_local.public_id())
            .unwrap()
    );
    let (untouched, _) = History::read_for_identity_copy(&failed_identity, &peer_id).unwrap();
    assert!(untouched.is_empty());

    let store_e = root.join("store-e");
    std::fs::create_dir_all(&store_e).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_e));
    let replace_failed_identity = Identity::from_code(&code).unwrap();
    let (mut preexisting, _, _) = History::open(&replace_failed_identity, &peer_id).unwrap();
    preexisting
        .append(&message(3, "preserve this record"))
        .unwrap();
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_HISTORY_REPLACE_ONCE));
    assert!(History::import_backup(&replace_failed_identity, &backup, None).is_err());
    super::TEST_FAILURES.with(|flags| flags.set(0));
    let (preserved, _) =
        History::read_for_identity_copy(&replace_failed_identity, &peer_id).unwrap();
    assert_eq!(preserved, vec![message(3, "preserve this record")]);

    // ADBACK4 carries signed messages but no authenticated relationship metadata.
    let mut legacy_payload = Vec::new();
    legacy_payload.extend_from_slice(&super::decode_peer_id(&peer_id).unwrap());
    legacy_payload.extend_from_slice(&1_u32.to_be_bytes());
    let text = old_proof.text.as_bytes();
    legacy_payload.extend_from_slice(&old_proof.unix_time.to_be_bytes());
    legacy_payload.push(0);
    legacy_payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
    legacy_payload.extend_from_slice(text);
    let proof = old_proof.proof.as_ref().unwrap();
    legacy_payload.push(1);
    legacy_payload.extend_from_slice(&proof.id);
    legacy_payload.extend_from_slice(&proof.signer);
    legacy_payload.extend_from_slice(&proof.recipient);
    legacy_payload.extend_from_slice(&proof.signature);
    let nonce = super::random_nonce().unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(
        super::derive_backup_key(&replacement.storage_key()).as_ref(),
    )
    .unwrap();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &legacy_payload,
                aad: &super::backup_aad(&replacement, super::BACKUP_SIGNED_MAGIC, None),
            },
        )
        .unwrap();
    let mut old_backup = super::BACKUP_SIGNED_MAGIC.to_vec();
    old_backup.extend_from_slice(&nonce);
    old_backup.extend_from_slice(&ciphertext);
    assert!(History::verify_backup(&failed_identity, &old_backup, None).is_err());
}

#[test]
fn pending_link_retries_marker_only_partial_failure_without_duplicate_marker() {
    let _data = IsolatedData::new();
    let (old, _) = Identity::create().unwrap();
    let (current, _) = Identity::create().unwrap();
    old.copy_local_data_to(&current).unwrap();
    let peer = "4a".repeat(32);
    let old_id = old.public_id();
    let entry = StoredMessage {
        unix_time: 22,
        sender: MessageSender::Me,
        text: format!(
            "{}self:{old_id}:{}",
            super::IDENTITY_EVENT_PREFIX,
            current.public_id()
        ),
        proof: None,
    };
    let (mut history, _, _) = History::open(&current, &peer).unwrap();
    assert!(history.append_system_once(&current, entry.clone()).unwrap());
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
    assert!(super::record_linked_local_identity(&current, &peer, &old_id).is_err());
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert_eq!(
        super::pending_local_identity_links(&current, &peer, std::slice::from_ref(&old_id))
            .unwrap(),
        vec![old_id.clone()]
    );
    assert!(!history.append_system_once(&current, entry).unwrap());
    super::record_linked_local_identity(&current, &peer, &old_id).unwrap();
    assert!(super::record_linked_local_identity(&current, &peer, &"ff".repeat(32)).is_err());
    assert!(
        super::pending_local_identity_links(&current, &peer, &[old_id])
            .unwrap()
            .is_empty()
    );
    let (messages, _) = History::read_for_identity_copy(&current, &peer).unwrap();
    assert_eq!(messages.len(), 1);

    let path = super::linked_key_path(&current, &peer).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(path, bytes).unwrap();
    assert!(super::pending_local_identity_links(&current, &peer, &["ff".repeat(32)]).is_err());
}

#[test]
fn repeated_identity_replacement_preserves_authenticated_peer_links_and_proofs() {
    let _data = IsolatedData::new();
    let (local_a, _) = Identity::create().unwrap();
    let (local_b, _) = Identity::create().unwrap();
    let (local_c, _) = Identity::create().unwrap();
    let (peer_old, _) = Identity::create().unwrap();
    let (peer_current, _) = Identity::create().unwrap();
    let current_peer_id = peer_current.public_id();
    let old_peer_id = peer_old.public_id();
    let mut proof =
        super::sign_message(&peer_old, &local_a.public_id(), 91, "old peer proof".into()).unwrap();
    proof.sender = MessageSender::Other;
    let (mut history, _, _) = History::open(&local_a, &current_peer_id).unwrap();
    history.append(&proof).unwrap();
    let mut links = (HashSet::new(), HashSet::new());
    links.1.insert(old_peer_id.clone());
    super::write_linked_keys(&local_a, &current_peer_id, &links).unwrap();

    local_a.copy_local_data_to(&local_b).unwrap();
    super::record_linked_local_identity(&local_b, &current_peer_id, &local_a.public_id()).unwrap();
    local_b.copy_local_data_to(&local_c).unwrap();
    let (messages, _) = History::read_for_identity_copy(&local_c, &current_peer_id).unwrap();
    let (local_aliases, peer_aliases) = super::linked_identity_keys(
        &local_c,
        &messages,
        &local_c.public_id(),
        &current_peer_id,
        &crate::identity::previous_public_ids(&local_c).unwrap(),
    )
    .unwrap();
    assert!(local_aliases.contains(&local_a.public_key()));
    assert!(peer_aliases.contains(&peer_old.public_key()));
    super::verify_stored_proof(
        &local_c,
        &current_peer_id,
        &proof,
        &local_aliases,
        &peer_aliases,
    )
    .unwrap();

    let source_path = super::linked_key_path(&local_c, &current_peer_id).unwrap();
    let source_bytes = std::fs::read(&source_path).unwrap();
    let (failed_replacement, _) = Identity::create().unwrap();
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
    assert!(local_c.copy_local_data_to(&failed_replacement).is_err());
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
    assert!(!super::data_directory()
        .unwrap()
        .join(failed_replacement.public_id())
        .exists());

    let (corrupt_replacement, _) = Identity::create().unwrap();
    let mut tampered = source_bytes;
    *tampered.last_mut().unwrap() ^= 1;
    std::fs::write(&source_path, tampered.clone()).unwrap();
    assert!(local_c.copy_local_data_to(&corrupt_replacement).is_err());
    assert_eq!(std::fs::read(&source_path).unwrap(), tampered);
    assert!(!super::data_directory()
        .unwrap()
        .join(corrupt_replacement.public_id())
        .exists());
}

#[test]
fn legacy_messages_remain_unsigned_and_are_not_claimed_as_verified() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "41".repeat(32);
    let legacy = message(10, "legacy record");
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&legacy).unwrap();
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages, vec![legacy]);
    assert!(messages[0].proof.is_none());
}

#[test]
fn legacy_adlog1_is_migrated_without_retroactive_signatures() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "43".repeat(32);
    let identity_id = identity.public_id();
    let directory = data.0.join(&identity_id);
    std::fs::create_dir_all(&directory).unwrap();
    let key = identity.storage_key();
    let index_key = super::derive_index_key(&key);
    let path = directory.join(format!(
        "{}.adlog",
        super::opaque_conversation_name(&index_key, &peer)
    ));
    let entry = message(77, "unsigned legacy");
    let mut plain = Vec::new();
    plain.extend_from_slice(&entry.unix_time.to_be_bytes());
    plain.push(0);
    plain.extend_from_slice(&(entry.text.len() as u32).to_be_bytes());
    plain.extend_from_slice(entry.text.as_bytes());
    let nonce = super::random_nonce().unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &super::associated_data(&identity_id, &peer, 0, &super::LogFormat::V1),
            },
        )
        .unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(super::LEGACY_MAGIC);
    bytes.extend_from_slice(&((nonce.len() + encrypted.len()) as u32).to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    std::fs::write(&path, bytes).unwrap();

    let (history, count, _) = History::open_for_chat(&identity, &peer).unwrap();
    let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
    assert_eq!(count, 1);
    let restored = reader.next_record().unwrap().unwrap();
    assert_eq!(restored, entry);
    assert!(restored.proof.is_none());
    assert_eq!(reader.next_record().unwrap(), None);
    drop(history);
    assert_eq!(&std::fs::read(path).unwrap()[..8], super::MAGIC);
}

fn conversation_path(identity: &Identity, peer: &str) -> PathBuf {
    let identity_id = identity.public_id();
    let key = identity.storage_key();
    super::data_directory()
        .unwrap()
        .join(&identity_id)
        .join(format!(
            "{}.adlog",
            super::opaque_conversation_name(&super::derive_index_key(&key), peer)
        ))
}

/// Splits a log into its header and the byte ranges of its records.
fn records_of(bytes: &[u8]) -> (usize, Vec<std::ops::Range<usize>>) {
    let header = if &bytes[..8] == super::MAGIC {
        super::HEADER_LEN as usize
    } else {
        8
    };
    let mut position = header;
    let mut ranges = Vec::new();
    while position < bytes.len() {
        let length = u32::from_be_bytes(bytes[position..position + 4].try_into().unwrap()) as usize;
        ranges.push(position..position + 4 + length);
        position += 4 + length;
    }
    (header, ranges)
}

#[test]
fn a_new_log_has_an_adlog3_header_with_a_random_generation() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let (first, second) = ("71".repeat(32), "72".repeat(32));
    for peer in [&first, &second] {
        let (mut history, _, _) = History::open(&identity, peer).unwrap();
        history.append(&message(1, "one")).unwrap();
    }
    let a = std::fs::read(conversation_path(&identity, &first)).unwrap();
    let b = std::fs::read(conversation_path(&identity, &second)).unwrap();
    assert_eq!(&a[..8], super::MAGIC);
    assert_ne!(a[8..24], b[8..24], "each log has its own generation");
    assert_ne!(a[8..24], [0; 16]);
}

#[test]
fn replacing_or_deleting_records_starts_a_new_generation() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "73".repeat(32);
    let path = conversation_path(&identity, &peer);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "one")).unwrap();
    history.append(&message(2, "two")).unwrap();
    let generation = |path: &PathBuf| std::fs::read(path).unwrap()[8..24].to_vec();
    let first = generation(&path);
    history.append(&message(3, "three")).unwrap();
    assert_eq!(generation(&path), first, "an append keeps the generation");
    history.replace(&[message(1, "one")]).unwrap();
    let second = generation(&path);
    assert_ne!(second, first);
    History::delete_time_range(&identity, &peer, 0, 10).unwrap();
    assert_ne!(generation(&path), second, "a delete rewrites the file too");
}

#[test]
fn a_record_from_an_earlier_generation_does_not_authenticate_in_the_current_one() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "74".repeat(32);
    let path = conversation_path(&identity, &peer);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "old first")).unwrap();
    history.append(&message(2, "old second")).unwrap();
    let old = std::fs::read(&path).unwrap();
    // The same keys and the same record numbers: only the generation differs.
    history
        .replace(&[message(1, "new first"), message(2, "new second")])
        .unwrap();
    drop(history);
    let (_, old_records) = records_of(&old);
    let current = std::fs::read(&path).unwrap();
    let (_, current_records) = records_of(&current);
    let mut spliced = current[..current_records[1].start].to_vec();
    spliced.extend_from_slice(&old[old_records[1].clone()]);
    std::fs::write(&path, &spliced).unwrap();
    let Err(error) = History::open(&identity, &peer) else {
        panic!("a spliced record was accepted");
    };
    assert!(error.to_string().contains("authentication"), "{error}");
    // Without the splice the file is fine, so the failure is the old record.
    std::fs::write(&path, &current).unwrap();
    assert_eq!(History::open(&identity, &peer).unwrap().1.len(), 2);
}

#[test]
fn adlog3_records_use_their_own_key_not_the_storage_key() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "78".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "secret")).unwrap();
    let bytes = std::fs::read(conversation_path(&identity, &peer)).unwrap();
    let (header, records) = records_of(&bytes);
    let record = &bytes[records[0].clone()][4..];
    let (nonce, encrypted) = record.split_at(super::NONCE_BYTES);
    let generation: [u8; 16] = bytes[8..header].try_into().unwrap();
    let aad = super::associated_data(
        &identity.public_id(),
        &peer,
        0,
        &super::LogFormat::V3 { generation },
    );
    let try_key = |key: &[u8; 32]| {
        ChaCha20Poly1305::new_from_slice(key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: encrypted,
                    aad: &aad,
                },
            )
            .is_ok()
    };
    assert!(
        !try_key(&identity.storage_key()),
        "the storage key must not decrypt it"
    );
    assert!(try_key(&super::record_key(
        &super::LogFormat::V3 { generation },
        &identity.storage_key()
    )));
}

#[test]
fn an_adlog2_log_still_opens_and_is_rewritten_as_adlog3() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "75".repeat(32);
    let path = conversation_path(&identity, &peer);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let key = identity.storage_key();
    let mut bytes = super::PREVIOUS_MAGIC.to_vec();
    let entries = [message(5, "kept one"), message(6, "kept two")];
    for (index, entry) in entries.iter().enumerate() {
        bytes.extend_from_slice(
            &super::encode_record(
                &key,
                &identity.public_id(),
                &peer,
                index as u64,
                &super::LogFormat::V2,
                entry,
            )
            .unwrap(),
        );
    }
    std::fs::write(&path, bytes).unwrap();
    let (mut history, count, _) = History::open_for_chat(&identity, &peer).unwrap();
    assert_eq!(count, 2);
    assert_eq!(&std::fs::read(&path).unwrap()[..8], super::MAGIC);
    // Appending after the migration uses the new generation.
    history.append(&message(7, "added")).unwrap();
    drop(history);
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    let texts: Vec<_> = messages.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(texts, ["kept one", "kept two", "added"]);
    // The streaming and the full-read open paths agree on an ADLOG2 file.
    let other = "76".repeat(32);
    let other_path = conversation_path(&identity, &other);
    let mut bytes = super::PREVIOUS_MAGIC.to_vec();
    bytes.extend_from_slice(
        &super::encode_record(
            &key,
            &identity.public_id(),
            &other,
            0,
            &super::LogFormat::V2,
            &message(9, "full read"),
        )
        .unwrap(),
    );
    std::fs::write(&other_path, bytes).unwrap();
    let (_, messages, _) = History::open(&identity, &other).unwrap();
    assert_eq!(messages[0].text, "full read");
    assert_eq!(&std::fs::read(&other_path).unwrap()[..8], super::MAGIC);
}

#[test]
fn a_header_cut_short_by_a_crash_is_rewritten() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "77".repeat(32);
    let path = conversation_path(&identity, &peer);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // ADLOG3 magic with only part of the generation id.
    let mut torn = super::MAGIC.to_vec();
    torn.extend_from_slice(&[7; 5]);
    std::fs::write(&path, &torn).unwrap();
    let (mut history, count, recovered) = History::open_for_chat(&identity, &peer).unwrap();
    assert_eq!(count, 0);
    assert!(recovered, "the discarded partial header is reported");
    history.append(&message(1, "after")).unwrap();
    drop(history);
    assert_eq!(History::open(&identity, &peer).unwrap().1.len(), 1);
}

fn warning_on_open(identity: &Identity, peer: &str) -> Option<super::IntegrityWarning> {
    let (history, _, _) = History::open_for_chat(identity, peer).unwrap();
    history.integrity_warning()
}

fn append_messages(identity: &Identity, peer: &str, count: u64) {
    let (mut history, _, _) = History::open_for_chat(identity, peer).unwrap();
    for index in 0..count {
        history.append(&message(index, "text")).unwrap();
    }
}

#[test]
fn a_log_cut_at_a_record_boundary_is_reported_once() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "81".repeat(32);
    append_messages(&identity, &peer, 3);
    let path = conversation_path(&identity, &peer);
    let bytes = std::fs::read(&path).unwrap();
    let (_, records) = records_of(&bytes);
    // Every remaining record still authenticates, so only the anchor can notice.
    std::fs::write(&path, &bytes[..records[1].end]).unwrap();
    assert_eq!(
        warning_on_open(&identity, &peer),
        Some(super::IntegrityWarning::Truncated {
            recorded: 3,
            found: 2
        })
    );
    assert_eq!(warning_on_open(&identity, &peer), None, "reported once");
}

#[test]
fn an_older_copy_of_the_log_is_reported_after_a_replace() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "82".repeat(32);
    append_messages(&identity, &peer, 4);
    let path = conversation_path(&identity, &peer);
    let old_copy = std::fs::read(&path).unwrap();
    History::delete_time_range(&identity, &peer, 0, 1).unwrap();
    assert_eq!(warning_on_open(&identity, &peer), None);
    // The deleted messages come back with an old file: valid records, wrong generation.
    std::fs::write(&path, &old_copy).unwrap();
    assert_eq!(
        warning_on_open(&identity, &peer),
        Some(super::IntegrityWarning::UnknownGeneration)
    );
}

#[test]
fn ordinary_use_never_raises_the_warning() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "83".repeat(32);
    assert_eq!(
        warning_on_open(&identity, &peer),
        None,
        "a new conversation"
    );
    append_messages(&identity, &peer, 5);
    assert_eq!(warning_on_open(&identity, &peer), None, "after appends");
    // Deleting makes the log shorter on purpose.
    History::delete_time_range(&identity, &peer, 0, 3).unwrap();
    assert_eq!(warning_on_open(&identity, &peer), None, "after a delete");
    let (mut history, _, _) = History::open_for_chat(&identity, &peer).unwrap();
    history.replace(&[message(1, "only")]).unwrap();
    drop(history);
    assert_eq!(warning_on_open(&identity, &peer), None, "after a replace");
    append_messages(&identity, &peer, 2);
    assert_eq!(warning_on_open(&identity, &peer), None);
}

#[test]
fn a_conversation_from_before_anchors_existed_is_adopted_without_a_warning() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "84".repeat(32);
    append_messages(&identity, &peer, 3);
    let path = conversation_path(&identity, &peer);
    let directory = path.parent().unwrap().to_owned();
    std::fs::remove_file(directory.join("conversations.anchor")).unwrap();
    assert_eq!(warning_on_open(&identity, &peer), None);
    assert!(directory.join("conversations.anchor").exists());
}

#[test]
fn crashes_between_the_steps_of_a_write_are_not_mistaken_for_tampering() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "85".repeat(32);
    append_messages(&identity, &peer, 3);
    let path = conversation_path(&identity, &peer);
    let directory = path.parent().unwrap().to_owned();
    let key = identity.storage_key();
    let id = identity.public_id();
    let generation =
        |path: &PathBuf| -> [u8; 16] { std::fs::read(path).unwrap()[8..24].try_into().unwrap() };
    let current = generation(&path);
    let store = |anchor| {
        crate::anchor::store(&key, &id, &directory, &peer, Some(anchor)).unwrap();
    };
    // An append reached the log but not the anchor: the anchor is behind.
    store(crate::anchor::Anchor {
        generation: current,
        records: 1,
        pending: None,
    });
    assert_eq!(warning_on_open(&identity, &peer), None);
    // A replacement announced itself and stopped before the rename.
    store(crate::anchor::Anchor {
        generation: current,
        records: 3,
        pending: Some([9; 16]),
    });
    assert_eq!(warning_on_open(&identity, &peer), None);
    // A replacement renamed the file and stopped before the final update.
    store(crate::anchor::Anchor {
        generation: [7; 16],
        records: 8,
        pending: Some(current),
    });
    assert_eq!(warning_on_open(&identity, &peer), None);
}

#[test]
fn an_unreadable_anchor_is_reported_and_then_replaced() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "86".repeat(32);
    append_messages(&identity, &peer, 2);
    let directory = conversation_path(&identity, &peer)
        .parent()
        .unwrap()
        .to_owned();
    std::fs::write(directory.join("conversations.anchor"), b"not an anchor").unwrap();
    assert_eq!(
        warning_on_open(&identity, &peer),
        Some(super::IntegrityWarning::AnchorUnreadable)
    );
    assert_eq!(warning_on_open(&identity, &peer), None);
}

#[test]
fn deleting_a_conversation_forgets_its_anchor() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "87".repeat(32);
    append_messages(&identity, &peer, 2);
    let directory = conversation_path(&identity, &peer)
        .parent()
        .unwrap()
        .to_owned();
    let key = identity.storage_key();
    let id = identity.public_id();
    assert!(crate::anchor::load(&key, &id, &directory, &peer)
        .unwrap()
        .is_some());
    History::delete_conversation(&identity, &peer).unwrap();
    assert_eq!(
        crate::anchor::load(&key, &id, &directory, &peer).unwrap(),
        None
    );
    // A new conversation with the same peer starts clean.
    append_messages(&identity, &peer, 1);
    assert_eq!(warning_on_open(&identity, &peer), None);
}

#[test]
fn encrypted_bundle_exports_and_restores_multiple_conversations() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let first = "61".repeat(32);
    let second = "62".repeat(32);
    for (peer, text) in [
        (&first, "first conversation"),
        (&second, "second conversation"),
    ] {
        let (mut history, _, _) = History::open(&identity, peer).unwrap();
        history.append(&message(1, text)).unwrap();
    }
    let bundle =
        History::export_backup_bundle(&identity, &[first.clone(), second.clone()]).unwrap();
    History::delete_conversation(&identity, &first).unwrap();
    History::delete_conversation(&identity, &second).unwrap();
    let mut corrupted = bundle.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(History::import_backup_bundle(&identity, &corrupted).is_err());
    assert!(History::known_peer_ids(&identity).unwrap().is_empty());
    let restored = History::import_backup_bundle(&identity, &bundle).unwrap();
    assert_eq!(restored, vec![(first.clone(), 1), (second.clone(), 1)]);
    assert_eq!(
        History::open(&identity, &first).unwrap().1[0].text,
        "first conversation"
    );
    assert_eq!(
        History::open(&identity, &second).unwrap().1[0].text,
        "second conversation"
    );
}

#[test]
fn bundle_partial_restore_error_reports_already_applied_conversations() {
    let data = IsolatedData::new();
    let (identity, code) = Identity::create().unwrap();
    let first = "63".repeat(32);
    let second = "64".repeat(32);
    for (peer, text) in [(&first, "first"), (&second, "second")] {
        let (mut history, _, _) = History::open(&identity, peer).unwrap();
        history.append(&message(1, text)).unwrap();
    }
    let bundle =
        History::export_backup_bundle(&identity, &[first.clone(), second.clone()]).unwrap();
    let destination = data.0.join("bundle-target");
    std::fs::create_dir_all(&destination).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(destination));
    let target_identity = Identity::from_code(&code).unwrap();
    let (missing_history, _, _) = History::open(&target_identity, &second).unwrap();
    let missing_path = missing_history.path.clone();
    drop(missing_history);
    std::fs::remove_file(missing_path).unwrap();

    let error = History::import_backup_bundle(&target_identity, &bundle)
        .unwrap_err()
        .to_string();
    assert!(error.contains("stopped after 1 conversations"));
    assert_eq!(
        History::read_for_identity_copy(&target_identity, &first)
            .unwrap()
            .0[0]
            .text,
        "first"
    );
}

#[test]
fn verified_contact_listing_skips_legacy_histories_and_rejects_corruption() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let verified = "11".repeat(32);
    let legacy = "22".repeat(32);
    History::open(&identity, &verified).unwrap();
    History::open(&identity, &legacy).unwrap();
    let directory = data.0.join(identity.public_id()).join("verified-contacts");
    let contact = crate::contacts::VerifiedContact {
        peer_key: [0x11; 32],
        rendezvous_secret: zeroize::Zeroizing::new([3; 32]),
    };
    crate::contacts::save(&directory, &identity, &contact).unwrap();
    let contacts = crate::contacts::list_known(&directory, &identity).unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].peer_key, [0x11; 32]);
    let record = std::fs::read_dir(directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&record).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(record, bytes).unwrap();
    assert!(crate::contacts::list_known(
        &data.0.join(identity.public_id()).join("verified-contacts"),
        &identity
    )
    .is_err());
}

#[test]
fn replacing_identity_copies_encrypted_history_and_contacts_without_removing_source() {
    let data = IsolatedData::new();
    let (old_identity, _) = Identity::create().unwrap();
    let peer_id = "33".repeat(32);
    let (mut old_history, _, _) = History::open(&old_identity, &peer_id).unwrap();
    let repeated = StoredMessage {
        unix_time: 123,
        sender: MessageSender::Other,
        text: "same message".to_owned(),
        proof: None,
    };
    old_history.append(&repeated).unwrap();
    old_history.append(&repeated).unwrap();
    let old_directory = data.0.join(old_identity.public_id());
    let history_path = old_history.path.clone();
    let original_history = std::fs::read(&history_path).unwrap();
    let contact = crate::contacts::VerifiedContact {
        peer_key: decode_peer_id(&peer_id).unwrap(),
        rendezvous_secret: zeroize::Zeroizing::new([8; 32]),
    };
    crate::contacts::save(
        &old_directory.join("verified-contacts"),
        &old_identity,
        &contact,
    )
    .unwrap();
    let contact_path = std::fs::read_dir(old_directory.join("verified-contacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original_contact = std::fs::read(&contact_path).unwrap();

    let (replacement, code) = Identity::create().unwrap();
    old_identity.copy_local_data_to(&replacement).unwrap();
    assert_ne!(old_identity.public_id(), replacement.public_id());
    assert_eq!(
        Identity::from_code(&code).unwrap().public_id(),
        replacement.public_id()
    );
    let (_, old_messages, _) = History::open(&old_identity, &peer_id).unwrap();
    let (_, new_messages, _) = History::open(&replacement, &peer_id).unwrap();
    assert_eq!(old_messages, vec![repeated.clone(), repeated.clone()]);
    assert_eq!(new_messages, old_messages);
    assert_eq!(
        *crate::contacts::load(
            &data
                .0
                .join(replacement.public_id())
                .join("verified-contacts"),
            &replacement,
            contact.peer_key
        )
        .unwrap()
        .rendezvous_secret,
        [8; 32]
    );
    assert_eq!(std::fs::read(history_path).unwrap(), original_history);
    assert_eq!(std::fs::read(contact_path).unwrap(), original_contact);
    assert_eq!(
        crate::identity::previous_public_ids(&replacement).unwrap(),
        vec![old_identity.public_id()]
    );
}

#[test]
fn identity_transition_link_merges_before_removing_previous_conversation() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let previous_peer = "51".repeat(32);
    let current_peer = "52".repeat(32);
    let repeated = StoredMessage {
        unix_time: 10,
        sender: MessageSender::Other,
        text: "repeated before transition".to_owned(),
        proof: None,
    };
    let current = message(20, "new identity session");
    let (mut old_history, _, _) = History::open(&identity, &previous_peer).unwrap();
    old_history.append(&repeated).unwrap();
    old_history.append(&repeated).unwrap();
    let (mut new_history, _, _) = History::open(&identity, &current_peer).unwrap();
    new_history.append(&current).unwrap();
    let transition = StoredMessage {
        unix_time: 30,
        sender: MessageSender::Me,
        text: format!(
            "{}peer:{previous_peer}:{current_peer}",
            super::IDENTITY_EVENT_PREFIX
        ),
        proof: None,
    };

    let merged = new_history
        .link_prior_identity(&identity, &previous_peer, transition.clone())
        .unwrap();

    assert_eq!(merged.iter().filter(|item| *item == &repeated).count(), 2);
    assert!(merged.contains(&current));
    assert!(merged.contains(&transition));
    assert!(History::known_peer_ids(&identity)
        .unwrap()
        .contains(&current_peer));
    assert!(!History::known_peer_ids(&identity)
        .unwrap()
        .contains(&previous_peer));
}

#[test]
fn delete_index_write_failure_restores_encrypted_history() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "71".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "preserve me")).unwrap();
    let original = std::fs::read(&history.path).unwrap();
    drop(history);
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_INDEX_WRITE));
    assert!(History::delete_conversation(&identity, &peer).is_err());
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert_eq!(
        std::fs::read(data.0.join(identity.public_id()).join(format!(
            "{}.adlog",
            super::opaque_conversation_name(
                &super::derive_index_key(&identity.storage_key()),
                &peer
            )
        )))
        .unwrap(),
        original
    );
}

#[test]
fn delete_restore_failure_reports_recoverable_tombstone() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "72".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "preserve me")).unwrap();
    let original = std::fs::read(&history.path).unwrap();
    drop(history);
    super::TEST_FAILURES
        .with(|flags| flags.set(super::FAIL_INDEX_WRITE | super::FAIL_DELETE_RESTORE));
    let error = History::delete_conversation(&identity, &peer)
        .unwrap_err()
        .to_string();
    super::TEST_FAILURES.with(|flags| flags.set(0));
    let tombstone = error.split("recoverable file: ").nth(1).unwrap();
    assert_eq!(std::fs::read(tombstone).unwrap(), original);
    assert!(error.contains("injected prior conversation restore failure"));
}

#[test]
fn missing_indexed_history_is_not_recreated_as_empty() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "73".repeat(32);
    let (history, _, _) = History::open(&identity, &peer).unwrap();
    let path = history.path.clone();
    drop(history);
    std::fs::remove_file(path).unwrap();
    let error = match History::open(&identity, &peer) {
        Ok(_) => panic!("missing indexed history was recreated"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn link_reports_prior_recovery_and_current_rollback_failures_together() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let previous_peer = "74".repeat(32);
    let current_peer = "75".repeat(32);
    let (mut previous, _, _) = History::open(&identity, &previous_peer).unwrap();
    previous.append(&message(1, "prior record")).unwrap();
    let (mut current, _, _) = History::open(&identity, &current_peer).unwrap();
    current.append(&message(2, "current record")).unwrap();
    super::TEST_FAILURES.with(|flags| {
        flags.set(
            super::FAIL_INDEX_WRITE | super::FAIL_DELETE_RESTORE | super::FAIL_ROLLBACK_REPLACE,
        )
    });
    let error = current
        .link_prior_identity(&identity, &previous_peer, message(3, "transition"))
        .unwrap_err()
        .to_string();
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert!(error.contains("recoverable file:"));
    let recovery_path = error
        .split("recoverable file: ")
        .nth(1)
        .unwrap()
        .split("); destination rollback")
        .next()
        .unwrap();
    assert!(std::path::Path::new(recovery_path).is_file());
    assert!(error.contains("destination rollback: injected current conversation rollback failure"));
    assert!(error.contains("injected current conversation rollback failure"));
}

#[test]
fn linked_identity_store_failure_rolls_back_merged_history() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let previous_peer = "76".repeat(32);
    let current_peer = "77".repeat(32);
    let (mut previous, _, _) = History::open(&identity, &previous_peer).unwrap();
    previous.append(&message(1, "prior record")).unwrap();
    let (mut current, _, _) = History::open(&identity, &current_peer).unwrap();
    current.append(&message(2, "current record")).unwrap();
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
    let error = current.link_prior_identity(&identity, &previous_peer, message(3, "link"));
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert!(error
        .unwrap_err()
        .to_string()
        .contains("injected linked identity store failure"));
    let (current_messages, _) = History::read_for_identity_copy(&identity, &current_peer).unwrap();
    let (prior_messages, _) = History::read_for_identity_copy(&identity, &previous_peer).unwrap();
    assert_eq!(current_messages.len(), 1);
    assert_eq!(current_messages[0].text, "current record");
    assert_eq!(prior_messages.len(), 1);
    assert!(!super::is_linked_peer_identity(&identity, &current_peer, &previous_peer).unwrap());
}

#[test]
fn identity_transition_merge_preserves_equal_messages_from_both_epochs() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let previous_peer = "61".repeat(32);
    let current_peer = "62".repeat(32);
    let same = message(10, "same text at same second");
    let (mut old_history, _, _) = History::open(&identity, &previous_peer).unwrap();
    old_history.append(&same).unwrap();
    let (mut new_history, _, _) = History::open(&identity, &current_peer).unwrap();
    new_history.append(&same).unwrap();
    let transition = message(20, "transition marker");
    let merged = new_history
        .link_prior_identity(&identity, &previous_peer, transition)
        .unwrap();
    assert_eq!(merged.iter().filter(|item| *item == &same).count(), 2);
}

#[test]
fn identity_replacement_stops_on_partial_source_without_changing_it() {
    let data = IsolatedData::new();
    let (old_identity, _) = Identity::create().unwrap();
    let peer_id = "44".repeat(32);
    let (mut history, _, _) = History::open(&old_identity, &peer_id).unwrap();
    history
        .append(&StoredMessage {
            unix_time: 456,
            sender: MessageSender::Me,
            text: "keep original".to_owned(),
            proof: None,
        })
        .unwrap();
    let source_path = history.path.clone();
    drop(history);
    let length = std::fs::metadata(&source_path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&source_path)
        .unwrap()
        .set_len(length - 1)
        .unwrap();
    let incomplete_source = std::fs::read(&source_path).unwrap();
    let (replacement, _) = Identity::create().unwrap();

    assert!(old_identity.copy_local_data_to(&replacement).is_err());
    assert_eq!(std::fs::read(source_path).unwrap(), incomplete_source);
    assert!(!data.0.join(replacement.public_id()).exists());
}

pub(crate) fn legacy_password_backup(
    identity: &Identity,
    peer: &str,
    messages: &[StoredMessage],
    password: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
    payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
    for message in messages {
        let text = message.text.as_bytes();
        payload.extend_from_slice(&message.unix_time.to_be_bytes());
        payload.push(match message.sender {
            MessageSender::Me => 0,
            MessageSender::Other => 1,
        });
        payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
        payload.extend_from_slice(text);
    }
    let salt = [0x31; super::BACKUP_SALT_BYTES];
    let nonce = [0x52; super::NONCE_BYTES];
    let key = super::derive_password_backup_key(password, &salt).unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &super::backup_aad(identity, super::BACKUP_PASSWORD_MAGIC, Some(&salt)),
            },
        )
        .unwrap();
    let mut backup = Vec::new();
    backup.extend_from_slice(super::BACKUP_PASSWORD_MAGIC);
    backup.extend_from_slice(&salt);
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&encrypted);
    backup
}

/// Writes `bytes` to a fresh file inside the isolated data directory.
fn write_backup_fixture(data: &IsolatedData, name: &str, bytes: &[u8]) -> PathBuf {
    let path = data.0.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn forged_other_message(text: &str) -> StoredMessage {
    StoredMessage {
        unix_time: 1_700_000_000,
        sender: MessageSender::Other,
        text: text.to_owned(),
        proof: None,
    }
}

#[test]
fn forged_password_only_backup_is_not_imported_by_default() {
    let data = IsolatedData::new();
    let (victim, _) = Identity::create().unwrap();
    let peer = "ab".repeat(32);
    // ADBACK2 derives its key from the password alone and authenticates only the
    // victim's *public* id, so an attacker needs nothing secret to build one.
    let forged = legacy_password_backup(
        &victim,
        &peer,
        &[forged_other_message("I agree to the payment")],
        "attacker chosen password",
    );
    let path = write_backup_fixture(&data, "forged.backup", &forged);

    let error = History::import_backup_file(&victim, &path, Some("attacker chosen password"))
        .expect_err("a password-only backup must not import without explicit opt-in");
    assert!(
        error.to_string().contains("ADBACK2"),
        "the error should name the rejected format: {error}"
    );
    let (_, messages, _) = History::open(&victim, &peer).unwrap();
    assert!(
        messages.is_empty(),
        "forged messages must not reach history"
    );
}

/// Every file and directory below `root` as (path, mode), excluding `root` itself.
#[cfg(unix)]
fn modes_below(root: &std::path::Path) -> Vec<(PathBuf, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let mut found = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            found.push((path.clone(), metadata.permissions().mode() & 0o777));
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    found
}

#[cfg(unix)]
#[test]
fn everything_written_for_an_identity_ends_up_owner_only_under_a_permissive_umask() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let (older, _) = Identity::create().unwrap();
    let peer = "a1".repeat(32);
    crate::fsutil::with_permissive_umask(|| {
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "first")).unwrap();
        // Replacing goes through a temporary file and a rename.
        history
            .replace(&[message(1, "first"), message(2, "second")])
            .unwrap();
        drop(history);
        // The linked-key store and the identity lineage are separate files.
        super::record_linked_local_identity(&identity, &peer, &older.public_id()).ok();
        crate::identity::replace_previous_public_ids(&identity, &[older.public_id()]).unwrap();
        let contacts = data.0.join(identity.public_id()).join("verified-contacts");
        crate::contacts::save(
            &contacts,
            &identity,
            &crate::contacts::VerifiedContact {
                peer_key: [7; 32],
                rendezvous_secret: zeroize::Zeroizing::new([9; 32]),
            },
        )
        .unwrap();
        // A backup transfer file and its workspace.
        let (_, mut file) =
            History::create_backup_transfer_file(&identity, &format!("{}.backup", "0".repeat(64)))
                .unwrap();
        History::export_backup_stream(&identity, &peer, None, &mut file).unwrap();
    });
    let found = modes_below(&data.0);
    assert!(
        found.len() >= 8,
        "the scenario should have written files: {found:?}"
    );
    for (path, mode) in &found {
        let expected = if path.is_dir() { 0o700 } else { 0o600 };
        assert_eq!(
            *mode,
            expected,
            "{} is {mode:o} but must be {expected:o}",
            path.display()
        );
    }
}

#[test]
fn macos_data_directory_depends_on_the_build_and_never_on_the_build_machine() {
    let home = std::path::Path::new("/Users/someone");
    let source = std::path::Path::new("/build/machine/another-dimension-v2");
    // A debug build keeps data in the source tree, as before.
    assert_eq!(
        super::macos_data_directory(home, true, source).unwrap(),
        std::path::Path::new("/build/machine/another-dimension-v2/chat-data")
    );
    // A release build uses the user's Application Support folder, so a binary
    // built elsewhere does not write to the builder's directories.
    let release = super::macos_data_directory(home, false, source).unwrap();
    assert_eq!(
        release,
        std::path::Path::new("/Users/someone/Library/Application Support/Another Dimension v2")
    );
    assert!(!release.starts_with(source));
    assert!(super::macos_data_directory(std::path::Path::new(""), false, source).is_none());
}

#[cfg(unix)]
#[test]
fn a_user_chosen_data_directory_must_be_safe_for_secrets() {
    use std::os::unix::fs::PermissionsExt;
    let data = IsolatedData::new();
    let check = |path: &std::path::Path| super::checked_data_directory(path.to_owned());
    let message = |path: &std::path::Path| check(path).unwrap_err().to_string();

    // Shape of the path.
    assert!(message(std::path::Path::new("relative/dir")).contains("absolute"));
    assert!(message(&data.0.join("a").join("..").join("b")).contains(".."));
    // Not created yet: fine, it will be created private.
    let fresh = data.0.join("not-yet");
    assert_eq!(check(&fresh).unwrap(), fresh);

    // An owner-only directory is accepted.
    let private = data.0.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(check(&private).unwrap(), private);

    // Group or world access is refused, and the permissions are left as they were.
    for mode in [0o750, 0o755, 0o707, 0o777] {
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(message(&private).contains("chmod 700"), "{mode:o}");
        let after = std::fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(after, mode, "a rejected directory must not be modified");
    }

    // A symbolic link, even to a good directory, and a plain file are refused.
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = data.0.join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    assert!(message(&link).contains("symbolic link"));
    let file = data.0.join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(message(&file).contains("not a directory"));
}

#[test]
fn legacy_data_is_reported_but_never_moved() {
    let data = IsolatedData::new();
    let (legacy, current) = (data.0.join("legacy"), data.0.join("current"));
    // Nothing there, or an empty directory, or the same place: no warning.
    assert!(super::legacy_data_warning(&current, &legacy).is_none());
    std::fs::create_dir_all(&legacy).unwrap();
    assert!(super::legacy_data_warning(&current, &legacy).is_none());
    std::fs::write(legacy.join("conversation"), b"data").unwrap();
    assert!(super::legacy_data_warning(&legacy, &legacy).is_none());

    let warning = super::legacy_data_warning(&current, &legacy).unwrap();
    assert!(warning.contains(&legacy.display().to_string()), "{warning}");
    assert!(
        warning.contains(&current.display().to_string()),
        "{warning}"
    );
    assert!(warning.contains("ANOTHER_DIMENSION_DATA_DIR="), "{warning}");
    // The warning only reports. The data stays where it was.
    assert!(legacy.join("conversation").exists());
    assert!(!current.exists());
}

/// The index as the previous version wrote it: ADIDX1, encrypted with the key that
/// also names the conversation files.
fn legacy_index_bytes(identity: &Identity, peers: &[String]) -> Vec<u8> {
    let mut payload = (peers.len() as u32).to_be_bytes().to_vec();
    for peer in peers {
        payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
    }
    let nonce = [0x33; super::NONCE_BYTES];
    let encrypted =
        ChaCha20Poly1305::new_from_slice(super::derive_index_key(&identity.storage_key()).as_ref())
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: identity.public_id().as_bytes(),
                },
            )
            .unwrap();
    let mut bytes = super::INDEX_MAGIC.to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    bytes
}

#[test]
fn an_index_from_the_previous_version_still_lists_conversations_and_is_upgraded_on_write() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let (first, second) = ("b1".repeat(32), "b2".repeat(32));
    let directory = data.0.join(identity.public_id());
    std::fs::create_dir_all(&directory).unwrap();
    let index_path = directory.join("conversations.idx");
    std::fs::write(
        &index_path,
        legacy_index_bytes(&identity, std::slice::from_ref(&first)),
    )
    .unwrap();
    assert_eq!(
        History::known_peer_ids(&identity).unwrap(),
        vec![first.clone()]
    );

    // Starting another conversation rewrites the index in the new format.
    History::open(&identity, &second)
        .unwrap()
        .0
        .append(&message(1, "x"))
        .unwrap();
    let rewritten = std::fs::read(&index_path).unwrap();
    assert_eq!(&rewritten[..8], super::INDEX_MAGIC_V2);
    let mut listed = History::known_peer_ids(&identity).unwrap();
    listed.sort();
    assert_eq!(listed, vec![first, second]);
}

#[test]
fn a_new_index_is_not_encrypted_with_the_key_that_names_files() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "b3".repeat(32);
    History::open(&identity, &peer)
        .unwrap()
        .0
        .append(&message(1, "x"))
        .unwrap();
    let bytes = std::fs::read(data.0.join(identity.public_id()).join("conversations.idx")).unwrap();
    assert_eq!(&bytes[..8], super::INDEX_MAGIC_V2);
    let opens_with = |key: &[u8; 32]| {
        ChaCha20Poly1305::new_from_slice(key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&bytes[8..8 + super::NONCE_BYTES]),
                Payload {
                    msg: &bytes[8 + super::NONCE_BYTES..],
                    aad: identity.public_id().as_bytes(),
                },
            )
            .is_ok()
    };
    let storage_key = identity.storage_key();
    assert!(opens_with(&crate::identity::purpose_key(
        &storage_key,
        super::INDEX_AEAD_LABEL
    )));
    assert!(
        !opens_with(&super::derive_index_key(&storage_key)),
        "the filename key must not open the index"
    );
    assert!(!opens_with(&storage_key), "nor may the storage key");
}

#[test]
fn a_linked_key_store_from_the_previous_version_still_reads_and_is_upgraded_on_write() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "b4".repeat(32);
    let (previous, other) = ("c1".repeat(32), "c2".repeat(32));
    let path = super::linked_key_path(&identity, &peer).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // ADLKEY1: the storage key itself, with the identity and peer ids as AAD.
    let mut plaintext = vec![1_u8, 1];
    plaintext.extend_from_slice(&super::decode_peer_id(&previous).unwrap());
    plaintext.extend_from_slice(&super::decode_peer_id(&other).unwrap());
    let nonce = [0x55; super::NONCE_BYTES];
    let aad = [identity.public_id().as_bytes(), peer.as_bytes()].concat();
    let encrypted = ChaCha20Poly1305::new_from_slice(identity.storage_key().as_ref())
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let mut bytes = super::LINKED_KEYS_MAGIC.to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    std::fs::write(&path, &bytes).unwrap();

    let (locals, peers) = super::read_linked_keys(&identity, &peer).unwrap();
    assert!(locals.contains(&previous));
    assert!(peers.contains(&other));

    super::write_linked_keys(&identity, &peer, &(locals, peers)).unwrap();
    let rewritten = std::fs::read(&path).unwrap();
    assert_eq!(&rewritten[..8], super::LINKED_KEYS_MAGIC_V2);
    let (locals, peers) = super::read_linked_keys(&identity, &peer).unwrap();
    assert!(locals.contains(&previous) && peers.contains(&other));
    // The new store does not open with the storage key that log records use.
    let opens_with_storage_key = ChaCha20Poly1305::new_from_slice(identity.storage_key().as_ref())
        .unwrap()
        .decrypt(
            Nonce::from_slice(&rewritten[8..8 + super::NONCE_BYTES]),
            Payload {
                msg: &rewritten[8 + super::NONCE_BYTES..],
                aad: &aad,
            },
        )
        .is_ok();
    assert!(!opens_with_storage_key);
    drop(data);
}

fn open_for_reading(path: &std::path::Path) -> std::fs::File {
    std::fs::File::open(path).unwrap()
}

#[test]
fn a_legacy_backup_is_read_up_to_the_limit_and_not_one_byte_more() {
    let data = IsolatedData::new();
    let at_limit = write_backup_fixture(
        &data,
        "at-limit",
        &vec![7_u8; super::MAX_LEGACY_BACKUP_BYTES],
    );
    let over = write_backup_fixture(
        &data,
        "over",
        &vec![7_u8; super::MAX_LEGACY_BACKUP_BYTES + 1],
    );
    let empty = write_backup_fixture(&data, "empty", &[]);
    assert_eq!(
        super::read_legacy_backup(&mut open_for_reading(&at_limit))
            .unwrap()
            .len(),
        super::MAX_LEGACY_BACKUP_BYTES
    );
    let error = super::read_legacy_backup(&mut open_for_reading(&over)).unwrap_err();
    assert!(error.to_string().contains("16 MiB"), "{error}");
    assert!(super::read_legacy_backup(&mut open_for_reading(&empty))
        .unwrap()
        .is_empty());
}

#[test]
fn a_legacy_backup_that_is_not_a_regular_file_is_refused_before_it_is_read() {
    // A FIFO reports a length of zero, so a size check on metadata lets it through,
    // and it can then supply any number of bytes.
    let data = IsolatedData::new();
    let fifo = data.0.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    // Keep a writer open so that opening for reading does not block, and make sure
    // the reader gives up at once instead of draining the pipe.
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();
    let mut reader = std::fs::File::open(&fifo).unwrap();
    // Run the read on its own thread: a reader that trusts the metadata would block on
    // the pipe forever, and a test that hangs hides the failure from CI.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(super::read_legacy_backup(&mut reader));
    });
    let error = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the read must not block on a pipe")
        .unwrap_err();
    assert!(error.to_string().contains("regular file"), "{error}");
    drop(writer);
    // A directory is not a regular file either.
    let mut directory = std::fs::File::open(&data.0).unwrap();
    assert!(super::read_legacy_backup(&mut directory).is_err());
}

#[test]
fn importing_verifying_and_reprotecting_all_refuse_an_oversized_legacy_file() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    // An unknown magic is treated as a legacy in-memory backup, so every path reads it
    // through read_legacy_backup.
    let mut bytes = vec![0_u8; super::MAX_LEGACY_BACKUP_BYTES + 1];
    bytes[..8].copy_from_slice(b"ADBACK1\0");
    let path = write_backup_fixture(&data, "oversized.backup", &bytes);
    let policy = super::LegacyBackupPolicy::Allow;
    let import = History::import_backup_file_with_policy(&identity, &path, None, policy);
    assert!(import.unwrap_err().to_string().contains("16 MiB"));
    let verify = History::verify_backup_file(&identity, &path, None);
    assert!(verify.unwrap_err().to_string().contains("16 MiB"));
    let (replacement, _) = Identity::create().unwrap();
    let mut output = tempfile_in(&data);
    let reprotect = History::reprotect_backup_file_with_policy(
        &identity,
        &replacement,
        &path,
        &mut output,
        None,
        None,
        policy,
    );
    assert!(reprotect.unwrap_err().to_string().contains("16 MiB"));
    assert_eq!(
        output.metadata().unwrap().len(),
        0,
        "nothing is written for a refused file"
    );
}

fn tempfile_in(data: &IsolatedData) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(data.0.join("reprotect-output"))
        .unwrap()
}

#[test]
fn only_formats_with_weaker_guarantees_need_confirmation() {
    let needs_confirmation = [
        super::BACKUP_PASSWORD_MAGIC,
        super::BACKUP_STREAM_V6_MAGIC,
        super::BACKUP_BUNDLE_MAGIC,
        super::BACKUP_STREAM_BUNDLE_V2_MAGIC,
    ];
    let authenticated_as_a_whole = [
        super::BACKUP_MAGIC,
        super::BACKUP_COMBINED_MAGIC,
        super::BACKUP_SIGNED_MAGIC,
        super::BACKUP_LINKED_MAGIC,
        super::BACKUP_STREAM_MAGIC,
        super::BACKUP_STREAM_BUNDLE_MAGIC,
    ];
    for magic in needs_confirmation {
        let (name, risk) = super::legacy_backup_risk(magic)
            .unwrap_or_else(|| panic!("{magic:?} must require confirmation"));
        assert!(name.starts_with("AD"), "{name}");
        assert!(!risk.is_empty());
    }
    for magic in authenticated_as_a_whole {
        assert!(
            super::legacy_backup_risk(magic).is_none(),
            "{magic:?} must not require confirmation"
        );
    }
    assert!(super::legacy_backup_risk(b"UNKNOWN\0").is_none());
}

#[test]
fn legacy_bundle_is_rejected_by_default_and_imports_after_opt_in() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "e1".repeat(32);
    History::open(&identity, &peer)
        .unwrap()
        .0
        .append(&message(5, "bundled message"))
        .unwrap();
    let bundle = History::export_backup_bundle(&identity, std::slice::from_ref(&peer)).unwrap();
    assert!(bundle.starts_with(super::BACKUP_BUNDLE_MAGIC));
    let path = write_backup_fixture(&data, "legacy-bundle.backup", &bundle);

    // A fresh identity directory models importing on another device.
    let target = data.0.join("bundle-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let error = History::import_backup_file(&identity, &path, None)
        .expect_err("ADPACK1 must not import without confirmation");
    assert!(error.to_string().contains("ADPACK1"), "{error}");
    assert!(History::read_for_identity_copy(&identity, &peer).is_err());

    let imported = History::import_backup_file_with_policy(
        &identity,
        &path,
        None,
        super::LegacyBackupPolicy::Allow,
    )
    .unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].0, peer);
}

#[test]
fn current_format_round_trip_keeps_unsigned_messages_unsigned() {
    let data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "f2".repeat(32);
    // A local record from before messages were signed.
    History::open(&identity, &peer)
        .unwrap()
        .0
        .append(&message(9, "written before signing existed"))
        .unwrap();
    let mut exported = Vec::new();
    History::export_backup_stream(&identity, &peer, None, &mut exported).unwrap();
    assert!(exported.starts_with(super::BACKUP_STREAM_MAGIC));
    let path = write_backup_fixture(&data, "current.backup", &exported);

    let target = data.0.join("current-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    // ADBACK7 needs no confirmation, so the unsigned record arrives silently;
    // the UI therefore has to mark it from `proof` alone.
    History::import_backup_file(&identity, &path, None).unwrap();
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].proof.is_none());
}

#[test]
fn forged_password_only_backup_imports_unsigned_only_after_opt_in() {
    let data = IsolatedData::new();
    let (victim, _) = Identity::create().unwrap();
    let peer = "ac".repeat(32);
    let forged = legacy_password_backup(
        &victim,
        &peer,
        &[forged_other_message("I agree to the payment")],
        "attacker chosen password",
    );
    let path = write_backup_fixture(&data, "forged-allowed.backup", &forged);

    History::import_backup_file_with_policy(
        &victim,
        &path,
        Some("attacker chosen password"),
        super::LegacyBackupPolicy::Allow,
    )
    .unwrap();
    let (_, messages, _) = History::open(&victim, &peer).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, MessageSender::Other);
    assert!(
        messages[0].proof.is_none(),
        "the imported message must stay unsigned so the UI can mark it unverified"
    );
}

fn legacy_identity_backup(identity: &Identity, peer: &str, messages: &[StoredMessage]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
    payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
    for message in messages {
        payload.extend_from_slice(&message.unix_time.to_be_bytes());
        payload.push(match message.sender {
            MessageSender::Me => 0,
            MessageSender::Other => 1,
        });
        payload.extend_from_slice(&(message.text.len() as u32).to_be_bytes());
        payload.extend_from_slice(message.text.as_bytes());
    }
    let nonce = [0x52; super::NONCE_BYTES];
    let key = super::derive_backup_key(&identity.storage_key());
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &super::backup_aad(identity, super::BACKUP_MAGIC, None),
            },
        )
        .unwrap();
    let mut backup = Vec::new();
    backup.extend_from_slice(super::BACKUP_MAGIC);
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&encrypted);
    backup
}

fn legacy_combined_backup(
    identity: &Identity,
    peer: &str,
    messages: &[StoredMessage],
    password: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
    payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
    for message in messages {
        payload.extend_from_slice(&message.unix_time.to_be_bytes());
        payload.push(match message.sender {
            MessageSender::Me => 0,
            MessageSender::Other => 1,
        });
        payload.extend_from_slice(&(message.text.len() as u32).to_be_bytes());
        payload.extend_from_slice(message.text.as_bytes());
    }
    let salt = [0x31; super::BACKUP_SALT_BYTES];
    let nonce = [0x53; super::NONCE_BYTES];
    let password_key = super::derive_password_backup_key(password, &salt).unwrap();
    let key = super::derive_combined_backup_key(&identity.storage_key(), &password_key);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &super::backup_aad(identity, super::BACKUP_COMBINED_MAGIC, Some(&salt)),
            },
        )
        .unwrap();
    let mut backup = Vec::new();
    backup.extend_from_slice(super::BACKUP_COMBINED_MAGIC);
    backup.extend_from_slice(&salt);
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&encrypted);
    backup
}

#[test]
fn backup_import_preserves_repeats_and_reads_existing_legacy_format() {
    let _data = IsolatedData::new();
    let identity = Identity::from_code(&Identity::create().unwrap().1).unwrap();
    let peer = "ab".repeat(32);
    let repeated = message(1_700_000_000, "same message");
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history
        .replace(&[repeated.clone(), repeated.clone()])
        .unwrap();

    // New exports use ADBACK5 and remain idempotent on repeated imports.
    let backup = History::export_backup(&identity, &peer, None).unwrap();
    assert_eq!(&backup[..8], b"ADBACK5\0");
    assert_eq!(
        History::import_backup(&identity, &backup, None).unwrap().1,
        2
    );
    assert_eq!(
        History::import_backup(&identity, &backup, None).unwrap().1,
        2
    );
    let (_, messages, _) = History::open(&identity, &peer).unwrap();
    assert_eq!(messages, vec![repeated.clone(), repeated]);

    let password_backup =
        History::export_backup(&identity, &peer, Some("correct horse battery")).unwrap();
    assert_eq!(&password_backup[..8], b"ADBACK5\0");
    let other_identity = Identity::create().unwrap().0;
    assert!(History::import_backup(
        &other_identity,
        &password_backup,
        Some("correct horse battery")
    )
    .is_err());
    assert!(History::import_backup(&identity, &password_backup, Some("wrong password")).is_err());
    let mut tampered = password_backup.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(History::import_backup(&identity, &tampered, Some("correct horse battery")).is_err());
    assert_eq!(
        History::import_backup(&identity, &password_backup, Some("correct horse battery"))
            .unwrap()
            .1,
        2
    );

    // ADBACK2 was password-only. It remains importable for existing users.
    let old_password_backup = legacy_password_backup(
        &identity,
        &peer,
        &[message(1_700_000_001, "legacy")],
        "correct horse battery",
    );
    assert_eq!(&old_password_backup[..8], b"ADBACK2\0");
    assert_eq!(
        History::import_backup(
            &identity,
            &old_password_backup,
            Some("correct horse battery")
        )
        .unwrap()
        .1,
        3
    );
    let old_identity_backup = legacy_identity_backup(
        &identity,
        &peer,
        &[message(1_700_000_002, "legacy identity backup")],
    );
    assert_eq!(&old_identity_backup[..8], b"ADBACK1\0");
    assert_eq!(
        History::import_backup(&identity, &old_identity_backup, None)
            .unwrap()
            .1,
        4
    );
    let old_combined_backup = legacy_combined_backup(
        &identity,
        &peer,
        &[message(1_700_000_003, "legacy combined backup")],
        "correct horse battery",
    );
    assert_eq!(&old_combined_backup[..8], b"ADBACK3\0");
    assert_eq!(
        History::import_backup(
            &identity,
            &old_combined_backup,
            Some("correct horse battery")
        )
        .unwrap()
        .1,
        5
    );
}

#[test]
fn old_identity_backup_can_be_reprotected_without_changing_the_source() {
    let _data = IsolatedData::new();
    let (old_identity, old_code) = Identity::create().unwrap();
    let (replacement, _) = Identity::create().unwrap();
    let peer = "ac".repeat(32);
    let original_messages = vec![
        message(1_700_000_001, "first"),
        message(1_700_000_001, "first"),
    ];
    let source = legacy_password_backup(
        &old_identity,
        &peer,
        &original_messages,
        "previous backup password",
    );
    let source_copy = source.clone();

    assert!(History::reprotect_backup(
        &old_identity,
        &replacement,
        &source,
        Some("wrong previous password"),
        None,
    )
    .is_err());
    let reprotected = History::reprotect_backup(
        &old_identity,
        &replacement,
        &source,
        Some("previous backup password"),
        Some("new backup password"),
    )
    .unwrap();

    assert_eq!(source, source_copy);
    assert_eq!(
        History::verify_backup(&replacement, &reprotected, Some("new backup password")).unwrap(),
        (peer.clone(), original_messages.len())
    );
    assert!(
        History::verify_backup(&old_identity, &reprotected, Some("new backup password")).is_err()
    );
    assert_eq!(
        History::verify_backup(&old_identity, &source, Some("previous backup password")).unwrap(),
        (peer, original_messages.len())
    );
    assert_eq!(
        Identity::from_code(&old_code).unwrap().public_id(),
        old_identity.public_id()
    );
}

#[test]
fn reprotected_backup_preserves_proofs_bound_to_previous_local_identity() {
    let _data = IsolatedData::new();
    let (previous, _) = Identity::create().unwrap();
    let (replacement, _) = Identity::create().unwrap();
    let (peer, _) = Identity::create().unwrap();
    let peer_id = peer.public_id();
    let outgoing =
        super::sign_message(&previous, &peer_id, 41, "signed before change".into()).unwrap();
    let mut incoming = super::sign_message(
        &peer,
        &previous.public_id(),
        42,
        "received before change".into(),
    )
    .unwrap();
    incoming.sender = super::MessageSender::Other;
    let source = super::encode_backup_with_links(
        &previous,
        &peer_id,
        &[outgoing, incoming],
        None,
        &super::BackupLinks::default(),
    )
    .unwrap();

    let result = History::reprotect_backup(&previous, &replacement, &source, None, None).unwrap();
    assert_eq!(
        History::verify_backup(&replacement, &result, None).unwrap(),
        (peer_id, 2)
    );
    let (_, _, links) = super::decode_backup_with_links(&replacement, &result, None).unwrap();
    assert!(links.local.contains(&previous.public_id()));
    assert!(links.origins.contains(&previous.public_id()));
}

#[test]
fn linking_multiple_peer_identity_epochs_carries_authenticated_aliases() {
    let _data = IsolatedData::new();
    let (local, _) = Identity::create().unwrap();
    let (peer_a, _) = Identity::create().unwrap();
    let (peer_b, _) = Identity::create().unwrap();
    let (peer_c, _) = Identity::create().unwrap();
    let peer_a_id = peer_a.public_id();
    let peer_b_id = peer_b.public_id();
    let peer_c_id = peer_c.public_id();
    let mut signed_by_a = super::sign_message(
        &peer_a,
        &local.public_id(),
        70,
        "proof from first peer identity".into(),
    )
    .unwrap();
    signed_by_a.sender = super::MessageSender::Other;
    let (mut history_a, _, _) = History::open(&local, &peer_a_id).unwrap();
    history_a.append(&signed_by_a).unwrap();

    let (mut history_b, _, _) = History::open(&local, &peer_b_id).unwrap();
    history_b
        .link_prior_identity(
            &local,
            &peer_a_id,
            message(
                71,
                &format!(
                    "{}peer:{peer_a_id}:{peer_b_id}",
                    super::IDENTITY_EVENT_PREFIX
                ),
            ),
        )
        .unwrap();
    let (mut history_c, _, _) = History::open(&local, &peer_c_id).unwrap();
    history_c
        .link_prior_identity(
            &local,
            &peer_b_id,
            message(
                72,
                &format!(
                    "{}peer:{peer_b_id}:{peer_c_id}",
                    super::IDENTITY_EVENT_PREFIX
                ),
            ),
        )
        .unwrap();

    let (messages, _) = History::read_for_identity_copy(&local, &peer_c_id).unwrap();
    let (_, peer_aliases) =
        super::linked_identity_keys(&local, &messages, &local.public_id(), &peer_c_id, &[])
            .unwrap();
    assert!(peer_aliases.contains(&peer_a.public_key()));
    assert!(peer_aliases.contains(&peer_b.public_key()));
    super::verify_stored_proof(&local, &peer_c_id, &signed_by_a, &[], &peer_aliases).unwrap();
}

fn messages_with_payload_len(payload_len: usize) -> Vec<StoredMessage> {
    // ADBACK4/5 add one proof-presence byte to each legacy record.
    let record_bytes = payload_len - 36;
    let count = record_bytes.div_ceil(MAX_MESSAGE_BYTES + 14);
    let mut remaining = record_bytes;
    let mut messages = Vec::with_capacity(count);
    for index in 0..count {
        let slots_left = count - index - 1;
        let size = remaining.saturating_sub(slots_left * (MAX_MESSAGE_BYTES + 14));
        let text_len = (size - 14).clamp(1, MAX_MESSAGE_BYTES);
        messages.push(message(index as u64, &"x".repeat(text_len)));
        remaining -= text_len + 14;
    }
    assert_eq!(remaining, 0);
    messages
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn streaming_backup_import_bundle_and_reprotection_exceed_legacy_limit() {
    let data = IsolatedData::new();
    let (identity, identity_code) = Identity::create().unwrap();
    let peer = "c9".repeat(32);
    let empty_peer = "ca".repeat(32);
    let long_text = "m".repeat(MAX_MESSAGE_BYTES);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    for index in 0..4_200 {
        history.append(&message(index, &long_text)).unwrap();
    }
    History::open(&identity, &empty_peer).unwrap();

    let transfer_dir = History::backup_transfer_directory(&identity).unwrap();
    let single_path = transfer_dir.join("large-single-fixture.adbak");
    let mut single = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&single_path)
        .unwrap();
    super::set_private_file(&single).unwrap();
    assert_eq!(
        History::export_backup_stream(&identity, &peer, Some("old backup password"), &mut single)
            .unwrap(),
        4_200
    );
    single.flush().unwrap();
    single.sync_all().unwrap();
    assert!(single.metadata().unwrap().len() > MAX_LEGACY_BACKUP_BYTES as u64);
    drop(single);
    let original_len = std::fs::metadata(&single_path).unwrap().len();
    assert_eq!(
        History::verify_backup_file(&identity, &single_path, Some("old backup password")).unwrap(),
        (peer.clone(), 4_200)
    );

    let replacement = Identity::create().unwrap().0;
    let reprotected_path = transfer_dir.join("large-reprotected-fixture.adbak");
    let mut reprotected = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&reprotected_path)
        .unwrap();
    super::set_private_file(&reprotected).unwrap();
    assert_eq!(
        History::reprotect_backup_file(
            &identity,
            &replacement,
            &single_path,
            &mut reprotected,
            Some("old backup password"),
            Some("new backup password"),
        )
        .unwrap(),
        4_200
    );
    reprotected.flush().unwrap();
    reprotected.sync_all().unwrap();
    drop(reprotected);
    assert_eq!(
        History::verify_backup_file(&replacement, &reprotected_path, Some("new backup password"))
            .unwrap(),
        (peer.clone(), 4_200)
    );
    assert_eq!(std::fs::metadata(&single_path).unwrap().len(), original_len);

    let bundle_path = transfer_dir.join("large-bundle-fixture.adbak");
    let mut bundle = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&bundle_path)
        .unwrap();
    super::set_private_file(&bundle).unwrap();
    History::export_backup_bundle_stream(
        &identity,
        &[peer.clone(), empty_peer.clone()],
        &mut bundle,
    )
    .unwrap();
    bundle.flush().unwrap();
    bundle.sync_all().unwrap();
    assert!(bundle.metadata().unwrap().len() > MAX_LEGACY_BACKUP_BYTES as u64);
    drop(bundle);

    let target = data.0.join("stream-backup-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let target_identity = Identity::from_code(&identity_code).unwrap();
    let (mut original_history, _, _) = History::open(&target_identity, &peer).unwrap();
    original_history
        .append(&message(9_000, "preserve on authentication failure"))
        .unwrap();
    let corrupted_path = transfer_dir.join("corrupted-large-fixture.adbak");
    std::fs::copy(&single_path, &corrupted_path).unwrap();
    let mut corrupted = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&corrupted_path)
        .unwrap();
    corrupted.seek(SeekFrom::Start(90)).unwrap();
    let mut byte = [0];
    corrupted.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    corrupted.seek(SeekFrom::Start(90)).unwrap();
    corrupted.write_all(&byte).unwrap();
    corrupted.sync_all().unwrap();
    assert!(History::import_backup_file(
        &target_identity,
        &corrupted_path,
        Some("old backup password")
    )
    .is_err());
    let mut unchanged = History::reader_for_identity_copy(&target_identity, &peer).unwrap();
    assert_eq!(
        unchanged.next_record().unwrap(),
        Some(message(9_000, "preserve on authentication failure"))
    );
    assert_eq!(unchanged.next_record().unwrap(), None);
    let imported =
        History::import_backup_file(&target_identity, &single_path, Some("old backup password"))
            .unwrap();
    assert_eq!(imported, vec![(peer.clone(), 4_200, false)]);
    let bundle_imported =
        History::import_backup_file(&target_identity, &bundle_path, None).unwrap();
    assert_eq!(bundle_imported.len(), 2);
    assert_eq!(bundle_imported[0].1, 4_200);
    assert_eq!(bundle_imported[1].1, 0);
    let mut reader = History::reader_for_identity_copy(&target_identity, &peer).unwrap();
    assert_eq!(reader.next_record().unwrap(), Some(message(0, &long_text)));
    assert_eq!(reader.next_record().unwrap(), Some(message(1, &long_text)));
    assert_eq!(reader.next_record().unwrap(), Some(message(2, &long_text)));
}

#[test]
fn backup_stream_file_id_rejects_cross_file_frame_and_completion_swaps() {
    let _data = IsolatedData::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "d1".repeat(32);
    let (mut history, _, _) = History::open(&identity, &peer).unwrap();
    history.append(&message(1, "frame one")).unwrap();
    history.append(&message(2, "frame two")).unwrap();

    let mut backups = Vec::new();
    for _ in 0..2 {
        let mut backup = Vec::new();
        History::export_backup_stream(&identity, &peer, None, &mut backup).unwrap();
        backups.push(backup);
    }
    assert!(backups[0].starts_with(b"ADBACK7\0"));
    let peer_bytes = super::decode_peer_id(&peer).unwrap();
    assert!(!backups[0][..25]
        .windows(peer_bytes.len())
        .any(|window| window == peer_bytes));
    let mut password_backup = Vec::new();
    History::export_backup_stream(
        &identity,
        &peer,
        Some("correct horse battery"),
        &mut password_backup,
    )
    .unwrap();
    let password_path = History::backup_transfer_directory(&identity)
        .unwrap()
        .join("wrong-password.adbak");
    std::fs::write(&password_path, password_backup).unwrap();
    assert!(History::verify_backup_file(
        &identity,
        &password_path,
        Some("incorrect horse battery")
    )
    .is_err());

    let frames_a = super::tests::stream_frame_ranges(&backups[0]);
    let frames_b = super::tests::stream_frame_ranges(&backups[1]);
    for (kind, index) in [(1, 1), (0, 3)] {
        let range_a = frames_a
            .iter()
            .find(|frame| frame.0 == kind && frame.1 == index)
            .unwrap()
            .2
            .clone();
        let range_b = frames_b
            .iter()
            .find(|frame| frame.0 == kind && frame.1 == index)
            .unwrap()
            .2
            .clone();
        assert_eq!(range_a.len(), range_b.len());
        let mut mixed = backups[0].clone();
        mixed[range_a].copy_from_slice(&backups[1][range_b]);
        let path = History::backup_transfer_directory(&identity)
            .unwrap()
            .join(format!("swapped-{kind}-{index}.adbak"));
        std::fs::write(&path, mixed).unwrap();
        assert!(History::verify_backup_file(&identity, &path, None).is_err());
    }
}

fn stream_frame_ranges(backup: &[u8]) -> Vec<(u8, u64, std::ops::Range<usize>)> {
    assert!(backup.starts_with(super::BACKUP_STREAM_MAGIC));
    let mut offset = 8 + 1 + 16;
    if backup[8] == 1 {
        offset += super::BACKUP_SALT_BYTES;
    }
    let mut frames = Vec::new();
    loop {
        let start = offset;
        let kind = backup[offset];
        let index = u64::from_be_bytes(backup[offset + 1..offset + 9].try_into().unwrap());
        let length = u32::from_be_bytes(
            backup[offset + 9 + super::NONCE_BYTES..offset + 13 + super::NONCE_BYTES]
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 1 + 8 + super::NONCE_BYTES + 4 + length;
        frames.push((kind, index, start..offset));
        if kind == 0 {
            break;
        }
    }
    frames
}

#[test]
fn v6_backup_and_v2_bundle_need_confirmation_but_remain_importable() {
    let data = IsolatedData::new();
    let (identity, code) = Identity::create().unwrap();
    let peer = "d2".repeat(32);
    let record = message(7, "legacy streaming backup");
    let backup = encode_v6_fixture(&identity, &peer, std::slice::from_ref(&record));
    let mut bundle = super::BACKUP_STREAM_BUNDLE_V2_MAGIC.to_vec();
    bundle.extend_from_slice(&1_u32.to_be_bytes());
    bundle.extend_from_slice(&(backup.len() as u64).to_be_bytes());
    bundle.extend_from_slice(&backup);

    let target = data.0.join("legacy-stream-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let target_identity = Identity::from_code(&code).unwrap();
    let backup_path = History::backup_transfer_directory(&target_identity)
        .unwrap()
        .join("legacy-v6.adbak");
    std::fs::write(&backup_path, backup).unwrap();
    assert!(
        History::verify_backup_file(&Identity::create().unwrap().0, &backup_path, None).is_err()
    );
    let error = History::import_backup_file(&target_identity, &backup_path, None)
        .expect_err("ADBACK6 must not import without confirmation");
    assert!(error.to_string().contains("ADBACK6"), "{error}");
    assert!(History::open(&target_identity, &peer).unwrap().1.is_empty());
    assert_eq!(
        History::import_backup_file_with_policy(
            &target_identity,
            &backup_path,
            None,
            super::LegacyBackupPolicy::Allow,
        )
        .unwrap(),
        vec![(peer.clone(), 1, false)]
    );

    let replacement = Identity::create().unwrap().0;
    let reprotected_path = History::backup_transfer_directory(&target_identity)
        .unwrap()
        .join("reprotected-v6.adbak");
    let mut reprotected = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&reprotected_path)
        .unwrap();
    let error = History::reprotect_backup_file(
        &target_identity,
        &replacement,
        &backup_path,
        &mut reprotected,
        None,
        None,
    )
    .expect_err("re-protecting ADBACK6 must need the same confirmation");
    assert!(error.to_string().contains("ADBACK6"), "{error}");
    assert_eq!(reprotected.metadata().unwrap().len(), 0);
    History::reprotect_backup_file_with_policy(
        &target_identity,
        &replacement,
        &backup_path,
        &mut reprotected,
        None,
        None,
        super::LegacyBackupPolicy::Allow,
    )
    .unwrap();
    reprotected.flush().unwrap();
    drop(reprotected);
    assert!(std::fs::read(&reprotected_path)
        .unwrap()
        .starts_with(super::BACKUP_STREAM_MAGIC));
    assert_eq!(
        History::verify_backup_file(&replacement, &reprotected_path, None).unwrap(),
        (peer.clone(), 1)
    );

    let bundle_path = History::backup_transfer_directory(&target_identity)
        .unwrap()
        .join("legacy-v2.adbak");
    std::fs::write(&bundle_path, bundle).unwrap();
    let bundle_target = data.0.join("legacy-v2-target");
    std::fs::create_dir_all(&bundle_target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(bundle_target));
    let bundle_identity = Identity::from_code(&code).unwrap();
    let error = History::import_backup_file(&bundle_identity, &bundle_path, None)
        .expect_err("ADPACK2 must not import without confirmation");
    assert!(error.to_string().contains("ADPACK2"), "{error}");
    assert_eq!(
        History::import_backup_file_with_policy(
            &bundle_identity,
            &bundle_path,
            None,
            super::LegacyBackupPolicy::Allow,
        )
        .unwrap(),
        vec![(peer.clone(), 1, false)]
    );
    let mut reader = History::reader_for_identity_copy(&bundle_identity, &peer).unwrap();
    assert_eq!(reader.next_record().unwrap(), Some(record));
    assert_eq!(reader.next_record().unwrap(), None);
}

#[test]
fn bundle3_rejects_membership_tampering_without_applying_any_child() {
    let data = IsolatedData::new();
    let (identity, code) = Identity::create().unwrap();
    let peers = ["d3".repeat(32), "d4".repeat(32), "d5".repeat(32)];
    for (index, peer) in peers.iter().enumerate() {
        History::open(&identity, peer)
            .unwrap()
            .0
            .append(&message(index as u64 + 1, "bundle member"))
            .unwrap();
        super::write_linked_keys(
            &identity,
            peer,
            &(
                HashSet::new(),
                HashSet::from([format!("f{index}").repeat(32)]),
            ),
        )
        .unwrap();
    }
    let directory = History::backup_transfer_directory(&identity).unwrap();
    let bundle_path = directory.join("members.adbak");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&bundle_path)
        .unwrap();
    History::export_backup_bundle_stream(&identity, &peers[..2], &mut output).unwrap();
    output.flush().unwrap();
    drop(output);
    let bundle = std::fs::read(&bundle_path).unwrap();
    let children = bundle3_children(&bundle);

    let replacement_path = directory.join("replacement-member.adbak");
    let mut replacement_output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&replacement_path)
        .unwrap();
    History::export_backup_bundle_stream(&identity, &peers[2..], &mut replacement_output).unwrap();
    replacement_output.flush().unwrap();
    drop(replacement_output);
    let replacement = std::fs::read(&replacement_path).unwrap();
    let replacement_child = bundle3_children(&replacement)[0];

    let mut removed = bundle[..24].to_vec();
    removed.extend_from_slice(&1_u32.to_be_bytes());
    append_bundle3_child(&mut removed, &bundle, children[0]);
    removed.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);

    let mut replaced = bundle[..24].to_vec();
    replaced.extend_from_slice(&2_u32.to_be_bytes());
    append_bundle3_child(&mut replaced, &bundle, children[0]);
    append_bundle3_child(&mut replaced, &replacement, replacement_child);
    replaced.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);

    let mut reordered = bundle[..24].to_vec();
    reordered.extend_from_slice(&2_u32.to_be_bytes());
    append_bundle3_child(&mut reordered, &bundle, children[1]);
    append_bundle3_child(&mut reordered, &bundle, children[0]);
    reordered.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);
    let mut invalid_tag = bundle.clone();
    let last = invalid_tag.len() - 1;
    invalid_tag[last] ^= 1;

    fn reject_without_changes(
        root: &std::path::Path,
        code: &str,
        file_name: &str,
        bundle: &[u8],
        peers: &[String],
    ) {
        let target = root.join(format!("{file_name}-target"));
        std::fs::create_dir_all(&target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
        let target_identity = Identity::from_code(code).unwrap();
        for (index, peer) in peers.iter().enumerate() {
            History::open(&target_identity, peer)
                .unwrap()
                .0
                .append(&message(index as u64 + 100, "existing local record"))
                .unwrap();
            super::write_linked_keys(
                &target_identity,
                peer,
                &(HashSet::new(), HashSet::from(["ee".repeat(32)])),
            )
            .unwrap();
        }
        let relationships: Vec<_> = peers
            .iter()
            .map(|peer| super::read_linked_keys(&target_identity, peer).unwrap())
            .collect();
        let path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join(file_name);
        std::fs::write(&path, bundle).unwrap();
        let error = History::import_backup_file(&target_identity, &path, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("backup bundle authentication failed"),
            "{error}"
        );
        assert!(!error.to_string().contains("applying "), "{error}");
        for (index, peer) in peers.iter().enumerate() {
            let mut reader = History::reader_for_identity_copy(&target_identity, peer).unwrap();
            assert_eq!(
                reader.next_record().unwrap(),
                Some(message(index as u64 + 100, "existing local record"))
            );
            assert_eq!(reader.next_record().unwrap(), None);
            assert_eq!(
                super::read_linked_keys(&target_identity, peer).unwrap(),
                relationships[index]
            );
        }
    }

    reject_without_changes(&data.0, &code, "removed.adbak", &removed, &peers);
    reject_without_changes(&data.0, &code, "replaced.adbak", &replaced, &peers);
    reject_without_changes(&data.0, &code, "reordered.adbak", &reordered, &peers);
    reject_without_changes(&data.0, &code, "invalid-tag.adbak", &invalid_tag, &peers);

    let target = data.0.join("valid-bundle-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let target_identity = Identity::from_code(&code).unwrap();
    let valid_path = History::backup_transfer_directory(&target_identity)
        .unwrap()
        .join("valid.adpak");
    std::fs::write(&valid_path, &bundle).unwrap();
    assert_eq!(
        History::import_backup_file(&target_identity, &valid_path, None).unwrap(),
        vec![(peers[0].clone(), 1, true), (peers[1].clone(), 1, true)]
    );
}

#[test]
fn bundle3_authenticated_save_failure_reports_partial_application() {
    let data = IsolatedData::new();
    let (identity, code) = Identity::create().unwrap();
    let peers = ["d6".repeat(32), "d7".repeat(32)];
    for peer in &peers {
        History::open(&identity, peer)
            .unwrap()
            .0
            .append(&message(1, "verified child"))
            .unwrap();
    }
    let linked_peer_id = "e8".repeat(32);
    super::write_linked_keys(
        &identity,
        &peers[1],
        &(HashSet::new(), HashSet::from([linked_peer_id])),
    )
    .unwrap();
    let directory = History::backup_transfer_directory(&identity).unwrap();
    let path = directory.join("late-error-source.adbak");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    History::export_backup_bundle_stream(&identity, &peers, &mut output).unwrap();
    output.flush().unwrap();
    drop(output);
    let target = data.0.join("late-error-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let target_identity = Identity::from_code(&code).unwrap();
    let bundle = std::fs::read(&path).unwrap();
    let import_path = History::backup_transfer_directory(&target_identity)
        .unwrap()
        .join("storage-error.adpak");
    std::fs::write(&import_path, bundle).unwrap();
    super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
    let error = History::import_backup_file(&target_identity, &import_path, None).unwrap_err();
    super::TEST_FAILURES.with(|flags| flags.set(0));
    assert!(
        error.to_string().contains("applying 1 conversation"),
        "{error}"
    );
    let mut reader = History::reader_for_identity_copy(&target_identity, &peers[0]).unwrap();
    assert_eq!(
        reader.next_record().unwrap(),
        Some(message(1, "verified child"))
    );
    assert_eq!(reader.next_record().unwrap(), None);
    assert!(super::read_linked_keys(&target_identity, &peers[1])
        .unwrap()
        .0
        .is_empty());
}

#[test]
fn streaming_bundle_import_accepts_an_empty_conversation() {
    let data = IsolatedData::new();
    let (identity, code) = Identity::create().unwrap();
    let peer = "cb".repeat(32);
    History::open(&identity, &peer).unwrap();
    let directory = History::backup_transfer_directory(&identity).unwrap();
    let path = directory.join("empty-bundle-test.adbak");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    History::export_backup_bundle_stream(&identity, std::slice::from_ref(&peer), &mut output)
        .unwrap();
    output.flush().unwrap();
    output.sync_all().unwrap();
    drop(output);
    let target = data.0.join("empty-bundle-target");
    std::fs::create_dir_all(&target).unwrap();
    super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
    let target_identity = Identity::from_code(&code).unwrap();
    assert_eq!(
        History::import_backup_file(&target_identity, &path, None).unwrap(),
        vec![(peer, 0, false)]
    );
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn exports_enforce_the_final_file_size_limit_for_both_formats() {
    let _data = IsolatedData::new();
    let identity = Identity::create().unwrap().0;
    let peer = "cd".repeat(32);
    for password in [None, Some("correct horse battery")] {
        let envelope_len = 8 + password.map_or(0, |_| 16) + 12 + 16;
        let exact_payload_len = MAX_LEGACY_BACKUP_BYTES - envelope_len - 11;
        let mut history = History::open(&identity, &peer).unwrap().0;
        history
            .replace(&messages_with_payload_len(exact_payload_len))
            .unwrap();
        let backup = History::export_backup(&identity, &peer, password).unwrap();
        assert_eq!(backup.len(), MAX_LEGACY_BACKUP_BYTES);

        history
            .replace(&messages_with_payload_len(exact_payload_len + 1))
            .unwrap();
        assert_eq!(
            History::export_backup(&identity, &peer, password)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
