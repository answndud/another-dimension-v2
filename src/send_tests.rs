use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn backup_transfer_api_uses_small_authenticated_chunks_for_export_and_import() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "ab".repeat(32);
    let (mut history, _, _) = history::History::open(&identity, &peer).unwrap();
    history
        .append(&history::StoredMessage {
            unix_time: 1,
            sender: history::MessageSender::Me,
            text: "chunked backup".to_owned(),
            proof: None,
        })
        .unwrap();
    let state = test_state(Some(Arc::new(identity)), HashMap::new());
    let exported = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &serde_json::json!({ "action": "export", "peerId": peer, "password": "" }).to_string(),
        "test-session",
    );
    assert!(exported.starts_with("HTTP/1.1 200 OK"), "{exported}");
    let export: serde_json::Value =
        serde_json::from_str(exported.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let export_id = export["transferId"].as_str().unwrap();
    let export_size = export["size"].as_u64().unwrap();
    let downloaded = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &serde_json::json!({ "action": "read", "transferId": export_id, "offset": 0 }).to_string(),
        "test-session",
    );
    let chunk: serde_json::Value =
        serde_json::from_str(downloaded.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(chunk["size"].as_u64(), Some(export_size));
    let backup = BASE64.decode(chunk["data"].as_str().unwrap()).unwrap();
    assert!(backup.starts_with(b"ADBACK7\0"));
    assert_eq!(backup.len() as u64, export_size);

    let upload = call_test_api(
        &state,
        "/api/history/backup-transfer",
        r#"{"action":"upload-start"}"#,
        "test-session",
    );
    let upload: serde_json::Value =
        serde_json::from_str(upload.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let upload_id = upload["transferId"].as_str().unwrap();
    let transfer_workspace = history::History::backup_transfer_directory(
        state.lock().unwrap().identity.as_ref().unwrap(),
    )
    .unwrap();
    assert!(transfer_workspace
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".process-")));
    let manifest = std::fs::read_to_string(transfer_workspace.join("manifest")).unwrap();
    assert!(manifest
        .lines()
        .any(|line| line.starts_with(&format!("{upload_id}.backup\t"))));
    let written = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &serde_json::json!({
            "action": "upload-chunk", "transferId": upload_id,
            "offset": 0, "data": BASE64.encode(&backup)
        })
        .to_string(),
        "test-session",
    );
    assert!(written.starts_with("HTTP/1.1 200 OK"), "{written}");
    let restored = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &serde_json::json!({ "action": "import", "transferId": upload_id, "password": "" })
            .to_string(),
        "test-session",
    );
    assert!(restored.starts_with("HTTP/1.1 200 OK"), "{restored}");
    let (messages, _) = history::History::read_for_identity_copy(
        state.lock().unwrap().identity.as_ref().unwrap(),
        &peer,
    )
    .unwrap();
    assert_eq!(messages.len(), 1);
    let cleaned = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &serde_json::json!({ "action": "cleanup", "transferId": export_id }).to_string(),
        "test-session",
    );
    assert!(cleaned.starts_with("HTTP/1.1 200 OK"));
}

fn test_state_for(identity: Identity) -> Arc<Mutex<State>> {
    test_state(Some(Arc::new(identity)), HashMap::new())
}

fn upload_backup_bytes(state: &Arc<Mutex<State>>, bytes: &[u8]) -> String {
    let started = call_test_api(
        state,
        "/api/history/backup-transfer",
        r#"{"action":"upload-start"}"#,
        "test-session",
    );
    let started: serde_json::Value =
        serde_json::from_str(started.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let id = started["transferId"].as_str().unwrap().to_owned();
    let written = call_test_api(
        state,
        "/api/history/backup-transfer",
        &serde_json::json!({
            "action": "upload-chunk", "transferId": id,
            "offset": 0, "data": BASE64.encode(bytes)
        })
        .to_string(),
        "test-session",
    );
    assert!(written.starts_with("HTTP/1.1 200 OK"), "{written}");
    id
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

/// Feeds prepared chunks, then reports a stall, like a client that went quiet.
struct ChunkedReader {
    chunks: VecDeque<Vec<u8>>,
    closed: bool,
}

impl ChunkedReader {
    fn new(data: &[u8], chunk: usize) -> Self {
        Self {
            chunks: data.chunks(chunk).map(<[u8]>::to_vec).collect(),
            closed: false,
        }
    }
}

impl ReadWithin for ChunkedReader {
    fn read_within(&mut self, buffer: &mut [u8], _: Instant) -> io::Result<usize> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                buffer[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            None if self.closed => Ok(0),
            None => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

fn head_of(size: usize) -> Vec<u8> {
    // A request head of exactly `size` bytes, ending in the blank line.
    let mut head = b"POST /x HTTP/1.1\r\nX-Pad: ".to_vec();
    head.resize(size - 4, b'a');
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), size);
    head
}

fn read_head(data: &[u8], chunk: usize) -> (Result<usize, RequestReadError>, Vec<u8>) {
    let mut reader = ChunkedReader::new(data, chunk);
    let mut request = Vec::new();
    let result = read_request_head(&mut reader, &mut request, Instant::now());
    (result, request)
}

#[test]
fn a_head_that_fits_is_accepted_even_when_the_read_overshoots_the_limit() {
    // The head ends at 8100 bytes, below the 8192 limit, and a body follows in the
    // same reads. 1000-byte reads put the end of the head in a read that carries
    // the buffer past the limit, which the old check rejected.
    let mut data = head_of(8100);
    data.extend_from_slice(&[b'b'; 1000]);
    let (result, request) = read_head(&data, 1000);
    assert_eq!(result, Ok(8100));
    assert!(
        request.len() > 8100,
        "the start of the body stays in the buffer"
    );
}

#[test]
fn a_head_over_the_limit_is_invalid() {
    assert_eq!(
        read_head(&vec![b'a'; 9000], 1000).0,
        Err(RequestReadError::Invalid)
    );
    // The blank line exists but only after the limit.
    assert_eq!(
        read_head(&head_of(MAX_HEADER + 4), 1024).0,
        Err(RequestReadError::Invalid)
    );
    assert_eq!(read_head(&head_of(MAX_HEADER), 1024).0, Ok(MAX_HEADER));
}

#[test]
fn the_end_of_the_head_is_found_across_read_boundaries() {
    let head = head_of(200);
    for chunk in [1, 2, 3, 7, 50] {
        assert_eq!(read_head(&head, chunk).0, Ok(200), "chunk size {chunk}");
    }
}

#[test]
fn a_closed_or_silent_client_is_not_a_complete_head() {
    let mut reader = ChunkedReader::new(b"POST /x HTTP/1.1\r\n", 8);
    reader.closed = true;
    let mut request = Vec::new();
    assert_eq!(
        read_request_head(&mut reader, &mut request, Instant::now()),
        Err(RequestReadError::Invalid)
    );
    assert_eq!(
        read_head(b"POST /x HTTP/1.1\r\n", 8).0,
        Err(RequestReadError::TimedOut)
    );
}

struct TestServer {
    address: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let (identity, _) = Identity::create().unwrap();
        let state = test_state_for(identity);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (host, stop) = (address.clone(), Arc::clone(&stop));
            thread::spawn(move || serve(listener, host, state, stop))
        };
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
    }

    fn get_page(&self) -> String {
        let mut stream = self.connect();
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.address
        )
        .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the loop sees the flag.
        let _ = TcpStream::connect(&self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_response(stream: &mut TcpStream) -> String {
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

#[test]
fn a_stalled_client_does_not_block_other_clients() {
    let server = TestServer::start();
    let mut stalled = server.connect();
    stalled
        .write_all(b"POST /api/identity/status HTTP/1.1\r\nHost: ")
        .unwrap();
    // While that connection sits half-open, another client is served at once.
    let started = Instant::now();
    let page = server.get_page();
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "served after {:?}, the stalled client held up the server",
        started.elapsed()
    );
}

#[test]
fn a_client_that_trickles_bytes_is_cut_off_at_the_header_deadline() {
    let server = TestServer::start();
    let mut slow = server.connect();
    let started = Instant::now();
    // One byte every 150 ms never hits a per-read timeout, but the head is not
    // complete when the deadline passes.
    for byte in b"POST /api/x HTTP/1.1".iter() {
        // Once the server has cut the connection off, further writes fail.
        if slow.write_all(&[*byte]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(150));
    }
    let response = read_response(&mut slow);
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "cut off after {:?}",
        started.elapsed()
    );
}

#[test]
fn a_stalled_body_is_cut_off_at_the_body_deadline() {
    let server = TestServer::start();
    let mut stream = server.connect();
    write!(
        stream,
        "POST /api/identity/status HTTP/1.1\r\nHost: {0}\r\nOrigin: http://{0}\r\n\
         Content-Type: text/plain;charset=UTF-8\r\nContent-Length: 100\r\n\r\n0123456789",
        server.address
    )
    .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
}

#[test]
fn connections_beyond_the_limit_are_refused_and_capacity_recovers() {
    let server = TestServer::start();
    let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS).map(|_| server.connect()).collect();
    thread::sleep(Duration::from_millis(150));
    let mut extra = server.connect();
    let response = read_response(&mut extra);
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    // The idle clients hit the header deadline, which frees their slots.
    thread::sleep(HEADER_DEADLINE + Duration::from_millis(400));
    let page = server.get_page();
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    drop(idle);
}

#[test]
fn malformed_framing_headers_are_rejected() {
    let server = TestServer::start();
    let post = |extra: &str| {
        let mut stream = server.connect();
        write!(
            stream,
            "POST /api/identity/status HTTP/1.1\r\nHost: {0}\r\nOrigin: http://{0}\r\n\
             Content-Type: text/plain;charset=UTF-8\r\n{extra}\r\n",
            server.address
        )
        .unwrap();
        read_response(&mut stream)
    };
    // "+5" parsed as a valid length before.
    assert!(post("Content-Length: +5\r\n").starts_with("HTTP/1.1 400"));
    assert!(post("Content-Length: 0x5\r\n").starts_with("HTTP/1.1 400"));
    assert!(post("Content-Length: \r\n").starts_with("HTTP/1.1 400"));
    // A header name with whitespace was ignored silently before.
    assert!(post("Content-Length : 0\r\n").starts_with("HTTP/1.1 400"));
    // A normal request still gets through to the session check.
    assert!(post("Content-Length: 0\r\n").starts_with("HTTP/1.1 401"));
}

/// Runs a request that is expected to finish quickly on another thread, so a test
/// fails with a message instead of hanging if the server is blocked.
fn call_within(
    state: &Arc<Mutex<State>>,
    path: &'static str,
    body: &str,
    limit: Duration,
) -> Result<String, String> {
    let (sender, receiver) = mpsc::channel();
    let (state, body, data) = (
        Arc::clone(state),
        body.to_owned(),
        history::test_data_directory(),
    );
    thread::spawn(move || {
        history::set_test_data_directory(data);
        let _ = sender.send(call_test_api(&state, path, &body, "test-session"));
    });
    receiver
        .recv_timeout(limit)
        .map_err(|_| format!("{path} did not answer within {limit:?}"))
}

#[test]
fn a_running_import_does_not_hold_the_state_lock_but_blocks_conflicting_work() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "ef".repeat(32);
    history::History::open(&identity, &peer)
        .unwrap()
        .0
        .append(&history::StoredMessage {
            unix_time: 7,
            sender: history::MessageSender::Me,
            text: "to be merged".to_owned(),
            proof: None,
        })
        .unwrap();
    let mut backup = Vec::new();
    history::History::export_backup_stream(&identity, &peer, None, &mut backup).unwrap();
    let state = test_state_for(identity);
    let upload_id = upload_backup_bytes(&state, &backup);

    // Make the import wait on the conversation lock after it has been reserved.
    let hold = history::hold_conversation_for_test(
        state.lock().unwrap().identity.as_ref().unwrap(),
        &peer,
    )
    .unwrap();
    let import_state = Arc::clone(&state);
    let data = history::test_data_directory();
    let import = thread::spawn(move || {
        history::set_test_data_directory(data);
        call_test_api(
            &import_state,
            "/api/history/backup-transfer",
            &serde_json::json!({ "action": "import", "transferId": upload_id, "password": "" })
                .to_string(),
            "test-session",
        )
    });
    // try_lock, so a State lock held by the import fails the test instead of hanging it.
    let started = Instant::now();
    loop {
        if state
            .try_lock()
            .is_ok_and(|guard| guard.history_import_active)
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the import never started, or it is holding the State lock"
        );
        thread::sleep(Duration::from_millis(5));
    }

    // The import is parked inside the history code. If it still held the State
    // lock, none of these would be answered.
    let limit = Duration::from_secs(3);
    let ok = |path: &'static str| {
        let response = call_within(&state, path, "", limit).unwrap();
        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "{path}: {response}"
        );
    };
    ok("/api/identity/status");
    ok("/api/settings/get");
    // Work that would race with the import is refused.
    for (path, body) in [
        ("/api/chat/create", "x"),
        ("/api/history/delete-conversation", peer.as_str()),
        ("/api/contacts/import-backup", "{}"),
    ] {
        let response = call_within(&state, path, body, limit).unwrap();
        assert!(
            status_line(&response).starts_with("HTTP/1.1 409"),
            "{path}: {response}"
        );
    }
    let second = call_within(
        &state,
        "/api/history/backup-transfer",
        r#"{"action":"import","transferId":"0000000000000000000000000000000000000000000000000000000000000000","password":""}"#,
        limit,
    )
    .unwrap();
    assert!(status_line(&second).starts_with("HTTP/1.1 409"), "{second}");

    drop(hold);
    let response = import.join().unwrap();
    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "{response}"
    );
    assert!(
        !state.lock().unwrap().history_import_active,
        "the reservation ends with the import"
    );
    let ok_again = call_within(&state, "/api/history/list", "", limit).unwrap();
    assert!(
        status_line(&ok_again).starts_with("HTTP/1.1 200"),
        "{ok_again}"
    );
}

const REQUIRED_RESPONSE_HEADERS: [&str; 6] = [
    "Content-Security-Policy:",
    "X-Content-Type-Options: nosniff",
    "Cache-Control: no-store",
    "Referrer-Policy: no-referrer",
    "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Resource-Policy: same-origin",
];

fn assert_security_headers(response: &str) {
    let head = response.split("\r\n\r\n").next().unwrap_or("");
    for header in REQUIRED_RESPONSE_HEADERS {
        assert!(head.contains(header), "missing {header} in:\n{head}");
    }
    assert!(head.contains("Permissions-Policy: camera=()"), "{head}");
    assert!(head.contains("frame-ancestors 'none'"), "{head}");
    assert!(head.contains("style-src 'self';"), "{head}");
    assert!(
        !head.contains("unsafe-inline") && !head.contains("unsafe-eval"),
        "the policy must not allow inline code: {head}"
    );
}

#[test]
fn every_response_carries_the_security_headers_and_the_page_has_no_inline_style() {
    let server = TestServer::start();
    let get = |path: &str| {
        let mut stream = server.connect();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            server.address
        )
        .unwrap();
        read_response(&mut stream)
    };
    let page = get("/");
    let stylesheet = get("/app.css");
    let script = get("/app.js");
    let missing = get("/nothing");
    for response in [&page, &stylesheet, &script, &missing] {
        assert_security_headers(response);
    }
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    assert!(stylesheet.starts_with("HTTP/1.1 200 OK"), "{stylesheet}");
    assert!(
        stylesheet.contains("Content-Type: text/css"),
        "{stylesheet}"
    );
    assert!(stylesheet.len() > 5000, "the stylesheet is served in full");
    assert!(missing.starts_with("HTTP/1.1 400") || missing.starts_with("HTTP/1.1 404"));
    // `style-src 'self'` blocks <style> and style="" so neither may come back.
    let body = page.split("\r\n\r\n").nth(1).unwrap();
    assert!(body.contains(r#"<link rel="stylesheet" href="/app.css">"#));
    assert!(!body.contains("<style"), "no inline <style> block");
    assert!(!body.contains(" style=\""), "no inline style attribute");
    // Rejections carry the headers too.
    let rejected = {
        let mut stream = server.connect();
        write!(
            stream,
            "POST /api/identity/status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            server.address
        )
        .unwrap();
        read_response(&mut stream)
    };
    assert!(rejected.starts_with("HTTP/1.1 403"), "{rejected}");
    assert_security_headers(&rejected);
}

#[test]
fn paths_in_error_text_are_reduced_to_the_file_name() {
    assert_eq!(
        redact_paths("history rewrite failed (disk full); recoverable file: /Users/alec/project/chat-data/abc/.tmp-12.adlog"),
        "history rewrite failed (disk full); recoverable file: …/.tmp-12.adlog"
    );
    assert_eq!(
        redact_paths("open (/var/folders/xx/secret/file.backup): denied"),
        "open (…/file.backup): denied"
    );
    // Words that merely look like routes or fractions are left alone.
    assert_eq!(
        redact_paths("backup import failed: invalid data /api"),
        "backup import failed: invalid data /api"
    );
    assert_eq!(redact_paths("a/b is not a path"), "a/b is not a path");
    assert_eq!(redact_paths(""), "");
    // Several paths, and a path at the very end.
    assert_eq!(
        redact_paths("copy /a/b/c.txt to /d/e/f.txt"),
        "copy …/c.txt to …/f.txt"
    );
}

#[test]
fn client_message_hides_the_directory_layout_of_the_machine() {
    let error = io::Error::other(
        "restore failed; recoverable file: /Users/someone/private/chat-data/store/result.tmp",
    );
    let message = client_message("테스트", &error);
    assert!(message.contains("result.tmp"));
    assert!(!message.contains("/Users/"), "{message}");
    assert!(!message.contains("private"), "{message}");
}

#[cfg(unix)]
#[test]
fn the_settings_file_is_owner_only_under_a_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;
    let data = TestDataDirectory::new();
    let path = data.0.join("nested").join("preferences.json");
    fsutil::with_permissive_umask(|| {
        save_settings_to_path(&path, &AppSettings::default()).unwrap();
    });
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

#[test]
fn rejected_session_is_401_but_missing_identity_is_412() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let state = test_state_for(identity);
    state.lock().unwrap().identity = None;
    // A valid session with no identity logged in is a precondition failure, not an
    // authentication failure, so the page does not send the user back to pairing.
    for route in [
        "/api/identity/status",
        "/api/history/list",
        "/api/history/backup-transfer",
        "/api/contacts/export-backup",
    ] {
        let valid = call_test_api(&state, route, "{}", "test-session");
        assert!(
            status_line(&valid).starts_with("HTTP/1.1 412"),
            "{route}: {valid}"
        );
        let wrong = call_test_api(&state, route, "{}", "not-a-session");
        assert!(
            status_line(&wrong).starts_with("HTTP/1.1 401"),
            "{route}: {wrong}"
        );
        let missing = call_test_api(&state, route, "{}", "");
        assert!(
            status_line(&missing).starts_with("HTTP/1.1 401"),
            "{route}: {missing}"
        );
    }
}

#[test]
fn a_new_connection_code_ends_every_existing_session() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let state = test_state_for(identity);
    state.lock().unwrap().identity = None;
    let first_code = {
        let mut guard = state.lock().unwrap();
        issue_code(&mut guard).unwrap();
        guard.code.clone()
    };
    let paired = call_test_api(&state, "/api/connect", &first_code, "");
    assert!(status_line(&paired).starts_with("HTTP/1.1 200"), "{paired}");
    let token = paired.split("\r\n\r\n").nth(1).unwrap().to_owned();
    let status = |token: &str| {
        status_line(&call_test_api(&state, "/api/identity/status", "", token)).to_owned()
    };
    assert!(status(&token).starts_with("HTTP/1.1 412"), "session works");
    // Issuing the first code already ended the fixture session.
    assert!(status("test-session").starts_with("HTTP/1.1 401"));

    // Pressing Enter in the terminal issues a new code.
    issue_code(&mut state.lock().unwrap()).unwrap();
    assert!(
        status(&token).starts_with("HTTP/1.1 401"),
        "paired session ended"
    );
    // The old connection code no longer works either.
    let replay = call_test_api(&state, "/api/connect", &first_code, "");
    assert!(status_line(&replay).starts_with("HTTP/1.1 403"), "{replay}");
}

#[test]
fn logout_ends_every_session_and_offers_a_new_connection_code() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let state = test_state_for(identity);
    state
        .lock()
        .unwrap()
        .sessions
        .issue("other-session".to_owned(), Instant::now());
    let status = |token: &str| {
        status_line(&call_test_api(&state, "/api/identity/status", "", token)).to_owned()
    };
    assert!(status("test-session").starts_with("HTTP/1.1 200"));
    assert!(status("other-session").starts_with("HTTP/1.1 200"));

    let logged_out = call_test_api(&state, "/api/identity/logout", "", "test-session");
    assert!(
        status_line(&logged_out).starts_with("HTTP/1.1 200"),
        "{logged_out}"
    );
    // A copied token must not survive the logout, or it would work for whoever
    // logs in next.
    assert!(status("test-session").starts_with("HTTP/1.1 401"));
    assert!(status("other-session").starts_with("HTTP/1.1 401"));
    assert!(state.lock().unwrap().identity.is_none());

    // The user can pair again with the code printed at logout.
    let code = state.lock().unwrap().code.clone();
    assert!(!code.is_empty(), "logout issues a new connection code");
    let paired = call_test_api(&state, "/api/connect", &code, "");
    assert!(status_line(&paired).starts_with("HTTP/1.1 200"), "{paired}");
    let token = paired.split("\r\n\r\n").nth(1).unwrap().to_owned();
    assert!(status(&token).starts_with("HTTP/1.1 412"));
}

#[test]
fn backup_transfer_api_enforces_the_legacy_format_opt_in_on_the_server() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let peer = "cd".repeat(32);
    // An attacker needs only the victim's public id and a password to build this.
    let forged = history::tests::legacy_password_backup(
        &identity,
        &peer,
        &[history::StoredMessage {
            unix_time: 1_700_000_000,
            sender: history::MessageSender::Other,
            text: "I agree to the payment".to_owned(),
            proof: None,
        }],
        "attacker chosen password",
    );
    let state = test_state_for(identity);
    let import = |extra: serde_json::Value| -> String {
        let id = upload_backup_bytes(&state, &forged);
        let mut body = serde_json::json!({
            "action": "import", "transferId": id, "password": "attacker chosen password"
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        call_test_api(
            &state,
            "/api/history/backup-transfer",
            &body.to_string(),
            "test-session",
        )
    };
    // A rejected import must not even create the conversation file.
    let stored = || match history::History::read_for_identity_copy(
        state.lock().unwrap().identity.as_ref().unwrap(),
        &peer,
    ) {
        Ok((messages, _)) => messages,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("unexpected history read error: {error}"),
    };

    // The server refuses on its own, whatever the page did or did not ask.
    for extra in [
        serde_json::json!({}),
        serde_json::json!({ "allowLegacy": false }),
    ] {
        let response = import(extra);
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("ADBACK2"), "{response}");
        assert!(
            stored().is_empty(),
            "a rejected import must not write history"
        );
    }
    // Only a literal boolean true counts; other types are malformed requests.
    let response = import(serde_json::json!({ "allowLegacy": "yes" }));
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(stored().is_empty());

    let response = import(serde_json::json!({ "allowLegacy": true }));
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let messages = stored();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, history::MessageSender::Other);
    assert!(
        messages[0].proof.is_none(),
        "a password-only backup can never produce a signed message"
    );
}

#[test]
fn settings_relay_defaults_and_legacy_fields_are_preserved() {
    assert_eq!(
        first_active_relay(&[
            "wss://first.example".to_owned(),
            "wss://second.example".to_owned(),
        ]),
        "wss://first.example"
    );
    assert_eq!(first_active_relay(&[]), DEFAULT_RELAY);
    let data = TestDataDirectory::new();
    let path = data.0.join("preferences.json");
    assert_eq!(
        load_settings_from_path(&path).unwrap(),
        AppSettings::default()
    );

    std::fs::write(
        &path,
        br#"{"torSocks":"127.0.0.1:9050","notifications":true}"#,
    )
    .unwrap();
    let loaded = load_settings_from_path(&path).unwrap();
    assert_eq!(loaded.relays, vec![DEFAULT_RELAY]);
    assert_eq!(loaded.tor_socks, Some("127.0.0.1:9050".parse().unwrap()));
    assert!(loaded.notifications);

    let updated = AppSettings {
        tor_socks: loaded.tor_socks,
        notifications: loaded.notifications,
        relays: vec!["wss://relay.example".to_owned()],
    };
    save_settings_to_path(&path, &updated).unwrap();
    assert_eq!(load_settings_from_path(&path).unwrap(), updated);
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["torSocks"], "127.0.0.1:9050");
    assert_eq!(saved["notifications"], true);
}

#[test]
fn settings_reject_invalid_relay_lists_without_changing_saved_state() {
    let data = TestDataDirectory::new();
    let path = data.0.join("preferences.json");
    let original = AppSettings::default();
    save_settings_to_path(&path, &original).unwrap();
    let original_file = std::fs::read(&path).unwrap();
    for relays in [
        vec![],
        vec!["ws://relay.example".to_owned()],
        vec!["wss://relay.example:65536".to_owned()],
        vec![format!("wss://relay.example/{}", "a".repeat(4096))],
        vec![
            "wss://relay.example".to_owned(),
            "wss://RELAY.EXAMPLE:443/".to_owned(),
        ],
    ] {
        let invalid = AppSettings {
            relays,
            ..original.clone()
        };
        assert!(save_settings_to_path(&path, &invalid).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original_file);
    }
    std::fs::write(&path, br#"{"relayUrls":[]}"#).unwrap();
    assert!(load_settings_from_path(&path).is_err());
}

#[test]
fn settings_api_reports_saved_and_active_relays_and_restart_gating() {
    let _data = TestDataDirectory::new();
    let state = test_state(None, HashMap::new());
    let read_settings = || call_test_api(&state, "/api/settings/get", "", "test-session");
    let initial = read_settings();
    assert!(initial.contains("\"savedRelays\":[\"wss://relay.primal.net\"]"));
    assert!(initial.contains("\"activeRelay\":\"wss://relay.primal.net\""));
    assert!(initial.contains("\"restartRequired\":false"));

    let changed = serde_json::json!({
        "mode":"general", "socks":"", "notifications":true,
        "relayUrls":["wss://relay.example", "wss://backup.example"]
    })
    .to_string();
    let operation = closed_test_operation("test-owner", "test-peer", 0, 0);
    operation.snapshot.lock().unwrap().phase = "connected";
    state
        .lock()
        .unwrap()
        .chats
        .insert("active-chat".to_owned(), Arc::clone(&operation));
    let blocked = call_test_api(&state, "/api/settings/save", &changed, "test-session");
    assert!(blocked.starts_with("HTTP/1.1 409 Conflict"));
    assert_eq!(state.lock().unwrap().settings.relays, vec![DEFAULT_RELAY]);
    state.lock().unwrap().chats.clear();

    let saved = call_test_api(&state, "/api/settings/save", &changed, "test-session");
    assert!(saved.starts_with("HTTP/1.1 200 OK"), "{saved}");
    assert!(saved.contains("\"relayRestartRequired\":true"));
    assert!(saved.contains("\"activeRelay\":\"wss://relay.primal.net\""));
    assert!(saved.contains("\"notifications\":true"));
    let invite = call_test_api(&state, "/api/invite/create", "", "test-session");
    assert!(invite.starts_with("HTTP/1.1 409 Conflict"));
    for route in ["/api/chat/create", "/api/chat/join", "/api/chat/reconnect"] {
        let blocked = call_test_api(&state, route, "test-payload", "test-session");
        assert!(
            blocked.starts_with("HTTP/1.1 409 Conflict"),
            "{route}: {blocked}"
        );
    }

    let invalid = serde_json::json!({
        "mode":"general", "notifications":false, "relayUrls":[]
    })
    .to_string();
    let rejected = call_test_api(&state, "/api/settings/save", &invalid, "test-session");
    assert!(rejected.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(rejected.contains("비어 있을 수 없습니다"));
    assert_eq!(
        state.lock().unwrap().settings.relays,
        vec!["wss://relay.example", "wss://backup.example"]
    );

    let reset = serde_json::json!({
        "mode":"general", "notifications":true,
        "relayUrls":[DEFAULT_RELAY]
    })
    .to_string();
    let reset = call_test_api(&state, "/api/settings/save", &reset, "test-session");
    assert!(reset.contains("\"restartRequired\":false"));

    let preferences = _data.0.join("preferences.json");
    std::fs::remove_file(&preferences).unwrap();
    std::fs::create_dir(&preferences).unwrap();
    std::fs::write(preferences.join("sentinel"), b"preserve").unwrap();
    let before_failure = state.lock().unwrap().settings.clone();
    let failed_save = call_test_api(&state, "/api/settings/save", &changed, "test-session");
    assert!(failed_save.starts_with("HTTP/1.1 500 Internal Server Error"));
    assert_eq!(state.lock().unwrap().settings, before_failure);
    assert_eq!(
        std::fs::read(preferences.join("sentinel")).unwrap(),
        b"preserve"
    );
}

struct TestDataDirectory(std::path::PathBuf);

impl TestDataDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ad2-sync-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        history::set_test_data_directory(Some(path.clone()));
        Self(path)
    }
}

impl Drop for TestDataDirectory {
    fn drop(&mut self) {
        history::set_test_data_directory(None);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn call_test_api(state: &Arc<Mutex<State>>, path: &str, body: &str, token: &str) -> String {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(request.as_bytes()).unwrap();
    let (server, _) = listener.accept().unwrap();
    handle(server, &address.to_string(), state).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    response
}

/// Sends an arbitrary request line with valid headers, to test routing.
fn call_test_request_line(state: &Arc<Mutex<State>>, request_line: &str, token: &str) -> String {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    let request = format!(
        "{request_line}\r\nHost: {address}\r\nOrigin: http://{address}\r\nAuthorization: Bearer {token}\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).unwrap();
    let (server, _) = listener.accept().unwrap();
    handle(server, &address.to_string(), state).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    response
}

/// A state with one live session ("test-session"), the given identity and chats, and
/// everything else at its default.
fn test_state(
    identity: Option<Arc<Identity>>,
    chats: HashMap<String, Arc<ChatOperation>>,
) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: SessionStore::with_token("test-session"),
        identity,
        chats,
        history_deletions: HashMap::new(),
        active_history_deletions: HashSet::new(),
        history_import_active: false,
        tor_socks: None,
        active_relays: vec![DEFAULT_RELAY.to_owned()],
        settings: AppSettings::default(),
        notifications_enabled: Arc::new(AtomicBool::new(false)),
        last_notification: Arc::new(Mutex::new(None)),
    }))
}

#[test]
fn an_unknown_path_is_404_and_a_known_path_with_the_wrong_method_is_405() {
    let state = test_state(None, HashMap::new());
    for line in [
        "GET /nothing HTTP/1.1",
        "POST /api/nothing HTTP/1.1",
        "POST /api/chat/send/extra HTTP/1.1",
        "POST /api/chat/send HTTP/2",
        "POST /api/chat/send",
        "",
    ] {
        let response = call_test_request_line(&state, line, "test-session");
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "{line:?}: {response}"
        );
    }
    for line in [
        "GET /api/chat/send HTTP/1.1",
        "PUT /api/identity/status HTTP/1.1",
        "DELETE /api/history/list HTTP/1.1",
        "POST / HTTP/1.1",
        "POST /app.js HTTP/1.1",
    ] {
        let response = call_test_request_line(&state, line, "test-session");
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{line:?}: {response}"
        );
    }
}

#[test]
fn assets_are_served_without_a_session_and_every_api_route_needs_one() {
    let state = test_state(None, HashMap::new());
    for line in [
        "GET / HTTP/1.1",
        "GET /app.css HTTP/1.1",
        "GET /app.js HTTP/1.1",
        "GET /reprotect-work.js HTTP/1.1",
    ] {
        let response = call_test_request_line(&state, line, "");
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{line}: {response}"
        );
    }
    for route in ROUTES.iter().filter(|route| match route.target {
        Target::Api { session, .. } => session,
        Target::Asset { .. } => false,
    }) {
        let line = format!("{} {} HTTP/1.1", route.method, route.path);
        let response = call_test_request_line(&state, &line, "not-a-session");
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{line}: {response}"
        );
    }
}

#[test]
fn the_route_table_has_no_duplicates_and_only_the_code_exchange_skips_the_session() {
    let mut seen = HashSet::new();
    for route in ROUTES {
        assert!(
            seen.insert((route.method, route.path)),
            "{} {} appears twice",
            route.method,
            route.path
        );
    }
    let open: Vec<_> = ROUTES
        .iter()
        .filter(|route| matches!(route.target, Target::Api { session: false, .. }))
        .map(|route| route.path)
        .collect();
    assert_eq!(open, ["/api/connect"]);
}

fn closed_test_operation(owner: &str, peer: &str, count: usize, epoch: u64) -> Arc<ChatOperation> {
    let (sender, _) = mpsc::channel();
    closed_test_operation_with_sender(owner, peer, count, epoch, sender)
}

fn closed_test_operation_with_sender(
    owner: &str,
    peer: &str,
    count: usize,
    epoch: u64,
    sender: mpsc::Sender<ChatCommand>,
) -> Arc<ChatOperation> {
    Arc::new(ChatOperation {
        owner_identity_id: owner.to_owned(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "closed",
            fingerprint: None,
            confirmation_code: None,
            peer_id: Some(peer.to_owned()),
            error: None,
            storage_error: None,
            messages: vec![ChatEntry {
                unix_time: 1,
                sender: "나",
                text: "cached".to_owned(),
            }],
            message_count: count,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: false,
            history_restore_state: "idle",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 0,
            history_restore_legacy_count: 0,
            history_restore_received: 0,
            history_restore_total: 0,
            history_restore_status: None,
            message_epoch: epoch,
        }),
        message_reader: Mutex::new(Some(MessagePageReader {
            peer_id: peer.to_owned(),
            epoch,
            next_index: 0,
            reader: history::HistoryReader::empty_for_test(File::open("/dev/null").unwrap()),
        })),
        sender,
        cancelled: Arc::new(AtomicBool::new(true)),
    })
}

fn connected_restore_test_operation(
    state: &'static str,
    peer: &str,
    offer_count: usize,
) -> (Arc<ChatOperation>, mpsc::Receiver<ChatCommand>) {
    let (sender, receiver) = mpsc::channel();
    let operation = Arc::new(ChatOperation {
        owner_identity_id: "test-identity".to_owned(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: Some(peer.to_owned()),
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 0,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: false,
            history_restore_state: state,
            history_restore_estimate_bytes: 8,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: offer_count,
            history_restore_legacy_count: 0,
            history_restore_received: offer_count,
            history_restore_total: offer_count,
            history_restore_status: None,
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender,
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    (operation, receiver)
}

#[test]
fn restore_timeout_fails_pending_estimate_and_allows_a_fresh_request() {
    let operation = closed_test_operation("test-identity", "peer", 0, 0);
    let now = Instant::now();
    let started_at = Some(now - HISTORY_RESTORE_TIMEOUT - Duration::from_millis(1));
    assert!(history_restore_timed_out(started_at, now));
    assert!(history_restore_work_timed_out(started_at, true, false, now));
    assert!(history_restore_work_timed_out(started_at, false, true, now));
    assert!(!history_restore_work_timed_out(
        started_at, false, false, now
    ));
    assert!(!history_restore_timed_out(
        Some(now - HISTORY_RESTORE_TIMEOUT),
        now
    ));
    assert!(!history_restore_timed_out(None, now));

    chat_update(&operation, |snapshot| {
        snapshot.phase = "connected";
        snapshot.history_restore_in_progress = true;
        snapshot.history_restore_state = "estimating";
        snapshot.history_restore_estimate_bytes = 8192;
        snapshot.history_restore_received = 2;
        snapshot.history_restore_total = 3;
        snapshot.history_restore_status = Some("estimate pending".to_owned());
    });
    assert!(try_reserve_history_restore_timeout(&operation));

    let snapshot = operation.snapshot.lock().unwrap();
    assert_eq!(snapshot.history_restore_state, "failed");
    assert!(!snapshot.history_restore_in_progress);
    assert_eq!(snapshot.history_restore_received, 0);
    assert_eq!(snapshot.history_restore_total, 0);
    assert_eq!(snapshot.history_restore_estimate_bytes, 0);
    assert!(snapshot
        .history_restore_status
        .as_deref()
        .unwrap()
        .contains("시간이 초과"));
    assert!(history_restore_request_allowed(&snapshot));
}

#[test]
fn restore_consent_and_timeout_are_arbitrated_before_staging_is_discarded() {
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let peer_id = "ab".repeat(32);
    let request_id = "cd".repeat(32);
    let (mut existing, _, _) = history::History::open(&identity, &peer_id).unwrap();
    let baseline = history::StoredMessage {
        unix_time: 1,
        sender: history::MessageSender::Me,
        text: "existing record".to_owned(),
        proof: None,
    };
    existing.append(&baseline).unwrap();

    let mut stage = history::RestoreStaging::create(&identity, &peer_id, &request_id).unwrap();
    stage
        .append_verified(&history::StoredMessage {
            unix_time: 2,
            sender: history::MessageSender::Other,
            text: "staged record".to_owned(),
            proof: None,
        })
        .unwrap();
    stage.finish().unwrap();

    let (operation, command_receiver) =
        connected_restore_test_operation("awaiting-merge-consent", &peer_id, 1);

    // Model the API winning the shared snapshot mutex immediately before
    // the worker's expired-timer check. The queued command owns the stage.
    {
        let mut snapshot = operation.snapshot.lock().unwrap();
        assert_eq!(
            reserve_history_restore_resolution(&mut snapshot, true),
            Ok("merge-queued")
        );
    }
    operation
        .sender
        .send(ChatCommand::ResolveHistoryRestore(true))
        .unwrap();
    assert!(history_restore_work_timed_out(
        Some(Instant::now() - HISTORY_RESTORE_TIMEOUT - Duration::from_millis(1)),
        false,
        true,
        Instant::now(),
    ));
    assert!(!try_reserve_history_restore_timeout(&operation));
    assert!(matches!(
        command_receiver.try_recv(),
        Ok(ChatCommand::ResolveHistoryRestore(true))
    ));
    assert_eq!(
        operation.snapshot.lock().unwrap().history_restore_state,
        "merge-queued"
    );
    assert_eq!(stage.count(), 1);

    // Exercise the worker's queued merge path with the retained staging.
    let mut current = history::History::open(&identity, &peer_id).unwrap().0;
    let summary = current
        .merge_restore_staging(&identity, &mut stage)
        .unwrap();
    stage.cleanup().unwrap();
    assert_eq!(summary.imported_count, 1);
    let (_, restored_messages, _) = history::History::open(&identity, &peer_id).unwrap();
    assert_eq!(restored_messages.len(), 2);

    // If the timeout reserves the state first, later consent is rejected
    // and cleanup removes only staging, leaving the existing history intact.
    let (timeout_first, _) =
        connected_restore_test_operation("awaiting-merge-consent", &peer_id, 1);
    let mut second_stage =
        history::RestoreStaging::create(&identity, &peer_id, &"ef".repeat(32)).unwrap();
    second_stage
        .append_verified(&history::StoredMessage {
            unix_time: 3,
            sender: history::MessageSender::Other,
            text: "must not be applied".to_owned(),
            proof: None,
        })
        .unwrap();
    second_stage.finish().unwrap();
    let mut pending = Some(second_stage);
    assert!(try_reserve_history_restore_timeout(&timeout_first));
    assert!(timeout_first
        .snapshot
        .lock()
        .unwrap()
        .history_restore_status
        .as_deref()
        .unwrap()
        .contains("시간이 초과"));
    let mut snapshot = timeout_first.snapshot.lock().unwrap();
    assert!(reserve_history_restore_resolution(&mut snapshot, true).is_err());
    drop(snapshot);
    discard_restore_staging(&mut pending, &timeout_first);
    assert!(pending.is_none());
    let (_, unchanged_messages, _) = history::History::open(&identity, &peer_id).unwrap();
    assert_eq!(unchanged_messages.len(), 2);
}

#[test]
fn transfer_consent_and_timeout_preserve_the_winning_request_state() {
    // Consent queued first: the worker must retain the request ID and
    // process the command rather than timing out the accepted action.
    let (accepted_operation, accepted_commands) =
        connected_restore_test_operation("awaiting-transfer-consent", &"93".repeat(32), 0);
    let request_id = Some("94".repeat(32));
    {
        let mut snapshot = accepted_operation.snapshot.lock().unwrap();
        assert_eq!(
            reserve_history_restore_resolution(&mut snapshot, true),
            Ok("transfer-queued")
        );
    }
    accepted_operation
        .sender
        .send(ChatCommand::ResolveHistoryRestore(true))
        .unwrap();
    assert!(!try_reserve_history_restore_timeout(&accepted_operation));
    assert!(request_id.is_some());
    assert!(matches!(
        accepted_commands.try_recv(),
        Ok(ChatCommand::ResolveHistoryRestore(true))
    ));
    assert!(request_id.is_some());

    // Timeout claimed first: the request is invalidated and a later
    // consent cannot be reported as accepted or enqueue worker work.
    let (timed_out_operation, timed_out_commands) =
        connected_restore_test_operation("awaiting-transfer-consent", &"93".repeat(32), 0);
    let mut timed_out_request_id = Some("95".repeat(32));
    assert!(history_restore_work_timed_out(
        Some(Instant::now() - HISTORY_RESTORE_TIMEOUT - Duration::from_millis(1)),
        true,
        false,
        Instant::now(),
    ));
    assert!(try_reserve_history_restore_timeout(&timed_out_operation));
    timed_out_request_id.take();
    assert!(timed_out_request_id.is_none());
    let mut snapshot = timed_out_operation.snapshot.lock().unwrap();
    assert!(reserve_history_restore_resolution(&mut snapshot, true).is_err());
    drop(snapshot);
    assert!(timed_out_commands.try_recv().is_err());
}

#[test]
fn concurrent_merge_consent_and_timeout_keep_the_winning_transition_and_stage() {
    use std::sync::Barrier;

    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let peer_id = "91".repeat(32);
    let request_id = "92".repeat(32);
    let mut staging = history::RestoreStaging::create(&identity, &peer_id, &request_id).unwrap();
    staging
        .append_verified(&history::StoredMessage {
            unix_time: 1,
            sender: history::MessageSender::Other,
            text: "race-owned staging".to_owned(),
            proof: None,
        })
        .unwrap();
    staging.finish().unwrap();

    let (operation, command_receiver) =
        connected_restore_test_operation("awaiting-merge-consent", &peer_id, 1);

    let barrier = Arc::new(Barrier::new(3));
    let api_operation = Arc::clone(&operation);
    let api_barrier = Arc::clone(&barrier);
    let api = thread::spawn(move || {
        api_barrier.wait();
        let accepted = {
            let mut snapshot = api_operation.snapshot.lock().unwrap();
            reserve_history_restore_resolution(&mut snapshot, true).is_ok()
        };
        if accepted {
            api_operation
                .sender
                .send(ChatCommand::ResolveHistoryRestore(true))
                .unwrap();
        }
        accepted
    });
    let timer_operation = Arc::clone(&operation);
    let timer_barrier = Arc::clone(&barrier);
    let timer = thread::spawn(move || {
        timer_barrier.wait();
        try_reserve_history_restore_timeout(&timer_operation)
    });

    barrier.wait();
    let accepted = api.join().unwrap();
    let timed_out = timer.join().unwrap();
    assert_ne!(accepted, timed_out);
    let state = operation.snapshot.lock().unwrap().history_restore_state;
    if accepted {
        assert_eq!(state, "merge-queued");
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(ChatCommand::ResolveHistoryRestore(true))
        ));
        assert_eq!(staging.count(), 1);
        // The worker can still take and apply the staging after its queued
        // command wins the same state transition race.
        let mut current = history::History::open(&identity, &peer_id).unwrap().0;
        let summary = current
            .merge_restore_staging(&identity, &mut staging)
            .unwrap();
        staging.cleanup().unwrap();
        assert_eq!(summary.imported_count, 1);
    } else {
        assert_eq!(state, "failed");
        assert!(command_receiver.try_recv().is_err());
        staging.cleanup().unwrap();
    }
}

#[test]
fn live_chat_rejects_unframed_text_without_waiting_for_history_lock() {
    let (alice, _) = Identity::create().unwrap();
    let (bob, _) = Identity::create().unwrap();
    let peer_id = alice.public_id().to_owned();
    let bob_id = bob.public_id();
    let operation = Arc::new(ChatOperation {
        owner_identity_id: bob.public_id().to_owned(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: Some(peer_id.clone()),
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 0,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: true,
            history_restore_state: "merging",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 0,
            history_restore_legacy_count: 0,
            history_restore_received: 0,
            history_restore_total: 0,
            history_restore_status: Some("merging".to_owned()),
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender: mpsc::channel().0,
        cancelled: Arc::new(AtomicBool::new(false)),
    });

    let plain_text = b"unsigned live text";
    assert!(is_unframed_live_chat_message(plain_text));
    let signed = history::sign_message(&alice, &bob_id, 7, "signed message".to_owned()).unwrap();
    let signed_frame = history::encode_signed_message(&signed).unwrap();
    assert!(!is_unframed_live_chat_message(&signed_frame));
    assert_eq!(
        history::decode_signed_message(&bob, &peer_id, &alice.public_key(), &signed_frame)
            .unwrap()
            .text,
        "signed message"
    );

    let control_frame = chat_control(serde_json::json!({"type":"history-sync-cancel"}));
    assert!(!is_unframed_live_chat_message(&control_frame));
    assert!(parse_chat_control(&control_frame).unwrap().is_some());

    let old_record = history::StoredMessage {
        unix_time: 8,
        sender: history::MessageSender::Me,
        text: "unsigned legacy restore".to_owned(),
        proof: None,
    };
    let transfer_frame = history::encode_transfer(&old_record).unwrap();
    assert!(!is_unframed_live_chat_message(&transfer_frame));
    assert!(
        history::decode_transfer(&bob, &peer_id, &alice.public_key(), &transfer_frame)
            .unwrap()
            .proof
            .is_none()
    );
    operation.snapshot.lock().unwrap().history_restore_state = "awaiting-transfer-consent";
    assert!(!restore_transfer_allowed(&operation));
    operation.snapshot.lock().unwrap().history_restore_state = "receiving";
    assert!(restore_transfer_allowed(&operation));
    operation.snapshot.lock().unwrap().history_restore_state = "merging";

    let (lock_held_send, lock_held_receive) = mpsc::channel();
    let (release_send, release_receive) = mpsc::channel();
    let locked_operation = Arc::clone(&operation);
    let holder = thread::spawn(move || {
        let _guard = locked_operation.history_state_lock.lock().unwrap();
        lock_held_send.send(()).unwrap();
        release_receive.recv().unwrap();
    });
    lock_held_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let (result_send, result_receive) = mpsc::channel();
    let rejecting_operation = Arc::clone(&operation);
    let reject = thread::spawn(move || {
        result_send
            .send(reject_unframed_live_chat_message(
                &rejecting_operation,
                plain_text,
            ))
            .unwrap();
    });
    assert!(result_receive.recv_timeout(Duration::from_secs(1)).unwrap());
    release_send.send(()).unwrap();
    holder.join().unwrap();
    reject.join().unwrap();

    let snapshot = operation.snapshot.lock().unwrap();
    assert_eq!(snapshot.phase, "disconnected");
    assert_eq!(snapshot.message_count, 0);
    assert!(snapshot.messages.is_empty());
    assert!(snapshot.error.as_deref().unwrap().contains("서명되지 않은"));
    drop(snapshot);
    drop(PendingMergeQueueNotice {
        operation: Arc::clone(&operation),
        has_pending: Arc::new(AtomicBool::new(true)),
    });
    let snapshot = operation.snapshot.lock().unwrap();
    assert!(snapshot.error.as_deref().unwrap().contains("서명되지 않은"));
    assert!(snapshot
        .error
        .as_deref()
        .unwrap()
        .contains("임시 대기하던 수신 메시지"));
}

#[test]
fn identity_transition_control_and_history_marker_roundtrip() {
    let previous = "ab".repeat(32);
    let current = "cd".repeat(32);
    let frame = chat_control(serde_json::json!({
        "type": "identity-transition",
        "previousPeerIds": [previous],
    }));
    let control = parse_chat_control(&frame).unwrap().unwrap();
    assert_eq!(
        control["previousPeerIds"][0].as_str().unwrap(),
        "ab".repeat(32)
    );

    let event = identity_event("peer", &"ab".repeat(32), &current);
    let displayed = chat_entry(event);
    assert_eq!(displayed.sender, "신원 변경");
    assert!(displayed.text.contains("cdcdcdcdcdcd"));
}

#[test]
fn restore_merge_acceptance_is_async_idempotent_and_reports_final_state() {
    let operation = Arc::new(ChatOperation {
        owner_identity_id: "test-identity".to_owned(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: None,
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 0,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: false,
            history_restore_state: "awaiting-merge-consent",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 0,
            history_restore_legacy_count: 0,
            history_restore_received: 0,
            history_restore_total: 0,
            history_restore_status: None,
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender: mpsc::channel().0,
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let worker_operation = Arc::clone(&operation);
    let worker_gate = Arc::clone(&gate);
    let worker = thread::spawn(move || {
        let (lock, changed) = &*worker_gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        chat_update(&worker_operation, |snapshot| {
            snapshot.history_restore_state = "completed";
            snapshot.history_restore_in_progress = false;
            snapshot.history_restore_status = Some("test merge complete".to_owned());
        });
    });

    {
        let mut snapshot = operation.snapshot.lock().unwrap();
        assert_eq!(
            reserve_history_restore_resolution(&mut snapshot, true),
            Ok("merge-queued")
        );
        assert_eq!(snapshot.history_restore_state, "merge-queued");
        assert!(snapshot.history_restore_in_progress);
        assert!(reserve_history_restore_resolution(&mut snapshot, true).is_err());
    }
    {
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_one();
    }
    worker.join().unwrap();
    let snapshot = operation.snapshot.lock().unwrap();
    assert_eq!(snapshot.history_restore_state, "completed");
    assert_eq!(
        snapshot.history_restore_status.as_deref(),
        Some("test merge complete")
    );
}

#[test]
fn restore_merge_api_returns_202_without_waiting_and_status_reports_completion() {
    let (test_identity, _) = Identity::create().unwrap();
    let owner_identity_id = test_identity.public_id().to_owned();
    let (command_sender, command_receiver) = mpsc::channel();
    let operation = Arc::new(ChatOperation {
        owner_identity_id,
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: None,
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 0,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: false,
            history_restore_state: "awaiting-merge-consent",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 1,
            history_restore_legacy_count: 0,
            history_restore_received: 1,
            history_restore_total: 1,
            history_restore_status: None,
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender: command_sender,
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    let mut chats = HashMap::new();
    chats.insert("restore-operation".to_owned(), Arc::clone(&operation));
    let state = test_state(Some(Arc::new(test_identity)), chats);
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let worker_gate = Arc::clone(&gate);
    let worker_operation = Arc::clone(&operation);
    let worker = thread::spawn(move || {
        assert!(matches!(
            command_receiver.recv().unwrap(),
            ChatCommand::ResolveHistoryRestore(true)
        ));
        let (lock, changed) = &*worker_gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        chat_update(&worker_operation, |snapshot| {
            snapshot.history_restore_state = "completed";
            snapshot.history_restore_in_progress = false;
            snapshot.history_restore_status = Some("merge complete".to_owned());
        });
    });
    let body = r#"{"operationId":"restore-operation","accept":true}"#;
    let accepted = call_test_api(
        &state,
        "/api/chat/resolve-history-restore",
        body,
        "test-session",
    );
    assert!(accepted.starts_with("HTTP/1.1 202 Accepted"));
    assert!(accepted.contains("Content-Length"));
    let duplicate = call_test_api(
        &state,
        "/api/chat/resolve-history-restore",
        body,
        "test-session",
    );
    assert!(duplicate.starts_with("HTTP/1.1 409 Conflict"));
    let pending = call_test_api(
        &state,
        "/api/chat/status",
        "restore-operation",
        "test-session",
    );
    assert!(pending.contains("\"historyRestoreState\":\"merge-queued\""));
    chat_update(&operation, |snapshot| snapshot.phase = "disconnected");
    {
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_one();
    }
    worker.join().unwrap();
    let complete = call_test_api(
        &state,
        "/api/chat/status",
        "restore-operation",
        "test-session",
    );
    assert!(complete.contains("\"historyRestoreState\":\"completed\""));
    assert!(complete.contains("merge complete"));
    chat_update(&operation, |snapshot| {
        snapshot.phase = "connected";
        snapshot.history_restore_state = "awaiting-merge-consent";
        snapshot.history_restore_in_progress = false;
        snapshot.history_restore_offer_count = 1;
    });
    assert!(try_reserve_history_restore_timeout(&operation));
    let after_timeout = call_test_api(
        &state,
        "/api/chat/resolve-history-restore",
        body,
        "test-session",
    );
    assert!(after_timeout.starts_with("HTTP/1.1 409 Conflict"));
    let failure = call_test_api(
        &state,
        "/api/chat/status",
        "restore-operation",
        "test-session",
    );
    assert!(failure.contains("\"historyRestoreState\":\"failed\""));
    assert!(failure.contains("시간이 초과"));
}

/// A connected chat whose worker never answers: the commands pile up in the receiver.
fn stalled_worker_operation(
    owner: &str,
    peer: &str,
) -> (Arc<ChatOperation>, mpsc::Receiver<ChatCommand>) {
    let (sender, receiver) = mpsc::channel();
    let operation = closed_test_operation_with_sender(owner, peer, 0, 0, sender);
    operation.cancelled.store(false, Ordering::SeqCst);
    operation.snapshot.lock().unwrap().phase = "connected";
    (operation, receiver)
}

#[test]
fn a_stalled_chat_worker_does_not_freeze_the_rest_of_the_api() {
    // These requests wait for the worker (ten seconds for a send, three for a restore
    // request), which may be stuck writing to a relay. Waiting with the global state
    // locked froze every other request, status polls of other chats included.
    for (path, body) in [
        ("/api/chat/send", "stalled\nhello"),
        ("/api/chat/request-history-restore", "stalled"),
    ] {
        let (identity, _) = Identity::create().unwrap();
        let owner = identity.public_id().to_owned();
        let peer = "7c".repeat(32);
        let (operation, receiver) = stalled_worker_operation(&owner, &peer);
        let mut chats = HashMap::new();
        chats.insert("stalled".to_owned(), operation);
        let state = test_state(Some(Arc::new(identity)), chats);
        let waiting = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || call_test_api(&state, path, body, "test-session"))
        };
        // The request is waiting once the worker's queue holds its command.
        let command = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        let asked = Instant::now();
        let status = call_test_api(&state, "/api/chat/status", "stalled", "test-session");
        assert!(status.starts_with("HTTP/1.1 200 OK"), "{path}: {status}");
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "{path}: the status request waited {:?} behind it",
            asked.elapsed()
        );
        // Dropping the command and the receiver ends the waiting request at once.
        drop(command);
        drop(receiver);
        let response = waiting.join().unwrap();
        assert!(!response.starts_with("HTTP/1.1 200"), "{path}: {response}");
    }
}

#[test]
fn a_chunk_cannot_be_appended_to_an_upload_while_an_import_is_running() {
    let data = TestDataDirectory::new();
    let _ = &data;
    let (identity, _) = Identity::create().unwrap();
    let state = test_state_for(identity);
    let started = call_test_api(
        &state,
        "/api/history/backup-transfer",
        r#"{"action":"upload-start"}"#,
        "test-session",
    );
    let started: serde_json::Value =
        serde_json::from_str(started.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let id = started["transferId"].as_str().unwrap().to_owned();
    let chunk = |offset: u64| {
        serde_json::json!({
            "action": "upload-chunk", "transferId": id,
            "offset": offset, "data": BASE64.encode(b"abc")
        })
        .to_string()
    };
    let first = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &chunk(0),
        "test-session",
    );
    assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
    state.lock().unwrap().history_import_active = true;
    let during = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &chunk(3),
        "test-session",
    );
    assert!(during.starts_with("HTTP/1.1 409 Conflict"), "{during}");
    state.lock().unwrap().history_import_active = false;
    let after = call_test_api(
        &state,
        "/api/history/backup-transfer",
        &chunk(3),
        "test-session",
    );
    assert!(
        after.starts_with("HTTP/1.1 200 OK"),
        "the refused chunk wrote nothing: {after}"
    );
}

#[test]
fn logging_out_forgets_the_plaintext_of_finished_chats_but_not_running_ones() {
    let (identity, _) = Identity::create().unwrap();
    let owner = identity.public_id().to_owned();
    let finished = closed_test_operation(&owner, &"7d".repeat(32), 1, 0);
    let (running, _receiver) = stalled_worker_operation(&owner, &"7e".repeat(32));
    let mut chats = HashMap::new();
    chats.insert("finished".to_owned(), finished);
    chats.insert("running".to_owned(), running);
    let state = test_state(Some(Arc::new(identity)), chats);
    let response = call_test_api(&state, "/api/identity/logout", "", "test-session");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    let state = state.lock().unwrap();
    assert!(!state.chats.contains_key("finished"));
    assert!(
        state.chats.contains_key("running"),
        "a chat that is still running must stay reachable for its cancellation"
    );
}

#[test]
fn an_identity_link_waits_for_no_deletion_of_the_previous_conversation() {
    // Linking copies the previous conversation and deletes it, so it must not run while
    // that conversation's history is being deleted.
    let _data = TestDataDirectory::new();
    let (identity, _) = Identity::create().unwrap();
    let owner = identity.public_id().to_owned();
    let previous = "7f".repeat(32);
    contacts::save(
        &contacts::directory_for(&identity).unwrap(),
        &identity,
        &contacts::VerifiedContact {
            peer_key: history::decode_peer_id(&previous).unwrap(),
            rendezvous_secret: zeroize::Zeroizing::new([3; 32]),
        },
    )
    .unwrap();
    let (operation, receiver) = stalled_worker_operation(&owner, &"80".repeat(32));
    operation.snapshot.lock().unwrap().identity_transition = Some(vec![previous.clone()]);
    let mut chats = HashMap::new();
    chats.insert("linking".to_owned(), operation);
    let state = test_state(Some(Arc::new(identity)), chats);
    state
        .lock()
        .unwrap()
        .active_history_deletions
        .insert(conversation_history_key(&owner, &previous));
    let body = format!("linking\n{previous}");
    let refused = call_test_api(&state, "/api/chat/link-identity", &body, "test-session");
    assert!(refused.starts_with("HTTP/1.1 409 Conflict"), "{refused}");
    assert!(
        receiver.try_recv().is_err(),
        "the worker was not asked to link"
    );
}

#[test]
fn chat_operation_apis_are_scoped_to_the_creating_identity() {
    let (identity_a, _) = Identity::create().unwrap();
    let owner_id = identity_a.public_id().to_owned();
    let (identity_b, _) = Identity::create().unwrap();
    let (sender, receiver) = mpsc::channel();
    let peer_id = "7a".repeat(32);
    let operation = Arc::new(ChatOperation {
        owner_identity_id: owner_id.clone(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: Some(peer_id.clone()),
            error: None,
            storage_error: None,
            messages: vec![ChatEntry {
                unix_time: 1,
                sender: "상대방",
                text: "private message".to_owned(),
            }],
            message_count: 1,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: Some(vec![peer_id.clone()]),
            history_restore_in_progress: false,
            history_restore_state: "awaiting-merge-consent",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: vec![RestoreOfferEntry {
                unix_time: 1,
                sender: "상대방",
                text: "private preview".to_owned(),
                signed: true,
            }],
            history_restore_offer_count: 1,
            history_restore_legacy_count: 0,
            history_restore_received: 1,
            history_restore_total: 1,
            history_restore_status: Some("private status".to_owned()),
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender,
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    let mut chats = HashMap::new();
    chats.insert("owned-operation".to_owned(), Arc::clone(&operation));
    let state = test_state(Some(Arc::new(identity_b)), chats);
    let requests = [
        ("/api/chat/status", "owned-operation".to_owned()),
        ("/api/chat/messages", "owned-operation\n0".to_owned()),
        ("/api/chat/confirm", "owned-operation".to_owned()),
        ("/api/chat/send", "owned-operation\nhello".to_owned()),
        ("/api/chat/cancel", "owned-operation".to_owned()),
        (
            "/api/chat/link-identity",
            format!("owned-operation\n{peer_id}"),
        ),
        (
            "/api/chat/request-history-restore",
            "owned-operation".to_owned(),
        ),
        (
            "/api/chat/resolve-history-restore",
            r#"{"operationId":"owned-operation","accept":true}"#.to_owned(),
        ),
    ];
    for (path, body) in requests {
        let response = call_test_api(&state, path, &body, "test-session");
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "{path}: {response}"
        );
    }
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    state.lock().unwrap().identity = None;
    let logged_out = call_test_api(
        &state,
        "/api/chat/status",
        "owned-operation",
        "test-session",
    );
    assert!(logged_out.starts_with("HTTP/1.1 404 Not Found"));

    state.lock().unwrap().identity = Some(Arc::new(identity_a));
    let owner_status = call_test_api(
        &state,
        "/api/chat/status",
        "owned-operation",
        "test-session",
    );
    assert!(owner_status.starts_with("HTTP/1.1 200 OK"));
    assert!(owner_status.contains("private preview"));
}

#[test]
fn restore_merge_serializes_snapshot_count_with_pre_and_post_replace_appends() {
    let data = TestDataDirectory::new();
    let (identity, access_code) = Identity::create().unwrap();
    let code = access_code.to_string();
    let owner_id = identity.public_id().to_owned();
    let peer_id = "8b".repeat(32);
    let (command_sender, command_receiver) = mpsc::channel();
    let (mut history, _, _) = history::History::open_for_chat(&identity, &peer_id).unwrap();
    let stored = |time, text: &str| history::StoredMessage {
        unix_time: time,
        sender: history::MessageSender::Me,
        text: text.to_owned(),
        proof: None,
    };
    history.append(&stored(1, "baseline")).unwrap();

    let operation = Arc::new(ChatOperation {
        owner_identity_id: owner_id,
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connected",
            fingerprint: None,
            confirmation_code: None,
            peer_id: Some(peer_id.clone()),
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 1,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: true,
            history_restore_state: "merging",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 0,
            history_restore_legacy_count: 0,
            history_restore_received: 0,
            history_restore_total: 0,
            history_restore_status: Some("merging".to_owned()),
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender: command_sender,
        cancelled: Arc::new(AtomicBool::new(false)),
    });

    {
        let _guard = operation.history_state_lock.lock().unwrap();
        history.append(&stored(2, "before merge lock")).unwrap();
        chat_update(&operation, |snapshot| {
            snapshot.message_count += 1;
            snapshot.messages.push(ChatEntry {
                unix_time: 2,
                sender: "나",
                text: "before merge lock".to_owned(),
            });
        });
    }

    let mut staging =
        history::RestoreStaging::create(&identity, &peer_id, &"9c".repeat(32)).unwrap();
    staging
        .append_verified(&stored(3, "restored proposal"))
        .unwrap();
    staging.finish().unwrap();
    assert!(restore_merge_active(&operation));
    assert!(restore_merge_send_error(&operation).is_some());

    let (replaced_send, replaced_receive) = mpsc::channel();
    let (release_replace_send, release_replace_receive) = mpsc::channel();
    let (status_send, status_receive) = mpsc::channel();
    let (release_status_send, release_status_receive) = mpsc::channel();
    let merge_operation = Arc::clone(&operation);
    let merge_directory = data.0.clone();
    let merge_code = code.clone();
    let merge_peer = peer_id.clone();
    let merge = thread::spawn(move || {
        history::set_test_data_directory(Some(merge_directory));
        let merge_identity = Identity::from_code(&merge_code).unwrap();
        let _guard = merge_operation.history_state_lock.lock().unwrap();
        let (mut current, _, _) =
            history::History::open_for_chat(&merge_identity, &merge_peer).unwrap();
        let summary = current
            .merge_restore_staging(&merge_identity, &mut staging)
            .unwrap();
        replaced_send.send(summary.total_count).unwrap();
        release_replace_receive.recv().unwrap();
        chat_update(&merge_operation, |snapshot| {
            snapshot.message_count = summary.total_count as usize;
            snapshot.message_epoch = snapshot.message_epoch.wrapping_add(1);
            snapshot.history_restore_in_progress = false;
            snapshot.history_restore_state = "completed";
            snapshot.history_restore_status = Some("merge complete".to_owned());
        });
        status_send.send(()).unwrap();
        release_status_receive.recv().unwrap();
        staging.cleanup().unwrap();
        history::set_test_data_directory(None);
    });
    assert_eq!(
        replaced_receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        3
    );

    let mut merge_pending = VecDeque::new();
    let mut merge_pending_bytes = 0;
    for index in 0..10 {
        queue_message_during_restore_merge(
            &mut merge_pending,
            &mut merge_pending_bytes,
            history::StoredMessage {
                unix_time: 5 + index,
                sender: history::MessageSender::Other,
                text: format!("queued-{index}"),
                proof: None,
            },
        )
        .unwrap();
    }
    assert_eq!(merge_pending.len(), 10);

    let (append_done_send, append_done_receive) = mpsc::channel();
    let (append_started_send, append_started_receive) = mpsc::channel();
    let append_operation = Arc::clone(&operation);
    let append_directory = data.0.clone();
    let append_code = code.clone();
    let append_peer = peer_id.clone();
    let append = thread::spawn(move || {
        history::set_test_data_directory(Some(append_directory));
        let append_identity = Identity::from_code(&append_code).unwrap();
        append_started_send.send(()).unwrap();
        let _guard = append_operation.history_state_lock.lock().unwrap();
        let (mut current, _, _) =
            history::History::open_for_chat(&append_identity, &append_peer).unwrap();
        let new_message = history::StoredMessage {
            unix_time: 4,
            sender: history::MessageSender::Other,
            text: "after replacement".to_owned(),
            proof: None,
        };
        current.append(&new_message).unwrap();
        chat_update(&append_operation, |snapshot| {
            snapshot.message_count += 1;
            snapshot.messages.push(chat_entry(new_message));
        });
        append_done_send.send(()).unwrap();
        history::set_test_data_directory(None);
    });
    append_started_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert!(append_done_receive
        .recv_timeout(Duration::from_millis(30))
        .is_err());
    release_replace_send.send(()).unwrap();
    status_receive.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(append_done_receive
        .recv_timeout(Duration::from_millis(30))
        .is_err());
    release_status_send.send(()).unwrap();
    append_done_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    merge.join().unwrap();
    append.join().unwrap();

    let mut current = Some(
        history::History::open_for_chat(&identity, &peer_id)
            .unwrap()
            .0,
    );
    assert!(queue_incoming_message(&operation, merge_pending.len()));
    assert_eq!(
        append_pending_restore_messages(
            &operation,
            &mut current,
            &mut merge_pending,
            &mut merge_pending_bytes,
            8,
        )
        .unwrap(),
        8
    );
    assert_eq!(merge_pending.len(), 2);
    let late_entry = history::StoredMessage {
        unix_time: 15,
        sender: history::MessageSender::Other,
        text: "arrived-after-first-batch".to_owned(),
        proof: None,
    };
    assert!(queue_incoming_message(&operation, merge_pending.len()));
    queue_message_during_restore_merge(&mut merge_pending, &mut merge_pending_bytes, late_entry)
        .unwrap();
    assert_eq!(merge_pending.len(), 3);
    assert_eq!(
        append_pending_restore_messages(
            &operation,
            &mut current,
            &mut merge_pending,
            &mut merge_pending_bytes,
            8,
        )
        .unwrap(),
        3
    );
    assert!(merge_pending.is_empty());

    let snapshot = operation.snapshot.lock().unwrap();
    assert_eq!(snapshot.message_count, 15);
    assert_eq!(snapshot.message_epoch, 12);
    drop(snapshot);
    let restored_identity = Identity::from_code(&code).unwrap();
    let state = test_state(
        Some(Arc::new(restored_identity)),
        HashMap::from([("count-operation".to_owned(), Arc::clone(&operation))]),
    );
    let response = call_test_api(
        &state,
        "/api/chat/messages",
        "count-operation\n0",
        "test-session",
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("after replacement"));
    let first_queued = response.find("queued-0").unwrap();
    let eighth_queued = response.find("queued-7").unwrap();
    let ninth_queued = response.find("queued-8").unwrap();
    let tenth_queued = response.find("queued-9").unwrap();
    let late_message = response.find("arrived-after-first-batch").unwrap();
    assert!(first_queued < eighth_queued);
    assert!(eighth_queued < ninth_queued);
    assert!(ninth_queued < tenth_queued);
    assert!(tenth_queued < late_message);
    operation.snapshot.lock().unwrap().history_restore_state = "merging";
    let rejected_send = call_test_api(
        &state,
        "/api/chat/send",
        "count-operation\nkeep during merge",
        "test-session",
    );
    assert!(rejected_send.starts_with("HTTP/1.1 409 Conflict"));
    assert!(rejected_send.contains(RESTORE_MERGE_SEND_REJECTION));
    assert!(matches!(
        command_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    {
        let mut snapshot = operation.snapshot.lock().unwrap();
        snapshot.history_restore_state = "receiving";
        snapshot.history_restore_in_progress = true;
    }
    let send_worker = thread::spawn(move || {
        let ChatCommand::Send(text, processed) = command_receiver.recv().unwrap() else {
            panic!("expected send during history transfer");
        };
        assert_eq!(text, "send while receiving history");
        processed.send(Ok(())).unwrap();
    });
    let accepted_send = call_test_api(
        &state,
        "/api/chat/send",
        "count-operation\nsend while receiving history",
        "test-session",
    );
    assert!(accepted_send.starts_with("HTTP/1.1 202 Accepted"));
    send_worker.join().unwrap();
    assert!(response.contains("restored proposal"));

    let mut unavailable_queue = VecDeque::new();
    let mut unavailable_bytes = 0;
    queue_message_during_restore_merge(
        &mut unavailable_queue,
        &mut unavailable_bytes,
        history::StoredMessage {
            unix_time: 16,
            sender: history::MessageSender::Other,
            text: "not saved".to_owned(),
            proof: None,
        },
    )
    .unwrap();
    let snapshot_count = operation.snapshot.lock().unwrap().message_count;
    let mut missing_history = None;
    assert!(append_pending_restore_messages(
        &operation,
        &mut missing_history,
        &mut unavailable_queue,
        &mut unavailable_bytes,
        8,
    )
    .is_err());
    assert_eq!(
        operation.snapshot.lock().unwrap().message_count,
        snapshot_count
    );
}

#[test]
fn merge_pending_message_queue_enforces_count_and_byte_limits() {
    let mut messages = VecDeque::new();
    let mut bytes = 0;
    for index in 0..MAX_MERGE_PENDING_MESSAGES {
        queue_message_during_restore_merge(
            &mut messages,
            &mut bytes,
            history::StoredMessage {
                unix_time: index as u64,
                sender: history::MessageSender::Other,
                text: "x".to_owned(),
                proof: None,
            },
        )
        .unwrap();
    }
    assert!(queue_message_during_restore_merge(
        &mut messages,
        &mut bytes,
        history::StoredMessage {
            unix_time: MAX_MERGE_PENDING_MESSAGES as u64,
            sender: history::MessageSender::Other,
            text: "overflow".to_owned(),
            proof: None,
        },
    )
    .is_err());
    assert_eq!(messages.len(), MAX_MERGE_PENDING_MESSAGES);

    let mut empty = VecDeque::new();
    let mut bytes_at_limit = MAX_MERGE_PENDING_BYTES - 1;
    assert!(queue_message_during_restore_merge(
        &mut empty,
        &mut bytes_at_limit,
        history::StoredMessage {
            unix_time: 0,
            sender: history::MessageSender::Other,
            text: "xx".to_owned(),
            proof: None,
        },
    )
    .is_err());
}

#[test]
fn history_restore_blocks_chat_io_only_during_final_merge_states() {
    assert!(history_restore_is_merging("merge-queued"));
    assert!(history_restore_is_merging("merging"));
    for state in [
        "idle",
        "estimating",
        "awaiting-transfer-consent",
        "transfer-queued",
        "receiving",
        "awaiting-merge-consent",
        "completed",
        "failed",
    ] {
        assert!(
            !history_restore_is_merging(state),
            "{state} must allow normal chat I/O"
        );
    }
}

#[test]
#[ignore = "slow stress test (large files / many records); run with --ignored"]
fn history_sync_streams_large_offers_through_chunks_staging_and_final_merge() {
    let _data = TestDataDirectory::new();
    let (sender_identity, _) = Identity::create().unwrap();
    let sender_key = sender_identity.public_key();
    for (case, (count, text_bytes)) in [(100_001usize, 1usize), (17_000, 4_096)]
        .into_iter()
        .enumerate()
    {
        let (receiver_identity, _) = Identity::create().unwrap();
        let peer_id = crate::hex::encode(&sender_key);
        let request_id = format!("{:064x}", 0x600 + case);
        let mut sender =
            HistorySyncSender::for_generated_test(request_id.clone(), count, text_bytes);
        let mut receiver = HistorySyncReceiver::default();
        receiver.begin(&request_id, count).unwrap();
        let mut staging =
            history::RestoreStaging::create(&receiver_identity, &peer_id, &request_id).unwrap();
        let (mut current_history, _, _) =
            history::History::open(&receiver_identity, &peer_id).unwrap();
        let mut chunks = 0usize;
        let mut first_chunk_count = None;
        loop {
            let (chunk, frames) = sender.next_chunk().unwrap().unwrap();
            assert!(!frames.is_empty());
            assert!(frames.len() <= SYNC_CHUNK_RECORDS);
            assert!(frames.iter().map(Vec::len).sum::<usize>() <= SYNC_CHUNK_BYTES);
            first_chunk_count.get_or_insert(frames.len());
            receiver
                .begin_chunk(&request_id, chunk, frames.len())
                .unwrap();
            for frame in frames {
                let (frame_id, frame_chunk, payload) =
                    history::transfer_chunk_metadata(&frame).unwrap();
                assert_eq!(frame_id, request_id);
                assert_eq!(frame_chunk, chunk);
                receiver
                    .record(&request_id, frame_chunk, frame.len())
                    .unwrap();
                let item =
                    history::decode_transfer(&receiver_identity, &peer_id, &sender_key, payload)
                        .unwrap();
                staging.append_verified(&item).unwrap();
            }
            receiver.end_chunk(&request_id, chunk).unwrap();
            if chunks == 0 {
                current_history
                    .append(&history::StoredMessage {
                        unix_time: count as u64 + 1,
                        sender: history::MessageSender::Me,
                        text: "arrived during transfer".to_owned(),
                        proof: None,
                    })
                    .unwrap();
            }
            assert!(!sender.acknowledge(&"ff".repeat(32), chunk).unwrap());
            let finished = sender.acknowledge(&request_id, chunk).unwrap();
            chunks += 1;
            if finished {
                break;
            }
        }
        receiver.finish(&request_id, count).unwrap();
        assert!(chunks > count / SYNC_CHUNK_RECORDS);
        if text_bytes > 1 {
            assert!(first_chunk_count.unwrap() < SYNC_CHUNK_RECORDS);
        }
        staging.finish().unwrap();
        if text_bytes > 1 {
            assert!(staging.storage_bytes().unwrap() > 64 * 1024 * 1024);
        }
        let summary = current_history
            .merge_restore_staging(&receiver_identity, &mut staging)
            .unwrap();
        assert_eq!(summary.imported_count, count as u64);
        assert_eq!(summary.total_count, count as u64 + 1);
        assert!(summary.peak_sort_buffer_bytes <= 2 * 1024 * 1024);
        let mut page_state = None;
        let mut cursor = 0usize;
        while cursor < summary.total_count as usize {
            let page = read_chat_history_page(
                &mut page_state,
                &receiver_identity,
                &peer_id,
                case as u64 + 1,
                cursor,
                summary.total_count as usize,
                256,
            )
            .unwrap();
            assert!(!page.is_empty());
            cursor += page.len();
        }
        assert_eq!(cursor, count + 1);
        staging.cleanup().unwrap();
    }
}

#[test]
fn history_sync_receiver_rejects_missing_duplicate_and_out_of_order_chunks() {
    let request_id = "de".repeat(32);
    let mut receiver = HistorySyncReceiver::default();
    receiver.begin(&request_id, 33).unwrap();
    assert!(receiver.begin_chunk(&request_id, 1, 1).is_err());
    receiver.begin_chunk(&request_id, 0, 32).unwrap();
    assert!(receiver.begin_chunk(&request_id, 0, 32).is_err());
    assert!(receiver.record(&"aa".repeat(32), 0, 1_000).is_err());
    assert!(receiver.record(&request_id, 1, 1_000).is_err());
    for _ in 0..31 {
        receiver.record(&request_id, 0, 1_000).unwrap();
    }
    assert!(receiver.end_chunk(&request_id, 0).is_err());
    assert!(receiver.finish(&request_id, 33).is_err());

    let mut retried = HistorySyncReceiver::default();
    let retry_id = "ef".repeat(32);
    retried.begin(&retry_id, 1).unwrap();
    retried.begin_chunk(&retry_id, 0, 1).unwrap();
    assert!(retried.record(&request_id, 0, 1_000).is_err());
    assert!(retried.finish(&request_id, 1).is_err());
    retried.record(&retry_id, 0, 1_000).unwrap();
    retried.end_chunk(&retry_id, 0).unwrap();
    retried.finish(&retry_id, 1).unwrap();
}

#[test]
fn queued_message_is_not_acknowledged_if_worker_exits() {
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let command = receiver.recv().unwrap();
        drop(command);
    });
    assert!(submit_chat_message(&sender, "unsent".into(), Duration::from_secs(1)).is_err());
    worker.join().unwrap();
}

#[test]
fn message_is_acknowledged_after_worker_processing() {
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        if let ChatCommand::Send(text, processed) = receiver.recv().unwrap() {
            assert_eq!(text, "hello");
            processed.send(Ok(())).unwrap();
        } else {
            panic!("expected message");
        }
    });
    assert!(submit_chat_message(&sender, "hello".into(), Duration::from_secs(1)).is_ok());
    worker.join().unwrap();
}

#[test]
fn heartbeat_rejection_does_not_remove_pending_message() {
    let mut pending = HashSet::from(["message".to_owned()]);
    assert!(!rejected_message(&mut pending, "heartbeat"));
    assert!(pending.contains("message"));
    assert!(rejected_message(&mut pending, "message"));
}

#[test]
fn closed_history_updates_are_scoped_to_the_local_identity() {
    let identity_a = "identity-a";
    let identity_b = "identity-b";
    let peer_id = "ab".repeat(32);
    let operation_a = closed_test_operation(identity_a, &peer_id, 10, 3);
    let operation_b = closed_test_operation(identity_b, &peer_id, 20, 7);
    let state = State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: SessionStore::default(),
        identity: None,
        chats: HashMap::from([
            ("a".to_owned(), Arc::clone(&operation_a)),
            ("b".to_owned(), Arc::clone(&operation_b)),
        ]),
        history_deletions: HashMap::new(),
        active_history_deletions: HashSet::new(),
        history_import_active: false,
        tor_socks: None,
        active_relays: vec![DEFAULT_RELAY.to_owned()],
        settings: AppSettings::default(),
        notifications_enabled: Arc::new(AtomicBool::new(false)),
        last_notification: Arc::new(Mutex::new(None)),
    };
    update_closed_chat_history(&state, identity_a, &peer_id, 4);
    let a = operation_a.snapshot.lock().unwrap();
    assert_eq!(a.message_count, 4);
    assert_eq!(a.message_epoch, 4);
    assert!(a.messages.is_empty());
    drop(a);
    assert!(operation_a.message_reader.lock().unwrap().is_none());
    let b = operation_b.snapshot.lock().unwrap();
    assert_eq!(b.message_count, 20);
    assert_eq!(b.message_epoch, 7);
    assert_eq!(b.messages.len(), 1);
    drop(b);
    assert!(operation_b.message_reader.lock().unwrap().is_some());

    update_closed_chat_history(&state, identity_b, &peer_id, 8);
    assert_eq!(operation_a.snapshot.lock().unwrap().message_count, 4);
    assert_eq!(operation_b.snapshot.lock().unwrap().message_count, 8);
}

#[test]
fn history_delete_runs_without_global_state_lock_and_remains_queryable_after_identity_switch() {
    let _data = TestDataDirectory::new();
    let (identity_a, code_a) = Identity::create().unwrap();
    let (identity_b, code_b) = Identity::create().unwrap();
    let peer_id = identity_b.public_id();
    let (mut history, _, _) = history::History::open(&identity_a, &peer_id).unwrap();
    history
        .append(&history::StoredMessage {
            unix_time: 1,
            sender: history::MessageSender::Me,
            text: "delete me".to_owned(),
            proof: None,
        })
        .unwrap();
    let version = history::History::read_page(&identity_a, &peer_id, None, 10)
        .unwrap()
        .version;
    let operation_a = closed_test_operation(identity_a.public_id().as_str(), &peer_id, 1, 9);
    let operation_b = closed_test_operation(identity_b.public_id().as_str(), &peer_id, 7, 12);
    operation_a.message_reader.lock().unwrap().take();
    let state = test_state(
        Some(Arc::new(Identity::from_code(&code_a).unwrap())),
        HashMap::from([
            ("closed-a".to_owned(), Arc::clone(&operation_a)),
            ("closed-b".to_owned(), Arc::clone(&operation_b)),
        ]),
    );
    let gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
    history::set_history_delete_test_gate(Some(Arc::clone(&gate)));
    let request_body = serde_json::json!({
        "operationId": "test-delete-job-1",
        "peerId": peer_id,
        "version": version,
        "indices": [0],
    })
    .to_string();
    let accepted = call_test_api(
        &state,
        "/api/history/delete-messages",
        &request_body,
        "test-session",
    );
    assert!(accepted.starts_with("HTTP/1.1 202 Accepted"), "{accepted}");
    let (gate_state, gate_changed) = &*gate;
    let gate_deadline = Instant::now() + Duration::from_secs(2);
    let mut gate_state = gate_state.lock().unwrap();
    while !gate_state.0 {
        let remaining = gate_deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "delete did not reach the locked rewrite gate"
        );
        let (next, timeout) = gate_changed.wait_timeout(gate_state, remaining).unwrap();
        gate_state = next;
        assert!(
            !timeout.timed_out() || gate_state.0,
            "delete did not reach the locked rewrite gate"
        );
    }
    drop(gate_state);
    assert!(history_delete_active(
        &state.lock().unwrap(),
        &identity_a.public_id(),
        &peer_id,
    ));

    let data_directory = _data.0.clone();
    let state_for_list = Arc::clone(&state);
    let list_data_directory = data_directory.clone();
    let (list_started_send, list_started_receive) = mpsc::channel();
    let (list_done_send, list_done_receive) = mpsc::channel();
    let list_worker = thread::spawn(move || {
        history::set_test_data_directory(Some(list_data_directory));
        list_started_send.send(()).unwrap();
        let response = call_test_api(&state_for_list, "/api/history/list", "", "test-session");
        history::set_test_data_directory(None);
        list_done_send.send(response).unwrap();
    });
    let state_for_page = Arc::clone(&state);
    let page_data_directory = data_directory;
    let (page_started_send, page_started_receive) = mpsc::channel();
    let (page_done_send, page_done_receive) = mpsc::channel();
    let page_body = serde_json::json!({"peerId": peer_id, "cursor": null, "limit": 50}).to_string();
    let page_worker = thread::spawn(move || {
        history::set_test_data_directory(Some(page_data_directory));
        page_started_send.send(()).unwrap();
        let response = call_test_api(
            &state_for_page,
            "/api/history/messages",
            &page_body,
            "test-session",
        );
        history::set_test_data_directory(None);
        page_done_send.send(response).unwrap();
    });
    let state_for_chat_messages = Arc::clone(&state);
    let chat_messages_data_directory = _data.0.clone();
    let (chat_messages_started_send, chat_messages_started_receive) = mpsc::channel();
    let (chat_messages_done_send, chat_messages_done_receive) = mpsc::channel();
    let chat_messages_worker = thread::spawn(move || {
        history::set_test_data_directory(Some(chat_messages_data_directory));
        chat_messages_started_send.send(()).unwrap();
        let response = call_test_api(
            &state_for_chat_messages,
            "/api/chat/messages",
            "closed-a\n0",
            "test-session",
        );
        history::set_test_data_directory(None);
        chat_messages_done_send.send(response).unwrap();
    });
    list_started_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    page_started_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    chat_messages_started_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    thread::sleep(Duration::from_millis(30));
    assert!(list_done_receive.try_recv().is_err());
    assert!(page_done_receive.try_recv().is_err());
    assert!(chat_messages_done_receive.try_recv().is_err());
    let state_for_probe = Arc::clone(&state);
    let (probe_send, probe_receive) = mpsc::channel();
    let probe_worker = thread::spawn(move || {
        let response = call_test_api(&state_for_probe, "/api/settings/get", "", "test-session");
        let _ = probe_send.send(response);
    });
    let probe_response = probe_receive.recv_timeout(Duration::from_millis(500)).ok();
    let probe_was_immediate = probe_response.is_some();
    if probe_response.is_some() {
        let reconnect = call_test_api(&state, "/api/chat/reconnect", &peer_id, "test-session");
        assert!(reconnect.starts_with("HTTP/1.1 409 Conflict"));
        state.lock().unwrap().identity = Some(Arc::new(Identity::from_code(&code_b).unwrap()));
        let forbidden = call_test_api(
            &state,
            "/api/history/delete-status",
            "test-delete-job-1",
            "test-session",
        );
        assert!(forbidden.starts_with("HTTP/1.1 404 Not Found"));
    }
    {
        let (gate_state, changed) = &*gate;
        gate_state.lock().unwrap().1 = true;
        changed.notify_all();
    }
    history::set_history_delete_test_gate(None);
    let probe_response =
        probe_response.or_else(|| probe_receive.recv_timeout(Duration::from_secs(2)).ok());
    let list_response = list_done_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let page_response = page_done_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let chat_messages_response = chat_messages_done_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    probe_worker.join().unwrap();
    list_worker.join().unwrap();
    page_worker.join().unwrap();
    chat_messages_worker.join().unwrap();
    assert!(probe_response
        .as_deref()
        .is_some_and(|response| response.starts_with("HTTP/1.1 200 OK")));
    assert!(
        probe_was_immediate,
        "unrelated API waited for history file lock"
    );
    assert!(
        list_response.starts_with("HTTP/1.1 200 OK"),
        "{list_response}"
    );
    assert!(list_response.contains("\"messageCount\":0"));
    assert!(
        page_response.starts_with("HTTP/1.1 200 OK"),
        "{page_response}"
    );
    assert!(page_response.contains("\"messages\":[]"));
    assert!(
        chat_messages_response.starts_with("HTTP/1.1 200 OK"),
        "{chat_messages_response}"
    );
    assert!(chat_messages_response.contains("[]"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let current = state.lock().unwrap();
        let complete = current
            .history_deletions
            .get("test-delete-job-1")
            .unwrap()
            .snapshot
            .lock()
            .unwrap()
            .state
            == "completed";
        if complete {
            break;
        }
        drop(current);
        assert!(
            Instant::now() < deadline,
            "deletion worker did not complete"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(operation_a.snapshot.lock().unwrap().message_count, 0);
    assert_eq!(operation_a.snapshot.lock().unwrap().message_epoch, 10);
    assert!(operation_a.message_reader.lock().unwrap().is_none());
    assert_eq!(operation_b.snapshot.lock().unwrap().message_count, 7);
    assert_eq!(operation_b.snapshot.lock().unwrap().message_epoch, 12);
    assert!(operation_b.message_reader.lock().unwrap().is_some());
    state.lock().unwrap().identity = Some(Arc::new(Identity::from_code(&code_a).unwrap()));
    let completed = call_test_api(
        &state,
        "/api/history/delete-status",
        "test-delete-job-1",
        "test-session",
    );
    assert!(completed.starts_with("HTTP/1.1 200 OK"));
    assert!(completed.contains("\"state\":\"completed\""));

    let (mut current, _, _) = history::History::open(&identity_a, &peer_id).unwrap();
    current
        .append(&history::StoredMessage {
            unix_time: 2,
            sender: history::MessageSender::Me,
            text: "newer record".to_owned(),
            proof: None,
        })
        .unwrap();
    let stale_request = serde_json::json!({
        "operationId": "test-delete-job-stale",
        "peerId": peer_id,
        "version": version,
        "indices": [0],
    })
    .to_string();
    let stale_accepted = call_test_api(
        &state,
        "/api/history/delete-messages",
        &stale_request,
        "test-session",
    );
    assert!(stale_accepted.starts_with("HTTP/1.1 202 Accepted"));
    let stale_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let current_state = state.lock().unwrap();
        let status = current_state
            .history_deletions
            .get("test-delete-job-stale")
            .unwrap()
            .snapshot
            .lock()
            .unwrap();
        if status.state == "failed" {
            assert!(status.error.as_deref().unwrap().contains("history changed"));
            break;
        }
        drop(status);
        drop(current_state);
        assert!(Instant::now() < stale_deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let still_present = history::History::read_page(&identity_a, &peer_id, None, 10).unwrap();
    assert_eq!(still_present.entries.len(), 1);
    assert_eq!(still_present.entries[0].message.text, "newer record");
}
