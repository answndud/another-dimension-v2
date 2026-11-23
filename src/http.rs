//! HTTP plumbing for the loopback web UI: request parsing, responses, limits.

use super::*;

pub(crate) const PAGE: &[u8] = include_bytes!("../web/index.html");

pub(crate) const SCRIPT: &[u8] = include_bytes!("../web/app.js");

pub(crate) const STYLESHEET: &[u8] = include_bytes!("../web/app.css");

pub(crate) const REPROTECT_WORK_SCRIPT: &[u8] = include_bytes!("../web/reprotect-work.js");

pub(crate) const MAX_HEADER: usize = 8192;

// Full backups use the chunked transfer API; regular JSON bodies stay bounded.
pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;

/// Total time a client may take to send the request line and headers. A client that
/// trickles one byte at a time is cut off instead of holding a connection open.
pub(crate) const HEADER_DEADLINE: Duration = if cfg!(test) {
    Duration::from_millis(700)
} else {
    Duration::from_secs(5)
};

/// Total time for the request body once the headers have arrived.
pub(crate) const BODY_DEADLINE: Duration = if cfg!(test) {
    Duration::from_millis(900)
} else {
    Duration::from_secs(30)
};

/// Requests handled at the same time. Further connections get 503 right away.
pub(crate) const MAX_CONNECTIONS: usize = if cfg!(test) { 4 } else { 16 };

/// Returned when the session is valid but no identity is logged in. A rejected or
/// expired session is a plain 401 instead, so the page can tell the two apart.
pub(crate) const IDENTITY_REQUIRED: &str = "412 Precondition Failed";

pub(crate) fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    crate::random::fill(&mut bytes)?;
    Ok(crate::hex::encode(&bytes))
}

pub(crate) fn equal_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Reads that give up at an absolute deadline, so the limit covers the whole request
/// and not each individual read.
pub(crate) trait ReadWithin {
    fn read_within(&mut self, buffer: &mut [u8], deadline: Instant) -> io::Result<usize>;
}

impl ReadWithin for TcpStream {
    fn read_within(&mut self, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.set_read_timeout(Some(remaining.min(Duration::from_secs(2))))?;
        self.read(buffer)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RequestReadError {
    TimedOut,
    Invalid,
}

impl RequestReadError {
    pub(crate) fn status(&self) -> &'static str {
        match self {
            Self::TimedOut => "408 Request Timeout",
            Self::Invalid => "400 Bad Request",
        }
    }
}

pub(crate) fn read_error(error: &io::Error) -> RequestReadError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        RequestReadError::TimedOut
    } else {
        RequestReadError::Invalid
    }
}

/// Reads until the end of the headers and returns the header length. Bytes after the
/// headers (the start of the body) stay in `request`. The size limit applies to the
/// headers only, so a small body arriving in the same read is not counted against it.
pub(crate) fn read_request_head(
    stream: &mut impl ReadWithin,
    request: &mut Vec<u8>,
    deadline: Instant,
) -> Result<usize, RequestReadError> {
    let mut buffer = Zeroizing::new([0_u8; 1024]);
    let mut searched: usize = 0;
    loop {
        let start = searched.saturating_sub(3);
        if let Some(index) = request[start..]
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
        {
            let end = start + index + 4;
            return if end > MAX_HEADER {
                Err(RequestReadError::Invalid)
            } else {
                Ok(end)
            };
        }
        searched = request.len();
        if request.len() > MAX_HEADER {
            return Err(RequestReadError::Invalid);
        }
        match stream.read_within(buffer.as_mut(), deadline) {
            Ok(0) => return Err(RequestReadError::Invalid),
            Ok(n) => request.extend_from_slice(&buffer[..n]),
            Err(error) => return Err(read_error(&error)),
        }
    }
}

pub(crate) fn redact_paths(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let is_edge =
                |character: char| matches!(character, '(' | ')' | ',' | ';' | ':' | '"' | '\'');
            let start = word.len() - word.trim_start_matches(is_edge).len();
            let end = word.trim_end_matches(is_edge).len().max(start);
            let core = &word[start..end];
            if core.starts_with('/') && core[1..].contains('/') {
                let name = core.rsplit('/').next().unwrap_or("");
                format!("{}…/{name}{}", &word[..start], &word[end..])
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The text of an error for the page. The full error, which may name paths, goes to
/// the terminal log so a person at the machine can still diagnose it.
pub(crate) fn client_message(context: &str, error: &dyn std::fmt::Display) -> String {
    let full = error.to_string();
    eprintln!("{context}: {full}");
    redact_paths(&full)
}

/// Sent with every response, including rejections. No inline styles or scripts are
/// allowed, nothing may frame the page, and nothing is shared across origins.
pub(crate) const SECURITY_HEADERS: &str = "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n\
X-Content-Type-Options: nosniff\r\n\
Cache-Control: no-store\r\n\
Referrer-Policy: no-referrer\r\n\
Cross-Origin-Opener-Policy: same-origin\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), hid=()\r\n";

pub(crate) fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{SECURITY_HEADERS}Connection: close\r\n\r\n", body.len())?;
    stream.write_all(body)
}

pub(crate) fn reject(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    respond(stream, status, "text/plain; charset=utf-8", b"")
}

/// Decrements the active-connection count when a request thread ends, even by panic.
pub(crate) struct ConnectionSlot(pub(crate) Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accepts connections until `stop` is set. Each request runs on its own thread, so a
/// slow client cannot block the others, and at most `MAX_CONNECTIONS` run at once.
pub(crate) fn serve(
    listener: TcpListener,
    expected_host: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("로컬 연결 오류: {error}");
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = reject(&mut stream, "503 Service Unavailable");
            continue;
        }
        let slot = ConnectionSlot(Arc::clone(&active));
        let host = expected_host.clone();
        let state = Arc::clone(&state);
        if let Err(error) = thread::Builder::new()
            .name("local-request".to_owned())
            .spawn(move || {
                let _slot = slot;
                let _ = handle(stream, &host, &state);
            })
        {
            eprintln!("요청 처리 스레드를 만들지 못했습니다: {error}");
        }
    }
}
