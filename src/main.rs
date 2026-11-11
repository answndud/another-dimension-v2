mod identity;

use identity::Identity;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PAGE: &[u8] = include_bytes!("../web/index.html");
const SCRIPT: &[u8] = include_bytes!("../web/app.js");
const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 256;
const CODE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS: u8 = 5;

struct State {
    code: String,
    issued: Instant,
    attempts: u8,
    sessions: Vec<String>,
    identity: Option<Identity>,
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn equal_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn issue_code(state: &mut State) -> io::Result<()> {
    state.code = random_token()?;
    state.issued = Instant::now();
    state.attempts = 0;
    println!("로컬 연결 코드: {}", state.code);
    println!("새 연결 코드를 발급하려면 Enter를 누르세요.");
    Ok(())
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(body)
}

fn reject(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    respond(stream, status, "text/plain; charset=utf-8", b"")
}

fn handle(mut stream: TcpStream, expected_host: &str, state: &Arc<Mutex<State>>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0; 1024]);
    let header_end = loop {
        if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        let n = stream.read(buffer.as_mut())?;
        if n == 0 || request.len() + n > MAX_HEADER {
            return reject(&mut stream, "400 Bad Request");
        }
        request.extend_from_slice(&buffer[..n]);
    };
    if header_end > MAX_HEADER {
        return reject(&mut stream, "400 Bad Request");
    }
    let header = match std::str::from_utf8(&request[..header_end]) {
        Ok(value) => value,
        Err(_) => return reject(&mut stream, "400 Bad Request"),
    };
    let mut lines = header.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut host = None;
    let mut origin = None;
    let mut authorization = None;
    let mut length = None;
    let mut content_type = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return reject(&mut stream, "400 Bad Request");
        };
        let value = value.trim();
        let slot = if name.eq_ignore_ascii_case("host") {
            Some(&mut host)
        } else if name.eq_ignore_ascii_case("origin") {
            Some(&mut origin)
        } else if name.eq_ignore_ascii_case("authorization") {
            Some(&mut authorization)
        } else if name.eq_ignore_ascii_case("content-length") {
            Some(&mut length)
        } else if name.eq_ignore_ascii_case("content-type") {
            Some(&mut content_type)
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return reject(&mut stream, "400 Bad Request");
        } else {
            None
        };
        if let Some(slot) = slot {
            if slot.replace(value).is_some() {
                return reject(&mut stream, "400 Bad Request");
            }
        }
    }
    if host != Some(expected_host) {
        return reject(&mut stream, "400 Bad Request");
    }
    if first == "GET / HTTP/1.1" {
        return respond(&mut stream, "200 OK", "text/html; charset=utf-8", PAGE);
    }
    if first == "GET /app.js HTTP/1.1" {
        return respond(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            SCRIPT,
        );
    }
    if !matches!(
        first,
        "POST /api/connect HTTP/1.1"
            | "POST /api/session HTTP/1.1"
            | "POST /api/disconnect HTTP/1.1"
            | "POST /api/identity/create HTTP/1.1"
            | "POST /api/identity/login HTTP/1.1"
            | "POST /api/identity/status HTTP/1.1"
            | "POST /api/identity/logout HTTP/1.1"
    ) {
        return reject(&mut stream, "404 Not Found");
    }
    if origin != Some(format!("http://{expected_host}").as_str())
        || content_type != Some("text/plain;charset=UTF-8")
    {
        return reject(&mut stream, "403 Forbidden");
    }
    let body_len = match length.and_then(|value| value.parse::<usize>().ok()) {
        Some(value) if value <= MAX_BODY => value,
        _ => return reject(&mut stream, "400 Bad Request"),
    };
    let first = first.to_owned();
    let auth = authorization.map(str::to_owned);
    while request.len() < header_end + body_len {
        let n = stream.read(buffer.as_mut())?;
        if n == 0 {
            return reject(&mut stream, "400 Bad Request");
        }
        request.extend_from_slice(&buffer[..n]);
    }
    if request.len() != header_end + body_len {
        return reject(&mut stream, "400 Bad Request");
    }
    let body = match std::str::from_utf8(&request[header_end..]) {
        Ok(value) => value,
        Err(_) => return reject(&mut stream, "400 Bad Request"),
    };
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state unavailable"))?;
    if first == "POST /api/connect HTTP/1.1" {
        if state.code.is_empty()
            || state.issued.elapsed() >= CODE_LIFETIME
            || state.attempts >= MAX_ATTEMPTS
        {
            return reject(&mut stream, "403 Forbidden");
        }
        if !equal_token(body, &state.code) {
            state.attempts += 1;
            return reject(&mut stream, "403 Forbidden");
        }
        let token = random_token()?;
        state.code.clear();
        state.sessions.push(token.clone());
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            token.as_bytes(),
        );
    }
    let token = auth
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    let Some(index) = state
        .sessions
        .iter()
        .position(|item| equal_token(item, token))
    else {
        return reject(&mut stream, "401 Unauthorized");
    };
    if first == "POST /api/disconnect HTTP/1.1" {
        state.sessions.remove(index);
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    match first.as_str() {
        "POST /api/identity/create HTTP/1.1" => {
            if state.identity.is_some() {
                return reject(&mut stream, "409 Conflict");
            }
            let (identity, code) = Identity::create()?;
            // Do not activate a new identity unless the response was written successfully.
            respond(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                code.as_bytes(),
            )?;
            state.identity = Some(identity);
            return Ok(());
        }
        "POST /api/identity/login HTTP/1.1" => {
            if state.identity.is_some() {
                return reject(&mut stream, "409 Conflict");
            }
            let Some(identity) = Identity::from_code(body) else {
                return reject(&mut stream, "400 Bad Request");
            };
            state.identity = Some(identity);
        }
        "POST /api/identity/status HTTP/1.1" => {
            let Some(identity) = state.identity.as_ref() else {
                return reject(&mut stream, "401 Unauthorized");
            };
            return respond(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                identity.public_id().as_bytes(),
            );
        }
        "POST /api/identity/logout HTTP/1.1" => {
            state.identity = None;
        }
        _ => {}
    }
    respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let state = Arc::new(Mutex::new(State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: Vec::new(),
        identity: None,
    }));
    println!("http://{address}/");
    {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("state unavailable"))?;
        issue_code(&mut state)?;
    }
    let input_state = Arc::clone(&state);
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if line.is_err() {
                break;
            }
            if let Ok(mut state) = input_state.lock() {
                if let Err(error) = issue_code(&mut state) {
                    eprintln!("연결 코드 발급 오류: {error}");
                }
            }
        }
    });
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let _ = handle(stream, &address.to_string(), &state);
            }
            Err(error) => eprintln!("로컬 연결 오류: {error}"),
        }
    }
    Ok(())
}
