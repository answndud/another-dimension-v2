use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const PAGE: &[u8] = include_bytes!("../web/index.html");
const MAX_REQUEST: usize = 8192;

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

fn handle(mut stream: TcpStream, expected_host: &str) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let n = stream.read(&mut buffer)?;
        if n == 0 || request.len() + n > MAX_REQUEST {
            return respond(&mut stream, "400 Bad Request", b"Bad Request");
        }
        request.extend_from_slice(&buffer[..n]);
    }
    let request = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return respond(&mut stream, "400 Bad Request", b"Bad Request"),
    };
    let mut lines = request.split("\r\n");
    let first = lines.next().unwrap_or("");
    let hosts: Vec<_> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect();
    if hosts.len() != 1 || hosts[0] != expected_host {
        return respond(&mut stream, "400 Bad Request", b"Bad Request");
    }
    match first {
        "GET / HTTP/1.1" => respond(&mut stream, "200 OK", PAGE),
        _ => respond(&mut stream, "404 Not Found", b"Not Found"),
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    println!("http://{address}/");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let _ = handle(stream, &address.to_string());
            }
            Err(error) => eprintln!("로컬 연결 오류: {error}"),
        }
    }
    Ok(())
}
