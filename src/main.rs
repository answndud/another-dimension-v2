mod anchor;

pub mod channel;

mod contacts;

mod fsutil;
mod hex;

pub mod history;

mod identity;

mod random;

pub mod relay;

mod session;

use base64::engine::general_purpose::STANDARD as BASE64;

use base64::Engine;

use identity::Identity;

use relay::{InviteCode, RelayError, RelayRendezvous, RelaySession, RelayUpdate, DEFAULT_RELAY};

use session::SessionStore;

use std::collections::{HashMap, HashSet, VecDeque};

use std::fs::File;

use std::io::{self, BufRead, Read, Seek, Write};

use std::net::{SocketAddr, TcpListener, TcpStream};

use std::path::PathBuf;

#[cfg(target_os = "macos")]
use std::process::Command;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};

use std::sync::{Arc, Mutex};

use std::thread;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

fn main() -> io::Result<()> {
    if std::env::args().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "실행 옵션은 지원하지 않습니다. 연결 모드는 앱 설정에서 선택하세요.",
        ));
    }
    // Say where the data lives, and warn if an earlier run kept some elsewhere.
    match history::data_directory() {
        Ok(directory) => {
            println!("데이터 위치: {}", directory.display());
            if cfg!(target_os = "macos") {
                if let Some(warning) =
                    history::legacy_data_warning(&directory, &history::source_tree_data_directory())
                {
                    eprintln!("{warning}");
                }
            }
        }
        Err(error) => {
            eprintln!("데이터 위치를 사용할 수 없습니다: {error}");
            return Err(error);
        }
    }
    match history::History::cleanup_abandoned_backup_transfers() {
        Ok(removed) if removed > 0 => {
            eprintln!("이전 실행의 백업 전송 임시 파일 {removed}개 작업 공간을 정리했습니다.")
        }
        Ok(_) => {}
        Err(error) => eprintln!("백업 전송 임시 파일 정리 실패: {error}"),
    }
    let settings = load_settings()?;
    let tor_socks = settings.tor_socks;
    let active_relays = settings.relays.clone();
    let notifications_enabled = Arc::new(AtomicBool::new(settings.notifications));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let state = Arc::new(Mutex::new(State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: SessionStore::default(),
        identity: None,
        chats: HashMap::new(),
        history_deletions: HashMap::new(),
        active_history_deletions: HashSet::new(),
        history_import_active: false,
        tor_socks,
        active_relays,
        settings,
        notifications_enabled,
        last_notification: Arc::new(Mutex::new(None)),
    }));
    println!("http://{address}/");
    if let Some(proxy) = tor_socks {
        println!("Tor/SOCKS 전용 모드: {proxy}; 프록시 실패 시 직접 연결하지 않습니다.");
    } else {
        println!("일반 연결 모드");
    }
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
    serve(
        listener,
        address.to_string(),
        state,
        Arc::new(AtomicBool::new(false)),
    );
    Ok(())
}

mod api;
mod chat_worker;
mod history_sync;
mod http;
mod restore;
#[cfg(test)]
mod send_tests;
mod settings;
mod state;

use api::*;
use chat_worker::*;
use history_sync::*;
use http::*;
use restore::*;
use settings::*;
use state::*;
