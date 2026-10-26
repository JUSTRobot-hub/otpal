//! Temporary LAN endpoint so a phone can hand over a photographed QR code.
//!
//! It serves the phone page and accepts one kind of POST. The payload is
//! end-to-end encrypted by the phone page with a key that never reaches this
//! code (it lives in the URL fragment), so this server only forwards opaque
//! text to the window. It stops when the dialog closes or after ten minutes.

use std::{
    io::{self, ErrorKind, Read, Write},
    net::{IpAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, State};

const MAX_BODY: usize = 256 * 1024;
const MAX_HEADER: usize = 16 * 1024;
const LIFETIME: Duration = Duration::from_secs(600);
const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'";

#[derive(Default)]
pub struct Receiver(Mutex<Option<Arc<AtomicBool>>>);

/// The address of the interface that would be used to reach the LAN. Connecting
/// a UDP socket sends nothing; it only makes the OS pick a route.
fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// Starts the receiver and returns the URL the phone should open (without the key).
#[tauri::command]
pub fn start_receiver(app: AppHandle, state: State<Receiver>, token: String) -> Result<String, String> {
    if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid token".into());
    }
    let ip = lan_ip().ok_or("No network connection found")?;
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let stop = Arc::new(AtomicBool::new(false));
    if let Some(old) = state.0.lock().unwrap().replace(stop.clone()) {
        old.store(true, Ordering::SeqCst);
    }

    let url_token = token.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + LIFETIME;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    let app = app.clone();
                    let token = token.clone();
                    thread::spawn(move || {
                        let _ = handle(stream, &app, &token);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
    });
    Ok(format!("http://{ip}:{port}/s/{url_token}/"))
}

#[tauri::command]
pub fn stop_receiver(state: State<Receiver>) {
    if let Some(flag) = state.0.lock().unwrap().take() {
        flag.store(true, Ordering::SeqCst);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn respond(stream: &mut TcpStream, status: u16, mime: &str, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {CSP}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn serve(stream: &mut TcpStream, app: &AppHandle, path: &str) -> io::Result<()> {
    match app.asset_resolver().get(path.to_string()) {
        Some(asset) => respond(stream, 200, &asset.mime_type, &asset.bytes),
        None => respond(stream, 404, "text/plain", b"not found"),
    }
}

fn handle(mut stream: TcpStream, app: &AppHandle, token: &str) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER {
            return respond(&mut stream, 413, "text/plain", b"too large");
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("");
    let path = request.next().unwrap_or("").split('?').next().unwrap_or("");
    let content_length = lines
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") { v.trim().parse::<usize>().ok() } else { None }
        })
        .next()
        .unwrap_or(0);

    let prefix = format!("/s/{token}/");
    let Some(rest) = path.strip_prefix(prefix.as_str()) else {
        return respond(&mut stream, 404, "text/plain", b"not found");
    };

    match (method, rest) {
        ("GET", "") => serve(&mut stream, app, "phone.html"),
        ("GET", asset) if asset.starts_with("assets/") && !asset.contains("..") && !asset.contains('\\') => {
            serve(&mut stream, app, asset)
        }
        ("POST", "submit") => {
            if content_length == 0 || content_length > MAX_BODY {
                return respond(&mut stream, 413, "text/plain", b"bad size");
            }
            let mut body = buf[header_end + 4..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(content_length);
            let looks_like_base64 = body.len() == content_length
                && body.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
            if !looks_like_base64 {
                return respond(&mut stream, 400, "text/plain", b"bad payload");
            }
            // Only base64 characters passed the check above, so this is valid UTF-8.
            let _ = app.emit("phone-payload", String::from_utf8_lossy(&body).to_string());
            respond(&mut stream, 200, "text/plain", b"ok")
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}
