//! Минимальный HTTPS GET (HTTP/1.1, `Connection: close`) поверх tokio-rustls с
//! проверкой сертификата по корням Mozilla (webpki-roots).
//!
//! Нужен ровно для двух вещей — скачать список CF-доменов с GitHub и сделать
//! DoH-запрос — и заменяет reqwest (+hyper, tower, url, serde), который весил
//! заметную часть нативной библиотеки.

use once_cell::sync::Lazy;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

static VERIFIED_TLS: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
});

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// GET `https://{host}{path}`. `connect_ip` — куда подключаться вместо DNS
/// (DoH по IP, закреплённый IP GitHub); SNI и `Host` всегда `host`.
pub async fn https_get(
    host: &str,
    connect_ip: Option<IpAddr>,
    path: &str,
    accept: &str,
    timeout: Duration,
    max_body: usize,
) -> Result<HttpResponse, String> {
    tokio::time::timeout(timeout, get_inner(host, connect_ip, path, accept, max_body))
        .await
        .map_err(|_| "timeout".to_string())?
}

async fn get_inner(
    host: &str,
    connect_ip: Option<IpAddr>,
    path: &str,
    accept: &str,
    max_body: usize,
) -> Result<HttpResponse, String> {
    let tcp = match connect_ip {
        Some(ip) => TcpStream::connect((ip, 443)).await,
        None => crate::ws::connect_tcp_ipv4_first(host, 443).await,
    }
    .map_err(|e| format!("connect: {}", e))?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("bad host: {}", e))?;
    let mut tls = TlsConnector::from(VERIFIED_TLS.clone())
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls: {}", e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: tg-ws-proxy\r\nAccept: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        path, host, accept
    );
    tls.write_all(request.as_bytes()).await.map_err(|e| format!("write: {}", e))?;

    let mut raw = Vec::with_capacity(8 * 1024);
    let mut buf = [0u8; 8192];
    loop {
        if let Some(done) = parse_response(&raw, max_body)? {
            return Ok(done);
        }
        let n = match tls.read(&mut buf).await {
            Ok(n) => n,
            // Многие серверы закрывают TCP без close_notify — для
            // `Connection: close` это обычный конец ответа.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(format!("read: {}", e)),
        };
        if n == 0 {
            return finish_at_eof(&raw, max_body);
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_HEADER_BYTES + max_body + 64 * 1024 {
            return Err("response too large".to_string());
        }
    }
}

struct Head {
    status: u16,
    body_start: usize,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_head(raw: &[u8]) -> Result<Option<Head>, String> {
    let end = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p,
        None if raw.len() > MAX_HEADER_BYTES => return Err("headers too large".to_string()),
        None => return Ok(None),
    };
    let text = std::str::from_utf8(&raw[..end]).map_err(|_| "non-utf8 headers".to_string())?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {}", status_line))?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    Ok(Some(Head {
        status,
        body_start: end + 4,
        content_length,
        chunked,
    }))
}

/// Готовый ответ, если он уже целиком в `raw`.
fn parse_response(raw: &[u8], max_body: usize) -> Result<Option<HttpResponse>, String> {
    let Some(head) = parse_head(raw)? else { return Ok(None) };
    let body = &raw[head.body_start..];
    if head.chunked {
        return match decode_chunked(body)? {
            Some(decoded) if decoded.len() > max_body => Err("body too large".to_string()),
            Some(decoded) => Ok(Some(HttpResponse {
                status: head.status,
                body: decoded,
            })),
            None => Ok(None),
        };
    }
    if let Some(len) = head.content_length {
        if len > max_body {
            return Err("body too large".to_string());
        }
        if body.len() >= len {
            return Ok(Some(HttpResponse {
                status: head.status,
                body: body[..len].to_vec(),
            }));
        }
    }
    Ok(None)
}

fn finish_at_eof(raw: &[u8], max_body: usize) -> Result<HttpResponse, String> {
    let head = parse_head(raw)?.ok_or_else(|| "connection closed before headers".to_string())?;
    if head.chunked || head.content_length.is_some() {
        return parse_response(raw, max_body)?.ok_or_else(|| "truncated body".to_string());
    }
    let body = &raw[head.body_start..];
    if body.len() > max_body {
        return Err("body too large".to_string());
    }
    Ok(HttpResponse {
        status: head.status,
        body: body.to_vec(),
    })
}

/// Тело `Transfer-Encoding: chunked`; None — ещё не всё пришло.
fn decode_chunked(mut data: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
        let size_text = std::str::from_utf8(&data[..line_end]).map_err(|_| "bad chunk size".to_string())?;
        let size_hex = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| format!("bad chunk size: {}", size_hex))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// IPv4-адреса из DoH JSON (`application/dns-json`): значения `"data"`,
/// которые парсятся как IPv4 (у CNAME там имя — оно отсеется).
pub fn doh_json_ipv4(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.find("\"data\"") {
        rest = &rest[pos + 6..];
        let Some(colon) = rest.find(':') else { break };
        let after = rest[colon + 1..].trim_start();
        let Some(stripped) = after.strip_prefix('"') else { continue };
        let Some(end) = stripped.find('"') else { break };
        let value = &stripped[..end];
        if value.parse::<std::net::Ipv4Addr>().is_ok() {
            out.push(value.to_string());
        }
        rest = &stripped[end..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhelloEXTRA";
        let r = parse_response(raw, 100).unwrap().unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", 100)
            .unwrap()
            .is_none());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", 100).is_err());
    }

    #[test]
    fn chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n";
        let r = parse_response(raw, 100).unwrap().unwrap();
        assert_eq!(r.body, b"Wikipedia");
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi";
        assert!(parse_response(partial, 100).unwrap().is_none());
    }

    #[test]
    fn eof_delimited_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\nnope";
        assert!(parse_response(raw, 100).unwrap().is_none());
        let r = finish_at_eof(raw, 100).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (404, &b"nope"[..]));
        assert!(finish_at_eof(b"HTTP/1.1 200", 100).is_err());
    }

    #[test]
    fn doh_json_extracts_only_ipv4() {
        let body = r#"{"Status":0,"Answer":[{"name":"a.example.","type":5,"TTL":60,"data":"b.example."},
            {"name":"b.example.","type":1,"TTL":60,"data":"104.16.1.2"},{"type":1,"data": "104.16.1.3"}]}"#;
        assert_eq!(doh_json_ipv4(body), vec!["104.16.1.2", "104.16.1.3"]);
        assert!(doh_json_ipv4(r#"{"Status":3}"#).is_empty());
    }
}
