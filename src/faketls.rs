//! Fake TLS (ee-secret) — порт proxy/fake_tls.py из Flowseal/tg-ws-proxy v1.12:
//! защита от повторного ClientHello, ServerHello с зеркалированием key share
//! и шифронабора клиента, размер первой зашифрованной записи по профилю
//! сайта маскировки.

use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const TLS_VERSION_12: [u8; 2] = [0x03, 0x03];

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519MLKEM768: u16 = 0x11ec;
const X25519_KEY_LEN: usize = 32;
const X25519MLKEM768_CLIENT_SHARE_LEN: usize = 1216;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

// TLS 1.3 шифронаборы в порядке, в котором их обычно выбирает сервер.
const CIPHER_PREFERENCE: [u16; 3] = [0x1301, 0x1303, 0x1302];

// Границы единственной ApplicationData-записи после CCS. Без профиля сайта
// держимся около 64 байт (как telemt), далеко от 1900-2100 байт
// классического MTProxy, по которым его узнаёт DPI.
const APPDATA_MIN: usize = 64;
const FALLBACK_APPDATA_RANGE: (usize, usize) = (64, 160);

const SERVER_HELLO_DELAY_MS: (u64, u64) = (8, 24);
const PROFILE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

// ClientHello проходит проверку времени TIMESTAMP_TOLERANCE в обе стороны,
// плюс секунда на усечение часов — столько и помним client_random.
const REPLAY_WINDOW: Duration = Duration::from_secs((2 * TIMESTAMP_TOLERANCE + 1) as u64);
const REPLAY_CACHE_SIZE: usize = 65536;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
const SH_RANDOM_OFF: usize = 11;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

// ---------------------------------------------------------------------------
// Replay cache
// ---------------------------------------------------------------------------

/// client_random принятых ClientHello. Повтор — признак активного зонда:
/// ответив на него, мы бы выдали, что это прокси, а не сайт маскировки.
/// Один кеш на процесс — переживает перезапуск прокси.
struct ReplayCache {
    window: Duration,
    size: usize,
    order: VecDeque<([u8; 32], Instant)>,
    seen: HashSet<[u8; 32]>,
}

impl ReplayCache {
    fn new(window: Duration, size: usize) -> Self {
        ReplayCache {
            window,
            size,
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    fn first_seen_at(&mut self, client_random: &[u8; 32], now: Instant) -> bool {
        while let Some((key, expiry)) = self.order.front() {
            if *expiry > now {
                break;
            }
            self.seen.remove(key);
            self.order.pop_front();
        }
        if self.seen.contains(client_random) {
            return false;
        }
        if self.order.len() >= self.size {
            if let Some((key, _)) = self.order.pop_front() {
                self.seen.remove(&key);
            }
        }
        self.order.push_back((*client_random, now + self.window));
        self.seen.insert(*client_random);
        true
    }
}

static REPLAY_CACHE: Lazy<parking_lot::Mutex<ReplayCache>> =
    Lazy::new(|| parking_lot::Mutex::new(ReplayCache::new(REPLAY_WINDOW, REPLAY_CACHE_SIZE)));

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
pub struct ClientHelloInfo {
    pub cipher_suites: HashSet<u16>,
    /// named group -> длина key_exchange
    pub key_shares: HashMap<u16, usize>,
}

pub fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], [u8; 32], i64)> {
    // 5 (record hdr) + 6 (hs type+len+version) + 32 (random) = 43
    if data.len() < 43 || data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    // Сравнение без раннего выхода (hmac.compare_digest).
    let diff = expected[..28]
        .iter()
        .zip(&client_random[..28])
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }
    Some((client_random, session_id, timestamp))
}

fn be16(data: &[u8], pos: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize)
}

/// Предлагаемые клиентом шифронаборы и группы key_share. На битом входе —
/// пустой результат (ответ X25519 / TLS_AES_128_GCM_SHA256).
pub fn parse_client_hello(data: &[u8]) -> ClientHelloInfo {
    fn parse(data: &[u8]) -> Option<ClientHelloInfo> {
        let mut pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN;
        pos += 1 + *data.get(pos)? as usize;

        let suites_len = be16(data, pos)?;
        pos += 2;
        let suites_end = pos + suites_len;
        if suites_end > data.len() {
            return None;
        }
        let mut info = ClientHelloInfo::default();
        let mut off = pos;
        while off + 1 < suites_end {
            info.cipher_suites.insert(be16(data, off)? as u16);
            off += 2;
        }
        pos = suites_end;
        pos += 1 + *data.get(pos)? as usize;

        let ext_total = be16(data, pos)?;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());
        while pos + 4 <= ext_end {
            let ext_type = be16(data, pos)? as u16;
            let ext_len = be16(data, pos + 2)?;
            pos += 4;
            if ext_type == EXT_KEY_SHARE && pos + 2 <= ext_end {
                let shares_end = (pos + 2 + be16(data, pos)?).min(ext_end);
                let mut off = pos + 2;
                while off + 4 <= shares_end {
                    let group = be16(data, off)? as u16;
                    let key_len = be16(data, off + 2)?;
                    off += 4 + key_len;
                    if off <= shares_end {
                        info.key_shares.entry(group).or_insert(key_len);
                    }
                }
            }
            pos += ext_len;
        }
        Some(info)
    }
    parse(data).unwrap_or_default()
}

fn select_cipher_suite(info: &ClientHelloInfo) -> u16 {
    CIPHER_PREFERENCE
        .iter()
        .copied()
        .find(|s| info.cipher_suites.contains(s))
        .unwrap_or(CIPHER_PREFERENCE[0])
}

fn x25519_public_key() -> [u8; X25519_KEY_LEN] {
    // Настоящие публичные ключи — элементы поля < 2^255: старший бит сброшен.
    let mut key = [0u8; X25519_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key[X25519_KEY_LEN - 1] &= 0x7f;
    key
}

/// Зеркалим гибридную пост-квантовую группу, если клиент её предложил —
/// так делают современные браузеры и серверы; ключи из неё никто не выводит.
fn server_key_share(info: &ClientHelloInfo) -> (u16, Vec<u8>) {
    if info.key_shares.get(&GROUP_X25519MLKEM768) == Some(&X25519MLKEM768_CLIENT_SHARE_LEN) {
        let mut kx = vec![0u8; MLKEM768_CIPHERTEXT_LEN];
        rand::thread_rng().fill_bytes(&mut kx);
        kx.extend_from_slice(&x25519_public_key());
        return (GROUP_X25519MLKEM768, kx);
    }
    (GROUP_X25519, x25519_public_key().to_vec())
}

// Размер первой зашифрованной записи сайта маскировки (0 — профиля нет).
static PROFILED_APPDATA_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn set_profiled_appdata_len(length: Option<usize>) {
    let v = length.map_or(0, |l| l.clamp(APPDATA_MIN, TLS_APPDATA_MAX));
    PROFILED_APPDATA_LEN.store(v, Ordering::Relaxed);
}

fn appdata_len() -> usize {
    match PROFILED_APPDATA_LEN.load(Ordering::Relaxed) {
        0 => rand::thread_rng().gen_range(FALLBACK_APPDATA_RANGE.0..=FALLBACK_APPDATA_RANGE.1),
        n => n,
    }
}

/// ServerHello + CCS + одна ApplicationData. Клиенты Telegram разбирают ровно
/// эти три записи и проверяют HMAC по всем, поэтому форма фиксирована, а
/// размеры могут меняться.
pub fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    info: &ClientHelloInfo,
) -> Vec<u8> {
    let (group, key_exchange) = server_key_share(info);
    let mut extensions = Vec::with_capacity(16 + key_exchange.len());
    extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());
    extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&((4 + key_exchange.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_exchange);

    let mut body = Vec::with_capacity(80 + extensions.len());
    body.extend_from_slice(&TLS_VERSION_12);
    body.extend_from_slice(&[0u8; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&select_cipher_suite(info).to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(0x02);
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);

    let app_len = appdata_len();
    let mut response = Vec::with_capacity(5 + message.len() + CCS_FRAME.len() + 5 + app_len);
    response.push(TLS_RECORD_HANDSHAKE);
    response.extend_from_slice(&TLS_VERSION_12);
    response.extend_from_slice(&(message.len() as u16).to_be_bytes());
    response.extend_from_slice(&message);
    response.extend_from_slice(&CCS_FRAME);
    response.push(TLS_RECORD_APPDATA);
    response.extend_from_slice(&TLS_VERSION_12);
    response.extend_from_slice(&(app_len as u16).to_be_bytes());
    let start = response.len();
    response.resize(start + app_len, 0);
    rand::thread_rng().fill_bytes(&mut response[start..]);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    response
}

// ---------------------------------------------------------------------------
// Профиль сайта маскировки
// ---------------------------------------------------------------------------

/// Длина первой ApplicationData-записи в первом ответе сервера.
/// None — нужно больше данных, Some(0) — такой записи там быть не может.
pub fn first_appdata_record_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let rtype = data[pos];
        let rec_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        if rtype == TLS_RECORD_APPDATA {
            return Some(rec_len);
        }
        if rtype != TLS_RECORD_HANDSHAKE && rtype != TLS_RECORD_CCS {
            return Some(0);
        }
        pos += 5 + rec_len;
    }
    None
}

fn probe_client_hello(domain: &str) -> Option<Vec<u8>> {
    let mut provider = rustls::crypto::ring::default_provider();
    // Как set_x25519() в оригинале: только X25519.
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::ws::NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name = rustls_pki_types::ServerName::try_from(domain.to_string()).ok()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).ok()?;
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).ok()? == 0 {
            break;
        }
    }
    Some(out)
}

/// fake_tls.probe_appdata_len: размер первой зашифрованной записи, которую
/// сайт маскировки шлёт после ServerHello. Читается только сырой первый
/// ответ, TLS-рукопожатие не завершается.
pub async fn probe_appdata_len(domain: &str, port: u16) -> Option<usize> {
    let client_hello = probe_client_hello(domain)?;
    let probe = async {
        let mut sock = TcpStream::connect((domain, port)).await?;
        sock.write_all(&client_hello).await?;
        let mut flight = Vec::with_capacity(16384);
        let mut buf = [0u8; 16384];
        loop {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                return Ok(None);
            }
            flight.extend_from_slice(&buf[..n]);
            if let Some(len) = first_appdata_record_len(&flight) {
                return Ok(if len == 0 { None } else { Some(len) });
            }
            if flight.len() > 256 * 1024 {
                return Ok(None);
            }
        }
    };
    match tokio::time::timeout(PROFILE_PROBE_TIMEOUT, probe).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let e: std::io::Error = e;
            log_warn(&format!("Fake TLS profile: cannot probe {}:{}: {}", domain, port, e));
            None
        }
        Err(_) => {
            log_warn(&format!("Fake TLS profile: cannot probe {}:{}: timeout", domain, port));
            None
        }
    }
}

// ---------------------------------------------------------------------------
// TLS record framing (cancel-safe state machines)
// ---------------------------------------------------------------------------

fn wrap_tls_record_into(out: &mut Vec<u8>, chunk: &[u8]) {
    out.push(TLS_RECORD_APPDATA);
    out.extend_from_slice(&TLS_VERSION_12);
    out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    out.extend_from_slice(chunk);
}

/// Достаёт payload из ApplicationData-записей, пропуская CCS. Всё состояние
/// хранится в структуре, поэтому отменённый/повторный poll ничего не теряет.
struct TlsRecordReader<R> {
    inner: R,
    hdr: [u8; 5],
    hdr_filled: usize,
    read_left: usize,
    skip_left: usize,
    eof: bool,
}

impl<R> TlsRecordReader<R> {
    fn new(inner: R) -> Self {
        TlsRecordReader {
            inner,
            hdr: [0; 5],
            hdr_filled: 0,
            read_left: 0,
            skip_left: 0,
            eof: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TlsRecordReader<R> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.eof || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.read_left > 0 {
                let want = this.read_left.min(buf.remaining());
                let mut sub = buf.take(want);
                match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = sub.filled().len();
                        if n == 0 {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        // SAFETY: sub — окно в незаполненную часть buf; n байт
                        // в нём проинициализированы и заполнены poll_read.
                        unsafe { buf.assume_init(n) };
                        buf.advance(n);
                        this.read_left -= n;
                        return Poll::Ready(Ok(()));
                    }
                }
            }
            if this.skip_left > 0 {
                let mut junk = [0u8; 256];
                let want = this.skip_left.min(junk.len());
                let mut rb = ReadBuf::new(&mut junk[..want]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        this.skip_left -= n;
                        continue;
                    }
                }
            }
            // Заголовок записи.
            let mut rb = ReadBuf::new(&mut this.hdr[this.hdr_filled..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.hdr_filled += n;
                }
            }
            if this.hdr_filled < 5 {
                continue;
            }
            this.hdr_filled = 0;
            let rtype = this.hdr[0];
            let rec_len = u16::from_be_bytes([this.hdr[3], this.hdr[4]]) as usize;
            match rtype {
                TLS_RECORD_CCS => this.skip_left = rec_len,
                TLS_RECORD_APPDATA => this.read_left = rec_len,
                _ => {
                    // Alert/прочее — клиент закрывает соединение.
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

/// Заворачивает исходящие данные в ApplicationData-записи. Принятый кусок
/// сразу отражается в счётчике, а недописанный хвост записи держится в
/// `pending` и дописывается следующими poll_write/poll_flush/poll_shutdown.
struct TlsRecordWriter<W> {
    inner: W,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl<W> TlsRecordWriter<W> {
    fn new(inner: W) -> Self {
        TlsRecordWriter {
            inner,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }
}

impl<W: AsyncWrite + Unpin> TlsRecordWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "faketls: write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TlsRecordWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &buf[..buf.len().min(TLS_APPDATA_MAX)];
        wrap_tls_record_into(&mut this.pending, chunk);
        // Пытаемся сразу отправить; что не влезло — допишется позже.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let record_len = u16::from_be_bytes([hdr_rest[2], hdr_rest[3]]) as usize;
    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.push(first);
    client_hello.extend_from_slice(&hdr_rest);
    client_hello.resize(5 + record_len, 0);
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut client_hello[5..])).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let verified = verify_client_hello(&client_hello, secret);
    // Записанный hello валиден несколько минут; ответ на повтор выдал бы
    // активному зонду, что здесь прокси, а не сайт маскировки.
    let replayed = match &verified {
        Some((client_random, _, _)) => !REPLAY_CACHE.lock().first_seen_at(client_random, Instant::now()),
        None => false,
    };

    let (client_random, session_id, ts) = match verified {
        Some(v) if !replayed => v,
        _ => {
            log_debug(&format!(
                "[{}] Fake TLS {} (size={} rec={}) -> masking",
                label,
                if replayed { "hello replayed" } else { "verify failed" },
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            return None;
        }
    };

    log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
    let info = parse_client_hello(&client_hello);
    let server_hello = build_server_hello(secret, &client_random, &session_id, &info);
    let delay = rand::thread_rng().gen_range(SERVER_HELLO_DELAY_MS.0..=SERVER_HELLO_DELAY_MS.1);
    tokio::time::sleep(Duration::from_millis(delay)).await;
    if conn.write_all(&server_hello).await.is_err() {
        return None;
    }
    let _ = conn.flush().await;

    let (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) = tokio::io::split(conn);
    Some(FakeTlsStream {
        read: Box::new(TlsRecordReader::new(r)),
        write: Box::new(TlsRecordWriter::new(w)),
    })
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let mut upstream =
        match tokio::time::timeout(MASKING_CONNECT_TIMEOUT, TcpStream::connect((domain, 443u16))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log_warn(&format!("[{}] masking: cannot connect to {}:443: {}", label, domain, e));
                return;
            }
            Err(_) => {
                log_warn(&format!("[{}] masking: cannot connect to {}:443: timeout", label, domain));
                return;
            }
        };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS.connections_masked.fetch_add(1, Ordering::Relaxed);

    if upstream.write_all(&initial).await.is_err() {
        return;
    }
    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);
    let up = async {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    };
    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    // PROFILED_APPDATA_LEN — глобальный; тесты, которые его трогают, идут по очереди.
    static PROFILE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn make_client_hello(secret: &[u8], ts: u32, extensions: &[u8]) -> Vec<u8> {
        // Handshake body: version, random, session id, suites, compression, extensions.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(32);
        body.extend_from_slice(&[0x42u8; 32]);
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x02, 0x13, 0x03, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        // client_random = HMAC(secret, hello с нулевым random), последние 4
        // байта XOR с timestamp — так делает клиент Telegram.
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&rec);
        let digest = mac.finalize().into_bytes();
        let mut random = [0u8; 32];
        random.copy_from_slice(&digest);
        let tsb = ts.to_le_bytes();
        for i in 0..4 {
            random[28 + i] ^= tsb[i];
        }
        rec[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + 32].copy_from_slice(&random);
        rec
    }

    fn key_share_ext(groups: &[(u16, usize)]) -> Vec<u8> {
        let mut shares = Vec::new();
        for (g, len) in groups {
            shares.extend_from_slice(&g.to_be_bytes());
            shares.extend_from_slice(&(*len as u16).to_be_bytes());
            shares.extend(std::iter::repeat(0xAB).take(*len));
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        ext.extend_from_slice(&shares);
        ext
    }

    fn now_ts() -> u32 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
    }

    #[test]
    fn verify_accepts_valid_and_rejects_wrong_secret_or_time() {
        let secret = [7u8; 16];
        let hello = make_client_hello(&secret, now_ts(), &key_share_ext(&[(GROUP_X25519, 32)]));
        let (_, sid, _) = verify_client_hello(&hello, &secret).expect("valid hello");
        assert_eq!(sid, [0x42u8; 32]);
        assert!(verify_client_hello(&hello, &[8u8; 16]).is_none());
        let old = make_client_hello(&secret, now_ts() - 1000, &[]);
        assert!(verify_client_hello(&old, &secret).is_none());
    }

    #[test]
    fn parse_and_mirror_key_share() {
        let secret = [1u8; 16];
        let hello = make_client_hello(
            &secret,
            now_ts(),
            &key_share_ext(&[(GROUP_X25519MLKEM768, X25519MLKEM768_CLIENT_SHARE_LEN), (GROUP_X25519, 32)]),
        );
        let info = parse_client_hello(&hello);
        assert!(info.cipher_suites.contains(&0x1301));
        assert_eq!(info.key_shares.get(&GROUP_X25519), Some(&32));
        assert_eq!(select_cipher_suite(&info), 0x1301);

        let (client_random, session_id, _) = verify_client_hello(&hello, &secret).unwrap();
        let _guard = PROFILE_LOCK.lock();
        set_profiled_appdata_len(None);
        let sh = build_server_hello(&secret, &client_random, &session_id, &info);
        // ServerHello: key_share с гибридной группой, длина 1088+32.
        let sh_len = u16::from_be_bytes([sh[3], sh[4]]) as usize;
        let hello_rec = &sh[..5 + sh_len];
        let pos = hello_rec
            .windows(2)
            .rposition(|w| w == EXT_KEY_SHARE.to_be_bytes())
            .expect("key_share ext");
        let group = u16::from_be_bytes([hello_rec[pos + 4], hello_rec[pos + 5]]);
        let kx_len = u16::from_be_bytes([hello_rec[pos + 6], hello_rec[pos + 7]]) as usize;
        assert_eq!(group, GROUP_X25519MLKEM768);
        assert_eq!(kx_len, MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN);
        // Затем CCS и одна ApplicationData-запись в fallback-диапазоне.
        let rest = &sh[5 + sh_len..];
        assert_eq!(&rest[..6], &CCS_FRAME);
        assert_eq!(rest[6], TLS_RECORD_APPDATA);
        let app_len = u16::from_be_bytes([rest[9], rest[10]]) as usize;
        assert!((FALLBACK_APPDATA_RANGE.0..=FALLBACK_APPDATA_RANGE.1).contains(&app_len));
        assert_eq!(rest.len(), 6 + 5 + app_len);
        // server_random = HMAC(secret, client_random + ответ с нулевым random).
        let mut zeroed = sh.clone();
        zeroed[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].fill(0);
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&client_random);
        mac.update(&zeroed);
        assert_eq!(&mac.finalize().into_bytes()[..], &sh[SH_RANDOM_OFF..SH_RANDOM_OFF + 32]);
    }

    #[test]
    fn profiled_appdata_len_is_clamped() {
        let _guard = PROFILE_LOCK.lock();
        set_profiled_appdata_len(Some(10));
        assert_eq!(appdata_len(), APPDATA_MIN);
        set_profiled_appdata_len(Some(1_000_000));
        assert_eq!(appdata_len(), TLS_APPDATA_MAX);
        set_profiled_appdata_len(Some(300));
        assert_eq!(appdata_len(), 300);
        set_profiled_appdata_len(None);
    }

    #[test]
    fn plain_x25519_without_hybrid_offer() {
        let info = parse_client_hello(&make_client_hello(&[3u8; 16], now_ts(), &key_share_ext(&[(GROUP_X25519, 32)])));
        let (g, kx) = server_key_share(&info);
        assert_eq!(g, GROUP_X25519);
        assert_eq!(kx.len(), 32);
        assert_eq!(kx[31] & 0x80, 0);
        // Мусор на входе не паникует.
        let empty = parse_client_hello(&[0x16, 0x03, 0x01]);
        assert!(empty.cipher_suites.is_empty());
    }

    #[test]
    fn replay_cache_rejects_repeat_and_expires() {
        let mut cache = ReplayCache::new(Duration::from_secs(10), 2);
        let t0 = Instant::now();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert!(cache.first_seen_at(&a, t0));
        assert!(!cache.first_seen_at(&a, t0));
        assert!(cache.first_seen_at(&b, t0));
        // Переполнение вытесняет самый старый.
        assert!(cache.first_seen_at(&c, t0));
        assert!(cache.first_seen_at(&a, t0));
        // После окна — снова "впервые".
        assert!(cache.first_seen_at(&b, t0 + Duration::from_secs(11)));
    }

    #[test]
    fn first_appdata_record_detection() {
        let mut flight = vec![TLS_RECORD_HANDSHAKE, 3, 3, 0, 2, 0xAA, 0xBB];
        assert_eq!(first_appdata_record_len(&flight), None);
        flight.extend_from_slice(&CCS_FRAME);
        flight.extend_from_slice(&[TLS_RECORD_APPDATA, 3, 3, 0x01, 0x2c]);
        assert_eq!(first_appdata_record_len(&flight), Some(300));
        assert_eq!(first_appdata_record_len(&[0x15, 3, 3, 0, 2]), Some(0));
    }

    #[tokio::test]
    async fn record_reader_survives_fragmented_records() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut reader = TlsRecordReader::new(rx);
        let writer = tokio::spawn(async move {
            let mut wire = Vec::new();
            wire.extend_from_slice(&CCS_FRAME);
            wrap_tls_record_into(&mut wire, b"hello ");
            wrap_tls_record_into(&mut wire, b"world");
            // Отдаём по байту, чтобы заголовки записей резались между poll.
            for b in wire {
                tx.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn record_writer_handles_partial_writes() {
        let (tx, rx) = tokio::io::duplex(1024);
        let mut writer = TlsRecordWriter::new(tx);
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let reader = tokio::spawn(async move {
            let mut r = TlsRecordReader::new(rx);
            let mut out = Vec::new();
            r.read_to_end(&mut out).await.unwrap();
            out
        });
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);
        assert_eq!(reader.await.unwrap(), expected);
    }
}
