//! HTTP/2-транспорт медиа через Cloudflare — порт proxy/cf_h2.py из
//! Flowseal/tg-ws-proxy v1.12 (MIT), по мотивам src/cf_h2.rs из
//! valnesfjord/tg-ws-proxy-rs (MIT).
//!
//! Зачем: большие ответы `upload.getFile` через CF WebSocket на Android
//! обрываются (Flowseal/tg-ws-proxy#1655, #1695). HTTP-эндпоинт Telegram
//! (`/api` за тем же CF-доменом) принимает голые MTProto-пакеты без
//! транспортной обёртки и обфускации: каждый POST несёт пакет клиента и даёт
//! серверу одно «окно» для ответа. Все медиа-соединения к DC идут
//! мультиплексом в одном HTTP/2-соединении (lane) с Cloudflare.
//!
//! Ответ на POST может содержать только подтверждение, а сам RPC-ответ
//! придёт позже — для него нужно ещё одно окно. Поэтому последний небольшой
//! зашифрованный пакет повторяется (replay): Telegram отбрасывает дубликат
//! msg_id, а запрос служит окном приёма. Пакеты создания ключа
//! (auth_key_id = 0) и большие загрузки не повторяются.
//!
//! Отличия от оригинала:
//! - GOAWAY от Cloudflare (плановая ротация соединения, код 0) не рвёт
//!   медиа: начатые запросы дорабатывают на старом соединении, новые идут в
//!   новое, а отвергнутый до обработки запрос повторяется один раз
//!   (в оригинале любой GOAWAY закрывал все каналы, Flowseal/tg-ws-proxy#1700).
//! - Лимиты буферов меньше (телефон), без подробной трассировки запросов.

use crate::config::*;
use crate::crypto::TrackedStream;
use crate::{ldebug, linfo, lwarn};
use bytes::Bytes;
use h2::client::SendRequest;
use http::{header, Method, Request};
use once_cell::sync::Lazy;
use parking_lot::Mutex as SyncMutex;
use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, Id as TaskId, JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

pub const MAX_PACKET: usize = 4 * 1024 * 1024;
const MAX_PLAIN_PADDING: usize = 256;
const MAX_CHANNEL_REQUESTS: usize = 8;
const MAX_CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_LANE_REQUESTS: usize = 64;
const MAX_LANE_BYTES: usize = 16 * 1024 * 1024;
const MAX_LANE_REPLY_BYTES: usize = 16 * 1024 * 1024;
const DOMAIN_COOLDOWN: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
const REPLAY_IDLE: Duration = Duration::from_secs(1);
const REPLAY_REQUEST: Duration = Duration::from_secs(3);
const REPLAY_CHECK: Duration = Duration::from_millis(250);
const REPLAY_MAX_AGE: Duration = Duration::from_secs(30);
const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const MAX_CHANNEL_REPLAYS: usize = 2;
const REPLAY_SLOT: Duration = Duration::from_secs(30);
const REPLAY_RETRY: Duration = Duration::from_secs(2);
const REPLAY_MAX_ATTEMPTS: u32 = 3;
const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const UPLOAD_CHUNK: usize = 16 * 1024;
const NATIVE_QUEUE: usize = 16;
const CLIENT_READ_BUF: usize = 64 * 1024;
/// Соединение lane без ответов дольше этого после сна телефона считается
/// подозрительным: при включении экрана новые запросы идут в свежее.
const LANE_STALE_AFTER: Duration = Duration::from_secs(30);

/// Медиа через CF идёт HTTP/2 (proxy/config.py::h2_enabled).
pub fn h2_enabled() -> bool {
    CF_H2_MEDIA.load(Ordering::Relaxed)
        && CFPROXY_ENABLED.load(Ordering::Relaxed)
        && !DISABLE_SECURE.load(Ordering::Relaxed)
        && !FORCE_TEST_DC.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Подключение lane
// ---------------------------------------------------------------------------

pub trait H2Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> H2Io for T {}
pub type BoxIo = Box<dyn H2Io>;
pub type DialFuture = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// Как открыть новое соединение для lane (в тестах — к локальному h2c).
pub type DialFn = Arc<dyn Fn() -> DialFuture + Send + Sync>;

static H2_TLS: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(32);
    Arc::new(cfg)
});

/// TLS (с проверкой сертификата, ALPN h2) к `host`:443 с дроблением
/// ClientHello, как у CF WebSocket.
fn cf_dialer(host: String) -> DialFn {
    Arc::new(move || -> DialFuture {
        let host = host.clone();
        Box::pin(async move {
            let dpi = crate::ws::CF_DPI_SPLIT.load(Ordering::Relaxed);
            let tls = crate::ws::tls_connect_cf(&host, H2_TLS.clone(), dpi, SETUP_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                return Err("CF did not negotiate HTTP/2".to_string());
            }
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

fn monotonic_ms() -> u64 {
    (now_monotonic() * 1000.0) as u64
}

fn cf_ray(headers: &http::HeaderMap) -> String {
    headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.chars()
                .take(64)
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect()
        })
        .unwrap_or_else(|| "-".to_string())
}

#[derive(Debug)]
pub enum PostError {
    /// MTProto transport error (-404 и т.п.): клиент должен его получить.
    Transport(i32, String),
    /// Сетевая/HTTP-ошибка: хост уходит на паузу, канал закрывается.
    Http(String),
    /// Исчерпан локальный лимит буферов (домен не виноват).
    Buffer(String),
}

impl std::fmt::Display for PostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostError::Transport(code, why) => write!(f, "transport error {} ({})", code, why),
            PostError::Http(why) | PostError::Buffer(why) => f.write_str(why),
        }
    }
}

/// Отметки запроса, которые читает цикл канала.
#[derive(Default)]
pub struct ReqState {
    /// Тело ушло целиком (мс монотонного времени, 0 — ещё нет).
    sent_ms: AtomicU64,
    /// Пришли заголовки ответа, читается тело.
    receiving: AtomicBool,
}

impl ReqState {
    fn mark_sent(&self) {
        self.sent_ms.store(monotonic_ms().max(1), Ordering::Relaxed);
    }

    fn sent_ago(&self, now_ms: u64) -> Option<Duration> {
        match self.sent_ms.load(Ordering::Relaxed) {
            0 => None,
            t => Some(Duration::from_millis(now_ms.saturating_sub(t))),
        }
    }

    fn receiving(&self) -> bool {
        self.receiving.load(Ordering::Relaxed)
    }
}

pub struct LanePermits {
    _slot: OwnedSemaphorePermit,
    upload: OwnedSemaphorePermit,
}

struct Conn {
    sender: SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    id: u64,
}

/// Одно HTTP/2-соединение к kwsN.<домен> (переподключается по требованию).
pub struct Lane {
    pub host: String,
    pub id: u64,
    url: String,
    dial: DialFn,
    conn: tokio::sync::Mutex<Option<Conn>>,
    conn_seq: AtomicU64,
    requests: Arc<Semaphore>,
    upload_bytes: Arc<Semaphore>,
    reply_bytes: AtomicUsize,
    failed_until: SyncMutex<Option<Instant>>,
    last_rx_ms: AtomicU64,
    channels: AtomicUsize,
}

impl Lane {
    pub fn new(host: &str, id: u64, dial: DialFn) -> Lane {
        Lane {
            host: host.to_string(),
            id,
            url: format!("https://{}/api", host),
            dial,
            conn: tokio::sync::Mutex::new(None),
            conn_seq: AtomicU64::new(0),
            requests: Arc::new(Semaphore::new(MAX_LANE_REQUESTS)),
            upload_bytes: Arc::new(Semaphore::new(MAX_LANE_BYTES)),
            reply_bytes: AtomicUsize::new(0),
            failed_until: SyncMutex::new(None),
            last_rx_ms: AtomicU64::new(monotonic_ms()),
            channels: AtomicUsize::new(0),
        }
    }

    fn cooling(&self) -> bool {
        self.failed_until.lock().is_some_and(|t| Instant::now() < t)
    }

    fn mark_failed(&self) {
        *self.failed_until.lock() = Some(Instant::now() + DOMAIN_COOLDOWN);
    }

    pub fn connections_opened(&self) -> u64 {
        self.conn_seq.load(Ordering::Relaxed)
    }

    async fn open_conn(&self) -> Result<Conn, String> {
        let io = (self.dial)().await?;
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_RECEIVE_WINDOW)
            .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
            .max_header_list_size(16 * 1024)
            .enable_push(false)
            .handshake::<BoxIo, Bytes>(io)
            .await
            .map_err(|e| format!("HTTP/2 handshake: {}", e))?;
        let id = self.conn_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let dead = Arc::new(AtomicBool::new(false));
        let flag = dead.clone();
        let (lane_id, host) = (self.id, self.host.clone());
        tokio::spawn(async move {
            let res = connection.await;
            flag.store(true, Ordering::Relaxed);
            match res {
                Ok(()) => ldebug!("H2 lane={} conn={} host={} closed", lane_id, id, host),
                Err(e) => ldebug!("H2 lane={} conn={} host={} closed: {}", lane_id, id, host, e),
            }
        });
        ldebug!("H2 lane={} conn={} host={} open", self.id, id, self.host);
        self.last_rx_ms.store(monotonic_ms(), Ordering::Relaxed);
        Ok(Conn { sender, dead, id })
    }

    /// Текущее соединение; `avoid` — соединение, которое только что
    /// отвергло запрос (GOAWAY/разрыв): вместо него открывается новое.
    async fn sender(&self, avoid: Option<u64>) -> Result<(SendRequest<Bytes>, u64), String> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref() {
            if !c.dead.load(Ordering::Relaxed) && Some(c.id) != avoid {
                return Ok((c.sender.clone(), c.id));
            }
        }
        // Старое соединение не закрываем: начатые на нём запросы дорабатывают.
        *slot = None;
        let conn = tokio::time::timeout(SETUP_TIMEOUT, self.open_conn())
            .await
            .map_err(|_| "HTTP/2 connect timed out".to_string())??;
        let out = (conn.sender.clone(), conn.id);
        *slot = Some(conn);
        Ok(out)
    }

    /// После сна телефона соединение могло умереть молча (NAT забыл его).
    /// Если ответов давно не было, новые запросы пойдут в свежее соединение.
    fn retire_if_stale(&self) {
        let idle = monotonic_ms().saturating_sub(self.last_rx_ms.load(Ordering::Relaxed));
        if Duration::from_millis(idle) < LANE_STALE_AFTER {
            return;
        }
        if let Ok(mut slot) = self.conn.try_lock() {
            if slot.take().is_some() {
                ldebug!("H2 lane={} host={}: idle connection retired after wake", self.id, self.host);
            }
        }
    }

    /// HEAD /api: убедиться, что домен проксирует HTTP-эндпоинт Telegram.
    pub async fn preflight(&self) -> Result<u16, String> {
        let (sender, _) = self.sender(None).await?;
        let mut sender = sender.ready().await.map_err(|e| format!("HTTP/2: {}", e))?;
        let req = Request::builder()
            .method(Method::HEAD)
            .uri(self.url.as_str())
            .body(())
            .map_err(|e| e.to_string())?;
        let (response, _) = sender
            .send_request(req, true)
            .map_err(|e| format!("HTTP/2: {}", e))?;
        let response = response.await.map_err(|e| format!("HTTP/2: {}", e))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) || status == 405 || status == 501 {
            self.last_rx_ms.store(monotonic_ms(), Ordering::Relaxed);
            Ok(status)
        } else {
            Err(format!(
                "CF /api preflight HTTP {} cf_ray={}",
                status,
                cf_ray(response.headers())
            ))
        }
    }

    /// Места под запрос в lane без ожидания (ждёт цикл канала по таймеру).
    fn try_permits(&self, len: usize) -> Option<LanePermits> {
        let slot = self.requests.clone().try_acquire_owned().ok()?;
        let upload = self
            .upload_bytes
            .clone()
            .try_acquire_many_owned(len.max(1) as u32)
            .ok()?;
        Some(LanePermits { _slot: slot, upload })
    }

    pub async fn post(self: Arc<Self>, body: Bytes, st: Arc<ReqState>, permits: LanePermits) -> Result<Vec<u8>, PostError> {
        let LanePermits { _slot, upload } = permits;
        let res = match tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(body, &st, upload)).await {
            Ok(r) => r,
            Err(_) => Err(PostError::Http("HTTP/2 request timed out".to_string())),
        };
        if matches!(res, Err(PostError::Http(_))) {
            self.mark_failed();
        }
        res
    }

    async fn exchange(&self, body: Bytes, st: &ReqState, upload: OwnedSemaphorePermit) -> Result<Vec<u8>, PostError> {
        let mut upload = Some(upload);
        let mut avoid = None;
        let response = loop {
            let (sender, conn_id) = self.sender(avoid).await.map_err(PostError::Http)?;
            match self.send_once(sender, body.clone(), st, &mut upload).await {
                Ok(r) => break r,
                // Запрос не дошёл до обработки (GOAWAY, REFUSED_STREAM, мёртвое
                // соединение): один повтор в новом соединении. Повтор безопасен —
                // Telegram отбрасывает дубликаты msg_id.
                Err(e) if avoid.is_none() && retryable(&e) => {
                    ldebug!(
                        "H2 lane={} conn={} refused a request ({}); retrying on a new connection",
                        self.id,
                        conn_id,
                        e
                    );
                    avoid = Some(conn_id);
                }
                Err(e) => return Err(PostError::Http(format!("HTTP/2: {}", e))),
            }
        };
        drop(upload);

        let status = response.status().as_u16();
        if matches!(status, 403 | 404 | 429 | 444) {
            return Err(PostError::Transport(
                -(status as i32),
                format!("HTTP {} cf_ray={}", status, cf_ray(response.headers())),
            ));
        }
        if status != 200 {
            return Err(PostError::Http(format!(
                "CF /api HTTP {} cf_ray={}",
                status,
                cf_ray(response.headers())
            )));
        }
        let headers = response.headers();
        let header_str = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
        if header_str(header::CONTENT_TYPE).to_ascii_lowercase().contains("text/html") {
            return Err(PostError::Http("CF /api returned HTML instead of MTProto".to_string()));
        }
        let encoding = header_str(header::CONTENT_ENCODING);
        if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            return Err(PostError::Http(format!("CF /api returned {} response", encoding)));
        }
        let declared = match headers.get(header::CONTENT_LENGTH) {
            None => None,
            Some(v) => match v.to_str().ok().and_then(|v| v.trim().parse::<usize>().ok()) {
                Some(n) if n <= MAX_PACKET => Some(n),
                Some(_) => return Err(PostError::Http("H2 response Content-Length exceeds packet bound".to_string())),
                None => return Err(PostError::Http("invalid H2 response Content-Length".to_string())),
            },
        };

        struct Receiving<'a>(&'a ReqState, &'a AtomicUsize, usize);
        impl Drop for Receiving<'_> {
            fn drop(&mut self) {
                self.0.receiving.store(false, Ordering::Relaxed);
                self.1.fetch_sub(self.2, Ordering::Relaxed);
            }
        }
        st.receiving.store(true, Ordering::Relaxed);
        let mut guard = Receiving(st, &self.reply_bytes, 0);
        let mut recv = response.into_body();
        let mut content = Vec::with_capacity(declared.unwrap_or(0));
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.map_err(|e| PostError::Http(format!("HTTP/2 body: {}", e)))?;
            let n = chunk.len();
            if content.len() + n > MAX_PACKET {
                return Err(PostError::Http("H2 response exceeds packet bound".to_string()));
            }
            if self.reply_bytes.fetch_add(n, Ordering::Relaxed) + n > MAX_LANE_REPLY_BYTES {
                self.reply_bytes.fetch_sub(n, Ordering::Relaxed);
                return Err(PostError::Buffer("H2 lane response buffers exceeded bound".to_string()));
            }
            guard.2 += n;
            content.extend_from_slice(&chunk);
            let _ = recv.flow_control().release_capacity(n);
            self.last_rx_ms.store(monotonic_ms(), Ordering::Relaxed);
        }
        drop(guard);
        self.last_rx_ms.store(monotonic_ms(), Ordering::Relaxed);
        if declared.is_some_and(|n| n != content.len()) {
            return Err(PostError::Http("incomplete H2 response body".to_string()));
        }
        if !content.len().is_multiple_of(4) {
            return Err(PostError::Http("CF /api response is not an aligned MTProto packet".to_string()));
        }
        if content.len() == 4 {
            let code = i32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            if code < 0 {
                return Err(PostError::Transport(code, "HTTP 200 payload".to_string()));
            }
        }
        Ok(content)
    }

    async fn send_once(
        &self,
        sender: SendRequest<Bytes>,
        mut body: Bytes,
        st: &ReqState,
        upload: &mut Option<OwnedSemaphorePermit>,
    ) -> Result<http::Response<h2::RecvStream>, h2::Error> {
        let mut sender = sender.ready().await?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(self.url.as_str())
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CONTENT_LENGTH, body.len())
            .body(())
            .expect("static request parts");
        let (response, mut stream) = sender.send_request(req, false)?;
        while !body.is_empty() {
            stream.reserve_capacity(body.len().min(UPLOAD_CHUNK));
            let capacity = match poll_fn(|cx| stream.poll_capacity(cx)).await {
                Some(r) => r?,
                // Сервер закрыл поток раньше — исход скажет ответ.
                None => break,
            };
            let take = capacity.min(body.len()).min(UPLOAD_CHUNK);
            if take == 0 {
                continue;
            }
            let chunk = body.split_to(take);
            stream.send_data(chunk, body.is_empty())?;
        }
        upload.take();
        st.mark_sent();
        response.await
    }
}

fn retryable(e: &h2::Error) -> bool {
    e.is_go_away() || e.is_io() || e.reason() == Some(h2::Reason::REFUSED_STREAM)
}

// ---------------------------------------------------------------------------
// Пул lane по хостам (proxy/cf_h2.py::CfH2Pool)
// ---------------------------------------------------------------------------

pub struct Channel {
    pub lane: Arc<Lane>,
    pub id: u64,
}

impl Channel {
    pub fn new(lane: Arc<Lane>, id: u64) -> Channel {
        lane.channels.fetch_add(1, Ordering::Relaxed);
        Channel { lane, id }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.lane.channels.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct H2Pool {
    lanes: SyncMutex<HashMap<String, Arc<Lane>>>,
    host_locks: SyncMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    failed_until: SyncMutex<HashMap<String, Instant>>,
    setup_retry_after: SyncMutex<HashMap<i32, Instant>>,
    next_lane: AtomicU64,
    next_channel: AtomicU64,
    generation: AtomicU64,
}

pub static H2: Lazy<H2Pool> = Lazy::new(H2Pool::default);

impl H2Pool {
    /// Канал к медиа-DC через HTTP/2 или None (тогда — CF WebSocket).
    pub async fn open(&self, dc: i32, label: &str) -> Option<Channel> {
        if self
            .setup_retry_after
            .lock()
            .get(&dc)
            .is_some_and(|t| Instant::now() < *t)
        {
            return None;
        }
        match tokio::time::timeout(SETUP_TIMEOUT, self.open_inner(dc, label)).await {
            Ok(channel) => channel,
            Err(_) => {
                self.setup_retry_after
                    .lock()
                    .insert(dc, Instant::now() + DOMAIN_COOLDOWN);
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                lwarn!(
                    "[{}] H2 DC{} setup timed out; using WS for {:.0}s",
                    label,
                    dc,
                    DOMAIN_COOLDOWN.as_secs_f64()
                );
                None
            }
        }
    }

    async fn open_inner(&self, dc: i32, label: &str) -> Option<Channel> {
        if !DC_DEFAULT_IPS.contains_key(&dc) {
            lwarn!("[{}] H2 unsupported DC{} -> existing WS route", label, dc);
            return None;
        }
        let generation = self.generation.load(Ordering::Relaxed);
        let bases = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
        for base in bases {
            let host = format!("kws{}.{}", dc, base);
            if crate::cfproxy::cf_tls_in_cooldown(&host)
                || crate::cfproxy::cfproxy_429_cooldown_remaining(&base) > Duration::ZERO
            {
                continue;
            }
            let lock = self.host_locks.lock().entry(host.clone()).or_default().clone();
            let _guard = lock.lock().await;
            let existing = self.lanes.lock().get(&host).cloned();
            let host_failed = self
                .failed_until
                .lock()
                .get(&host)
                .is_some_and(|t| Instant::now() < *t);
            if host_failed || existing.as_ref().is_some_and(|l| l.cooling()) {
                continue;
            }
            let lane = match existing {
                Some(lane) => lane,
                None => {
                    let id = self.next_lane.fetch_add(1, Ordering::Relaxed) + 1;
                    let lane = Arc::new(Lane::new(&host, id, cf_dialer(host.clone())));
                    match lane.preflight().await {
                        Ok(status) => {
                            ldebug!("H2 lane={} ready host={} status={}", id, host, status);
                        }
                        Err(e) => {
                            STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                            self.failed_until
                                .lock()
                                .insert(host.clone(), Instant::now() + DOMAIN_COOLDOWN);
                            lwarn!("[{}] H2 lane={} preflight failed host={}: {}", label, id, host, e);
                            continue;
                        }
                    }
                    if self.generation.load(Ordering::Relaxed) != generation {
                        // Сеть сменилась, пока шёл preflight.
                        return None;
                    }
                    self.lanes.lock().insert(host.clone(), lane.clone());
                    lane
                }
            };
            let channel = Channel::new(lane.clone(), self.next_channel.fetch_add(1, Ordering::Relaxed) + 1);
            crate::balancer::BALANCER.write().update_domain_for_dc(dc, &base);
            linfo!(
                "[{}] ROUTE DC{} media -> H2 lane={} channel={} host={} channels={}",
                label,
                dc,
                lane.id,
                channel.id,
                host,
                lane.channels.load(Ordering::Relaxed)
            );
            return Some(channel);
        }
        ldebug!("[{}] H2 DC{} unavailable; using WS", label, dc);
        None
    }

    /// Смена сети или остановка: соединения старой сети больше не нужны.
    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.lanes.lock().clear();
        self.failed_until.lock().clear();
        self.setup_retry_after.lock().clear();
    }

    /// Включился экран: паузы, накопленные во сне, снимаются, а молчавшие
    /// соединения заменяются свежими.
    pub fn wake(&self) {
        self.failed_until.lock().clear();
        self.setup_retry_after.lock().clear();
        for lane in self.lanes.lock().values() {
            *lane.failed_until.lock() = None;
            lane.retire_if_stale();
        }
    }
}

// ---------------------------------------------------------------------------
// Транспортная обёртка нативного клиента
// ---------------------------------------------------------------------------

struct PacketReader<R> {
    reader: R,
    dec: TrackedStream,
    buf: Vec<u8>,
    off: usize,
    filled: usize,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    fn new(reader: R, dec: TrackedStream) -> Self {
        PacketReader {
            reader,
            dec,
            buf: vec![0u8; CLIENT_READ_BUF],
            off: 0,
            filled: 0,
        }
    }

    async fn read_exact(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        let mut written = 0;
        while written < dst.len() {
            if self.off == self.filled {
                let n = self.reader.read(&mut self.buf).await?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                self.dec.xor(&mut self.buf[..n]);
                self.off = 0;
                self.filled = n;
            }
            let take = (dst.len() - written).min(self.filled - self.off);
            dst[written..written + take].copy_from_slice(&self.buf[self.off..self.off + take]);
            written += take;
            self.off += take;
        }
        Ok(())
    }

    /// Следующий голый MTProto-пакет клиента (без длины и паддинга).
    async fn packet(&mut self, proto: u32) -> Result<Bytes, String> {
        let io = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                "eof".to_string()
            } else {
                format!("client: {:?}", e.kind())
            }
        };
        let mut header = [0u8; 4];
        let length = if proto == PROTO_TAG_ABRIDGED {
            self.read_exact(&mut header[..1]).await.map_err(io)?;
            let words = if header[0] & 0x7f == 0x7f {
                self.read_exact(&mut header[..3]).await.map_err(io)?;
                (u32::from_le_bytes([header[0], header[1], header[2], 0])) as usize
            } else {
                (header[0] & 0x7f) as usize
            };
            words * 4
        } else {
            self.read_exact(&mut header).await.map_err(io)?;
            (u32::from_le_bytes(header) & 0x7fff_ffff) as usize
        };
        let padding = if proto == PROTO_TAG_SECURE { MAX_PLAIN_PADDING } else { 0 };
        if !(24..=MAX_PACKET + padding).contains(&length) {
            return Err(format!("native packet length outside supported range: {}", length));
        }
        let mut body = vec![0u8; length];
        self.read_exact(&mut body).await.map_err(io)?;
        strip_padding(&mut body, proto)?;
        Ok(Bytes::from(body))
    }
}

/// Паддинг padded-intermediate и проверки proxy/cf_h2.py::_read_packet.
fn strip_padding(body: &mut Vec<u8>, proto: u32) -> Result<(), String> {
    if proto == PROTO_TAG_SECURE {
        let length = body.len();
        let (packet_length, max_padding) = if body[..8] == [0u8; 8] {
            let declared = u32::from_le_bytes([body[16], body[17], body[18], body[19]]) as usize;
            (20usize.saturating_add(declared), MAX_PLAIN_PADDING)
        } else {
            (24 + (length - 24) / 16 * 16, 15)
        };
        if packet_length < 24 || packet_length > length || length - packet_length > max_padding {
            return Err(format!(
                "invalid padded native packet: frame={} packet={} limit={}",
                length, packet_length, max_padding
            ));
        }
        body.truncate(packet_length);
    }
    if !body.len().is_multiple_of(4) || body.len() > MAX_PACKET {
        return Err("invalid native packet alignment or size".to_string());
    }
    Ok(())
}

/// Ответ сервера в транспортной обёртке клиента (proxy/cf_h2.py::_encode_reply).
pub fn encode_reply(body: &[u8], proto: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    if proto == PROTO_TAG_ABRIDGED {
        let words = body.len() / 4;
        if words < 0x7f {
            out.push(words as u8);
        } else {
            out.push(0x7f);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(body);
    } else {
        let pad = if proto == PROTO_TAG_SECURE {
            rand::thread_rng().gen_range(0..4usize)
        } else {
            0
        };
        out.extend_from_slice(&((body.len() + pad) as u32).to_le_bytes());
        out.extend_from_slice(body);
        if pad > 0 {
            let mut p = [0u8; 3];
            rand::thread_rng().fill_bytes(&mut p[..pad]);
            out.extend_from_slice(&p[..pad]);
        }
    }
    out
}

enum NativeMsg {
    Reply(Vec<u8>),
    Error(i32),
}

#[derive(Default)]
struct NativeState {
    /// Байты ответов в очереди и в записи (обратное давление на replay).
    queued: AtomicUsize,
    /// Остаток очереди выбросить (канал закрывается).
    drop_pending: AtomicBool,
    failed: AtomicBool,
    progress: Notify,
    down: AtomicU64,
}

async fn native_writer<W>(mut w: W, mut enc: TrackedStream, proto: u32, mut rx: mpsc::Receiver<NativeMsg>, st: Arc<NativeState>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(msg) = rx.recv().await {
        match msg {
            NativeMsg::Reply(body) => {
                let len = body.len();
                if !st.drop_pending.load(Ordering::Relaxed) && !st.failed.load(Ordering::Relaxed) {
                    let mut out = encode_reply(&body, proto);
                    enc.xor(&mut out);
                    if w.write_all(&out).await.is_err() || w.flush().await.is_err() {
                        st.failed.store(true, Ordering::Relaxed);
                    } else {
                        st.down.fetch_add(len as u64, Ordering::Relaxed);
                        STATS.bytes_down.fetch_add(len as i64, Ordering::Relaxed);
                    }
                }
                st.queued.fetch_sub(len, Ordering::Relaxed);
                st.progress.notify_one();
            }
            NativeMsg::Error(code) => {
                if !st.failed.load(Ordering::Relaxed) {
                    let mut out = encode_reply(&code.to_le_bytes(), proto);
                    enc.xor(&mut out);
                    if w.write_all(&out).await.is_ok() && w.flush().await.is_ok() {
                        st.down.fetch_add(4, Ordering::Relaxed);
                        STATS.bytes_down.fetch_add(4, Ordering::Relaxed);
                    }
                }
                break;
            }
        }
    }
    let _ = w.shutdown().await;
}

// ---------------------------------------------------------------------------
// Канал: один нативный клиент поверх lane (proxy/cf_h2.py::_HttpChannel)
// ---------------------------------------------------------------------------

struct Req {
    len: usize,
    replay: bool,
    seq: Option<u64>,
    st: Arc<ReqState>,
    abort: AbortHandle,
}

/// Зашифрованный пакет, который можно повторить ради окна приёма.
struct Entry {
    seq: u64,
    sent_at: Instant,
    body: Bytes,
    attempts: u32,
    last_attempt: Option<Instant>,
    pending: Option<TaskId>,
    originals: Vec<TaskId>,
    retired: bool,
    reply_id: Option<Vec<u8>>,
}

impl Entry {
    fn replayed(&self) -> bool {
        self.last_attempt.is_some() || self.attempts > 0
    }
}

enum End {
    Stopped,
    Client(String),
    Transport(i32),
    Error(String),
    Idle,
}

struct ChannelLoop {
    lane: Arc<Lane>,
    label: String,
    channel_id: u64,
    tasks: JoinSet<Result<Vec<u8>, PostError>>,
    reqs: HashMap<TaskId, Req>,
    pending_bytes: usize,
    history: Vec<Entry>,
    replay_key: Option<[u8; 8]>,
    staged: Option<(Bytes, Instant)>,
    requests: u64,
    replay_requests: u64,
    replay_rotations: u64,
    capacity_rotations: u64,
    up: u64,
    last_progress: Instant,
    last_native_send: Instant,
    native: Arc<NativeState>,
    wtx: mpsc::Sender<NativeMsg>,
}

impl ChannelLoop {
    fn can_admit(&self, len: usize) -> bool {
        self.reqs.len() < MAX_CHANNEL_REQUESTS && self.pending_bytes + len <= MAX_CHANNEL_BYTES
    }

    fn native_backpressure(&self) -> bool {
        self.native.queued.load(Ordering::Relaxed) > 0
    }

    fn receiving(&self, id: &TaskId) -> bool {
        self.reqs.get(id).is_some_and(|r| r.st.receiving())
    }

    fn is_latest(&self, e: &Entry) -> bool {
        self.history.last().is_some_and(|l| l.seq == e.seq)
    }

    fn entry_mut(&mut self, seq: u64) -> Option<&mut Entry> {
        self.history.iter_mut().find(|e| e.seq == seq)
    }

    fn overdue(&self, e: &Entry, now_ms: u64) -> bool {
        e.retired
            || e.originals.iter().any(|id| {
                self.reqs.get(id).is_some_and(|r| {
                    !r.st.receiving() && r.st.sent_ago(now_ms).is_some_and(|ago| ago >= REPLAY_REQUEST)
                })
            })
    }

    fn replay_limit(&self, e: &Entry) -> u32 {
        if !e.originals.is_empty() || e.retired || self.is_latest(e) {
            REPLAY_MAX_ATTEMPTS
        } else {
            0
        }
    }

    /// proxy/cf_h2.py::_replay_blocker: None — пакет пора повторить.
    fn replay_blocker(&self, e: &Entry, now: Instant, now_ms: u64) -> Option<&'static str> {
        if now.saturating_duration_since(e.sent_at) > REPLAY_MAX_AGE {
            return Some("expired");
        }
        if e.attempts >= self.replay_limit(e) {
            return Some("budget-used");
        }
        if self.native_backpressure() {
            return Some("native-backpressure");
        }
        if e.originals.iter().any(|id| self.receiving(id)) {
            return Some("original-body");
        }
        if e.pending.is_some_and(|id| self.receiving(&id)) {
            return Some("replay-body");
        }
        if e.replayed() && e.last_attempt.is_some_and(|t| now.saturating_duration_since(t) < REPLAY_RETRY) {
            return Some("backoff-or-progress");
        }
        if self.overdue(e, now_ms) {
            return None;
        }
        if !self.is_latest(e) || self.reqs.keys().any(|id| Some(*id) != e.pending) {
            return Some("receiver-active");
        }
        if e.replayed() && now.saturating_duration_since(self.last_progress) < REPLAY_IDLE {
            return Some("backoff-or-progress");
        }
        None
    }

    fn spawn(&mut self, body: Bytes, permits: LanePermits, replay: bool, seq: Option<u64>) -> TaskId {
        let len = body.len();
        let st = Arc::new(ReqState::default());
        let abort = self.tasks.spawn(self.lane.clone().post(body, st.clone(), permits));
        let id = abort.id();
        self.requests += 1;
        self.up += len as u64;
        self.pending_bytes += len;
        STATS.bytes_up.fetch_add(len as i64, Ordering::Relaxed);
        self.reqs.insert(id, Req { len, replay, seq, st, abort });
        id
    }

    /// Запомнить зашифрованный пакет для replay (proxy/cf_h2.py::_remember_packet).
    fn remember(&mut self, body: &Bytes, now: Instant) -> Option<u64> {
        let key: [u8; 8] = body.get(..8)?.try_into().ok()?;
        if key == [0u8; 8] {
            return None;
        }
        if self.replay_key != Some(key) {
            self.history.clear();
            self.replay_key = Some(key);
        }
        if body.len() > REPLAY_HISTORY_BYTES {
            return None;
        }
        if let Some(e) = self.history.iter().find(|e| e.body == *body) {
            return Some(e.seq);
        }
        let seq = self.requests + 1;
        self.history.push(Entry {
            seq,
            sent_at: now,
            body: body.clone(),
            attempts: 0,
            last_attempt: None,
            pending: None,
            originals: Vec::new(),
            retired: false,
            reply_id: None,
        });
        Some(seq)
    }

    fn trim_history(&mut self, now: Instant) {
        let mut retained: usize = self.history.iter().map(|e| e.body.len()).sum();
        while self.history.len() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES {
            let victim = self
                .history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired
                            && e.attempts < REPLAY_MAX_ATTEMPTS
                            && now.saturating_duration_since(e.sent_at) <= REPLAY_MAX_AGE)
                })
                .unwrap_or(0);
            retained -= self.history.remove(victim).body.len();
        }
    }

    /// Отправить пакет клиента, если есть место в канале и lane.
    fn try_admit(&mut self) -> Result<(), End> {
        let Some((body, since)) = self.staged.as_ref() else {
            return Ok(());
        };
        let len = body.len();
        if self.can_admit(len) {
            if let Some(permits) = self.lane.try_permits(len) {
                let (body, _) = self.staged.take().expect("staged packet");
                let now = Instant::now();
                self.last_native_send = now;
                let seq = self.remember(&body, now);
                let id = self.spawn(body, permits, false, seq);
                if let Some(seq) = seq {
                    if let Some(e) = self.entry_mut(seq) {
                        e.originals.push(id);
                    }
                    self.trim_history(now);
                }
                return Ok(());
            }
        }
        if since.elapsed() >= REQUEST_TIMEOUT {
            return Err(End::Error("upload waited too long for an HTTP/2 slot".to_string()));
        }
        Ok(())
    }

    fn send_replay(&mut self, seq: u64, now: Instant, now_ms: u64) -> bool {
        if self.staged.is_some() {
            return false;
        }
        let Some(idx) = self.history.iter().position(|e| e.seq == seq) else {
            return false;
        };
        let len = self.history[idx].body.len();
        if !self.can_admit(len) {
            return false;
        }
        let e = &self.history[idx];
        if e.pending.is_some() || self.replay_blocker(e, now, now_ms).is_some() {
            return false;
        }
        let Some(permits) = self.lane.try_permits(len) else {
            return false;
        };
        let body = e.body.clone();
        let id = self.spawn(body, permits, true, Some(seq));
        self.replay_requests += 1;
        let e = &mut self.history[idx];
        e.attempts += 1;
        e.last_attempt = Some(now);
        e.pending = Some(id);
        true
    }

    /// Учёт завершения/отмены запроса (proxy/cf_h2.py::_finish_request).
    fn finish(&mut self, id: TaskId) -> Option<Req> {
        let req = self.reqs.remove(&id)?;
        self.pending_bytes -= req.len;
        for e in self.history.iter_mut() {
            e.originals.retain(|x| *x != id);
            if e.pending == Some(id) {
                e.pending = None;
            }
        }
        Some(req)
    }

    fn cancel(&mut self, id: TaskId) {
        if let Some(req) = self.finish(id) {
            req.abort.abort();
        }
    }

    /// Освободить место для пакета клиента, отменив запрос, который сервер
    /// держит дольше REPLAY_REQUEST (proxy/cf_h2.py::_make_upload_room).
    fn make_upload_room(&mut self, now: Instant, now_ms: u64) {
        let Some((body, _)) = self.staged.as_ref() else {
            return;
        };
        if self.can_admit(body.len()) {
            return;
        }
        let mut candidates: Vec<(TaskId, bool, Duration)> = self
            .reqs
            .iter()
            .filter(|(_, r)| !r.st.receiving())
            .filter_map(|(id, r)| r.st.sent_ago(now_ms).map(|ago| (*id, r.replay, ago)))
            .filter(|(_, _, ago)| *ago >= REPLAY_REQUEST)
            .collect();
        // Сначала повторы, потом самые давние.
        candidates.sort_by_key(|(_, replay, ago)| (!*replay, std::cmp::Reverse(*ago)));
        for (id, replay, _) in candidates {
            if !replay {
                let Some(e) = self.history.iter_mut().find(|e| e.originals.contains(&id)) else {
                    continue;
                };
                if now.saturating_duration_since(e.sent_at) > REPLAY_MAX_AGE {
                    continue;
                }
                e.retired = true;
            }
            ldebug!(
                "H2 CAPACITY lane={} channel={} released a held request (replay={}) for an upload",
                self.lane.id,
                self.channel_id,
                replay
            );
            self.cancel(id);
            self.capacity_rotations += 1;
            return;
        }
    }

    /// Повторить пакет, если пора (proxy/cf_h2.py::_recover).
    fn recover(&mut self) {
        if self.native_backpressure() || self.history.is_empty() {
            return;
        }
        let now = Instant::now();
        let now_ms = monotonic_ms();
        let mut order: Vec<(bool, i64, u64)> = self
            .history
            .iter()
            .map(|e| {
                let overdue = self.overdue(e, now_ms);
                (!overdue, if overdue { e.seq as i64 } else { -(e.seq as i64) }, e.seq)
            })
            .collect();
        order.sort();
        for (_, _, seq) in order {
            let Some(e) = self.history.iter().find(|e| e.seq == seq) else {
                continue;
            };
            if self.replay_blocker(e, now, now_ms).is_some() {
                continue;
            }
            let mut replace = e.pending;
            if replace.is_none() && self.reqs.values().filter(|r| r.replay).count() >= MAX_CHANNEL_REPLAYS {
                replace = self
                    .reqs
                    .iter()
                    .find(|(_, r)| r.replay && !r.st.receiving())
                    .map(|(id, _)| *id);
                if replace.is_none() {
                    continue;
                }
            }
            if let Some(rid) = replace {
                let Some(r) = self.reqs.get(&rid) else {
                    continue;
                };
                if r.st.receiving() || r.st.sent_ago(now_ms).is_none_or(|ago| ago < REPLAY_SLOT) {
                    continue;
                }
                self.cancel(rid);
                self.replay_rotations += 1;
            }
            self.send_replay(seq, now, now_ms);
            break;
        }
    }

    fn on_joined(&mut self, joined: Result<(TaskId, Result<Vec<u8>, PostError>), JoinError>) -> Option<End> {
        let (id, result) = match joined {
            Ok(v) => v,
            Err(e) => {
                // Отменённые нами запросы уже учтены в cancel().
                self.finish(e.id())?;
                return Some(End::Error(format!("request task failed: {}", e)));
            }
        };
        // None — запрос отменили, но он успел завершиться: ответ всё равно
        // доставляем, ошибку отменённого игнорируем.
        let req = self.finish(id);
        if req.is_none() && result.is_err() {
            return None;
        }
        let (req_len, req_replay, req_seq) = req.map_or((0, false, None), |r| (r.len, r.replay, r.seq));
        match result {
            Ok(reply) => {
                self.last_progress = Instant::now();
                if reply.is_empty() {
                    return None;
                }
                if let Some(e) = req_seq.and_then(|s| self.entry_mut(s)) {
                    let rid = &reply[..reply.len().min(24)];
                    if e.reply_id.as_deref() != Some(rid) {
                        e.reply_id = Some(rid.to_vec());
                        e.attempts = 0;
                    }
                }
                let len = reply.len();
                if self.native.queued.load(Ordering::Relaxed) + len > MAX_CHANNEL_BYTES {
                    return Some(End::Error("H2 client response queue exceeded bound".to_string()));
                }
                self.native.queued.fetch_add(len, Ordering::Relaxed);
                if self.wtx.try_send(NativeMsg::Reply(reply)).is_err() {
                    self.native.queued.fetch_sub(len, Ordering::Relaxed);
                    return Some(End::Error("H2 client response queue exceeded bound".to_string()));
                }
                None
            }
            Err(PostError::Transport(code, why)) => {
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                lwarn!(
                    "[{}] H2 lane={} channel={} host={} MTProto transport error={} ({}) bytes={} replay={}; reporting to client",
                    self.label,
                    self.lane.id,
                    self.channel_id,
                    self.lane.host,
                    code,
                    why,
                    req_len,
                    req_replay
                );
                Some(End::Transport(code))
            }
            Err(e) => {
                STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                lwarn!(
                    "[{}] H2 lane={} channel={} request failed: {}; closing native channel, reconnect may select another domain",
                    self.label,
                    self.lane.id,
                    self.channel_id,
                    e
                );
                Some(End::Error(e.to_string()))
            }
        }
    }

    async fn run(&mut self, urx: &mut mpsc::Receiver<Result<Bytes, String>>, session: &CancellationToken) -> End {
        let mut tick = tokio::time::interval(REPLAY_CHECK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let native = self.native.clone();
        loop {
            if let Err(end) = self.try_admit() {
                return end;
            }
            let want_upload = self.staged.is_none();
            tokio::select! {
                _ = session.cancelled() => return End::Stopped,
                msg = urx.recv(), if want_upload => match msg {
                    Some(Ok(packet)) => self.staged = Some((packet, Instant::now())),
                    Some(Err(e)) => return End::Client(e),
                    None => return End::Client("eof".to_string()),
                },
                joined = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    if let Some(joined) = joined {
                        if let Some(end) = self.on_joined(joined) {
                            return end;
                        }
                    }
                    self.recover();
                }
                _ = native.progress.notified() => {
                    if native.failed.load(Ordering::Relaxed) {
                        return End::Client("client: write_failed".to_string());
                    }
                    self.last_progress = Instant::now();
                    self.recover();
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    self.make_upload_room(now, monotonic_ms());
                    self.recover();
                    let quiet = now.saturating_duration_since(self.last_progress.max(self.last_native_send));
                    if self.reqs.is_empty() && self.staged.is_none() && quiet >= BRIDGE_READ_TIMEOUT {
                        return End::Idle;
                    }
                }
            }
        }
    }
}

/// proxy/cf_h2.py::bridge_h2: нативный клиент <-> HTTP/2-канал.
#[allow(clippy::too_many_arguments)]
pub async fn bridge<R, W>(
    conn_read: R,
    conn_write: W,
    channel: Channel,
    proto: u32,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    label: String,
    dc: i32,
    cancel: CancellationToken,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let start = Instant::now();
    let native = Arc::new(NativeState::default());
    let (wtx, wrx) = mpsc::channel::<NativeMsg>(NATIVE_QUEUE);
    let writer = tokio::spawn(native_writer(conn_write, clt_enc, proto, wrx, native.clone()));
    let writer_abort = writer.abort_handle();

    let (utx, mut urx) = mpsc::channel::<Result<Bytes, String>>(1);
    let reader = tokio::spawn(async move {
        let mut packets = PacketReader::new(conn_read, clt_dec);
        loop {
            let res = packets.packet(proto).await;
            let stop = res.is_err();
            if utx.send(res).await.is_err() || stop {
                return;
            }
        }
    });

    let mut ch = ChannelLoop {
        lane: channel.lane.clone(),
        label: label.clone(),
        channel_id: channel.id,
        tasks: JoinSet::new(),
        reqs: HashMap::new(),
        pending_bytes: 0,
        history: Vec::new(),
        replay_key: None,
        staged: None,
        requests: 0,
        replay_requests: 0,
        replay_rotations: 0,
        capacity_rotations: 0,
        up: 0,
        last_progress: start,
        last_native_send: start,
        native: native.clone(),
        wtx: wtx.clone(),
    };
    let session = cancel.child_token();
    let end = ch.run(&mut urx, &session).await;

    reader.abort();
    ch.tasks.abort_all();
    native.drop_pending.store(true, Ordering::Relaxed);
    let reason = match &end {
        End::Stopped => "proxy stopped".to_string(),
        End::Client(e) if e == "eof" => "client closed".to_string(),
        End::Client(e) => e.clone(),
        End::Transport(code) => format!("transport error {}", code),
        End::Error(e) => format!("upstream: {}", e),
        End::Idle => "idle".to_string(),
    };
    if let End::Transport(code) = end {
        let _ = tokio::time::timeout(Duration::from_secs(2), wtx.send(NativeMsg::Error(code))).await;
    }
    drop(wtx);
    drop(ch.wtx);
    if tokio::time::timeout(Duration::from_secs(3), writer).await.is_err() {
        writer_abort.abort();
    }
    linfo!(
        "[{}] DC{}m H2 session closed ({}): ^{} ({} req, {} replays) v{} in {:.1}s lane={} channel={}",
        label,
        dc,
        reason,
        human_bytes(ch.up as i64),
        ch.requests,
        ch.replay_requests,
        human_bytes(native.down.load(Ordering::Relaxed) as i64),
        start.elapsed().as_secs_f64(),
        channel.lane.id,
        channel.id
    );
    if ch.replay_rotations + ch.capacity_rotations > 0 {
        ldebug!(
            "[{}] H2 channel={} rotations: replay={} capacity={}",
            label,
            channel.id,
            ch.replay_rotations,
            ch.capacity_rotations
        );
    }
}

#[cfg(test)]
mod tests;
