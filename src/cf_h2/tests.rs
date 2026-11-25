//! Тесты HTTP/2-транспорта на локальном h2c-сервере, который ведёт себя как
//! HTTP-эндпоинт Telegram: держит запрос как long poll, отвечает пустым
//! телом, а результат RPC отдаёт в следующее «окно».

use super::*;
use std::collections::{HashSet, VecDeque};
use tokio::io::DuplexStream;
use tokio::net::{TcpListener, TcpStream};

const AUTH_KEY: [u8; 8] = [0x11; 8];

fn packet(msg_id: u64, cmd: &[u8; 4], extra: usize) -> Vec<u8> {
    let mut p = AUTH_KEY.to_vec();
    p.extend_from_slice(&msg_id.to_le_bytes());
    p.extend_from_slice(cmd);
    p.extend(std::iter::repeat_n(0u8, 4 + extra));
    assert!(p.len() % 4 == 0);
    p
}

fn reply(msg_id: u64, tag: &[u8; 4], extra: usize) -> Vec<u8> {
    let mut r = AUTH_KEY.to_vec();
    let mut msg_key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut msg_key);
    r.extend_from_slice(&msg_key);
    r.extend_from_slice(&msg_id.to_le_bytes());
    r.extend_from_slice(tag);
    r.extend(std::iter::repeat_n(0xabu8, extra));
    r
}

fn reply_tag(r: &[u8]) -> (u64, [u8; 4]) {
    (
        u64::from_le_bytes(r[24..32].try_into().unwrap()),
        r[32..36].try_into().unwrap(),
    )
}

#[derive(Default)]
struct MockTg {
    queue: SyncMutex<VecDeque<Vec<u8>>>,
    notify: Notify,
    seen: SyncMutex<HashSet<u64>>,
    posts: AtomicUsize,
    connections: AtomicUsize,
    hold: SyncMutex<Duration>,
    head_status: SyncMutex<u16>,
    goaway_after_first: AtomicBool,
}

fn respond(mut tx: h2::server::SendResponse<Bytes>, status: u16, body: Vec<u8>) -> bool {
    let resp = http::Response::builder()
        .status(status)
        .header("content-length", body.len())
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();
    match tx.send_response(resp, body.is_empty()) {
        Ok(mut stream) => {
            if !body.is_empty() {
                let _ = stream.send_data(Bytes::from(body), true);
            }
            true
        }
        Err(_) => false,
    }
}

impl MockTg {
    fn new(hold: Duration) -> Arc<MockTg> {
        let m = MockTg::default();
        *m.hold.lock() = hold;
        *m.head_status.lock() = 501;
        Arc::new(m)
    }

    async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let index = self.connections.fetch_add(1, Ordering::SeqCst);
            let me = self.clone();
            tokio::spawn(async move {
                let mut conn = match h2::server::handshake(tcp).await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut accepted = 0;
                while let Some(next) = conn.accept().await {
                    let (req, tx) = match next {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    accepted += 1;
                    tokio::spawn(me.clone().handle(req, tx));
                    if index == 0 && accepted == 1 && me.goaway_after_first.load(Ordering::SeqCst) {
                        conn.graceful_shutdown();
                    }
                }
            });
        }
    }

    async fn handle(self: Arc<Self>, req: http::Request<h2::RecvStream>, tx: h2::server::SendResponse<Bytes>) {
        if req.method() == Method::HEAD {
            let status = *self.head_status.lock();
            respond(tx, status, Vec::new());
            return;
        }
        let mut body = req.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => return,
            };
            let _ = body.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
        }
        self.posts.fetch_add(1, Ordering::SeqCst);
        let msg_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let cmd: [u8; 4] = data[16..20].try_into().unwrap();
        let first = self.seen.lock().insert(msg_id);
        match &cmd {
            b"ECHO" if first => {
                respond(tx, 200, reply(msg_id, b"ECHO", 0));
            }
            b"BIGR" if first => {
                respond(tx, 200, reply(msg_id, b"BIGR", 600 * 1024));
            }
            b"BIGU" if first => {
                let extra = data.len();
                respond(tx, 200, reply(msg_id, b"BIGU", (extra / 4) * 4));
            }
            b"E404" => {
                respond(tx, 404, Vec::new());
            }
            b"N404" => {
                respond(tx, 200, (-404i32).to_le_bytes().to_vec());
            }
            b"SLOW" if first => {
                tokio::time::sleep(Duration::from_millis(800)).await;
                respond(tx, 200, reply(msg_id, b"SLOW", 0));
            }
            b"LATE" if first => {
                let me = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    me.queue.lock().push_back(reply(msg_id, b"DONE", 0));
                    me.notify.notify_waiters();
                });
                self.long_poll(tx).await;
            }
            _ => self.long_poll(tx).await,
        }
    }

    async fn long_poll(&self, tx: h2::server::SendResponse<Bytes>) {
        let deadline = tokio::time::Instant::now() + *self.hold.lock();
        loop {
            let notified = self.notify.notified();
            let item = self.queue.lock().pop_front();
            if let Some(item) = item {
                if !respond(tx, 200, item.clone()) {
                    self.queue.lock().push_front(item);
                }
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                respond(tx, 200, Vec::new());
                return;
            }
        }
    }
}

async fn start_mock(hold: Duration) -> (Arc<MockTg>, Arc<Lane>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = MockTg::new(hold);
    tokio::spawn(mock.clone().serve(listener));
    let dial: DialFn = Arc::new(move || -> DialFuture {
        Box::pin(async move {
            let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
            Ok(Box::new(tcp) as BoxIo)
        })
    });
    (mock, Arc::new(Lane::new("kws2.test.invalid", 1, dial)))
}

/// Нативный клиент Telegram поверх duplex с obfuscated2-шифрованием.
struct Client {
    io: DuplexStream,
    enc: TrackedStream,
    dec: TrackedStream,
    proto: u32,
}

impl Client {
    async fn send(&mut self, body: &[u8]) {
        let mut frame = Vec::new();
        if self.proto == PROTO_TAG_ABRIDGED {
            let words = body.len() / 4;
            if words < 0x7f {
                frame.push(words as u8);
            } else {
                frame.push(0x7f);
                frame.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
            }
            frame.extend_from_slice(body);
        } else {
            let pad = if self.proto == PROTO_TAG_SECURE { 7 } else { 0 };
            frame.extend_from_slice(&((body.len() + pad) as u32).to_le_bytes());
            frame.extend_from_slice(body);
            frame.extend(std::iter::repeat_n(0x5au8, pad));
        }
        self.enc.xor(&mut frame);
        self.io.write_all(&frame).await.unwrap();
    }

    async fn read_plain(&mut self, n: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.io.read_exact(&mut buf).await.ok()?;
        self.dec.xor(&mut buf);
        Some(buf)
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        let len = if self.proto == PROTO_TAG_ABRIDGED {
            let first = self.read_plain(1).await?[0];
            let words = if first == 0x7f {
                let b = self.read_plain(3).await?;
                u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize
            } else {
                first as usize
            };
            words * 4
        } else {
            let h = self.read_plain(4).await?;
            (u32::from_le_bytes(h.try_into().unwrap()) & 0x7fff_ffff) as usize
        };
        let mut body = self.read_plain(len).await?;
        if self.proto == PROTO_TAG_SECURE {
            body.truncate(len / 4 * 4);
        }
        Some(body)
    }

    async fn recv_within(&mut self, secs: u64) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(secs), self.recv())
            .await
            .expect("timed out waiting for a reply")
    }
}

fn start_bridge(lane: Arc<Lane>, proto: u32) -> (Client, tokio::task::JoinHandle<()>, CancellationToken) {
    let mut key_up = [0u8; 32];
    let mut iv_up = [0u8; 16];
    let mut key_down = [0u8; 32];
    let mut iv_down = [0u8; 16];
    for b in [&mut key_up[..], &mut iv_up[..], &mut key_down[..], &mut iv_down[..]] {
        rand::thread_rng().fill_bytes(b);
    }
    let (client_io, proxy_io) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(proxy_io);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(bridge(
        r,
        w,
        Channel::new(lane, 1),
        proto,
        TrackedStream::new(&key_up, &iv_up),
        TrackedStream::new(&key_down, &iv_down),
        "test".to_string(),
        2,
        cancel.clone(),
    ));
    let client = Client {
        io: client_io,
        enc: TrackedStream::new(&key_up, &iv_up),
        dec: TrackedStream::new(&key_down, &iv_down),
        proto,
    };
    (client, handle, cancel)
}

#[test]
fn reply_framing_matches_native_transports() {
    let body = vec![7u8; 8];
    assert_eq!(encode_reply(&body, PROTO_TAG_ABRIDGED)[0], 2);
    let big = vec![1u8; 0x7f * 4];
    let enc = encode_reply(&big, PROTO_TAG_ABRIDGED);
    assert_eq!(&enc[..4], &[0x7f, 0x7f, 0, 0]);
    assert_eq!(enc.len(), big.len() + 4);
    let enc = encode_reply(&body, PROTO_TAG_INTERMEDIATE);
    assert_eq!(&enc[..4], &8u32.to_le_bytes());
    for _ in 0..32 {
        let enc = encode_reply(&body, PROTO_TAG_SECURE);
        let declared = u32::from_le_bytes(enc[..4].try_into().unwrap()) as usize;
        assert!((8..=11).contains(&declared));
        assert_eq!(enc.len(), 4 + declared);
        assert_eq!(&enc[4..12], &body[..]);
    }
}

#[test]
fn padded_packets_are_stripped_and_validated() {
    // Зашифрованный: длина = 24 + k*16, паддинг до 15 байт.
    let mut p = vec![1u8; 24 + 16 + 12];
    strip_padding(&mut p, PROTO_TAG_SECURE).unwrap();
    assert_eq!(p.len(), 40);
    // Незашифрованный (auth_key_id = 0): длина из заголовка, паддинг до 256.
    let mut p = vec![0u8; 20 + 40 + 100];
    p[16..20].copy_from_slice(&40u32.to_le_bytes());
    strip_padding(&mut p, PROTO_TAG_SECURE).unwrap();
    assert_eq!(p.len(), 60);
    let mut p = vec![0u8; 20 + 40 + 300];
    p[16..20].copy_from_slice(&40u32.to_le_bytes());
    assert!(strip_padding(&mut p, PROTO_TAG_SECURE).is_err());
    let mut p = vec![1u8; 26];
    assert!(strip_padding(&mut p, PROTO_TAG_INTERMEDIATE).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preflight_accepts_501_and_rejects_403() {
    let (mock, lane) = start_mock(Duration::from_millis(100)).await;
    assert_eq!(lane.preflight().await.unwrap(), 501);
    *mock.head_status.lock() = 403;
    let err = lane.preflight().await.unwrap_err();
    assert!(err.contains("403"), "{}", err);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_roundtrip_for_every_transport() {
    for proto in [PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE] {
        let (_mock, lane) = start_mock(Duration::from_millis(200)).await;
        let (mut client, handle, _cancel) = start_bridge(lane, proto);
        client.send(&packet(1, b"ECHO", 0)).await;
        let r = client.recv_within(5).await.expect("echo reply");
        assert_eq!(reply_tag(&r), (1, *b"ECHO"));
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_upload_and_download_respect_flow_control() {
    let (_mock, lane) = start_mock(Duration::from_millis(200)).await;
    let (mut client, _handle, _cancel) = start_bridge(lane, PROTO_TAG_ABRIDGED);
    client.send(&packet(1, b"BIGR", 0)).await;
    let r = client.recv_within(10).await.expect("big reply");
    assert_eq!(reply_tag(&r), (1, *b"BIGR"));
    assert_eq!(r.len(), 36 + 600 * 1024);
    // Upload больше окна потока HTTP/2 (64 KiB по умолчанию).
    client.send(&packet(2, b"BIGU", 300 * 1024)).await;
    let r = client.recv_within(10).await.expect("upload ack");
    assert_eq!(reply_tag(&r).1, *b"BIGU");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_reply_arrives_through_replay() {
    // Сервер отвечает на POST пустым телом, а результат RPC появляется
    // через 1,5 с — его должен забрать повтор пакета.
    let (mock, lane) = start_mock(Duration::from_millis(300)).await;
    let (mut client, _handle, _cancel) = start_bridge(lane, PROTO_TAG_INTERMEDIATE);
    client.send(&packet(7, b"LATE", 0)).await;
    let r = client.recv_within(8).await.expect("late reply");
    assert_eq!(reply_tag(&r), (7, *b"DONE"));
    assert!(mock.posts.load(Ordering::SeqCst) >= 2, "reply needs a replayed POST");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_errors_reach_the_client() {
    for cmd in [b"E404", b"N404"] {
        let (_mock, lane) = start_mock(Duration::from_millis(200)).await;
        let (mut client, handle, _cancel) = start_bridge(lane, PROTO_TAG_INTERMEDIATE);
        client.send(&packet(9, cmd, 0)).await;
        let r = client.recv_within(5).await.expect("transport error");
        assert_eq!(r, (-404i32).to_le_bytes().to_vec());
        assert!(client.recv_within(5).await.is_none(), "channel must close after the error");
        tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_goaway_keeps_inflight_and_moves_new_requests() {
    let (mock, lane) = start_mock(Duration::from_millis(300)).await;
    mock.goaway_after_first.store(true, Ordering::SeqCst);
    let (mut client, _handle, _cancel) = start_bridge(lane.clone(), PROTO_TAG_INTERMEDIATE);
    client.send(&packet(3, b"SLOW", 0)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.send(&packet(4, b"ECHO", 0)).await;
    let mut got = HashSet::new();
    for _ in 0..2 {
        let r = client.recv_within(5).await.expect("reply after GOAWAY");
        got.insert(reply_tag(&r));
    }
    assert!(got.contains(&(3, *b"SLOW")), "in-flight request finished on the old connection");
    assert!(got.contains(&(4, *b"ECHO")), "new request moved to a new connection");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    assert_eq!(lane.connections_opened(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_requests_are_rotated_to_admit_uploads() {
    // Сервер держит каждый запрос 20 с: восемь слотов канала заняты, девятый
    // пакет должен пройти после отмены «зависшего» запроса (через ~3 с).
    let (mock, lane) = start_mock(Duration::from_secs(20)).await;
    let (mut client, _handle, _cancel) = start_bridge(lane, PROTO_TAG_INTERMEDIATE);
    for id in 0..9u64 {
        client.send(&packet(100 + id, b"HOLD", 0)).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while mock.seen.lock().len() < 9 {
        assert!(tokio::time::Instant::now() < deadline, "ninth packet was never sent");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_token_closes_the_channel() {
    let (_mock, lane) = start_mock(Duration::from_secs(5)).await;
    let (mut client, handle, cancel) = start_bridge(lane.clone(), PROTO_TAG_INTERMEDIATE);
    client.send(&packet(1, b"HOLD", 0)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(lane.channels.load(Ordering::SeqCst), 1);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle).await.unwrap().unwrap();
    assert!(client.recv_within(5).await.is_none());
    assert_eq!(lane.channels.load(Ordering::SeqCst), 0);
}

/// Живая проверка против настоящего Cloudflare -> Telegram `/api` через
/// HTTPS-прокси окружения (CONNECT, проверка сертификата по его CA).
/// Запуск: `cargo test --lib live_cf -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_cf_api_answers_req_pq() {
    use rustls_pki_types::pem::PemObject;
    let Ok(proxy) = std::env::var("HTTPS_PROXY") else {
        return;
    };
    let proxy_addr = proxy.trim_start_matches("http://").trim_end_matches('/').to_string();
    let ca = std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| "/root/.ccr/ca-bundle.crt".to_string());
    let pem = std::fs::read(&ca).expect("CA bundle");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
        let _ = roots.add(cert.expect("PEM"));
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let cfg = Arc::new(cfg);
    let host = format!("kws2.{}", crate::cfproxy::default_cfproxy_domains()[0]);
    let dial: DialFn = {
        let host = host.clone();
        Arc::new(move || -> DialFuture {
            let (host, proxy_addr, cfg) = (host.clone(), proxy_addr.clone(), cfg.clone());
            Box::pin(async move {
                let mut tcp = TcpStream::connect(&proxy_addr).await.map_err(|e| e.to_string())?;
                let connect = format!("CONNECT {h}:443 HTTP/1.1\r\nHost: {h}:443\r\n\r\n", h = host);
                tcp.write_all(connect.as_bytes()).await.map_err(|e| e.to_string())?;
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    tcp.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
                    return Err(format!("CONNECT refused: {}", head.lines().next().unwrap_or("")));
                }
                let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
                let tls = tokio_rustls::TlsConnector::from(cfg)
                    .connect(name, tcp)
                    .await
                    .map_err(|e| e.to_string())?;
                let alpn = tls.get_ref().1.alpn_protocol().map(|a| String::from_utf8_lossy(a).to_string());
                if alpn.as_deref() != Some("h2") {
                    return Err(format!("no HTTP/2 through the proxy: alpn={:?}", alpn));
                }
                Ok(Box::new(tls) as BoxIo)
            })
        })
    };
    let req_pq = |nonce: &[u8; 16]| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let msg_id = ((now * 4294967296.0) as u64) & !3;
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&msg_id.to_le_bytes());
        body.extend_from_slice(&20u32.to_le_bytes());
        body.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes()); // req_pq_multi
        body.extend_from_slice(nonce);
        body
    };
    let lane = Arc::new(Lane::new(&host, 1, dial));
    let status = lane.preflight().await.expect("preflight");
    println!("preflight https://{}/api -> HTTP {}", host, status);

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let body = req_pq(&nonce);
    let permits = lane.try_permits(body.len()).unwrap();
    let reply = lane
        .clone()
        .post(Bytes::from(body), Arc::new(ReqState::default()), permits)
        .await
        .expect("POST /api");
    assert_eq!(u32::from_le_bytes(reply[20..24].try_into().unwrap()), 0x05162463, "resPQ");
    assert_eq!(&reply[24..40], &nonce[..]);
    println!("POST req_pq_multi -> resPQ ({} bytes), nonce matches", reply.len());

    // Тот же путь целиком: нативный клиент (abridged + obfuscated2) -> канал.
    let (mut client, _handle, _cancel) = start_bridge(lane.clone(), PROTO_TAG_ABRIDGED);
    rand::thread_rng().fill_bytes(&mut nonce);
    client.send(&req_pq(&nonce)).await;
    let reply = client.recv_within(20).await.expect("resPQ through the bridge");
    assert_eq!(u32::from_le_bytes(reply[20..24].try_into().unwrap()), 0x05162463, "resPQ");
    assert_eq!(&reply[24..40], &nonce[..]);
    println!("bridge: native abridged client got resPQ ({} bytes) over HTTP/2", reply.len());
}
