use crate::config::*;
use crate::ws::{is_http_status_error, RawWebSocket, WsError};
use crate::{ldebug, linfo, lwarn};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;

use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// Domain decoding
// ---------------------------------------------------------------------------

pub fn decode_cf_domain(s: &str) -> String {
    if !s.ends_with(".com") {
        return s.to_string();
    }
    let suffix = ".co.uk";
    let p = &s[..s.len() - 4];
    let mut n = 0i32;
    for c in p.chars() {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            n += 1;
        }
    }
    let mut result: Vec<u8> = Vec::new();
    for &c in p.as_bytes() {
        if c >= b'a' && c <= b'z' {
            let v = (((c - b'a') as i32 - n % 26 + 26) % 26) as u8 + b'a';
            result.push(v);
        } else if c >= b'A' && c <= b'Z' {
            let v = (((c - b'A') as i32 - n % 26 + 26) % 26) as u8 + b'A';
            result.push(v);
        } else {
            result.push(c);
        }
    }
    let mut out = String::from_utf8_lossy(&result).to_string();
    out.push_str(suffix);
    out
}

pub fn normalize_cf_domain(s: &str) -> String {
    let mut decoded = decode_cf_domain(s.trim()).trim().to_lowercase();
    while decoded.ends_with('.') {
        decoded.pop();
    }
    if decoded.is_empty() || !decoded.ends_with(".co.uk") {
        return String::new();
    }
    decoded
}

pub fn default_cfproxy_domains() -> Vec<String> {
    let mut domains = Vec::with_capacity(CFPROXY_ENC.len());
    for enc in CFPROXY_ENC {
        let d = normalize_cf_domain(enc);
        if !d.is_empty() {
            domains.push(d);
        }
    }
    domains
}

pub fn merge_cfproxy_domains(lists: &[Vec<String>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for list in lists {
        for raw in list {
            let d = normalize_cf_domain(raw);
            if d.is_empty() || seen.contains(&d) {
                continue;
            }
            // Дополнительно валидируем как в _normalize_domain_pool оригинала.
            if !crate::config::is_valid_domain(&d) {
                continue;
            }
            seen.insert(d.clone());
            merged.push(d);
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 429 cooldown logic
// ---------------------------------------------------------------------------

pub fn clear_cfproxy_429_cooldowns() {
    CFPROXY_429.write().clear();
}

pub fn clear_cfproxy_429_cooldown(domain: &str) {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return;
    }
    CFPROXY_429.write().remove(&d);
}

pub fn retry_after_delay(err: &WsError) -> Duration {
    let h = match err.handshake() {
        Some(h) => h,
        None => return Duration::ZERO,
    };
    let retry_after = h.headers.get("retry-after").map(|s| s.trim()).unwrap_or("");
    if retry_after.is_empty() {
        return Duration::ZERO;
    }
    if let Ok(seconds) = retry_after.parse::<i64>() {
        if seconds > 0 {
            return Duration::from_secs(seconds as u64);
        }
    }
    // http date parse (best-effort): пропускаем, как маловероятный кейс
    Duration::ZERO
}

pub fn next_cfproxy_429_cooldown_delay(prev: &Cfproxy429State, retry_after: Duration) -> Duration {
    if retry_after > Duration::ZERO {
        if retry_after > CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
        return retry_after;
    }
    let mut strikes = prev.strikes;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 0;
    }
    let mut delay = CFPROXY_429_COOLDOWN;
    for _ in 0..strikes {
        delay *= 2;
        if delay >= CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
    }
    if delay > CFPROXY_429_MAX_COOLDOWN {
        return CFPROXY_429_MAX_COOLDOWN;
    }
    delay
}

pub fn mark_cfproxy_429_cooldown(domain: &str, err: &WsError) {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return;
    }
    let retry_after = retry_after_delay(err);
    let mut map = CFPROXY_429.write();
    let prev = map.get(&d).cloned().unwrap_or_default();
    let delay = next_cfproxy_429_cooldown_delay(&prev, retry_after);
    let mut strikes = prev.strikes + 1;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 1;
    }
    map.insert(
        d.clone(),
        Cfproxy429State {
            until: Some(Instant::now() + delay),
            strikes,
        },
    );
    drop(map);
    ldebug!(" CF cooldown {}: {:.0}s after 429", d, delay.as_secs_f64().ceil());
}

pub fn cfproxy_429_cooldown_remaining(domain: &str) -> Duration {
    let d = normalize_cf_domain(domain);
    if d.is_empty() {
        return Duration::ZERO;
    }
    let map = CFPROXY_429.read();
    let state = match map.get(&d) {
        Some(s) => s.clone(),
        None => return Duration::ZERO,
    };
    drop(map);
    let until = match state.until {
        Some(u) => u,
        None => return Duration::ZERO,
    };
    let now = Instant::now();
    if until <= now {
        CFPROXY_429.write().remove(&d);
        return Duration::ZERO;
    }
    until - now
}

// ---------------------------------------------------------------------------
// Cache files
// ---------------------------------------------------------------------------

fn cfproxy_cache_path() -> Option<PathBuf> {
    let dir = CFPROXY.read().cache_dir.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join(CFPROXY_CACHE_FILE_NAME))
}

// Активный домен больше не сохраняется в отдельный файл. Балансер работает в памяти.

fn load_cfproxy_domains_from_cache() -> Vec<String> {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let list: Vec<String> = data.split('\n').map(|s| s.to_string()).collect();
    merge_cfproxy_domains(&[list])
}



fn save_cfproxy_domains_to_cache(domains: &[String]) {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return,
    };
    if domains.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            ldebug!(" CF: кеш создать не удалось: {}", e);
            return;
        }
    }
    let data = domains.join("\n");
    if let Err(e) = std::fs::write(&path, data) {
        ldebug!(" CF: кеш сохранить не удалось: {}", e);
    }
}



fn should_refresh_cfproxy_domains() -> bool {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return true,
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    match modified.elapsed() {
        Ok(elapsed) => elapsed >= CFPROXY_REFRESH_INTERVAL,
        Err(_) => true,
    }
}



pub fn init_cfproxy_domains() {
    let defaults = default_cfproxy_domains();
    let cached = load_cfproxy_domains_from_cache();

    let mut cfg = CFPROXY.write();
    if !cfg.user_domain.is_empty() {
        // Пользовательских доменов может быть несколько (через , ; или пробел),
        // как --cfproxy-domain (repeatable) в оригинале.
        let user = normalize_domain_pool(&coerce_domain_list_str(&cfg.user_domain));
        if !user.is_empty() {
            cfg.domains = user;
            crate::balancer::BALANCER.write().update_domains_list(&cfg.domains);
            return;
        }
    }

    if !cached.is_empty() {
        let n = cached.len();
        cfg.domains = merge_cfproxy_domains(&[cached, defaults]);
        crate::balancer::BALANCER.write().update_domains_list(&cfg.domains);
        drop(cfg);
        linfo!(" CF: кеш доменов загружен ({} шт.)", n);
    } else {
        cfg.domains = defaults;
        crate::balancer::BALANCER.write().update_domains_list(&cfg.domains);
    }
}

pub fn start_cfproxy_refresh(cancel: CancellationToken) {
    // Порт proxy/config.py::start_cfproxy_domain_refresh: сначала пробуем
    // обновить сразу (до 3 попыток), затем раз в час фоновым таском.
    // На мобиле уважаем свежесть дискового кеша для первой попытки.
    // Таск привязан к жизни прокси: StopProxy его отменяет.
    if !CFPROXY.read().user_domain.trim().is_empty() {
        return;
    }
    if !should_refresh_cfproxy_domains() {
        ldebug!(" CF: кеш свежий, откладываю обновление списка на час");
    }
    tokio::spawn(async move {
        let work = async {
            if should_refresh_cfproxy_domains() {
                for _ in 0..3 {
                    if try_refresh_cfproxy_domains().await {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
            loop {
                tokio::time::sleep(CFPROXY_REFRESH_INTERVAL).await;
                try_refresh_cfproxy_domains().await;
            }
        };
        tokio::select! {
            _ = cancel.cancelled() => {}
            _ = work => {}
        }
    });
}

pub async fn try_refresh_cfproxy_domains() -> bool {
    let has_user = !CFPROXY.read().user_domain.is_empty();
    if has_user {
        return true;
    }

    // Cache-buster как в оригинале ("?" + 7 случайных букв), UA tg-ws-proxy.
    let nonce: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..7)
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect()
    };
    let path = format!("{}?{}", CFPROXY_DOMAINS_PATH, nonce);
    // Как _PinnedHTTPSHandler оригинала: сначала закреплённый IP GitHub
    // (на случай подменённого DNS), затем обычный резолв.
    let mut resp = None;
    for ip in [Some(GITHUB_RAW_PINNED_IP), None] {
        let ip = ip.and_then(|s| s.parse::<std::net::IpAddr>().ok());
        match crate::https::https_get(
            CFPROXY_DOMAINS_HOST,
            ip,
            &path,
            "text/plain",
            Duration::from_secs(10),
            256 * 1024,
        )
        .await
        {
            Ok(r) => {
                resp = Some(r);
                break;
            }
            Err(e) => ldebug!(" CF: GitHub недоступен{}: {}", if ip.is_some() { " (pinned IP)" } else { "" }, e),
        }
    }
    let resp = match resp {
        Some(r) => r,
        None => return false,
    };
    if resp.status != 200 {
        ldebug!(" CF: GitHub вернул {}", resp.status);
        return false;
    }
    let body = String::from_utf8_lossy(&resp.body).into_owned();

    let mut fetched_raw = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        fetched_raw.push(line.to_string());
    }

    // Валидация пула как в оригинале: минимум CFPROXY_MIN_VALID_DOMAINS
    // валидных доменов, иначе игнорируем payload и остаёмся на текущем пуле.
    let decoded: Vec<String> = fetched_raw.iter().map(|d| normalize_cf_domain(d)).collect();
    let pool = normalize_domain_pool(&decoded);
    if pool.len() >= CFPROXY_MIN_VALID_DOMAINS {
        let merged = merge_cfproxy_domains(&[pool.clone(), default_cfproxy_domains()]);
        {
            let mut cfg = CFPROXY.write();
            if !cfg.user_domain.is_empty() {
                return true;
            }
            cfg.domains = merged.clone();
        }
        crate::balancer::BALANCER.write().update_domains_list(&merged);
        save_cfproxy_domains_to_cache(&merged);
        linfo!(" CF: список доменов обновлен ({} шт.)", pool.len());
        return true;
    }

    if !fetched_raw.is_empty() {
        lwarn!(
            " CF: игнорирую список доменов (total={}, valid={}, need>={}); остаюсь на текущем пуле",
            fetched_raw.len(),
            pool.len(),
            CFPROXY_MIN_VALID_DOMAINS
        );
    } else {
        ldebug!(" CF: обновить список доменов не удалось (пустой ответ), остаюсь на кеше/встроенном списке");
    }
    false
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH) resolve
// ---------------------------------------------------------------------------

static DOH_CACHE: Lazy<parking_lot::RwLock<std::collections::HashMap<String, (String, Instant)>>> =
    Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

fn pick_preferred_ip(candidates: &[String]) -> String {
    let mut fallback_v6 = String::new();
    for c in candidates {
        let c = c.trim();
        if let Ok(ip) = c.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => return v4.to_string(),
                std::net::IpAddr::V6(v6) => {
                    if fallback_v6.is_empty() {
                        fallback_v6 = v6.to_string();
                    }
                }
            }
        }
    }
    fallback_v6
}

pub async fn resolve_doh(domain: &str) -> Option<String> {
    if let Some((ip, exp)) = DOH_CACHE.read().get(domain).cloned() {
        if Instant::now() < exp {
            return Some(ip);
        }
    }

    // DoH по IP: сломанный/подменённый системный DNS не мешает дойти до
    // самого DoH-сервера. Сертификат проверяется по имени в SNI.
    let endpoints: [(&str, &str, &str); 3] = [
        ("cloudflare-dns.com", "1.1.1.1", "/dns-query"),
        ("dns.google", "8.8.8.8", "/resolve"),
        ("dns.adguard-dns.com", "94.140.14.14", "/resolve"),
    ];

    let (tx, mut rx) = tokio::sync::mpsc::channel(endpoints.len() + 1);
    let mut tasks = Vec::new();

    for (host, ip, path) in endpoints {
        let domain = domain.to_string();
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let query = format!("{}?name={}&type=A", path, domain);
            let ip = ip.parse::<std::net::IpAddr>().ok();
            if let Ok(resp) = crate::https::https_get(
                host,
                ip,
                &query,
                "application/dns-json",
                Duration::from_millis(1500),
                64 * 1024,
            )
            .await
            {
                if resp.status == 200 {
                    let body = String::from_utf8_lossy(&resp.body);
                    if let Some(first) = crate::https::doh_json_ipv4(&body).into_iter().next() {
                        let _ = tx.send(Some(first)).await;
                        return;
                    }
                }
            }
            let _ = tx.send(None).await;
        }));
    }

    // UDP-резолв через системный resolver как дополнительный кандидат
    {
        let domain2 = domain.to_string();
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let host = format!("{}:443", domain2);
            if let Ok(Ok(addrs)) = tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::lookup_host(host),
            )
            .await
            {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                let p = pick_preferred_ip(&ips);
                if !p.is_empty() {
                    let _ = tx.send(Some(p)).await;
                    return;
                }
            }
            let _ = tx.send(None).await;
        }));
    }

    drop(tx); // Чтобы rx.recv() завершился, когда все таски завершатся

    let deadline = tokio::time::sleep(Duration::from_millis(1500));
    tokio::pin!(deadline);

    let mut final_ip = None;
    loop {
        tokio::select! {
            _ = &mut deadline => {
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(Some(ip)) => {
                        final_ip = Some(ip);
                        break;
                    }
                    Some(None) => {} // Таска ничего не нашла
                    None => break,   // Все таски завершились
                }
            }
        }
    }

    // Отменяем все незавершенные фоновые таски (исправление утечки)
    for t in tasks {
        t.abort();
    }

    if let Some(ip) = &final_ip {
        DOH_CACHE.write().insert(
            domain.to_string(),
            (ip.clone(), Instant::now() + Duration::from_secs(300)),
        );
    }
    
    final_ip
}

// ---------------------------------------------------------------------------
// connect_cf_domains — порт proxy/cf_websocket.py (Flowseal v1.12):
// перебор CF-доменов с короткими таймаутами (3,3,5,5,10с), чередование
// TLS(443)/HTTP(80) после таймаутов и 30-секундный cooldown пары
// (домен, tls). Предпочитается тот режим, который чаще срабатывал.
// Поверх оригинала — 429-cooldown домена (мобильное улучшение форка).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CfConnState {
    timeout_until: HashMap<(String, bool), f64>,
    tls: u64,
    no_tls: u64,
}

static CF_CONN: Lazy<parking_lot::Mutex<CfConnState>> =
    Lazy::new(|| parking_lot::Mutex::new(CfConnState::default()));

pub fn reset_cf_timeouts() {
    *CF_CONN.lock() = CfConnState::default();
}

/// Снять cooldown'ы таймаутов. `forget_mode` — забыть и предпочтение
/// TLS/HTTP (сеть сменилась, на новой может работать другой порт).
pub fn clear_cf_cooldowns(forget_mode: bool) {
    let mut st = CF_CONN.lock();
    st.timeout_until.clear();
    if forget_mode {
        st.tls = 0;
        st.no_tls = 0;
    }
}

/// proxy/cf_websocket.py::cf_tls_in_cooldown — TLS-попытки к хосту
/// kwsN.<домен> сейчас на паузе после таймаута.
pub fn cf_tls_in_cooldown(host: &str) -> bool {
    CF_CONN
        .lock()
        .timeout_until
        .get(&(host.to_string(), true))
        .is_some_and(|until| now_monotonic() < *until)
}

pub fn cf_prefers_tls() -> bool {
    let st = CF_CONN.lock();
    st.tls >= st.no_tls
}

/// Возвращает прежний cooldown, если попытку, занявшую слот повтора
/// (INFINITY), отменили посреди подключения (аналог finally в оригинале).
struct RetryClaim {
    key: (String, bool),
    retry_at: Option<f64>,
}

impl Drop for RetryClaim {
    fn drop(&mut self) {
        if let Some(retry_at) = self.retry_at {
            let mut st = CF_CONN.lock();
            if st.timeout_until.get(&self.key) == Some(&f64::INFINITY) {
                st.timeout_until.insert(self.key.clone(), retry_at);
            }
        }
    }
}

/// Параметры гонки CF-маршрутов (идея из pvtarget-glitch/tg-ws-proxy-android):
/// следующая попытка стартует через STAGGER или сразу после отказа
/// предыдущей; первая успешная побеждает, остальные отменяются.
pub const CF_RACE_STAGGER: Duration = Duration::from_millis(700);
pub const CF_RACE_MAX_PARALLEL: usize = 3;
pub const CF_RACE_ATTEMPT_TIMEOUT: f64 = 5.0;
// Сколько попыток (домен+режим) максимум на одно соединение клиента —
// иначе при недоступном CF клиенты плодили сотни висящих сокетов.
pub const CF_RACE_MAX_ATTEMPTS: usize = 8;

/// Запускает `attempts` попыток «лесенкой». Возвращает индекс и результат
/// первой успешной; None — все провалились или вышел общий бюджет.
pub async fn race<T, F, Fut>(
    attempts: usize,
    mut attempt: F,
    stagger: Duration,
    max_parallel: usize,
    budget: Duration,
) -> Option<(usize, T)>
where
    T: Send + 'static,
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Option<T>> + Send + 'static,
{
    use tokio::time::Instant;
    let deadline = Instant::now() + budget;
    let mut set = tokio::task::JoinSet::new();
    let (mut next, mut running) = (0usize, 0usize);
    let mut next_start = Instant::now();
    loop {
        while next < attempts && running < max_parallel.max(1) && Instant::now() >= next_start {
            let idx = next;
            let fut = attempt(idx);
            set.spawn(async move { (idx, fut.await) });
            next += 1;
            running += 1;
            next_start = Instant::now() + stagger;
        }
        if running == 0 && next >= attempts {
            return None;
        }
        let wake_at = if next < attempts && running < max_parallel.max(1) {
            next_start.min(deadline)
        } else {
            deadline
        };
        tokio::select! {
            joined = set.join_next(), if running > 0 => {
                running -= 1;
                if let Some(Ok((idx, Some(value)))) = joined {
                    set.abort_all();
                    return Some((idx, value));
                }
                // Отказ — следующую попытку не ждём.
                next_start = Instant::now();
            }
            _ = tokio::time::sleep_until(wake_at) => {
                if Instant::now() >= deadline {
                    set.abort_all();
                    return None;
                }
            }
        }
    }
}

/// Одна попытка подключения к CF с учётом cooldown пары (хост, tls).
async fn cf_attempt(name: String, host: String, use_tls: bool, label: String, path: String) -> Option<(RawWebSocket, String)> {
    if cfproxy_429_cooldown_remaining(&name) > Duration::ZERO {
        ldebug!("[{}] CF skip {}: 429 cooldown", label, host);
        return None;
    }
    // Карантин по хосту kwsN.<домен>, а не по базовому домену: таймаут
    // одного DC не должен выключать CF-путь для всех DC
    // (Flowseal/tg-ws-proxy#1701).
    let key = (host.clone(), use_tls);
    let retry_at = {
        let mut st = CF_CONN.lock();
        let retry_at = st.timeout_until.get(&key).copied();
        if let Some(until) = retry_at {
            if now_monotonic() < until {
                return None;
            }
            // Занимаем слот повторной попытки, чтобы параллельные клиенты
            // не ломились в тот же хост одновременно.
            st.timeout_until.insert(key.clone(), f64::INFINITY);
        }
        retry_at
    };
    let _claim = RetryClaim {
        key: key.clone(),
        retry_at,
    };

    let result = tokio::time::timeout(
        Duration::from_secs_f64(CF_RACE_ATTEMPT_TIMEOUT),
        crate::ws::ws_connect_full_opts(
            &host,
            &host,
            &path,
            CF_RACE_ATTEMPT_TIMEOUT,
            None,
            Some(use_tls),
            crate::ws::CF_DPI_SPLIT.load(std::sync::atomic::Ordering::Relaxed),
        ),
    )
    .await
    .unwrap_or(Err(WsError::Timeout));

    match result {
        Ok(ws) => {
            {
                let mut st = CF_CONN.lock();
                st.timeout_until.remove(&key);
                if use_tls {
                    st.tls += 1;
                } else {
                    st.no_tls += 1;
                }
            }
            clear_cfproxy_429_cooldown(&name);
            Some((ws, name))
        }
        Err(e) if e.is_timeout() => {
            let now = now_monotonic();
            let mut st = CF_CONN.lock();
            if !should_record_failure(None) {
                // Без сети таймаут ничего не говорит о домене.
                st.timeout_until.remove(&key);
            } else if retry_at.is_some() || !st.timeout_until.contains_key(&key) {
                st.timeout_until.retain(|_, until| *until + CF_TIMEOUT_COOLDOWN > now);
                st.timeout_until.insert(key, now + CF_TIMEOUT_COOLDOWN);
                drop(st);
                lwarn!(
                    "[{}] CF WebSocket timed out (host={} tls={}); retry in {:.0}s",
                    label, host, use_tls, CF_TIMEOUT_COOLDOWN
                );
            }
            None
        }
        Err(e) => {
            CF_CONN.lock().timeout_until.remove(&key);
            if let WsError::Io(io) = &e {
                if !should_record_failure(Some(io)) {
                    ldebug!("[{}] CF WebSocket: no network ({})", label, io);
                    return None;
                }
            }
            if is_http_status_error(&e, 429) {
                mark_cfproxy_429_cooldown(&name, &e);
            }
            log_cf_conn_error(
                &format!("[{}] CF WebSocket failed (host={} tls={}): {}", label, host, use_tls, e.compact()),
                &e,
            );
            None
        }
    }
}

/// candidates: (имя для балансера, хост для подключения), в порядке
/// предпочтения (первым — домен, который недавно работал для этого DC).
///
/// Порт proxy/cf_websocket.py (Flowseal v1.12) — cooldown пары (хост, tls),
/// предпочтение режима, который чаще срабатывал, переключение TLS(443) ⇄
/// HTTP(80) — но попытки идут гонкой, а не строго по очереди: заблокированный
/// домен больше не стоит каждому соединению 3–5 секунд таймаута.
pub async fn connect_cf_domains(
    candidates: Vec<(String, String)>,
    label: &str,
    secure: bool,
    path: &str,
    timeout: f64,
) -> Option<(RawWebSocket, String)> {
    let tls_first = secure && cf_prefers_tls();
    // Для каждого домена — предпочтительный режим и сразу за ним второй:
    // если 443 молчит, через STAGGER пробуется 80 (и наоборот).
    let mut attempts: Vec<(String, String, bool)> = Vec::new();
    for (name, host) in candidates {
        attempts.push((name.clone(), host.clone(), tls_first));
        if secure {
            attempts.push((name, host, !tls_first));
        }
        if attempts.len() >= CF_RACE_MAX_ATTEMPTS {
            break;
        }
    }
    attempts.truncate(CF_RACE_MAX_ATTEMPTS);
    if attempts.is_empty() {
        return None;
    }
    let label = label.to_string();
    let path = path.to_string();
    let budget = Duration::from_secs_f64(timeout.max(CF_RACE_ATTEMPT_TIMEOUT));
    let list = attempts.clone();
    race(
        list.len(),
        move |i| {
            let (name, host, tls) = list[i].clone();
            cf_attempt(name, host, tls, label.clone(), path.clone())
        },
        CF_RACE_STAGGER,
        CF_RACE_MAX_PARALLEL,
        budget,
    )
    .await
    .map(|(_, won)| won)
}

#[cfg(test)]
mod race_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn first_failure_starts_next_immediately() {
        let t = Instant::now();
        let r = race(
            3,
            |i| async move {
                if i == 0 {
                    None
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some(i)
                }
            },
            Duration::from_secs(5),
            3,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r, Some((1, 1)));
        assert!(t.elapsed() < Duration::from_secs(1), "must not wait for stagger after a failure");
    }

    #[tokio::test]
    async fn silent_attempt_is_overtaken_after_stagger() {
        let t = Instant::now();
        let r = race(
            2,
            |i| async move {
                if i == 0 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Some(0)
                } else {
                    Some(1)
                }
            },
            Duration::from_millis(50),
            3,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r, Some((1, 1)));
        let e = t.elapsed();
        assert!(e >= Duration::from_millis(45) && e < Duration::from_secs(2), "{:?}", e);
    }

    #[tokio::test]
    async fn all_fail_or_budget_runs_out() {
        let r: Option<(usize, u8)> = race(4, |_| async { None }, Duration::from_millis(10), 2, Duration::from_secs(5)).await;
        assert!(r.is_none());
        let t = Instant::now();
        let r: Option<(usize, u8)> = race(
            4,
            |_| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Some(1)
            },
            Duration::from_millis(10),
            2,
            Duration::from_millis(100),
        )
        .await;
        assert!(r.is_none());
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn parallelism_is_bounded() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (l, p) = (live.clone(), peak.clone());
        let r: Option<(usize, ())> = race(
            6,
            move |_| {
                let (l, p) = (l.clone(), p.clone());
                async move {
                    let now = l.fetch_add(1, Ordering::SeqCst) + 1;
                    p.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    l.fetch_sub(1, Ordering::SeqCst);
                    None
                }
            },
            Duration::from_millis(1),
            2,
            Duration::from_secs(5),
        )
        .await;
        assert!(r.is_none());
        assert!(peak.load(Ordering::SeqCst) <= 2);
    }
}

pub fn log_cf_conn_error(msg: &str, err: &WsError) {
    if let WsError::Io(e) = err {
        if e.kind() == std::io::ErrorKind::ConnectionReset {
            return;
        }
    }
    // Оригинал пишет сбои CF-подключений как warning.
    lwarn!("{}", msg);
}

// активный домен set/save
pub fn set_active_domain_and_save(_chosen: &str) {
    // Больше не используется для файлов. Балансер обновляется внутри proxy.rs
}