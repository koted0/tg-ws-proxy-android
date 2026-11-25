//! Ядро прокси — порт proxy/tg_ws_proxy.py, proxy/pool.py и proxy/bridge.py
//! из Flowseal/tg-ws-proxy (v1.12.0) с мобильными доработками форка.

use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use parking_lot::Mutex as SyncMutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// proxy/pool.py::_WsPool.try_fronting_first — начинается с false и
/// запоминает режим последнего удачного подключения.
static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(false);

pub fn pool_size() -> usize {
    POOL_SIZE.load(Ordering::Relaxed).max(0) as usize
}

fn close_later(ws: RawWebSocket) {
    tokio::spawn(async move {
        ws.close().await;
    });
}

fn backoff_delay(initial: f64, failures: u32, max_shift: u32, max: f64) -> f64 {
    let shift = failures.saturating_sub(1).min(max_shift);
    (initial * 2f64.powi(shift as i32)).min(max)
}

/// proxy_config.dc_redirects.get(dc) с поддержкой отдельного IP для media
/// (отрицательный ключ -dc — расширение Android-форка).
pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    let map = DC_OPT.read();
    if is_media {
        if let Some(t) = map.get(&(-dc)) {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    map.get(&dc).filter(|t| !t.is_empty()).cloned()
}

/// DC_DEFAULT_IPS / DC_TEST_IPS — куда идут CF worker и TCP fallback.
pub fn resolve_fallback_target(dc: i32, is_test: bool) -> String {
    let table = if is_test { &*DC_TEST_IPS } else { &*DC_DEFAULT_IPS };
    table.get(&dc).map(|s| s.to_string()).unwrap_or_default()
}

/// proxy/utils.py::ws_domains: основное соединение — только kwsN,
/// media — сначала kwsN-1, затем kwsN.
pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let dc = DC_OVERRIDES.get(&dc).copied().unwrap_or(dc);
    if !is_media {
        return vec![format!("kws{}.web.telegram.org", dc)];
    }
    vec![
        format!("kws{}-1.web.telegram.org", dc),
        format!("kws{}.web.telegram.org", dc),
    ]
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PoolKey {
    pub dc: i32,
    pub is_media: bool,
    pub is_test: bool,
}

impl PoolKey {
    fn tag(&self) -> String {
        format!(
            "DC{}{}{}",
            self.dc,
            if self.is_test { "t" } else { "" },
            if self.is_media { "m" } else { "" }
        )
    }
}

struct PoolEntry {
    ws: RawWebSocket,
    created: f64,
}

fn entry_stale(ws: &RawWebSocket, created: f64, now: f64, max_age: f64) -> bool {
    now - created >= max_age || ws.is_stale()
}

#[derive(Default)]
struct WsPoolState {
    idle: HashMap<PoolKey, VecDeque<PoolEntry>>,
    refilling: HashMap<PoolKey, u64>,
    rotating: HashSet<PoolKey>,
    refill_failures: HashMap<PoolKey, u32>,
    refill_after: HashMap<PoolKey, f64>,
}

pub struct WsPool {
    state: SyncMutex<WsPoolState>,
    next_gen: AtomicU64,
    cancel: CancellationToken,
}

impl WsPool {
    pub fn new(cancel: CancellationToken) -> WsPool {
        WsPool {
            state: SyncMutex::new(WsPoolState::default()),
            next_gen: AtomicU64::new(1),
            cancel,
        }
    }

    /// Готовый WS к DC из пула или None (тогда клиент сразу идёт в fallback).
    pub fn get(self: &Arc<Self>, dc: i32, is_media: bool, is_test: bool) -> Option<RawWebSocket> {
        let target_ip = resolve_configured_target(dc, is_media)?;
        if pool_size() == 0 {
            return None;
        }
        let key = PoolKey { dc, is_media, is_test };
        let now = now_monotonic();
        let mut stale = Vec::new();
        let hit = {
            let mut st = self.state.lock();
            let bucket = st.idle.entry(key).or_default();
            let mut hit = None;
            while let Some(e) = bucket.pop_front() {
                if entry_stale(&e.ws, e.created, now, WS_POOL_REUSE_MAX_AGE) {
                    stale.push(e.ws);
                    continue;
                }
                hit = Some((e, bucket.len()));
                break;
            }
            hit
        };
        for ws in stale {
            close_later(ws);
        }
        let result = match hit {
            Some((e, left)) => {
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "WS pool hit {} (age={:.1}s, left={})",
                    key.tag(),
                    now - e.created,
                    left
                );
                Some(e.ws)
            }
            None => {
                STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        };
        self.schedule_refill(key, target_ip);
        result
    }

    fn schedule_refill(self: &Arc<Self>, key: PoolKey, target_ip: String) {
        if pool_size() == 0 || self.cancel.is_cancelled() {
            return;
        }
        // Без сети не дёргаем радио зря; пул прогреется по SetNetworkAvailable.
        if network_down() {
            return;
        }
        self.schedule_rotation(key, target_ip.clone());
        let gen = {
            let mut st = self.state.lock();
            if st.refilling.contains_key(&key)
                || now_monotonic() < st.refill_after.get(&key).copied().unwrap_or(0.0)
            {
                return;
            }
            let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
            st.refilling.insert(key, gen);
            gen
        };
        let pool = self.clone();
        tokio::spawn(async move {
            pool.refill(key, target_ip, gen).await;
        });
    }

    async fn refill(self: Arc<Self>, key: PoolKey, target_ip: String, gen: u64) {
        let needed = {
            let st = self.state.lock();
            pool_size().saturating_sub(st.idle.get(&key).map_or(0, |b| b.len()))
        };
        if needed > 0 {
            let domains = ws_domains(key.dc, key.is_media);
            let path = ws_path_for(key.is_test);
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..needed {
                let ip = target_ip.clone();
                let domains = domains.clone();
                set.spawn(async move { connect_pooled_ws(&ip, &domains, path).await });
            }
            let mut connected = 0usize;
            let mut cancelled = false;
            loop {
                let next = tokio::select! {
                    _ = self.cancel.cancelled() => { cancelled = true; break; }
                    r = set.join_next() => r,
                };
                let ws = match next {
                    None => break,
                    Some(Ok(Some(ws))) => ws,
                    Some(_) => continue,
                };
                let mut st = self.state.lock();
                if st.refilling.get(&key) != Some(&gen) {
                    drop(st);
                    close_later(ws);
                    cancelled = true;
                    break;
                }
                st.idle.entry(key).or_default().push_back(PoolEntry {
                    ws,
                    created: now_monotonic(),
                });
                connected += 1;
            }
            // Незавершённые попытки отменяются вместе с JoinSet; готовые, но
            // не принятые соединения закрываются при drop.
            set.abort_all();

            if !cancelled {
                let mut st = self.state.lock();
                if connected > 0 {
                    st.refill_failures.remove(&key);
                    st.refill_after.remove(&key);
                } else if !should_record_failure(None) {
                    st.refill_after.insert(key, now_monotonic() + 5.0);
                } else {
                    let failures = st.refill_failures.get(&key).copied().unwrap_or(0) + 1;
                    st.refill_failures.insert(key, failures);
                    let delay = backoff_delay(
                        WS_POOL_REFILL_BACKOFF_INITIAL,
                        failures,
                        12,
                        WS_POOL_REFILL_BACKOFF_MAX,
                    );
                    st.refill_after.insert(key, now_monotonic() + delay);
                    drop(st);
                    linfo!("WS pool refill failed for {}, retry in {:.0}s", key.tag(), delay);
                }
                let ready = self.state.lock().idle.get(&key).map_or(0, |b| b.len());
                ldebug!("WS pool refilled {}: {} ready", key.tag(), ready);
            }
        }
        let mut st = self.state.lock();
        if st.refilling.get(&key) == Some(&gen) {
            st.refilling.remove(&key);
        }
    }

    fn schedule_rotation(self: &Arc<Self>, key: PoolKey, target_ip: String) {
        {
            let mut st = self.state.lock();
            if !st.rotating.insert(key) {
                return;
            }
        }
        let pool = self.clone();
        tokio::spawn(async move {
            pool.rotate(key, target_ip).await;
        });
    }

    /// Выкидывает протухшие соединения и доливает пул до pool_size.
    async fn rotate(self: Arc<Self>, key: PoolKey, target_ip: String) {
        while pool_size() > 0 && !self.cancel.is_cancelled() {
            let now = now_monotonic();
            let (expired, ready, wake_at) = {
                let mut st = self.state.lock();
                let bucket = st.idle.entry(key).or_default();
                let mut expired = Vec::new();
                let mut keep = VecDeque::with_capacity(bucket.len());
                while let Some(e) = bucket.pop_front() {
                    if entry_stale(&e.ws, e.created, now, WS_POOL_REUSE_MAX_AGE) {
                        expired.push(e.ws);
                    } else {
                        keep.push_back(e);
                    }
                }
                let mut wake_at = now + WS_POOL_CHECK_INTERVAL;
                for e in &keep {
                    wake_at = wake_at.min(e.created + WS_POOL_REUSE_MAX_AGE);
                }
                *bucket = keep;
                let ready = bucket.len();
                let after = st.refill_after.get(&key).copied().unwrap_or(0.0);
                if !st.refilling.contains_key(&key) && after > now {
                    wake_at = wake_at.min(after);
                }
                (expired, ready, wake_at)
            };
            if !expired.is_empty() {
                ldebug!(
                    "WS pool rotated {}: {} stale, {} ready",
                    key.tag(),
                    expired.len(),
                    ready
                );
                for ws in expired {
                    close_later(ws);
                }
            }
            if ready < pool_size() {
                self.schedule_refill(key, target_ip.clone());
            }
            let sleep_for = (wake_at - now_monotonic()).max(0.0);
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_for)) => {}
            }
        }
        self.state.lock().rotating.remove(&key);
    }

    pub fn warmup(self: &Arc<Self>, log: bool) {
        let dcs: Vec<i32> = {
            let map = DC_OPT.read();
            let mut v: Vec<i32> = map.keys().map(|k| k.abs()).collect();
            v.sort();
            v.dedup();
            v
        };
        let is_test = FORCE_TEST_DC.load(Ordering::Relaxed);
        let mut n = 0;
        for dc in dcs {
            let mut any = false;
            for is_media in [false, true] {
                if let Some(target) = resolve_configured_target(dc, is_media) {
                    self.schedule_refill(PoolKey { dc, is_media, is_test }, target);
                    any = true;
                }
            }
            if any {
                n += 1;
            }
        }
        if log {
            linfo!("WS pool warmup started for {} DC(s)", n);
        } else {
            ldebug!("WS pool warmup started for {} DC(s)", n);
        }
    }

    /// Сброс backoff пополнения (сеть вернулась / экран включён).
    pub fn reset_backoff(&self) {
        let mut st = self.state.lock();
        st.refill_failures.clear();
        st.refill_after.clear();
    }

    pub fn close_all(&self) {
        let entries: Vec<PoolEntry> = {
            let mut st = self.state.lock();
            st.idle.drain().flat_map(|(_, b)| b.into_iter()).collect()
        };
        for e in entries {
            close_later(e.ws);
        }
    }

    pub fn reset(&self) {
        self.close_all();
        *self.state.lock() = WsPoolState::default();
        TRY_FRONTING_FIRST.store(false, Ordering::Relaxed);
    }
}

/// pool._connect_one: для каждого домена пробуем прямое подключение и
/// domain fronting (SNI sprinthost.ru), начиная с режима, сработавшего
/// последним.
async fn connect_pooled_ws(target_ip: &str, domains: &[String], path: &str) -> Option<RawWebSocket> {
    for domain in domains {
        let fronting_first = TRY_FRONTING_FIRST.load(Ordering::Relaxed);
        let modes = if fronting_first { [true, false] } else { [false, true] };
        for fronted in modes {
            let (timeout, sni) = if fronted {
                (WS_POOL_FRONTING_TIMEOUT, Some(FRONTING_SNI))
            } else {
                (WS_POOL_CONNECT_TIMEOUT, None)
            };
            match ws_connect_once_full(
                target_ip,
                domain,
                path,
                Duration::from_secs_f64(timeout),
                sni,
                true,
                false,
            )
            .await
            {
                Ok(ws) => {
                    TRY_FRONTING_FIRST.store(fronted, Ordering::Relaxed);
                    if fronted {
                        STATS.connections_fronting.fetch_add(1, Ordering::Relaxed);
                    }
                    ldebug!(
                        "WS pool connected {}{} via {} (fronting={})",
                        domain, path, target_ip, fronted
                    );
                    return Some(ws);
                }
                Err(e) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ldebug!(
                        "WS pool connect {}{} via {} (fronting={}): {}",
                        domain,
                        path,
                        target_ip,
                        fronted,
                        e.compact()
                    );
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// CfWorkerPool — порт proxy/pool.py::_CfWorkerPool
// ---------------------------------------------------------------------------

struct CfWorkerEntry {
    ws: RawWebSocket,
    created: f64,
    worker_domain: String,
}

#[derive(Default)]
struct CfWorkerState {
    idle: HashMap<i32, VecDeque<CfWorkerEntry>>,
    refilling: HashMap<i32, u64>,
    rotating: HashSet<i32>,
    refill_failures: HashMap<i32, u32>,
    refill_after: HashMap<i32, f64>,
    // домен воркера -> (до какого момента пауза, дневной лимит 429)
    exhausted_until: HashMap<String, (f64, bool)>,
}

impl CfWorkerState {
    /// Все воркеры на паузе — откладываем refill до ближайшего освобождения.
    fn defer_if_all_workers_paused(&mut self, dc: i32, worker_domains: &[String], now: f64) -> bool {
        let first_available = worker_domains
            .iter()
            .map(|d| self.exhausted_until.get(d).map_or(now, |e| e.0))
            .fold(f64::INFINITY, f64::min);
        if first_available <= now {
            return false;
        }
        self.refill_after.insert(dc, first_available);
        true
    }
}

pub struct CfWorkerPool {
    state: SyncMutex<CfWorkerState>,
    try_secure_first: AtomicBool,
    next_gen: AtomicU64,
    cancel: CancellationToken,
}

fn cf_worker_target_size() -> usize {
    pool_size().min(CF_WORKER_PER_DC_LIMIT)
}

impl CfWorkerPool {
    pub fn new(cancel: CancellationToken) -> CfWorkerPool {
        CfWorkerPool {
            state: SyncMutex::new(CfWorkerState::default()),
            try_secure_first: AtomicBool::new(true),
            next_gen: AtomicU64::new(1),
            cancel,
        }
    }

    pub fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: &str,
        worker_domains: &[String],
    ) -> Option<(RawWebSocket, String)> {
        if pool_size() == 0 || worker_domains.is_empty() {
            return None;
        }
        let now = now_monotonic();
        let mut stale = Vec::new();
        let hit = {
            let mut st = self.state.lock();
            let bucket = st.idle.entry(dc).or_default();
            let mut hit = None;
            while let Some(e) = bucket.pop_front() {
                if entry_stale(&e.ws, e.created, now, CF_WORKER_POOL_MAX_AGE) {
                    stale.push(e.ws);
                    continue;
                }
                hit = Some((e, bucket.len()));
                break;
            }
            hit
        };
        for ws in stale {
            close_later(ws);
        }
        let result = match hit {
            Some((e, left)) => {
                STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "CF worker pool hit DC{} via {} (age={:.1}s, left={})",
                    dc,
                    e.worker_domain,
                    now - e.created,
                    left
                );
                Some((e.ws, e.worker_domain))
            }
            None => {
                STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        };
        self.schedule_refill(dc, fallback_dst.to_string(), worker_domains.to_vec());
        result
    }

    fn schedule_refill(self: &Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        if pool_size() == 0 || worker_domains.is_empty() || self.cancel.is_cancelled() || network_down() {
            return;
        }
        self.schedule_rotation(dc, fallback_dst.clone(), worker_domains.clone());
        let now = now_monotonic();
        let gen = {
            let mut st = self.state.lock();
            if st.refilling.contains_key(&dc)
                || st.defer_if_all_workers_paused(dc, &worker_domains, now)
                || now < st.refill_after.get(&dc).copied().unwrap_or(0.0)
            {
                return;
            }
            let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
            st.refilling.insert(dc, gen);
            gen
        };
        let pool = self.clone();
        tokio::spawn(async move {
            pool.refill(dc, fallback_dst, worker_domains, gen).await;
        });
    }

    async fn refill(self: Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>, gen: u64) {
        let needed = {
            let st = self.state.lock();
            cf_worker_target_size().saturating_sub(st.idle.get(&dc).map_or(0, |b| b.len()))
        };
        let mut aborted = false;
        let mut connected = 0usize;
        for _ in 0..needed {
            let result = tokio::select! {
                _ = self.cancel.cancelled() => { aborted = true; break; }
                r = self.connect_one(&worker_domains, &fallback_dst, dc, CF_WORKER_CONNECT_TIMEOUT) => r,
            };
            let mut st = self.state.lock();
            if st.refilling.get(&dc) != Some(&gen) {
                drop(st);
                if let Some((ws, _)) = result {
                    close_later(ws);
                }
                aborted = true;
                break;
            }
            match result {
                None => break,
                Some((ws, worker_domain)) => {
                    st.idle.entry(dc).or_default().push_back(CfWorkerEntry {
                        ws,
                        created: now_monotonic(),
                        worker_domain,
                    });
                    connected += 1;
                }
            }
        }
        if needed > 0 && !aborted {
            let now = now_monotonic();
            let mut st = self.state.lock();
            if connected > 0 {
                st.refill_failures.remove(&dc);
                st.refill_after.remove(&dc);
            } else if !should_record_failure(None) {
                st.refill_after.insert(dc, now + 5.0);
            } else if !st.defer_if_all_workers_paused(dc, &worker_domains, now) {
                let failures = st.refill_failures.get(&dc).copied().unwrap_or(0) + 1;
                st.refill_failures.insert(dc, failures);
                let delay = backoff_delay(
                    WS_POOL_REFILL_BACKOFF_INITIAL,
                    failures,
                    12,
                    WS_POOL_REFILL_BACKOFF_MAX,
                );
                st.refill_after.insert(dc, now + delay);
                drop(st);
                linfo!("CF worker pool refill failed for DC{}, retry in {:.0}s", dc, delay);
            }
            let ready = self.state.lock().idle.get(&dc).map_or(0, |b| b.len());
            ldebug!("CF worker pool refilled DC{}: {} ready", dc, ready);
        }
        let mut st = self.state.lock();
        if st.refilling.get(&dc) == Some(&gen) {
            st.refilling.remove(&dc);
        }
    }

    fn schedule_rotation(self: &Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        {
            let mut st = self.state.lock();
            if !st.rotating.insert(dc) {
                return;
            }
        }
        let pool = self.clone();
        tokio::spawn(async move {
            pool.rotate(dc, fallback_dst, worker_domains).await;
        });
    }

    async fn rotate(self: Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        while pool_size() > 0 && !self.cancel.is_cancelled() {
            let now = now_monotonic();
            let (expired, ready, wake_at) = {
                let mut st = self.state.lock();
                let bucket = st.idle.entry(dc).or_default();
                let mut expired = Vec::new();
                let mut keep = VecDeque::with_capacity(bucket.len());
                while let Some(e) = bucket.pop_front() {
                    if entry_stale(&e.ws, e.created, now, CF_WORKER_POOL_MAX_AGE) {
                        expired.push(e.ws);
                    } else {
                        keep.push_back(e);
                    }
                }
                let mut wake_at = now + CF_WORKER_POOL_CHECK_INTERVAL;
                for e in &keep {
                    wake_at = wake_at.min(e.created + CF_WORKER_POOL_MAX_AGE);
                }
                *bucket = keep;
                let ready = bucket.len();
                let after = st.refill_after.get(&dc).copied().unwrap_or(0.0);
                if !st.refilling.contains_key(&dc) && after > now {
                    wake_at = wake_at.min(after);
                }
                (expired, ready, wake_at)
            };
            if !expired.is_empty() {
                ldebug!(
                    "CF worker pool rotated DC{}: {} stale, {} ready",
                    dc,
                    expired.len(),
                    ready
                );
                for ws in expired {
                    close_later(ws);
                }
            }
            if ready < cf_worker_target_size() {
                self.schedule_refill(dc, fallback_dst.clone(), worker_domains.clone());
            }
            let sleep_for = (wake_at - now_monotonic()).max(0.0);
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_for)) => {}
            }
        }
        self.state.lock().rotating.remove(&dc);
    }

    /// _CfWorkerPool.connect_one: перебор доступных воркеров; для каждого —
    /// TLS и HTTP (переключение на другой режим только после таймаута).
    pub async fn connect_one(
        &self,
        worker_domains: &[String],
        fallback_dst: &str,
        dc: i32,
        timeout: f64,
    ) -> Option<(RawWebSocket, String)> {
        let path = format!("/apiws?dst={}&dc={}", fallback_dst, dc);
        let modes: Vec<bool> = if DISABLE_SECURE.load(Ordering::Relaxed) {
            vec![false]
        } else {
            let first = self.try_secure_first.load(Ordering::Relaxed);
            vec![first, !first]
        };
        for worker_domain in self.available_domains(worker_domains) {
            for (attempt, &secure) in modes.iter().enumerate() {
                let res = tokio::time::timeout(
                    Duration::from_secs_f64(timeout),
                    ws_connect_full_opts(
                        &worker_domain,
                        &worker_domain,
                        &path,
                        timeout,
                        None,
                        Some(secure),
                        CF_DPI_SPLIT.load(Ordering::Relaxed),
                    ),
                )
                .await
                .unwrap_or(Err(WsError::Timeout));
                match res {
                    Ok(ws) => {
                        self.try_secure_first.store(secure, Ordering::Relaxed);
                        return Some((ws, worker_domain));
                    }
                    Err(e) => {
                        ldebug!(
                            "CF worker connect DC{} via {} for {} failed (tls={}): {}",
                            dc,
                            worker_domain,
                            fallback_dst,
                            secure,
                            e.compact()
                        );
                        if attempt + 1 < modes.len() && e.is_timeout() {
                            continue;
                        }
                        self.report_failure(&worker_domain, &e);
                        break;
                    }
                }
            }
        }
        None
    }

    pub fn available_domains(&self, worker_domains: &[String]) -> Vec<String> {
        let now = now_monotonic();
        let mut st = self.state.lock();
        let mut domains: Vec<String> = Vec::new();
        for domain in worker_domains {
            if domains.contains(domain) {
                continue;
            }
            let until = st.exhausted_until.get(domain).map_or(0.0, |e| e.0);
            if until > now {
                continue;
            }
            if until > 0.0 {
                st.exhausted_until.remove(domain);
            }
            domains.push(domain.clone());
        }
        drop(st);
        use rand::seq::SliceRandom;
        domains.shuffle(&mut rand::thread_rng());
        domains
    }

    /// _CfWorkerPool.report_failure: 429 на бесплатном тарифе Workers —
    /// исчерпан дневной лимит запросов (пауза до 00:00 UTC); 5xx и сетевые
    /// ошибки — пауза 60с. Челлендж/кривой маршрут домен не выключают.
    pub fn report_failure(&self, worker_domain: &str, err: &WsError) {
        let now = now_monotonic();
        let (until, reason, daily) = match err {
            WsError::Handshake(h) if h.status_code == 429 => {
                let secs_left = 86400.0 - (now_unix_f64() % 86400.0);
                (now + secs_left, "daily request limit".to_string(), true)
            }
            WsError::Handshake(h) if h.status_code >= 500 => {
                (now + CF_WORKER_FAILURE_COOLDOWN, format!("HTTP {}", h.status_code), false)
            }
            WsError::Handshake(_) => return,
            WsError::Io(e) if !should_record_failure(Some(e)) => return,
            WsError::Timeout if !should_record_failure(None) => return,
            WsError::Io(_) | WsError::Timeout => (now + CF_WORKER_FAILURE_COOLDOWN, err.compact(), false),
            _ => return,
        };
        {
            let mut st = self.state.lock();
            if st.exhausted_until.get(worker_domain).map_or(0.0, |e| e.0) > now {
                return;
            }
            st.exhausted_until.insert(worker_domain.to_string(), (until, daily));
        }
        lwarn!(
            "CF worker {} disabled for {} seconds: {}",
            worker_domain,
            ((until - now) as i64).max(1),
            reason
        );
    }

    /// Сброс пауз после возвращения сети / включения экрана. Дневной лимит
    /// воркера (429) не сбрасывается — он от сети не зависит.
    pub fn reset_backoff(&self) {
        let mut st = self.state.lock();
        st.refill_failures.clear();
        st.refill_after.clear();
        st.exhausted_until.retain(|_, (_, daily)| *daily);
    }

    pub fn warmup(self: &Arc<Self>, log: bool) {
        let worker_domains = CF_WORKER_DOMAINS.read().clone();
        if pool_size() == 0 || worker_domains.is_empty() {
            return;
        }
        let fallbacks: Vec<(i32, String)> = {
            let map = DC_OPT.read();
            DC_DEFAULT_IPS
                .iter()
                .filter(|(dc, _)| !map.contains_key(dc))
                .map(|(dc, ip)| (*dc, ip.to_string()))
                .collect()
        };
        if fallbacks.is_empty() {
            return;
        }
        for (dc, fallback_dst) in &fallbacks {
            self.schedule_refill(*dc, fallback_dst.clone(), worker_domains.clone());
        }
        if log {
            linfo!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
        }
    }

    pub fn close_all(&self) {
        let entries: Vec<CfWorkerEntry> = {
            let mut st = self.state.lock();
            st.idle.drain().flat_map(|(_, b)| b.into_iter()).collect()
        };
        for e in entries {
            close_later(e.ws);
        }
    }

    pub fn reset(&self) {
        self.close_all();
        *self.state.lock() = CfWorkerState::default();
        self.try_secure_first.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Shared pools (WS + CF worker)
// ---------------------------------------------------------------------------

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
}

impl ProxyPools {
    pub fn new(cancel_token: CancellationToken) -> Self {
        ProxyPools {
            ws: Arc::new(WsPool::new(cancel_token.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel_token)),
        }
    }

    pub fn warmup(&self, log: bool) {
        self.ws.warmup(log);
        self.cf_worker.warmup(log);
    }

    pub fn close_all(&self) {
        self.ws.close_all();
        self.cf_worker.close_all();
    }

    pub fn reset(&self) {
        self.ws.reset();
        self.cf_worker.reset();
    }

    pub fn reset_backoff(&self) {
        self.ws.reset_backoff();
        self.cf_worker.reset_backoff();
    }
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridges
// ---------------------------------------------------------------------------

/// Монотонные миллисекунды для отметок активности сессии.
fn now_ms() -> u64 {
    (now_monotonic() * 1000.0) as u64
}

fn idle_for(last_activity: &AtomicU64) -> Duration {
    Duration::from_millis(now_ms().saturating_sub(last_activity.load(Ordering::Relaxed)))
}

pub struct CryptoCtx {
    pub clt_dec: TrackedStream,
    pub clt_enc: TrackedStream,
    pub tg_enc: TrackedStream,
    pub tg_dec: TrackedStream,
}

impl CryptoCtx {
    fn fork(&self) -> CryptoCtx {
        CryptoCtx {
            clt_dec: self.clt_dec.clone_state(),
            clt_enc: self.clt_enc.clone_state(),
            tg_enc: self.tg_enc.clone_state(),
            tg_dec: self.tg_dec.clone_state(),
        }
    }
}

/// bridge_ws_reencrypt: клиент <-> WS с перешифровкой и сессионной статистикой.
/// Сессию закрывает первая завершившаяся сторона ("липкая" отмена через
/// CancellationToken — уведомление не теряется, как было с Notify).
pub async fn bridge_ws<R, W>(
    mut conn_read: R,
    mut conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    ctx: CryptoCtx,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let CryptoCtx {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ctx;
    let dc_tag = format!("DC{}{}", dc, if is_media { "m" } else { "" });
    let ws = Arc::new(ws);
    let session = cancel_token.child_token();
    let last_activity = Arc::new(AtomicU64::new(now_ms()));
    let start = now_monotonic();

    // WS ping при простое: Cloudflare рвёт молчащие WebSocket примерно через
    // 100с, мобильные NAT — ещё раньше (доработка форка поверх оригинала).
    let ping_task = {
        let ws = ws.clone();
        let session = session.clone();
        let last_activity = last_activity.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(BRIDGE_PING_INTERVAL);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = session.cancelled() => return,
                    _ = interval.tick() => {
                        if idle_for(&last_activity) >= BRIDGE_PING_INTERVAL
                            && ws.send_ping().await.is_err()
                        {
                            session.cancel();
                            return;
                        }
                    }
                }
            }
        })
    };

    let up_task = {
        let ws = ws.clone();
        let session = session.clone();
        let last_activity = last_activity.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
            // Открытый текст куска (для границ пакетов) и собранные WS-фреймы —
            // переиспользуемые буферы, без аллокаций на каждый пакет.
            let mut plain: Vec<u8> = Vec::with_capacity(if splitter.is_some() { WS_BRIDGE_CHUNK_SIZE } else { 0 });
            let mut frames: Vec<u8> = Vec::with_capacity(WS_BRIDGE_CHUNK_SIZE + 1024);
            let mut bytes = 0i64;
            let mut packets = 0i64;
            let mut reason = String::new();
            loop {
                let read_res = tokio::select! {
                    _ = session.cancelled() => break,
                    r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, conn_read.read(&mut buf)) => r,
                };
                let n = match read_res {
                    Ok(Ok(0)) => {
                        if let Some(sp) = splitter.as_mut() {
                            let tail = sp.flush();
                            if !tail.is_empty() && ws.send_batch(&tail).await.is_err() {
                                reason = "upstream: send_failed".to_string();
                            }
                        }
                        break;
                    }
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        reason = format!("client: {:?}", e.kind());
                        break;
                    }
                    Err(_) => {
                        // Тишина от клиента не страшна, пока идут данные вниз.
                        if idle_for(&last_activity) >= BRIDGE_READ_TIMEOUT {
                            reason = "idle".to_string();
                            break;
                        }
                        continue;
                    }
                };
                let chunk = &mut buf[..n];
                STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
                bytes += n as i64;
                packets += 1;
                last_activity.store(now_ms(), Ordering::Relaxed);

                clt_dec.xor(chunk);
                frames.clear();
                match splitter.as_mut() {
                    Some(sp) => {
                        plain.clear();
                        plain.extend_from_slice(chunk);
                        tg_enc.xor(chunk);
                        sp.split_with(chunk, &plain, |part| append_frame(&mut frames, OP_BINARY, part));
                    }
                    None => {
                        tg_enc.xor(chunk);
                        append_frame(&mut frames, OP_BINARY, chunk);
                    }
                }
                let sent = ws.send_raw_frames(&frames).await;
                if sent.is_err() {
                    reason = "upstream: send_failed".to_string();
                    break;
                }
            }
            session.cancel();
            (bytes, packets, reason)
        })
    };

    let down_task = {
        let ws = ws.clone();
        let session = session.clone();
        let last_activity = last_activity.clone();
        tokio::spawn(async move {
            let mut bytes = 0i64;
            let mut packets = 0i64;
            let mut reason = String::new();
            loop {
                let recv_res = tokio::select! {
                    _ = session.cancelled() => break,
                    r = ws.recv() => r,
                };
                let mut data = match recv_res {
                    Ok(d) => d,
                    Err(WsError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        reason = "upstream: ws_close".to_string();
                        break;
                    }
                    Err(e) => {
                        reason = format!("upstream: {}", e.compact());
                        break;
                    }
                };
                let n = data.len();
                STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
                bytes += n as i64;
                packets += 1;
                last_activity.store(now_ms(), Ordering::Relaxed);

                tg_dec.xor(&mut data);
                clt_enc.xor(&mut data);
                // flush нужен FakeTLS-обёртке: хвост записи может ждать в буфере.
                if conn_write.write_all(&data).await.is_err() || conn_write.flush().await.is_err() {
                    reason = "client: write_failed".to_string();
                    break;
                }
            }
            let _ = conn_write.shutdown().await;
            session.cancel();
            (bytes, packets, reason)
        })
    };

    let (up_bytes, up_packets, up_reason) = up_task.await.unwrap_or((0, 0, String::new()));
    let (down_bytes, down_packets, down_reason) = down_task.await.unwrap_or((0, 0, String::new()));
    session.cancel();
    ping_task.abort();

    let close_reason = if !down_reason.is_empty() {
        down_reason
    } else if !up_reason.is_empty() {
        up_reason
    } else if cancel_token.is_cancelled() {
        "proxy stopped".to_string()
    } else {
        "normal".to_string()
    };
    linfo!(
        "[{}] {} WS session closed ({}): ^{} ({} pkts) v{} ({} pkts) in {:.1}s",
        label,
        dc_tag,
        close_reason,
        human_bytes(up_bytes),
        up_packets,
        human_bytes(down_bytes),
        down_packets,
        now_monotonic() - start
    );

    ws.close().await;
}

/// _bridge_tcp_reencrypt: клиент <-> прямой TCP к DC.
pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    remote: TcpStream,
    ctx: CryptoCtx,
    label: String,
    cancel_token: CancellationToken,
) where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let CryptoCtx {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ctx;
    let (mut r_read, mut r_write) = remote.into_split();
    let session = cancel_token.child_token();
    let last_activity = Arc::new(AtomicU64::new(now_ms()));
    let start = now_monotonic();

    let up = {
        let session = session.clone();
        let last_activity = last_activity.clone();
        async move {
            let mut buf = vec![0u8; 128 * 1024];
            let mut total = 0i64;
            loop {
                let n = tokio::select! {
                    _ = session.cancelled() => break,
                    r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, c_read.read(&mut buf)) => match r {
                        Ok(Ok(0)) | Ok(Err(_)) => break,
                        Ok(Ok(n)) => n,
                        Err(_) => {
                            if idle_for(&last_activity) >= BRIDGE_READ_TIMEOUT { break; }
                            continue;
                        }
                    },
                };
                let chunk = &mut buf[..n];
                STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
                total += n as i64;
                last_activity.store(now_ms(), Ordering::Relaxed);
                clt_dec.xor(chunk);
                tg_enc.xor(chunk);
                if r_write.write_all(chunk).await.is_err() {
                    break;
                }
            }
            let _ = r_write.shutdown().await;
            session.cancel();
            total
        }
    };

    let down = {
        let session = session.clone();
        let last_activity = last_activity.clone();
        async move {
            let mut buf = vec![0u8; 128 * 1024];
            let mut total = 0i64;
            loop {
                let n = tokio::select! {
                    _ = session.cancelled() => break,
                    r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, r_read.read(&mut buf)) => match r {
                        Ok(Ok(0)) | Ok(Err(_)) => break,
                        Ok(Ok(n)) => n,
                        Err(_) => {
                            if idle_for(&last_activity) >= BRIDGE_READ_TIMEOUT { break; }
                            continue;
                        }
                    },
                };
                let chunk = &mut buf[..n];
                STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
                total += n as i64;
                last_activity.store(now_ms(), Ordering::Relaxed);
                tg_dec.xor(chunk);
                clt_enc.xor(chunk);
                if c_write.write_all(chunk).await.is_err() || c_write.flush().await.is_err() {
                    break;
                }
            }
            let _ = c_write.shutdown().await;
            session.cancel();
            total
        }
    };

    let (up_bytes, down_bytes) = tokio::join!(up, down);
    linfo!(
        "[{}] TCP session closed: ^{} v{} in {:.1}s",
        label,
        human_bytes(up_bytes),
        human_bytes(down_bytes),
        now_monotonic() - start
    );
}

// ---------------------------------------------------------------------------
// Fallbacks — порт proxy/bridge.py: cf_worker -> cf -> tcp.
// Каждый способ сначала добывает upstream, не трогая клиента; клиентские
// halves уходят в bridge только при успехе, иначе — к следующему способу.
// ---------------------------------------------------------------------------

struct TcpBackoff {
    failures: HashMap<(String, u16), u32>,
    retry_after: HashMap<(String, u16), f64>,
    connecting: HashSet<(String, u16)>,
}

static TCP_BACKOFF: once_cell::sync::Lazy<SyncMutex<TcpBackoff>> = once_cell::sync::Lazy::new(|| {
    SyncMutex::new(TcpBackoff {
        failures: HashMap::new(),
        retry_after: HashMap::new(),
        connecting: HashSet::new(),
    })
});

pub fn reset_tcp_backoff() {
    let mut b = TCP_BACKOFF.lock();
    b.failures.clear();
    b.retry_after.clear();
    b.connecting.clear();
}

/// bridge._tcp_fallback: прямое TCP к DC с экспоненциальным backoff
/// (30с..1ч) и без параллельных попыток к одному адресу.
async fn tcp_fallback_connect(dst: &str, port: u16, relay_init: &[u8], label: &str) -> Option<TcpStream> {
    let key = (dst.to_string(), port);
    {
        let mut b = TCP_BACKOFF.lock();
        if b.connecting.contains(&key) || now_monotonic() < b.retry_after.get(&key).copied().unwrap_or(0.0) {
            ldebug!("[{}] TCP fallback to {}:{} skipped (backoff or connecting)", label, dst, port);
            return None;
        }
        b.connecting.insert(key.clone());
    }
    linfo!("[{}] TCP fallback to {}:{}", label, dst, port);
    let attempt = async {
        let mut remote = TcpStream::connect((dst, port)).await?;
        let _ = remote.set_nodelay(true);
        remote.write_all(relay_init).await?;
        Ok::<TcpStream, std::io::Error>(remote)
    };
    let result = match tokio::time::timeout(Duration::from_secs(10), attempt).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err((e.to_string(), should_record_failure(Some(&e)))),
        Err(_) => Err(("timeout".to_string(), should_record_failure(None))),
    };
    let mut b = TCP_BACKOFF.lock();
    b.connecting.remove(&key);
    match result {
        Ok(remote) => {
            b.failures.remove(&key);
            b.retry_after.remove(&key);
            Some(remote)
        }
        Err((e, false)) => {
            drop(b);
            ldebug!("[{}] TCP fallback to {}:{} failed without network: {}", label, dst, port, e);
            None
        }
        Err((e, true)) => {
            let failures = b.failures.get(&key).copied().unwrap_or(0) + 1;
            b.failures.insert(key.clone(), failures);
            let delay = backoff_delay(TCP_BACKOFF_INITIAL, failures, 7, TCP_BACKOFF_MAX);
            b.retry_after.insert(key, now_monotonic() + delay);
            drop(b);
            lwarn!(
                "[{}] TCP fallback to {}:{} failed: {}; retry in {:.0}s",
                label, dst, port, e, delay
            );
            None
        }
    }
}

/// bridge._cfproxy_worker_fallback (без клиента): WS через Cloudflare Worker.
async fn cfproxy_worker_acquire(
    pools: &ProxyPools,
    label: &str,
    dc: i32,
    is_test: bool,
    is_media: bool,
    fallback_dst: &str,
    worker_domains: &[String],
) -> Option<RawWebSocket> {
    let m_tag = media_tag(is_media);
    let pooled = if is_test {
        None
    } else {
        pools.cf_worker.get(dc, fallback_dst, worker_domains)
    };
    if let Some((ws, worker_domain)) = pooled {
        linfo!(
            "[{}] DC{}{} -> CF worker pool hit via {} for {}",
            label, dc, m_tag, worker_domain, fallback_dst
        );
        return Some(ws);
    }
    let (ws, worker_domain) = pools
        .cf_worker
        .connect_one(worker_domains, fallback_dst, dc, CF_WORKER_FALLBACK_TIMEOUT)
        .await?;
    linfo!(
        "[{}] DC{}{} -> CF worker {} for {}",
        label, dc, m_tag, worker_domain, fallback_dst
    );
    Some(ws)
}

// Холодный перебор CF для DC делает одно соединение; одновременные (Telegram
// открывает по 3–4 сразу) ждут его и идут к победителю, а не запускают каждое
// свой перебор. Пока для DC есть недавний успех, соединения идут параллельно.
static CF_DIAL_LOCKS: once_cell::sync::Lazy<SyncMutex<HashMap<i32, Arc<tokio::sync::Mutex<()>>>>> =
    once_cell::sync::Lazy::new(|| SyncMutex::new(HashMap::new()));
static CF_LAST_OK: once_cell::sync::Lazy<SyncMutex<HashMap<i32, f64>>> =
    once_cell::sync::Lazy::new(|| SyncMutex::new(HashMap::new()));
const CF_WARM_WINDOW: f64 = 120.0;

fn cf_recently_ok(dc: i32) -> bool {
    CF_LAST_OK
        .lock()
        .get(&dc)
        .is_some_and(|t| now_monotonic() - *t < CF_WARM_WINDOW)
}

pub fn reset_cf_dial_state() {
    CF_LAST_OK.lock().clear();
}

/// bridge._cfproxy_fallback (без клиента): WS к kwsN.<домен> через CF proxy.
async fn cfproxy_acquire(label: &str, dc: i32, is_media: bool) -> Option<RawWebSocket> {
    let _cold_guard = if cf_recently_ok(dc) {
        None
    } else {
        let lock = CF_DIAL_LOCKS.lock().entry(dc).or_default().clone();
        Some(lock.lock_owned().await)
    };
    let ws = cfproxy_acquire_inner(label, dc, is_media).await;
    if ws.is_some() {
        CF_LAST_OK.lock().insert(dc, now_monotonic());
    }
    ws
}

async fn cfproxy_acquire_inner(label: &str, dc: i32, is_media: bool) -> Option<RawWebSocket> {
    let candidates: Vec<(String, String)> = crate::balancer::BALANCER
        .read()
        .get_domains_for_dc(dc)
        .into_iter()
        .map(|base| {
            let host = format!("kws{}.{}", dc, base);
            (base, host)
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    linfo!("[{}] DC{}{} -> trying CF proxy", label, dc, media_tag(is_media));
    let started = now_monotonic();
    let secure = !DISABLE_SECURE.load(Ordering::Relaxed);
    let (ws, chosen) = connect_cf_domains(candidates, label, secure, WS_PATH, CF_CONNECT_TIMEOUT).await?;
    ldebug!(
        "[{}] WS CONNECT DC{}{} route=cf setup_ms={:.0}",
        label,
        dc,
        media_tag(is_media),
        (now_monotonic() - started) * 1000.0
    );
    if crate::balancer::BALANCER.write().update_domain_for_dc(dc, &chosen) {
        linfo!("[{}] Switched active CF domain", label);
    }
    Some(ws)
}

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: &str,
    dc: i32,
    is_test: bool,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    ctx: &CryptoCtx,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let fallback_dst = resolve_fallback_target(dc, is_test);
    let use_cf = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();

    // 1. Cloudflare Worker
    if !worker_domains.is_empty() && !fallback_dst.is_empty() {
        if let Some(ws) =
            cfproxy_worker_acquire(pools, label, dc, is_test, is_media, &fallback_dst, &worker_domains).await
        {
            if ws.send_init(relay_init).await.is_ok() {
                STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                // Оригинал: для воркера splitter не используется.
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label.to_string(),
                    dc,
                    is_media,
                    None,
                    ctx.fork(),
                    cancel_token,
                )
                .await;
                return true;
            }
            lwarn!("[{}] DC{} CF worker: relay init failed", label, dc);
            ws.close().await;
        }
    }

    // 2. Cloudflare proxy
    if use_cf {
        if let Some(ws) = cfproxy_acquire(label, dc, is_media).await {
            if ws.send_init(relay_init).await.is_ok() {
                STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label.to_string(),
                    dc,
                    is_media,
                    splitter,
                    ctx.fork(),
                    cancel_token,
                )
                .await;
                return true;
            }
            lwarn!("[{}] DC{} CF proxy: relay init failed", label, dc);
            ws.close().await;
        }
    }

    // 3. Прямой TCP к DC (порт 80 только если пользователь выключил TLS).
    if !fallback_dst.is_empty() {
        let port = if DISABLE_SECURE.load(Ordering::Relaxed) { 80 } else { 443 };
        if let Some(remote) = tcp_fallback_connect(&fallback_dst, port, relay_init, label).await {
            STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
            bridge_tcp(
                conn_read,
                conn_write,
                remote,
                ctx.fork(),
                label.to_string(),
                cancel_token,
            )
            .await;
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' || line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

/// Сколько секунд после подключения следить, не ушёл ли Telegram, пока мы
/// ещё дозваниваемся до Telegram/Cloudflare.
const CLIENT_SETUP_WATCH: Duration = Duration::from_secs(25);

/// Порт client_setup оригинала (13d764f «Socket occupation fix»), реализация
/// по мотивам Alexingin/tg-ws-proxy-android: Telegram часто бросает соединение,
/// не дождавшись маршрута (сменил сеть, переподключился). Если клиент закрыл
/// сокет, пока мы дозваниваемся, дозвон отменяется — не держим сокеты зря и
/// не плодим сотни висящих попыток. Слежение событийное (epoll RDHUP по dup
/// сокета), без опроса.
#[cfg(unix)]
fn spawn_client_watch(conn: &TcpStream, gone: CancellationToken, stop: CancellationToken) {
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    let dup = match socket2::SockRef::from(conn).try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::spawn(async move {
        let afd = match AsyncFd::with_interest(dup, Interest::READABLE) {
            Ok(a) => a,
            Err(_) => return,
        };
        let deadline = tokio::time::sleep(CLIENT_SETUP_WATCH);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = &mut deadline => return,
                r = afd.readable() => {
                    let mut guard = match r {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    if guard.ready().is_read_closed() {
                        gone.cancel();
                        return;
                    }
                    guard.clear_ready();
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_client_watch(_conn: &TcpStream, _gone: CancellationToken, _stop: CancellationToken) {}

pub async fn handle_client(pools: Arc<ProxyPools>, conn: TcpStream, cancel_token: CancellationToken) {
    let gone = CancellationToken::new();
    let watch_stop = CancellationToken::new();
    spawn_client_watch(&conn, gone.clone(), watch_stop.clone());
    let _watch_guard = watch_stop.drop_guard();
    tokio::select! {
        _ = handle_client_inner(pools, conn, cancel_token) => {}
        _ = gone.cancelled() => {
            ldebug!("client closed the connection before the route was ready; dial cancelled");
        }
    }
}

async fn handle_client_inner(pools: Arc<ProxyPools>, mut conn: TcpStream, cancel_token: CancellationToken) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard;

    let mut label = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let _ = conn.set_nodelay(true);

    let secret_bytes = hex::decode(PROXY_SECRET.read().as_str()).unwrap_or_default();

    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!(
                        "[{}] expected PROXY header, got: {:?}",
                        label,
                        text.chars().take(60).collect::<String>()
                    );
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            if let Some(plain) = faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await {
                serve_core(&pools, plain.read, plain.write, label, secret_bytes, cancel_token).await;
            }
            return;
        }
        ldebug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first[0]);
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            masking
        );
        let _ = conn.write_all(redirect.as_bytes()).await;
        return;
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(&pools, conn_read, conn_write, label, secret_bytes, cancel_token).await;
}

/// Неверный secret/протокол: дочитываем немного и закрываем, чтобы поведение
/// не отличалось от обычного сервера (с лимитом объёма и времени).
async fn drain_bad_handshake<R: AsyncReadExt + Unpin>(reader: &mut R) {
    let drain = async {
        let mut remaining = BAD_HANDSHAKE_DRAIN_LIMIT;
        let mut buf = [0u8; 4096];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            match reader.read(&mut buf[..want]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => remaining -= n,
            }
        }
    };
    let _ = tokio::time::timeout(BAD_HANDSHAKE_DRAIN_TIMEOUT, drain).await;
}

/// relay_init для соединения к Telegram (proxy/tg_ws_proxy._generate_relay_init).
fn generate_relay_init(proto_tag: &[u8], dc_idx: i16) -> ([u8; 64], TrackedStream, TrackedStream) {
    let mut relay_init = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == RESERVED_FIRST_BYTE
            || is_reserved_start(&relay_init[..4])
            || relay_init[4..8] == [0, 0, 0, 0]
        {
            continue;
        }
        break;
    }

    let mut tg_dec_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
    }
    let mut tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
    let tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    LittleEndian::write_u16(&mut tail_plain[4..6], dc_idx as u16);
    rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

    // Шифруем весь буфер, чтобы продвинуть keystream ровно на 64 байта, и
    // подменяем хвост на зашифрованные proto_tag + dc_idx + random.
    let mut encrypted_full = relay_init;
    tg_encryptor.xor(&mut encrypted_full);
    for i in 0..8 {
        let keystream = encrypted_full[56 + i] ^ relay_init[56 + i];
        relay_init[56 + i] = tail_plain[i] ^ keystream;
    }
    (relay_init, tg_encryptor, tg_decryptor)
}

/// tg_ws_proxy._try_handshake: расшифровка 64-байтного obfuscated2-init.
/// Возвращает (dc без знака, is_media, proto_tag, clt_dec, clt_enc); оба
/// шифратора уже учли 64 байта init.
fn try_handshake(
    handshake: &[u8; HANDSHAKE_LEN],
    secret: &[u8],
) -> Option<(i32, bool, [u8; 4], TrackedStream, TrackedStream)> {
    let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hash_dec = Sha256::new();
    hash_dec.update(prekey);
    hash_dec.update(secret);
    let mut clt_dec = new_aes_ctr(&hash_dec.finalize(), iv);

    let mut decrypted = *handshake;
    clt_dec.xor(&mut decrypted);

    let proto_tag: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?;
    if !valid_proto(LittleEndian::read_u32(&proto_tag)) {
        return None;
    }
    let dc_raw = LittleEndian::read_u16(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]) as i16;

    // Обратное направление: prekey+iv в обратном порядке.
    let mut rev = [0u8; PREKEY_LEN + IV_LEN];
    for i in 0..rev.len() {
        rev[i] = handshake[SKIP_LEN + PREKEY_LEN + IV_LEN - 1 - i];
    }
    let mut hash_enc = Sha256::new();
    hash_enc.update(&rev[..PREKEY_LEN]);
    hash_enc.update(secret);
    let clt_enc = new_aes_ctr(&hash_enc.finalize(), &rev[PREKEY_LEN..]);

    Some(((dc_raw as i32).abs(), dc_raw < 0, proto_tag, clt_dec, clt_enc))
}

/// Ядро обслуживания: 64-байтный handshake -> WS из пула или fallback.
/// Generic над транспортом (TcpStream-halves или FakeTLS-halves).
async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let mut handshake = [0u8; HANDSHAKE_LEN];
    match tokio::time::timeout(Duration::from_secs(10), conn_read.read_exact(&mut handshake)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
        Err(_) => {
            lwarn!("[{}] timeout during handshake", label);
            return;
        }
    }

    if is_http_transport(&handshake) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    let (mut dc, is_media, proto_tag, clt_decryptor, clt_encryptor) = match try_handshake(&handshake, &secret_bytes) {
        Some(v) => v,
        None => {
            STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
            lwarn!("[{}] bad handshake (wrong secret or proto)", label);
            drain_bad_handshake(&mut conn_read).await;
            return;
        }
    };
    let proto = LittleEndian::read_u32(&proto_tag);

    let is_test = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    let m_tag = media_tag(is_media);
    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto,
        if is_test { " test" } else { "" }
    );

    let dc_idx: i16 = if is_media { -(dc as i16) } else { dc as i16 };
    let (relay_init, tg_encryptor, tg_decryptor) = generate_relay_init(&proto_tag, dc_idx);

    let ctx = CryptoCtx {
        clt_dec: clt_decryptor,
        clt_enc: clt_encryptor,
        tg_enc: tg_encryptor,
        tg_dec: tg_decryptor,
    };

    let pooled = pools.ws.get(dc, is_media, is_test);
    let ws = match pooled {
        Some(ws) => {
            if ws.send_init(&relay_init).await.is_ok() {
                Some(ws)
            } else {
                // Мобильная доработка: протухший WS из пула не роняет клиента.
                lwarn!("[{}] DC{}{} pooled WS died on relay init -> fallback", label, dc, m_tag);
                ws.close().await;
                None
            }
        }
        None => None,
    };

    let ws = match ws {
        Some(ws) => ws,
        None => {
            linfo!("[{}] DC{}{} WS pool unavailable -> fallback", label, dc, m_tag);
            let splitter = MsgSplitter::new(proto);
            let ok = do_fallback(
                pools,
                conn_read,
                conn_write,
                &relay_init,
                &label,
                dc,
                is_test,
                is_media,
                splitter,
                &ctx,
                cancel_token,
            )
            .await;
            if ok {
                linfo!("[{}] DC{}{} fallback closed", label, dc, m_tag);
            } else {
                lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
            }
            return;
        }
    };

    linfo!("[{}] DC{}{} -> WS pool hit", label, dc, m_tag);
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);
    let splitter = MsgSplitter::new(proto);
    if splitter.is_some() {
        ldebug!("[{}] MsgSplitter activated for proto 0x{:08X}", label, proto);
    }
    bridge_ws(conn_read, conn_write, ws, label, dc, is_media, splitter, ctx, cancel_token).await;
}

// ---------------------------------------------------------------------------
// Поколения клиентских сессий: смена сети (Wi-Fi <-> LTE) закрывает все
// активные сессии разом — их сокеты привязаны к старой сети и иначе висели бы
// до таймаута, а Telegram сразу переподключится по новой.
// ---------------------------------------------------------------------------

static SESSIONS: once_cell::sync::Lazy<SyncMutex<Option<CancellationToken>>> =
    once_cell::sync::Lazy::new(|| SyncMutex::new(None));

fn session_token(root: &CancellationToken) -> CancellationToken {
    let mut current = SESSIONS.lock();
    match current.as_ref() {
        Some(gen) if !gen.is_cancelled() => gen.child_token(),
        _ => {
            let gen = root.child_token();
            *current = Some(gen.clone());
            gen.child_token()
        }
    }
}

/// Закрыть все активные клиентские сессии (новые получат новое поколение).
pub fn drop_active_sessions() -> usize {
    match SESSIONS.lock().take() {
        Some(gen) => {
            gen.cancel();
            1
        }
        None => 0,
    }
}

/// Сброс накопленных пауз маршрутов. `network_switched` — сеть сменилась:
/// тогда забываем и то, что «работало лучше» (TLS/HTTP, fronting, 429 CF).
pub fn reset_route_state(pools: &ProxyPools, network_switched: bool) {
    reset_tcp_backoff();
    pools.reset_backoff();
    crate::cfproxy::clear_cf_cooldowns(network_switched);
    if network_switched {
        reset_cf_dial_state();
        TRY_FRONTING_FIRST.store(false, Ordering::Relaxed);
        crate::cfproxy::clear_cfproxy_429_cooldowns();
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

fn log_startup_banner(host: &str, port: u16, dc_opt_map: &HashMap<i32, String>) {
    linfo!("{}", "=".repeat(60));
    linfo!("  TG WS Proxy (Android, Flowseal tg-ws-proxy {})", UPSTREAM_VERSION);
    linfo!("  Listening:     {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            if dc < 0 {
                linfo!("    DC{} media: {}", -dc, ip);
            } else {
                linfo!("    DC{}: {}", dc, ip);
            }
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        let user = CFPROXY.read().user_domain.trim().to_string();
        linfo!("  CF proxy:      enabled ({})", if user.is_empty() { "auto".to_string() } else { user });
    }
    let workers = CF_WORKER_DOMAINS.read().clone();
    if !workers.is_empty() {
        linfo!("  CF worker:     enabled ({})", workers.join(", "));
    }
    if DISABLE_SECURE.load(Ordering::Relaxed) {
        linfo!("  No secure:     enabled (port 80 for CF proxy/worker)");
    }
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        linfo!("  Test DC:       forced");
    }
    let ftls = FAKE_TLS_DOMAIN.read().clone();
    if !ftls.is_empty() {
        linfo!("  Fake TLS:      {}", ftls);
    }
    linfo!("  Pool size:     {}", pool_size());
    linfo!("{}", "=".repeat(60));
}

/// Временные ошибки accept() (обрыв клиента до accept) — не повод что-то делать.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    *DC_OPT.write() = dc_opt_map.clone();
    reset_tcp_backoff();
    reset_cf_timeouts();

    let user_cf = CFPROXY.read().user_domain.trim().to_string();
    if user_cf.is_empty() {
        start_cfproxy_refresh(cancel_root.clone());
    }

    log_startup_banner(&host, port, &dc_opt_map);

    // Профиль сайта маскировки для ServerHello (fake_tls.probe_appdata_len).
    faketls::set_profiled_appdata_len(None);
    let ftls = FAKE_TLS_DOMAIN.read().clone();
    if !ftls.is_empty() {
        let cancel = cancel_root.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                len = faketls::probe_appdata_len(&ftls, 443) => {
                    faketls::set_profiled_appdata_len(len);
                    match len {
                        Some(n) => linfo!("Fake TLS profile: first encrypted record {} bytes", n),
                        None => lwarn!("Fake TLS profile unavailable, ServerHello uses random record sizes"),
                    }
                }
            }
        });
    }

    pools.warmup(true);

    let cancel_stats = cancel_root.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_stats.cancelled() => return,
                _ = interval.tick() => linfo!("stats: {}", STATS.summary()),
            }
        }
    });

    let mut listener = listener;
    let mut accept_errors = 0u32;
    loop {
        let accept = tokio::select! {
            _ = cancel_root.cancelled() => break,
            a = listener.accept() => a,
        };
        match accept {
            Ok((conn, _)) => {
                accept_errors = 0;
                let p = pools.clone();
                let cancel = session_token(&cancel_root);
                tokio::spawn(async move {
                    // Остановка прокси обрывает и клиентов на стадии handshake.
                    let stop = cancel.clone();
                    tokio::select! {
                        _ = stop.cancelled() => {}
                        _ = handle_client(p, conn, cancel) => {}
                    }
                });
            }
            Err(e) if is_transient_accept_error(&e) => continue,
            Err(e) => {
                // EMFILE и т.п.: не крутим пустой цикл; если сокет умер
                // окончательно — пересоздаём его (listener watchdog оригинала).
                accept_errors += 1;
                ldebug!("accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                if accept_errors < LISTENER_MAX_ACCEPT_ERRORS {
                    continue;
                }
                lwarn!("Listening socket died ({}), restarting server", e);
                drop(listener);
                tokio::time::sleep(LISTENER_RESTART_DELAY).await;
                match TcpListener::bind((host.as_str(), port)).await {
                    Ok(l) => {
                        listener = l;
                        accept_errors = 0;
                        lwarn!("Server restored, listening on {}:{}", host, port);
                    }
                    Err(e) => {
                        crate::lerror!("Failed to restart server: {}", e);
                        cancel_root.cancel();
                        return Err(e);
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    pools.close_all();
    Ok(())
}

/// "2:149.154.167.220,4:149.154.167.220,-4:1.2.3.4" -> {dc: ip}.
pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    for pair in cidrs_str.split(',') {
        let mut parts = pair.splitn(2, ':');
        let (dc_raw, ip_raw) = match (parts.next(), parts.next()) {
            (Some(d), Some(i)) => (d.trim(), i.trim()),
            _ => continue,
        };
        let dc = match dc_raw.parse::<i32>() {
            Ok(dc) => dc,
            Err(_) => continue,
        };
        // inet_pton(AF_INET) как в оригинале: только IPv4.
        if let Ok(ip) = ip_raw.parse::<std::net::Ipv4Addr>() {
            result.insert(dc, ip.to_string());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_domains_match_upstream() {
        assert_eq!(ws_domains(2, false), vec!["kws2.web.telegram.org"]);
        assert_eq!(
            ws_domains(4, true),
            vec!["kws4-1.web.telegram.org", "kws4.web.telegram.org"]
        );
        // DC203 обслуживается через DC2.
        assert_eq!(ws_domains(203, false), vec!["kws2.web.telegram.org"]);
    }

    #[test]
    fn parse_dc_list() {
        let m = parse_cidr_pool("2:149.154.167.220, 4:149.154.167.220,-4:1.2.3.4,bad,5:not-an-ip,7:");
        assert_eq!(m.get(&2).map(String::as_str), Some("149.154.167.220"));
        assert_eq!(m.get(&4).map(String::as_str), Some("149.154.167.220"));
        assert_eq!(m.get(&-4).map(String::as_str), Some("1.2.3.4"));
        assert!(!m.contains_key(&5));
        assert!(!m.contains_key(&7));
        assert!(parse_cidr_pool("").is_empty());
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_delay(1.0, 1, 12, 3600.0), 1.0);
        assert_eq!(backoff_delay(1.0, 2, 12, 3600.0), 2.0);
        assert_eq!(backoff_delay(1.0, 13, 12, 3600.0), 3600.0);
        assert_eq!(backoff_delay(30.0, 1, 7, 3600.0), 30.0);
        assert_eq!(backoff_delay(30.0, 3, 7, 3600.0), 120.0);
        assert_eq!(backoff_delay(30.0, 50, 7, 3600.0), 3600.0);
    }

    #[test]
    fn relay_init_has_no_reserved_prefix_and_carries_tag() {
        let tag = [0xEEu8, 0xEE, 0xEE, 0xEE];
        for _ in 0..200 {
            let (init, _, _) = generate_relay_init(&tag, -4);
            assert_ne!(init[0], RESERVED_FIRST_BYTE);
            assert!(!is_reserved_start(&init[..4]));
            assert_ne!(&init[4..8], &[0, 0, 0, 0]);
            // Telegram расшифровывает хвост тем же ключом.
            let mut dec = new_aes_ctr(&init[8..40], &init[40..56]);
            let mut copy = init;
            dec.xor(&mut copy);
            assert_eq!(&copy[56..60], &tag);
            assert_eq!(LittleEndian::read_u16(&copy[60..62]) as i16, -4);
        }
    }

    #[test]
    fn obfuscated2_handshake_roundtrip() {
        // Клиент Telegram: случайный nonce с proto_tag и dc внутри, ключи
        // SHA256(prekey + secret), хвост nonce шифруется.
        let secret = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce[56..60].copy_from_slice(&[0xDD; 4]);
        LittleEndian::write_u16(&mut nonce[60..62], (-2i16) as u16);

        let key = |pre: &[u8]| {
            let mut h = Sha256::new();
            h.update(pre);
            h.update(&secret);
            h.finalize().to_vec()
        };
        let mut client_enc = new_aes_ctr(&key(&nonce[8..40]), &nonce[40..56]);
        let mut rev = [0u8; 48];
        for i in 0..48 {
            rev[i] = nonce[55 - i];
        }
        let mut client_dec = new_aes_ctr(&key(&rev[..32]), &rev[32..]);

        let mut enc = nonce;
        client_enc.xor(&mut enc);
        let mut handshake = nonce;
        handshake[56..].copy_from_slice(&enc[56..]);

        let (dc, is_media, tag, mut srv_dec, mut srv_enc) = try_handshake(&handshake, &secret).expect("valid");
        assert_eq!((dc, is_media, tag), (2, true, [0xDD; 4]));

        let mut up = b"client -> telegram".to_vec();
        client_enc.xor(&mut up);
        srv_dec.xor(&mut up);
        assert_eq!(up, b"client -> telegram");

        let mut down = b"telegram -> client".to_vec();
        srv_enc.xor(&mut down);
        client_dec.xor(&mut down);
        assert_eq!(down, b"telegram -> client");

        // Чужой secret — handshake отвергается (с подавляющей вероятностью).
        assert!(try_handshake(&handshake, &[0u8; 16]).is_none());
    }

    /// Простейший WS echo-сервер: отвечает 101 и возвращает каждый бинарный
    /// фрейм без маски.
    async fn ws_echo_server(listener: TcpListener) {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        while !req.ends_with(b"\r\n\r\n") {
            if sock.read(&mut b).await.unwrap() == 0 {
                return;
            }
            req.push(b[0]);
        }
        sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n").await.unwrap();
        loop {
            let mut hdr = [0u8; 2];
            if sock.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let opcode = hdr[0] & 0x0f;
            let mut len = (hdr[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                sock.read_exact(&mut ext).await.unwrap();
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                sock.read_exact(&mut ext).await.unwrap();
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask = [0u8; 4];
            if hdr[1] & 0x80 != 0 {
                sock.read_exact(&mut mask).await.unwrap();
            }
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload).await.unwrap();
            for (i, x) in payload.iter_mut().enumerate() {
                *x ^= mask[i % 4];
            }
            match opcode {
                0x2 => {
                    let frame = build_frame(OP_BINARY, &payload, false);
                    sock.write_all(&frame).await.unwrap();
                }
                0x8 => return,
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn bridge_ws_reencrypts_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(ws_echo_server(listener));
        let conn = TcpStream::connect(addr).await.unwrap();
        let ws = ws_upgrade_plain(conn, "kws2.web.telegram.org", WS_PATH, Duration::from_secs(5))
            .await
            .unwrap();

        let (k1, iv1) = ([1u8; 32], [2u8; 16]);
        let (k2, iv2) = ([3u8; 32], [4u8; 16]);
        let (k4, iv4) = ([5u8; 32], [6u8; 16]);
        // tg_dec == tg_enc: echo-сервер возвращает ровно то, что получил.
        let ctx = CryptoCtx {
            clt_dec: new_aes_ctr(&k1, &iv1),
            clt_enc: new_aes_ctr(&k4, &iv4),
            tg_enc: new_aes_ctr(&k2, &iv2),
            tg_dec: new_aes_ctr(&k2, &iv2),
        };

        let (proxy_side, mut client_side) = tokio::io::duplex(1 << 20);
        let (pr, pw) = tokio::io::split(proxy_side);
        let bridge = tokio::spawn(bridge_ws(
            pr,
            pw,
            ws,
            "test".to_string(),
            2,
            false,
            None,
            ctx,
            CancellationToken::new(),
        ));

        let message: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut wire = message.clone();
        new_aes_ctr(&k1, &iv1).xor(&mut wire);
        client_side.write_all(&wire).await.unwrap();

        let mut got = vec![0u8; message.len()];
        tokio::time::timeout(Duration::from_secs(10), client_side.read_exact(&mut got))
            .await
            .expect("echo in time")
            .unwrap();
        new_aes_ctr(&k4, &iv4).xor(&mut got);
        assert_eq!(got, message);

        drop(client_side);
        tokio::time::timeout(Duration::from_secs(10), bridge).await.expect("bridge ends").unwrap();
        server.abort();
    }

    #[test]
    fn worker_report_failure_policy() {
        let pool = CfWorkerPool::new(CancellationToken::new());
        let h = |code: i32| {
            WsError::Handshake(WsHandshakeError {
                status_code: code,
                status_line: format!("HTTP/1.1 {}", code),
                headers: HashMap::new(),
                location: String::new(),
            })
        };
        let domains = vec!["a.workers.dev".to_string(), "b.workers.dev".to_string()];
        pool.report_failure("a.workers.dev", &h(403));
        assert_eq!(pool.available_domains(&domains).len(), 2, "403 must not disable worker");
        pool.report_failure("a.workers.dev", &h(429));
        let left = pool.available_domains(&domains);
        assert_eq!(left, vec!["b.workers.dev".to_string()]);
        pool.report_failure("b.workers.dev", &WsError::Timeout);
        assert!(pool.available_domains(&domains).is_empty());
        // Все воркеры на паузе — refill откладывается.
        let mut st = pool.state.lock();
        assert!(st.defer_if_all_workers_paused(2, &domains, now_monotonic()));
    }
}
