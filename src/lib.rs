pub mod balancer;
pub mod cf_h2;
pub mod cfproxy;
pub mod config;
pub mod crypto;
pub mod faketls;
pub mod https;
mod jni_api;
pub mod proxy;
pub mod ws;

use config::*;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use proxy::{parse_cidr_pool, run_proxy, ProxyPools};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

// Глобальный рантайм — никогда не дропается.
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

struct ProxyState {
    pools: Arc<ProxyPools>,
    handle: tokio::task::JoinHandle<()>,
    cancel_tasks: CancellationToken,
}

static STATE: OnceCell<Mutex<Option<ProxyState>>> = OnceCell::new();

fn state_cell() -> &'static Mutex<Option<ProxyState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("tgwsproxy-rt")
            .enable_all()
            .build()
            .expect("failed to build global tokio runtime")
    })
}

fn current_pools() -> Option<Arc<ProxyPools>> {
    state_cell().lock().as_ref().map(|s| s.pools.clone())
}

/// Паника в Rust-коде пишется в лог приложения, а не теряется молча.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            lerror!("panic: {}", info);
            default(info);
        }));
    });
}

/// Барьер на границе FFI: паника не уходит в JVM (это UB/abort), а
/// превращается в значение по умолчанию. Паники внутри задач tokio и так
/// гасятся рантаймом — падает одно соединение, а не приложение.
pub(crate) fn guarded<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(fallback)
}

// ---------------------------------------------------------------------------
// API ядра (вызывается из JNI, см. jni_api.rs)
// ---------------------------------------------------------------------------

/// 0 — слушает; -1 — уже запущен; -3 — не удалось занять порт.
pub fn start_proxy(host: &str, port: u16, dc_ips: &str, secret: &str, verbose: bool) -> i32 {
    install_panic_hook();
    let mut guard = state_cell().lock();
    if guard.is_some() {
        return -1;
    }

    init_logging(verbose);
    cfproxy::clear_cfproxy_429_cooldowns();
    if secret.len() == 32 && hex::decode(secret).is_ok() {
        *PROXY_SECRET.write() = secret.to_string();
    }
    cfproxy::init_cfproxy_domains();
    NET_AVAILABLE.store(true, Ordering::Relaxed);

    let dc_opt_map: HashMap<i32, String> = parse_cidr_pool(dc_ips);
    let rt = runtime();
    let cancel_tasks = CancellationToken::new();
    let pools = Arc::new(ProxyPools::new(cancel_tasks.clone()));

    // Ждём результат bind перед возвратом, чтобы UI знал, слушает ли прокси.
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let pools_task = pools.clone();
    let host_task = host.to_string();
    let cancel_root = cancel_tasks.clone();
    let handle = rt.spawn(async move {
        let addr = format!("{}:{}", host_task, port);
        match tokio::net::TcpListener::bind((host_task.as_str(), port)).await {
            Ok(listener) => {
                let _ = tx.send(Ok(()));
                if let Err(e) = run_proxy(pools_task, host_task, port, dc_opt_map, cancel_root, listener).await {
                    lerror!("listen on {}: {}", addr, e);
                }
            }
            Err(e) => {
                lerror!("listen on {}: {}", addr, e);
                let _ = tx.send(Err(format!("listen on {}: {}", addr, e)));
            }
        }
    });

    match rx.recv() {
        Ok(Ok(())) => {}
        _ => {
            handle.abort();
            return -3;
        }
    }
    *guard = Some(ProxyState {
        pools,
        handle,
        cancel_tasks,
    });
    0
}

pub fn stop_proxy() -> i32 {
    let mut guard = state_cell().lock();
    let state = match guard.take() {
        Some(s) => s,
        None => return -1,
    };

    // graceful shutdown — рантайм не дропаем
    linfo!("StopProxy: cancelling all tasks");
    state.cancel_tasks.cancel();
    let pools = state.pools.clone();
    let handle = state.handle;
    runtime().block_on(async move {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        pools.reset();
        // Даём закрыться WS из пула до возможного повторного StartProxy.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });

    STATS.reset();
    cfproxy::clear_cfproxy_429_cooldowns();
    cfproxy::reset_cf_timeouts();
    proxy::reset_tcp_backoff();
    proxy::reset_cf_dial_state();
    proxy::drop_active_sessions();
    proxy::reset_direct_health();
    cf_h2::H2.reset();
    linfo!("StopProxy: exit");
    0
}

pub fn set_pool_size(size: i32) {
    // pool_size = max(0, N); 0 отключает прямые WS (как в оригинале).
    POOL_SIZE.store(size.clamp(0, 16), Ordering::Relaxed);
}

pub fn set_buffer_size_kb(kb: i32) {
    let n = kb.clamp(4, 4096) * 1024;
    BUFFER_SIZE.store(n, Ordering::Relaxed);
    RECV_BUF.store(n, Ordering::Relaxed);
    SEND_BUF.store(n, Ordering::Relaxed);
}

pub fn set_cfproxy_cache_dir(dir: &str) {
    CFPROXY.write().cache_dir = dir.trim().to_string();
}

/// `user_domain` — свои домены CF proxy через `,` `;` или пробел.
pub fn set_cfproxy_config(enabled: bool, user_domain: &str) {
    CFPROXY_ENABLED.store(enabled, Ordering::Relaxed);
    let list = coerce_domain_list_str(user_domain);
    let mut cfg = CFPROXY.write();
    cfg.user_domain = user_domain.trim().to_string();
    if !list.is_empty() {
        cfg.domains = list.clone();
        cfg.active = list[0].clone();
        balancer::BALANCER.write().update_domains_list(&cfg.domains);
    }
}

pub fn set_cf_worker_domains(raw: &str) {
    *CF_WORKER_DOMAINS.write() = coerce_domain_list_str(raw);
}

pub fn set_fake_tls_domain(domain: &str) {
    *FAKE_TLS_DOMAIN.write() = domain.trim().to_string();
}

pub fn set_disable_secure(v: bool) {
    DISABLE_SECURE.store(v, Ordering::Relaxed);
}

pub fn set_force_test_dc(v: bool) {
    FORCE_TEST_DC.store(v, Ordering::Relaxed);
}

/// HTTP/2-транспорт медиа через CF (`--no-h2` оригинала выключает).
pub fn set_cf_h2_media(v: bool) {
    CF_H2_MEDIA.store(v, Ordering::Relaxed);
}

pub fn set_proxy_protocol(v: bool) {
    PROXY_PROTOCOL.store(v, Ordering::Relaxed);
}

/// DEBUG-логи можно включать и выключать на лету (без перезапуска прокси).
pub fn set_verbose(v: bool) {
    LOG_VERBOSE.store(v, Ordering::Relaxed);
}

pub fn stats_summary() -> String {
    STATS.summary()
}

/// ee-secret при включённом FakeTLS: ee{secret}{domain_hex}, иначе dd{secret}.
pub fn secret_with_prefix() -> String {
    let sec = PROXY_SECRET.read().clone();
    let ftls = FAKE_TLS_DOMAIN.read().clone();
    if ftls.is_empty() {
        format!("dd{}", sec)
    } else {
        format!("ee{}{}", sec, hex::encode(ftls.as_bytes()))
    }
}

/// Сеть пропала/появилась (ConnectivityManager). Пока её нет, провалы не
/// копятся в паузах маршрутов; при появлении паузы сбрасываются.
pub fn set_network_available(available: bool) {
    let was = NET_AVAILABLE.swap(available, Ordering::Relaxed);
    if was == available {
        return;
    }
    if !available {
        linfo!("Network lost: route failures are not counted until it is back");
        return;
    }
    linfo!("Network is back: resetting route pauses");
    if let Some(pools) = current_pools() {
        runtime().spawn(async move {
            proxy::reset_route_state(&pools, false);
            pools.warmup(false);
        });
    }
}

/// Сменилась сеть по умолчанию (Wi-Fi <-> LTE): сокеты старой сети мертвы.
/// Закрываем активные сессии и пул, забываем паузы и выученные режимы.
pub fn network_changed() -> i32 {
    NET_AVAILABLE.store(true, Ordering::Relaxed);
    let pools = match current_pools() {
        Some(p) => p,
        None => return -1,
    };
    linfo!("Network changed: closing old sessions and resetting routes");
    proxy::drop_active_sessions();
    runtime().spawn(async move {
        pools.reset();
        proxy::reset_route_state(&pools, true);
        pools.warmup(false);
    });
    0
}

/// Экран включён: снимаем накопленные за время сна паузы и прогреваем пул,
/// чтобы Telegram подключился сразу, а не после истечения backoff.
pub fn wake() -> i32 {
    let pools = match current_pools() {
        Some(p) => p,
        None => return -1,
    };
    runtime().spawn(async move {
        proxy::reset_route_state(&pools, false);
        pools.warmup(false);
    });
    0
}
