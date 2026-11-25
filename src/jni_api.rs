//! JNI-экспорты для `com.amurcanov.tgwsproxy.NativeProxy` (Kotlin, `external`).
//!
//! Раньше приложение ходило в ядро через JNA: это libjnidispatch.so на каждую
//! ABI и около 110 КБ классов в dex. Здесь прямые JNI-функции без зависимостей;
//! каждая обёрнута в `guarded`, чтобы паника не уходила в JVM.

#![allow(non_snake_case)]

use crate::guarded;
use std::ffi::{c_char, c_void, CStr, CString};

type JInt = i32;
type JObject = *mut c_void;
type JString = *mut c_void;

/// `JNIEnv*` — указатель на указатель на таблицу функций JNINativeInterface.
pub type JniEnv = *const *mut c_void;

// Индексы в таблице функций JNIEnv (jni.h, считая с reserved0 = 0).
const NEW_STRING_UTF: usize = 167;
const GET_STRING_UTF_CHARS: usize = 169;
const RELEASE_STRING_UTF_CHARS: usize = 170;

type NewStringUtfFn = unsafe extern "system" fn(*mut JniEnv, *const c_char) -> JString;
type GetStringUtfCharsFn = unsafe extern "system" fn(*mut JniEnv, JString, *mut u8) -> *const c_char;
type ReleaseStringUtfCharsFn = unsafe extern "system" fn(*mut JniEnv, JString, *const c_char);

unsafe fn fn_ptr(env: *mut JniEnv, index: usize) -> *mut c_void {
    // Читаем один слот таблицы, не создавая ссылок на всю структуру.
    unsafe {
        let table: *const *mut c_void = *env;
        *table.add(index)
    }
}

/// jstring -> String (null -> пустая строка). Modified UTF-8 для наших
/// значений (IP, домены, hex) совпадает с обычным UTF-8.
unsafe fn from_jstring(env: *mut JniEnv, s: JString) -> String {
    if env.is_null() || s.is_null() {
        return String::new();
    }
    unsafe {
        let get: GetStringUtfCharsFn = std::mem::transmute(fn_ptr(env, GET_STRING_UTF_CHARS));
        let release: ReleaseStringUtfCharsFn = std::mem::transmute(fn_ptr(env, RELEASE_STRING_UTF_CHARS));
        let chars = get(env, s, std::ptr::null_mut());
        if chars.is_null() {
            return String::new();
        }
        let out = CStr::from_ptr(chars).to_string_lossy().into_owned();
        release(env, s, chars);
        out
    }
}

unsafe fn to_jstring(env: *mut JniEnv, s: &str) -> JString {
    if env.is_null() {
        return std::ptr::null_mut();
    }
    let c = CString::new(s.replace('\0', "")).unwrap_or_default();
    unsafe {
        let new_string: NewStringUtfFn = std::mem::transmute(fn_ptr(env, NEW_STRING_UTF));
        new_string(env, c.as_ptr())
    }
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_startProxy(
    env: *mut JniEnv,
    _class: JObject,
    host: JString,
    port: JInt,
    dc_ips: JString,
    secret: JString,
    verbose: JInt,
) -> JInt {
    let (host, dc_ips, secret) = unsafe { (from_jstring(env, host), from_jstring(env, dc_ips), from_jstring(env, secret)) };
    guarded(-2, || crate::start_proxy(&host, port as u16, &dc_ips, &secret, verbose != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_stopProxy(_env: *mut JniEnv, _class: JObject) -> JInt {
    guarded(-2, crate::stop_proxy)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_setPoolSize(_env: *mut JniEnv, _class: JObject, size: JInt) {
    guarded((), || crate::set_pool_size(size))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_setBufferSizeKb(_env: *mut JniEnv, _class: JObject, kb: JInt) {
    guarded((), || crate::set_buffer_size_kb(kb))
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_setCfProxyCacheDir(
    env: *mut JniEnv,
    _class: JObject,
    dir: JString,
) {
    let dir = unsafe { from_jstring(env, dir) };
    guarded((), || crate::set_cfproxy_cache_dir(&dir))
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetCfProxyConfig(
    env: *mut JniEnv,
    _class: JObject,
    enabled: JInt,
    _priority: JInt,
    user_domain: JString,
) {
    let user_domain = unsafe { from_jstring(env, user_domain) };
    guarded((), || crate::set_cfproxy_config(enabled != 0, &user_domain))
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_setCfWorkerDomains(
    env: *mut JniEnv,
    _class: JObject,
    domains: JString,
) {
    let domains = unsafe { from_jstring(env, domains) };
    guarded((), || crate::set_cf_worker_domains(&domains))
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_setFakeTlsDomain(
    env: *mut JniEnv,
    _class: JObject,
    domain: JString,
) {
    let domain = unsafe { from_jstring(env, domain) };
    guarded((), || crate::set_fake_tls_domain(&domain))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetDisableSecure(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_disable_secure(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetForceTestDc(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_force_test_dc(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetProxyProtocol(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_proxy_protocol(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetCfH2Media(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_cf_h2_media(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetVerbose(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_verbose(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_nativeSetNetworkAvailable(_env: *mut JniEnv, _class: JObject, v: JInt) {
    guarded((), || crate::set_network_available(v != 0))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_networkChanged(_env: *mut JniEnv, _class: JObject) -> JInt {
    guarded(-2, crate::network_changed)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_wake(_env: *mut JniEnv, _class: JObject) -> JInt {
    guarded(-2, crate::wake)
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_getStats(env: *mut JniEnv, _class: JObject) -> JString {
    let s = guarded(String::new(), crate::stats_summary);
    unsafe { to_jstring(env, &s) }
}

/// # Safety
/// Вызывается JVM с валидным JNIEnv.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_amurcanov_tgwsproxy_NativeProxy_getSecretWithPrefix(
    env: *mut JniEnv,
    _class: JObject,
) -> JString {
    let s = guarded(String::new(), crate::secret_with_prefix);
    unsafe { to_jstring(env, &s) }
}
