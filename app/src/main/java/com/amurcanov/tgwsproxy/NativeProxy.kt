package com.amurcanov.tgwsproxy

/**
 * Мост к нативному ядру (libtgwsproxy.so, Rust) через JNI.
 *
 * Раньше здесь был JNA: libjnidispatch.so на каждую ABI и ~110 КБ классов в
 * dex ради десятка вызовов. Имена `external`-функций должны совпадать с
 * экспортами `Java_com_amurcanov_tgwsproxy_NativeProxy_*` в src/jni_api.rs.
 */
object NativeProxy {
    init {
        System.loadLibrary("tgwsproxy")
    }

    @JvmStatic external fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int
    @JvmStatic external fun stopProxy(): Int
    @JvmStatic external fun setPoolSize(size: Int)
    @JvmStatic external fun setBufferSizeKb(kb: Int)
    @JvmStatic external fun setCfProxyCacheDir(cacheDir: String)
    @JvmStatic external fun setCfWorkerDomains(domains: String)
    @JvmStatic external fun setFakeTlsDomain(domain: String)

    /** Полный секрет с префиксом (dd… или ee…+hex домена Fake TLS). */
    @JvmStatic external fun getSecretWithPrefix(): String?
    @JvmStatic external fun getStats(): String?

    /** Сменилась сеть по умолчанию (Wi-Fi <-> LTE): закрыть старые сессии, сбросить паузы. */
    @JvmStatic external fun networkChanged(): Int

    /** Экран включён: снять накопленные за сон паузы маршрутов и прогреть пул. */
    @JvmStatic external fun wake(): Int

    @JvmStatic private external fun nativeSetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)
    @JvmStatic private external fun nativeSetDisableSecure(v: Int)
    @JvmStatic private external fun nativeSetForceTestDc(v: Int)
    @JvmStatic private external fun nativeSetProxyProtocol(v: Int)
    @JvmStatic private external fun nativeSetVerbose(v: Int)
    @JvmStatic private external fun nativeSetCfH2Media(v: Int)
    @JvmStatic private external fun nativeSetNetworkAvailable(v: Int)

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) =
        nativeSetCfProxyConfig(if (enabled) 1 else 0, if (priority) 1 else 0, userDomain)

    fun setDisableSecure(v: Boolean) = nativeSetDisableSecure(if (v) 1 else 0)

    fun setForceTestDc(v: Boolean) = nativeSetForceTestDc(if (v) 1 else 0)

    fun setProxyProtocol(v: Boolean) = nativeSetProxyProtocol(if (v) 1 else 0)

    /** DEBUG-логи ядра; переключается на лету, без перезапуска прокси. */
    fun setVerbose(v: Boolean) = nativeSetVerbose(if (v) 1 else 0)

    fun setCfH2Media(v: Boolean) = nativeSetCfH2Media(if (v) 1 else 0)

    /** Есть ли сеть: пока её нет, ядро не записывает провалы в паузы маршрутов. */
    fun setNetworkAvailable(v: Boolean) = nativeSetNetworkAvailable(if (v) 1 else 0)
}
