<div align="center">

  # Telegram WS Proxy Android
<br>
  <img src="https://img.shields.io/badge/Android-SDK_21--35-3DDC84?style=for-the-badge&logo=android&logoColor=white" alt="Android SDK">
  <img src="https://img.shields.io/badge/Rust-stable-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Kotlin-Compose-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin">
  <img src="https://img.shields.io/badge/upstream-tg--ws--proxy_v1.12.0-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Upstream">
</div>
<br>

**TG WS Proxy Android** — локальный **MTProto-прокси** для Telegram на Android. Это мобильная версия [tg-ws-proxy от Flowseal](https://github.com/Flowseal/tg-ws-proxy): трафик Telegram уходит через WebSocket напрямую к датацентрам Telegram, а если они недоступны — через Cloudflare (Worker или CF-прокси) или прямой TCP.

Репозиторий продолжает заброшенный [Android-порт amurcanov](https://github.com/amurcanov/tg-ws-proxy-android): нативное ядро на Rust синхронизировано с оригиналом **v1.12.0**.

---

## Что нового в 1.4.0

**Работа при заблокированном экране:**
- Ядро знает о сети: пока её нет, провалы подключений не копятся в паузах маршрутов. При смене сети (Wi-Fi ⇄ LTE) старые сессии и пул закрываются, паузы сбрасываются. Раньше после выключенного экрана маршруты оставались «на паузе» до часа, и прокси не подключался.
- При включении экрана паузы, накопленные за время сна, снимаются, пул прогревается: Telegram подключается сразу после разблокировки.
- Сессия закрывается только после 15 минут тишины в обе стороны (было 120 с, это рвало фоновое соединение Telegram). Потолки backoff снижены: пул до 60 с, TCP до 120 с.
- Приложение просит исключение из оптимизации батареи: плашка на главном экране открывает системный диалог «Разрешить работу в фоне».

**Скорость и размер:**
- Аппаратный AES на arm64 (ARMv8 Crypto Extensions, раньше шифрование шло программно) и горячий путь данных со сборкой `opt-level=3`: шифрование в мосте быстрее в 5–8 раз (замер `crypto::bench`: 405 → ~2000 МБ/с на проход, uplink 194 → ~1650 МБ/с), меньше расход CPU и батареи.
- Сплиттер пакетов больше не расшифровывает поток второй раз, а WS-фреймы уходят одной записью вместо TLS-записи на каждый пакет.
- APK меньше на 36–42% (arm64: 5,1 → 3,2 МБ): JNI вместо JNA, R8 снова вырезает неиспользуемый код Compose/корутин/DataStore, убраны appcompat и reqwest (свой минимальный HTTPS-клиент для GitHub и DoH).
- DoH ходит на серверы по IP (1.1.1.1, 8.8.8.8, 94.140.14.14), поэтому сломанный системный DNS ему не мешает.

**Идеи из других форков tg-ws-proxy:**
- Гонка CF-маршрутов (pvtarget-glitch): попытки стартуют лесенкой, побеждает первая успешная, 80 и 443 пробуются параллельно. Холодный перебор для DC делает одно соединение, остальные ждут его результата.
- Дробление первого пакета против DPI на CF-маршрутах (pvtarget-glitch): ClientHello режется на два TLS-рекорда посередине SNI, HTTP-запрос — внутри `Host`.
- Отмена дозвона, если Telegram закрыл соединение раньше, чем маршрут был готов (Alexingin). Это убирает «шторм» висящих попыток.
- Паника в одном соединении больше не роняет приложение (tunneljet).
- Подключение к CF-доменам сначала по IPv4 (Flowseal/tg-ws-proxy#1695), карантин таймаутов по хосту, а не по домену (#1701).

## Что было в 1.3.0

Ядро синхронизировано с оригиналом v1.12.0: пул WebSocket без прямых коннектов вне пула, CF proxy с переключением TLS ⇄ HTTP, cooldown CF Worker (429 — до 00:00 UTC), TCP fallback с backoff, Fake TLS с защитой от повторного ClientHello, исправлены баги порта (WS на голом порту 80, поломка Fake TLS-потока и др.).

Не перенесено: **HTTP/2-мультиплексирование медиа через CF**. Медиа через CF идёт по обычному WebSocket `/apiws`, как в оригинале с `--no-h2`. Готовый ориентир для переноса — `cf_h2.rs` в [tg-ws-proxy-rs](https://github.com/valnesfjord/tg-ws-proxy-rs).

---

## Как это работает

```text
Telegram → 127.0.0.1:1443 (MTProto) → TG WS Proxy → WSS к kwsN.web.telegram.org
                                                   ↘ fallback: CF Worker → CF proxy → TCP к DC
```

1. Приложение поднимает локальный MTProto-прокси (нативное ядро на **Rust**).
2. По 64-байтному handshake определяет датацентр и тип соединения (обычное/медиа).
3. Берёт готовое WSS-соединение к датацентру из пула; если его нет — по очереди пробует Cloudflare Worker, CF proxy и прямой TCP.

## Быстрый старт

1. Скачайте `APK` со **[страницы релизов](https://github.com/koted0/tg-ws-proxy-android/releases)** (`arm64` подходит почти всем современным телефонам, `universal` — если не уверены).
2. Установите приложение и откройте его.
3. Нажмите **«Запустить прокси»**: появится уведомление о работе в фоне.
4. Нажмите **«Применить в Telegram»** и подтвердите подключение в клиенте.

### Если Telegram всё равно не грузит

- **Свой Cloudflare Worker** — бесплатно, без покупки домена. Инструкция и код воркера: [CfWorker.md](https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/RU/CfWorker.md). Домен вида `name.username.workers.dev` впишите в **Настройки → Домены Cloudflare Worker** (можно несколько через запятую).
- **Свой домен для CF proxy** — встроенные домены общие и могут упираться в лимиты Cloudflare. Инструкция: [CfProxy.md](https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/RU/CfProxy.md). Домен впишите в **Настройки → Свои домены CF proxy**.

### Прокси отваливается при заблокированном экране

1. Нажмите плашку «Android может усыплять прокси…» на главном экране и разрешите работу в фоне (или: Настройки → Приложения → TG WS Proxy → Батарея → «Без ограничений»).
2. На Xiaomi/HyperOS включите «Автозапуск» и «Контроль активности → Нет ограничений»; на Samsung уберите приложение из «Спящих приложений»; на OPPO/realme/OnePlus разрешите «Работу в фоне» и закрепите приложение в недавних (замочек). Подробности по прошивкам: [dontkillmyapp.com](https://dontkillmyapp.com).
3. В Telegram должна быть одна запись прокси `127.0.0.1:1443`: старые записи со старым секретом без конца стучатся в прокси.

---

## Сборка

Нужны Rust (stable), Android SDK с NDK и JDK 17.

```bash
./build_so.sh
```

```bash
./gradlew assembleRelease
```

`build_so.sh` собирает `libtgwsproxy.so` через `cargo-ndk` в `app/src/main/jniLibs` (готовые бинарники в репозитории больше не хранятся). На Windows есть `build_so.bat` и `build_apk.bat`.

Тесты ядра запускаются на любом хосте:

```bash
cargo test --lib
```

### CI и релизы

[`.github/workflows/android-build.yml`](.github/workflows/android-build.yml) на каждый push собирает ядро и три APK (`arm32`, `arm64`, `universal`). Push тега `v1.4.0` (или ручной запуск с `make_release`) публикует GitHub Release, и приложение предложит обновление.

> [!IMPORTANT]
> Без секретов `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD` APK подписываются случайным debug-ключом раннера, и новую сборку нельзя поставить поверх старой. Для обновляемых релизов добавьте свой keystore в секреты репозитория.

---

## Отчёты об ошибках

Если что-то не работает, нажмите **«Собрать отчёт»** внутри приложения и приложите его к [issue](https://github.com/koted0/tg-ws-proxy-android/issues). Мелкие ошибки в логах при нормально работающем прокси можно игнорировать.

## Благодарности

- [Flowseal](https://github.com/Flowseal/tg-ws-proxy) — оригинальный tg-ws-proxy, вся логика прокси.
- [amurcanov](https://github.com/amurcanov) и контрибьюторы — Android-порт, интерфейс и Rust-ядро.
- Идеи из форков: [pvtarget-glitch](https://github.com/pvtarget-glitch/tg-ws-proxy-android) (гонка CF-маршрутов, дробление ClientHello), [Alexingin](https://github.com/Alexingin/tg-ws-proxy-android) (отмена дозвона при уходе клиента), [artur0vi4/tunneljet](https://github.com/artur0vi4/tunneljet) (барьер паник, реакция на смену сети), [kamenwwcpp](https://github.com/kamenwwcpp/tg-ws-proxy-android), [valnesfjord/tg-ws-proxy-rs](https://github.com/valnesfjord/tg-ws-proxy-rs).

## Лицензия

Этот форк распространяется под лицензией **GPLv3**. Оригинальный код `tg-ws-proxy` от [Flowseal](https://github.com/Flowseal) доступен под лицензией **MIT**.
