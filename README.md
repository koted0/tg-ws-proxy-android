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

## Что нового в 1.3.0

Ядро догнало оригинал (было на уровне примерно июля 2026):

- **Пул WebSocket как в оригинале:** соединения к Telegram берутся только из заранее прогретого пула, иначе клиент сразу уходит в fallback (без долгих прямых попыток). Протухшие соединения в пуле отлавливаются и заменяются, есть ротация и backoff (1с…1ч), domain fronting.
- **CF proxy:** короткие таймауты попыток (3/3/5/5/10с), автоматическое переключение **TLS (443) ⇄ HTTP (80)** после таймаута и 30-секундный cooldown проблемных доменов. Сети, где режется 443, работают без ручной настройки.
- **Cloudflare Worker:** поле для своих доменов воркера в настройках. Воркер, упёршийся в дневной лимит (HTTP 429), выключается до 00:00 UTC, при 5xx/сетевых ошибках — на 60с.
- **TCP fallback** с экспоненциальным backoff (30с…1ч), без параллельных попыток к одному адресу.
- **Fake TLS (ee-secret):** защита от повторного ClientHello (replay → маскировка), ServerHello зеркалит шифронабор и key share клиента (включая X25519MLKEM768), размер первой зашифрованной записи берётся с сайта маскировки.
- **Исправлены баги порта:** прямые WS к Telegram уходили на голый порт 80, CF worker не выключал упавшие домены, Fake TLS-поток ломался при фрагментированных записях и частичной записи в сокет, обновление списка CF-доменов размножалось при перезапусках, несколько своих CF-доменов склеивались в один, мост мог «залипнуть» до 2 минут после закрытия одной из сторон.

Не перенесено: **HTTP/2-мультиплексирование медиа через CF** (`--no-h2` в оригинале). Медиа через CF идёт по обычному WebSocket `/apiws`, как в оригинале с отключённым H2.

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

[`.github/workflows/android-build.yml`](.github/workflows/android-build.yml) на каждый push собирает ядро и три APK (`arm32`, `arm64`, `universal`). Push тега `v1.3.0` (или ручной запуск с `make_release`) публикует GitHub Release, и приложение предложит обновление.

> [!IMPORTANT]
> Без секретов `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD` APK подписываются случайным debug-ключом раннера, и новую сборку нельзя поставить поверх старой. Для обновляемых релизов добавьте свой keystore в секреты репозитория.

---

## Отчёты об ошибках

Если что-то не работает, нажмите **«Собрать отчёт»** внутри приложения и приложите его к [issue](https://github.com/koted0/tg-ws-proxy-android/issues). Мелкие ошибки в логах при нормально работающем прокси можно игнорировать.

## Благодарности

- [Flowseal](https://github.com/Flowseal/tg-ws-proxy) — оригинальный tg-ws-proxy, вся логика прокси.
- [amurcanov](https://github.com/amurcanov) и контрибьюторы — Android-порт, интерфейс и Rust-ядро.

## Лицензия

Этот форк распространяется под лицензией **GPLv3**. Оригинальный код `tg-ws-proxy` от [Flowseal](https://github.com/Flowseal) доступен под лицензией **MIT**.
