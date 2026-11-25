#!/usr/bin/env bash
# Сборка нативного движка libtgwsproxy.so для Android (Linux/macOS).
# Нужны: Rust (rustup), Android NDK (ANDROID_NDK_HOME или $ANDROID_HOME/ndk/<версия>).
# После сборки: ./gradlew assembleRelease
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [ -n "$sdk" ] && [ -d "$sdk/ndk" ]; then
        ANDROID_NDK_HOME="$sdk/ndk/$(ls "$sdk/ndk" | sort -V | tail -1)"
        export ANDROID_NDK_HOME
    else
        echo "Android NDK не найден: задайте ANDROID_NDK_HOME или ANDROID_HOME" >&2
        exit 1
    fi
fi
echo "Using NDK: $ANDROID_NDK_HOME"

rustup target add aarch64-linux-android armv7-linux-androideabi >/dev/null
command -v cargo-ndk >/dev/null || cargo install cargo-ndk --locked

cargo ndk -t arm64-v8a --platform 24 -o app/src/main/jniLibs build --release --locked
cargo ndk -t armeabi-v7a --platform 21 -o app/src/main/jniLibs build --release --locked

ls -la app/src/main/jniLibs/arm64-v8a app/src/main/jniLibs/armeabi-v7a
