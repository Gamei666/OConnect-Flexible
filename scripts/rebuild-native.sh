#!/usr/bin/env bash
# Rebuild the native components in a separate directory on Linux or WSL.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
archives="$root/third-party/native-sources"
oc_ndk="$(realpath "${1:?Pass the Linux Android NDK r27c folder}")"
hev_ndk="$(realpath "${2:?Pass the Linux Android NDK r27d folder}")"
jobs="${JOBS:-2}"
work="$(mktemp -d)"
echo "Native build directory: $work"
test -x "$oc_ndk/ndk-build"
test -x "$hev_ndk/ndk-build"
(cd "$archives" && sha256sum --check SHA256SUMS)

mkdir -p "$work/oconnect/external" "$work/oconnect/app/src/main" "$work/hev"
external="$work/oconnect/external"
cp "$root/external/Makefile" "$root/external/csd-wrapper.c" "$external/"
mkdir -p "$external/openconnect" "$external/stoken"
tar -xzf "$archives/openconnect-8b702bf2dbaf11302ed98629214b1df5d50a12aa.tar.gz" \
  --strip-components=1 -C "$external/openconnect"
tar -xzf "$archives/stoken-bc25aa48922064881f17201c6302ab2640e36763.tar.gz" \
  --strip-components=1 -C "$external/stoken"
cp "$archives/curl-8.21.0.tar.xz" "$external/"
for file in libxml2-2.14.5.tar.xz gmp-6.3.0.tar.xz nettle-3.10.tar.gz \
  gnutls-3.7.11.tar.xz stoken-v0.93.tar.gz lz4-v1.10.0.tar.gz; do
  cp "$archives/$file" "$external/openconnect/android/"
done
# The source snapshots are pinned to commits and don't contain Git metadata.
# The upstream build installs all four ABIs into the isolated app tree.
make -C "$external" -j1 ANDROID_NDK="$oc_ndk" OPENCONNECT_REV=8b702bf2dbaf \
  STOKEN_REV=bc25aa489220 OPENCONNECT_GIT_DIR="$work/absent-git-dir" install

hev="$work/hev"
tar -xJf "$archives/hev-socks5-tunnel-2.20.0.tar.xz" --strip-components=1 -C "$hev"
(
  cd "$hev"
  ln -s . jni
  "$hev_ndk/ndk-build" APP_MODULES=hev-socks5-tunnel -j"$jobs"
  mkdir -p aar/jni classes
  for abi in armeabi-v7a arm64-v8a x86 x86_64; do
    mkdir -p "aar/jni/$abi"
    cp "libs/$abi/libhev-socks5-tunnel.so" "aar/jni/$abi/"
  done
  javac --release 8 -d classes android/hev/htproxy/TProxyService.java
  jar cf aar/classes.jar -C classes .
  printf '%s\n' '-keep class hev.htproxy.** { *; }' > aar/proguard.txt
  cat > aar/AndroidManifest.xml <<'MANIFEST'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="hev.socks5.tunnel">
    <uses-sdk android:minSdkVersion="29" />
</manifest>
MANIFEST
  (cd aar && zip -qr ../hev-socks5-tunnel.aar .)
)
echo "OpenConnect, stoken and CSD binaries: $work/oconnect/app/src/main/jniLibs"
echo "Hev AAR: $hev/hev-socks5-tunnel.aar"
