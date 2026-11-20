# Third-party components

[Русский](README-RU.md)

The Android application in this repository builds on [OConnect v1.17.0](https://github.com/pengyue-polaron/oconnect-android/releases/tag/v1.17.0). The release APK uses the four-ABI OpenConnect, stoken, curl and CSD binaries from that upstream APK. All 16 files were verified byte-for-byte against the upstream APK, whose SHA-256 is `6eb30e907f38554807d34407667be4b78d364da3b59003c90ec5032968afa6ca`. The Windows build checks [their hashes](native-binaries.sha256) before packaging.

| Component | Source included in this repository |
| --- | --- |
| OpenConnect and its Android/JNI build | [Commit 8b702bf2dbaf](https://gitlab.com/openconnect/openconnect/-/tree/8b702bf2dbaf11302ed98629214b1df5d50a12aa) |
| stoken JNI | [Commit bc25aa489220](https://github.com/stoken-dev/stoken/tree/bc25aa48922064881f17201c6302ab2640e36763) |
| curl helper | [curl 8.21.0](https://curl.se/download.html) |
| OpenConnect native dependencies | libxml2 2.14.5, GMP 6.3.0, Nettle 3.10, GnuTLS 3.7.11, stoken 0.93, LZ4 1.10.0. Versions and hashes match the pinned OpenConnect Android Makefile. |
| CSD helper | [external/csd-wrapper.c](../external/csd-wrapper.c), with the upstream `android_csd.sh` in the assets |
| Direct TCP/UDP backend | [HevSocks5Tunnel 2.20.0](https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.20.0), with HevSocks5Core, HevTaskSystem, lwIP and LibYAML included in the release source archive |

The exact archives and their [SHA-256 checksums](native-sources/SHA256SUMS) are in `native-sources/`. Java JNI wrappers are in `external/`. The unmodified Hev AAR has SHA-256 `ae8a2e96b80b4eccccd037805a4bb4a278090c89dbcae8bc6fcb7634e9a255b9`, matching the upstream release asset. Licenses for its components appear in the [APK assets](../app/src/main/assets/third-party/). Java runtime library sources resolved by Gradle are in `java-sources/`, with a runtime-coordinate manifest.

The Java sources directory also includes the [OpenJDK desugaring library 2.1.5 source](https://github.com/google/desugar_jdk_libs/commit/73170c345e6a762fc6a1f0301bb15218850023ef) used by the Android Gradle build. Gradle platform BOMs are listed as coordinates and do not contribute classes to the APK.

To rebuild the native components from these archives on Linux or WSL, install the Linux Android NDK r27c and r27d, JDK 17, GNU make, Autotools, pkg-config, gettext, curl, patch, Perl, tar with gzip/xz, and zip. Run:

```sh
./scripts/rebuild-native.sh /path/to/android-ndk-r27c /path/to/android-ndk-r27d
```

The script writes its output to a temporary build directory, leaving the checked-in libraries intact. The published APK uses the upstream binaries. Local release packaging, signature and unit tests were checked on Windows. The full Linux/WSL native rebuild was not run during this release preparation.
