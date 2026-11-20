# OConnect Flexible

[Русский](README-RU.md)

OConnect Flexible is an independent Android fork of [OConnect v1.17.0](https://github.com/pengyue-polaron/oconnect-android/releases/tag/v1.17.0). It adds server-managed dynamic split tunneling for ocserv.

- Reads `dynamic-split-include-domains` and `dynamic-split-exclude-domains` from `X-CSTP-Post-Auth-XML`.
- Shows domain rules and IP routes under **Connection details → Routes**.
- Offers English, Russian and system language under **Settings → App language**.
- Checks GitHub for updates under **Settings → Updates** and downloads the APK in the app.

Requires Android 10 or later. The APK includes ARMv7, ARM64, x86 and x86-64. Download the signed APK from the [latest GitHub release](https://github.com/Gamei666/OConnect-Flexible/releases/latest). If you installed an earlier development APK signed by a different key, Android requires a fresh install. Save any profile information you need before removing that copy.

To update later, tap **Check for updates → Download APK → Install update**. Android may ask you to allow installs from OConnect Flexible and always asks you to confirm installation. You can switch off automatic checks in **Settings → Updates**.

See [ocserv setup](docs/ocserv.md) for configuration examples and DNS limitations.

## Build

Install JDK 17, Android SDK Platform 37 and Build-Tools 36.0.0, then set `JAVA_HOME` and `ANDROID_HOME`. The checked-in wrapper uses Gradle 9.5.1. The APK build uses verified native libraries already in the repository and does not require an NDK.

On Windows, run `./build-android.ps1` from PowerShell. You can pass `-SdkPath C:\android` to provide a different SDK path. The script tests, builds and verifies a debug APK in `dist`. On Linux, run `./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug`.

[Release signing](docs/releasing.md) · [Native sources and provenance](third-party/README.md)

Project documentation is maintained in English and Russian. Update both editions together and link them to each other. Original upstream notices and reference documents in `doc/` are kept in their original form.

## License

The Android fork is distributed under GNU GPL v2 or later as described in [COPYING](COPYING) and [doc/LICENSE.txt](doc/LICENSE.txt). It builds on OConnect by pengyue-polaron and OpenConnect for Android by Kevin Cernekee, with code derived from OpenVPN for Android by Arne Schwabe. Upstream copyright notices and third-party licenses are retained. See [fork changes](FORK-CHANGES.md) and [third-party sources](third-party/README.md).
