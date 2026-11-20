# Build and sign a release APK

[Русский](releasing-RU.md)

Set up the Windows build described in [README.md](../README.md). Use a dedicated Android signing key, kept alongside its password in private storage outside the repository. Android uses this key to authorize updates to previously installed releases.

Set `OCONNECT_KEYSTORE_PASSWORD` in the PowerShell process using your local secret store. Optionally set `OCONNECT_KEY_PASSWORD` if the key password differs. Then run:

```powershell
.\build-android.ps1 -SdkPath C:\android -Keystore 'C:\path\to\release.p12' -KeyAlias oconnect-flexible
```

The script builds the unsigned release, aligns it, signs it, verifies the certificate and reports its SHA-256. Use the same signing key for later releases. Keep a private backup of the keystore and the password so you can sign releases after a system reinstall.

Attach the signed APK, matching source ZIP and both SHA-256 files to the same GitHub Release. The source snapshot includes the corresponding native archives and build scripts. Keep build outputs, keystores, credentials, VPN profiles and real server configuration outside the repository.

The updater checks the latest stable release in `Gamei666/OConnect-Flexible`. Upload a single universal APK with the exact name `OConnect-Flexible-<versionName>.apk`. For version `1.17.0-flexible.2`, use tag `v1.17.0-flexible.2` and asset `OConnect-Flexible-1.17.0-flexible.2.apk`. Publish the release as latest after uploading its assets. The app uses GitHub's SHA-256 digest for the APK asset and checks the APK's package, version and signing certificate before handing it to Android.

## Project versions

Use `vX.Y.Z-flexible.N` or `vX.Y.Z`, with the version after `v` matching Android's `versionName`. If the project adopts independent numbering, record the upstream OConnect version in the release notes. Increase Android's `versionCode` for each new release. Build the APK and source archive from the same commit. [Android app versioning](https://developer.android.com/studio/publish/versioning)
