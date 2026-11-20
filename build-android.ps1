param(
    [string]$SdkPath = $env:ANDROID_HOME,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'),
    [string]$Keystore,
    [string]$KeyAlias = 'oconnect-flexible'
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked($Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with code $LASTEXITCODE" }
}

if (-not $SdkPath) { throw 'Set ANDROID_HOME or pass -SdkPath.' }
$SdkPath = (Resolve-Path -LiteralPath $SdkPath).Path
$buildTools = Join-Path $SdkPath 'build-tools/36.0.0'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$apksigner = Join-Path $buildTools 'apksigner.bat'
if (-not ((Test-Path -LiteralPath $zipalign) -and (Test-Path -LiteralPath $apksigner))) {
    throw 'Install Android SDK Build-Tools 36.0.0.'
}
if ($Keystore) {
    $Keystore = (Resolve-Path -LiteralPath $Keystore).Path
    if (-not $env:OCONNECT_KEYSTORE_PASSWORD) {
        throw 'Supply the keystore password in OCONNECT_KEYSTORE_PASSWORD.'
    }
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

Push-Location -LiteralPath $PSScriptRoot
try {
    foreach ($line in Get-Content -LiteralPath 'third-party/native-binaries.sha256') {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw 'Invalid native checksum line.' }
        $expected = $Matches[1]
        $binary = $Matches[2]
        if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $expected) {
            throw "Native checksum mismatch for $binary"
        }
    }
    $sdkProperty = $SdkPath.Replace('\', '/').Replace(':', '\:')
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'local.properties'),
        ('sdk.dir=' + $sdkProperty + [char]10), [Text.UTF8Encoding]::new($false))
    $versionMatch = [regex]::Match((Get-Content -LiteralPath 'app/build.gradle' -Raw),
        '(?m)^\s*versionName\s*=\s*"([A-Za-z0-9.-]+)"')
    if (-not $versionMatch.Success) { throw 'Cannot determine versionName.' }
    $name = 'OConnect-Flexible-' + $versionMatch.Groups[1].Value
    if ($Keystore) {
        Invoke-Checked '.\gradlew.bat' @('--no-daemon', '--console=plain',
            ':app:testDebugUnitTest', ':app:lintRelease', ':app:assembleRelease')
        $unsigned = 'app/build/outputs/apk/release/app-release-unsigned.apk'
        $aligned = 'app/build/outputs/apk/release/app-release-aligned.apk'
        Invoke-Checked $zipalign @('-f', '-P', '16', '4', $unsigned, $aligned)
        $apk = Join-Path $OutputDirectory "$name.apk"
        $keyPasswordVariable = if ($env:OCONNECT_KEY_PASSWORD) { 'OCONNECT_KEY_PASSWORD' } else { 'OCONNECT_KEYSTORE_PASSWORD' }
        Invoke-Checked $apksigner @('sign', '--ks', $Keystore, '--ks-key-alias', $KeyAlias,
            '--ks-pass', 'env:OCONNECT_KEYSTORE_PASSWORD', '--key-pass', "env:$keyPasswordVariable",
            '--v4-signing-enabled', 'false', '--out', $apk, $aligned)
    } else {
        Invoke-Checked '.\gradlew.bat' @('--no-daemon', '--console=plain',
            ':app:testDebugUnitTest', ':app:lintDebug', ':app:assembleDebug')
        $apk = Join-Path $OutputDirectory "$name-debug.apk"
        Copy-Item -LiteralPath 'app/build/outputs/apk/debug/app-debug.apk' -Destination $apk -Force
    }
    Invoke-Checked $apksigner @('verify', '--verbose', '--print-certs', $apk)
    Invoke-Checked $zipalign @('-c', '-P', '16', '4', $apk)
    $hash = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(($apk + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($apk) + [char]10))
    Write-Output "APK: $apk"
} finally {
    Pop-Location
}
