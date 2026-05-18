# Aligne frida (PC) et frida-server (émulateur) en version 16.x
# Frida 17+ ne fournit plus Java dans les scripts .js — requis pour APK Analyzer

$ErrorActionPreference = "Stop"
$FridaVersion = "16.7.19"
$Serial = if ($args[0]) { $args[0] } else { "emulator-5554" }

Write-Host "=== APK Analyzer — installation Frida $FridaVersion ===" -ForegroundColor Cyan

$abi = (adb -s $Serial shell getprop ro.product.cpu.abi).Trim()
Write-Host "ABI emulateur: $abi"

$arch = switch -Regex ($abi) {
    "x86_64" { "android-x86_64" }
    "x86"    { "android-x86" }
    "arm64"  { "android-arm64" }
    "armeabi" { "android-arm" }
    default  { throw "ABI non supporte: $abi" }
}

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Installation frida $FridaVersion dans .venv ..." -ForegroundColor Yellow
.\.venv\Scripts\pip install "frida==$FridaVersion" "frida-tools>=12.3.0,<13"

$serverName = "frida-server-$FridaVersion-$arch"
$xzPath = Join-Path $env:TEMP "$serverName.xz"
$serverPath = Join-Path $env:TEMP $serverName
$url = "https://github.com/frida/frida/releases/download/$FridaVersion/$serverName.xz"

if (-not (Test-Path $serverPath)) {
    Write-Host "Telechargement $url ..."
    Invoke-WebRequest -Uri $url -OutFile $xzPath
    if (Get-Command xz -ErrorAction SilentlyContinue) {
        xz -d -k $xzPath
    } else {
        python -c "import lzma,shutil; shutil.copyfileobj(lzma.open(r'$xzPath','rb'), open(r'$serverPath','wb'))"
    }
}

Write-Host "Arret ancien frida-server ..." -ForegroundColor Yellow
adb -s $Serial shell "su -c 'killall frida-server'" 2>$null
adb -s $Serial shell "killall frida-server" 2>$null
Start-Sleep -Seconds 1

Write-Host "Push frida-server vers /data/local/tmp/ ..." -ForegroundColor Yellow
adb -s $Serial push $serverPath /data/local/tmp/frida-server
adb -s $Serial shell "chmod 755 /data/local/tmp/frida-server"
adb -s $Serial shell "/data/local/tmp/frida-server -D &"
Start-Sleep -Seconds 2

$pcVer = .\.venv\Scripts\python -c "import frida; print(frida.__version__)"
$devVer = (adb -s $Serial shell "/data/local/tmp/frida-server --version").Trim()
Write-Host ""
Write-Host "frida PC     : $pcVer" -ForegroundColor Green
Write-Host "frida-server : $devVer" -ForegroundColor Green
Write-Host "Termine. Relancez l'analyse." -ForegroundColor Cyan
