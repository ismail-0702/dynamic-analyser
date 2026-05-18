# Lance uvicorn depuis la racine du projet (obligatoire pour "import backend")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    . .\.venv\Scripts\Activate.ps1
}

$env:PYTHONPATH = $root
if ($env:ADB_SERIAL) {
    Write-Host "ADB_SERIAL=$env:ADB_SERIAL"
}

Write-Host "Backend: http://127.0.0.1:8000" -ForegroundColor Cyan
uvicorn backend.main:app --reload --port 8000
