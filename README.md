# APKAnalyzer — Plateforme d'analyse dynamique APK

Analyse dynamique temps réel d'applications Android via Frida + dashboard React.

## Architecture

```
APK → ADB → Émulateur Android → frida-server → hooks.js
                                                    ↓
                                             analyzer.py (Python)
                                                    ↓ WebSocket
                                            FastAPI backend (:8000)
                                                    ↓ WebSocket
                                          React Dashboard (:3000)
```

## Prérequis

- Python 3.11+
- Node.js 20+
- Android SDK (adb, aapt, emulator)
- frida-server pour Android x86_64 ([télécharger ici](https://github.com/frida/frida/releases))
- Docker + docker-compose (optionnel)

## Installation

### 1. Backend FastAPI
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2. Moteur d'analyse
```bash
cd analyzer
pip install -r requirements.txt
```

### 3. Frontend React
```bash
cd frontend
npm install
npm run dev
```

## Utilisation

### Étape 1 — Préparer l'émulateur
```bash
# Lancer un AVD existant
emulator -avd Pixel_6_API_33 -no-audio -no-window &

# Pousser frida-server
adb push frida-server-16.x-android-x86_64 /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Étape 2 — Lancer les services
```bash
# Terminal 1
cd backend && uvicorn main:app --reload

# Terminal 2
cd frontend && npm run dev
```

### Étape 3 — Analyser un APK
```bash
# Via l'interface web : http://localhost:3000
# Glisser-déposer l'APK → Cliquer "Démarrer l'analyse"

# Ou directement en CLI :
cd analyzer
python main.py /path/to/target.apk \
  --serial emulator-5554 \
  --ws ws://localhost:8000 \
  --frida-server /path/to/frida-server
```

## Docker (tout-en-un)
```bash
docker-compose up --build
# → Frontend : http://localhost:3000
# → Backend  : http://localhost:8000
```

## Fonctionnalités

### Analyse dynamique (temps réel via Frida)
- **Réseau** : OkHttp3, HttpURLConnection, URL, TLS handshake
- **Crypto** : Cipher, MessageDigest, SecretKeySpec, KeyStore, TrustManager custom
- **Fichiers** : FileInputStream/OutputStream, SharedPreferences, File.delete
- **SQL** : execSQL, rawQuery, INSERT, UPDATE, DELETE
- **Permissions** : requestPermissions runtime, checkSelfPermission
- **IPC** : startActivity, sendBroadcast, startService, ContentResolver
- **GPS** : LocationManager, FusedLocationProvider
- **Capteurs** : AudioRecord, Camera2, MediaRecorder, TelephonyManager
- **Clipboard** : setPrimaryClip, getPrimaryClip
- **Anti-analyse** : Debug.isDebuggerConnected (bypass), Runtime.exec, Build.FINGERPRINT

### Analyse statique (androguard)
- Manifest complet (debuggable, allowBackup, cleartext traffic)
- Permissions déclarées avec niveau de protection
- Activités/Services/Receivers exportés
- Secrets hardcodés (AWS keys, Google API keys, JWT, passwords)
- SDKs tiers détectés
- Bibliothèques natives

### Scoring de risque automatique
- Score global 0–100 (pondéré sur 5 dimensions)
- Dimensions : Réseau, Permissions, Crypto, Comportement, Statique
- 20+ règles de détection automatique
- Alertes temps réel classées CRITICAL / HIGH / MEDIUM

## Structure des fichiers

```
apk-analyzer/
├── docker-compose.yml
├── analyzer/
│   ├── main.py                    ← Entrée CLI
│   ├── analyzer.py                ← Orchestrateur Frida
│   ├── requirements.txt
│   ├── frida_agent/
│   │   └── hooks.js               ← 12 catégories de hooks
│   └── static_analysis/
│       └── apk_parser.py          ← Analyse statique androguard
├── backend/
│   ├── main.py                    ← FastAPI + WebSocket
│   ├── requirements.txt
│   └── Dockerfile
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── index.html
    └── src/
        ├── main.tsx
        └── App.tsx                ← Dashboard React complet
```

## API Endpoints

| Méthode | Route | Description |
|---------|-------|-------------|
| POST | `/api/apk/upload` | Upload APK → lance analyse statique |
| GET  | `/api/apk/{id}/static` | Rapport analyse statique |
| POST | `/api/analysis/start` | Démarrer analyse dynamique |
| POST | `/api/analysis/stop` | Arrêter + rapport final |
| GET  | `/api/analysis/{id}/report` | Rapport complet |
| GET  | `/api/sessions` | Liste des sessions |
| WS   | `/ws/{session_id}` | Stream événements → frontend |
| WS   | `/internal/{session_id}` | Stream analyzer.py → backend |