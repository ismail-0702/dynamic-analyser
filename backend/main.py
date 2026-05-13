"""FastAPI application for the APK Dynamic Analyzer."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.routers import analysis, apk, ws

app = FastAPI(title="APK Dynamic Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(apk.router)
app.include_router(analysis.router)
app.include_router(ws.router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Return backend health status."""
    return {"status": "ok"}
