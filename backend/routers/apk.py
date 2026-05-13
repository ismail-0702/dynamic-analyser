"""APK upload routes."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import aiofiles
from fastapi import APIRouter, HTTPException, UploadFile

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.static_analysis.apk_parser import APKStaticAnalyzer
from backend.models.session import UploadResponse
from backend.services.session_manager import UPLOAD_DIR, session_manager

router = APIRouter(prefix="/api/apk", tags=["apk"])


@router.post("/upload", response_model=UploadResponse)
async def upload_apk(file: UploadFile) -> UploadResponse:
    """Save an uploaded APK, run static analysis, and create a session."""
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename).name
    target_path = UPLOAD_DIR / safe_name
    async with aiofiles.open(target_path, "wb") as out_file:
        while chunk := await file.read(1024 * 1024):
            await out_file.write(chunk)

    session = session_manager.create_session(str(target_path))
    try:
        loop = asyncio.get_running_loop()
        static_report = await loop.run_in_executor(None, lambda: APKStaticAnalyzer(str(target_path)).get_full_report())
    except Exception as exc:
        try:
            os.remove(target_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Static analysis failed: {exc}") from exc

    session_manager.set_static_report(session.session_id, static_report)
    return UploadResponse(session_id=session.session_id, static_analysis=static_report)
