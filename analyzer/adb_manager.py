"""ADB and emulator helpers for the dynamic analyzer."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path

log = logging.getLogger(__name__)


class ADBManager:

    def __init__(self, serial: str | None = None) -> None:
        self.serial = serial
        self.base_cmd = ["adb"] + (["-s", serial] if serial else [])

    def wait_for_device(self, timeout_seconds: int = 90) -> None:
        log.info("Waiting for Android device via ADB")
        self._run("wait-for-device", timeout=timeout_seconds)

    def install_apk(self, apk_path: str) -> None:
        log.info("Installing APK: %s", apk_path)
        result = self._run("install", "-r", "-g", apk_path)
        if "Success" not in result.stdout:
            raise RuntimeError(f"APK installation failed: {result.stderr.strip()}")

    def push_frida_server(self, local_path: str, remote_path: str = "/data/local/tmp/frida-server") -> None:
        log.info("Pushing frida-server to %s", remote_path)
        self._run("push", local_path, remote_path)
        self._run("shell", "chmod", "755", remote_path)

    def start_frida_server(self, remote_path: str = "/data/local/tmp/frida-server") -> None:
        probe = self._run("shell", "pgrep", "-f", "frida-server", check=False)
        if probe.returncode == 0:
            log.info("frida-server already running")
            return
        log.info("Starting frida-server")
        subprocess.Popen(
            self.base_cmd + ["shell", f"{remote_path} >/dev/null 2>&1 &"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    def get_package_name(self, apk_path: str) -> str:
        try:
            aapt = self._find_aapt()
            result = subprocess.run(
                [aapt, "dump", "badging", apk_path],
                capture_output=True, text=True, check=False
            )
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
        except RuntimeError:
            log.info("aapt unavailable; falling back to androguard")

        from static_analysis.apk_parser import APKStaticAnalyzer
        manifest = APKStaticAnalyzer(apk_path).get_manifest_info()
        package_name = str(manifest.get("package") or "")
        if not package_name:
            raise RuntimeError("Could not extract package name from APK")
        return package_name

    def stop_app(self, package_name: str) -> None:
        self._run("shell", "am", "force-stop", package_name, check=False)

    def uninstall(self, package_name: str) -> None:
        self._run("uninstall", package_name, check=False)

    def _run(self, *args: str, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess:
        cmd = self.base_cmd + list(args)
        log.debug("ADB: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)

    @staticmethod
    def _find_aapt() -> str:
        for candidate in ("aapt", "aapt.exe"):
            try:
                subprocess.run([candidate, "version"], capture_output=True, check=False)
                return candidate
            except FileNotFoundError:
                continue
        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root:
            local_app_data = os.environ.get("LOCALAPPDATA")
            sdk_root = str(Path(local_app_data or "") / "Android" / "Sdk") if local_app_data else ""
        for path in sorted(Path(sdk_root).glob("build-tools/*/aapt.exe"), reverse=True):
            return str(path)
        raise RuntimeError("aapt not found. Set ANDROID_HOME or add build-tools to PATH.")