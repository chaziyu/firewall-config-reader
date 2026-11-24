"""
backend/update_service.py
GitHub Releases update checker, SHA-256 verified downloader, silent Inno Setup self-updater
(for frozen desktop .exe), and git-pull updater (for local source runs).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

APP_VERSION = "2.4.2"
GITHUB_REPO = os.environ.get("FW_GITHUB_REPO", "chaziyu/firewall-config-reader")
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ALLOWED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
ROOT_DIR = Path(__file__).resolve().parent.parent


def parse_version_tuple(ver_str: str) -> tuple[int, ...]:
    """Parse 'v2.3.1' or '2.3.1' into a tuple of ints (2, 3, 1) for comparison."""
    cleaned = ver_str.strip().lstrip("vV").split("-")[0]
    parts = []
    for p in cleaned.split("."):
        m = re.match(r"^(\d+)", p)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts) or (0,)


def is_newer_version(latest: str, current: str = APP_VERSION) -> bool:
    return parse_version_tuple(latest) > parse_version_tuple(current)


def is_frozen_desktop_exe() -> bool:
    """Return True only when running inside the packaged PyInstaller Windows .exe."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


def is_local_git_checkout() -> bool:
    """Return True when running from a local git clone with git available on PATH."""
    return not is_frozen_desktop_exe() and (ROOT_DIR / ".git").exists() and shutil.which("git") is not None


def get_runtime_mode(is_loopback: bool) -> str:
    """Return 'cloud' | 'desktop' | 'source'."""
    if not is_loopback:
        return "cloud"
    if is_frozen_desktop_exe():
        return "desktop"
    return "source"


def check_for_updates(timeout: float = 4.0, is_loopback: bool = True) -> dict[str, Any]:
    """Query GitHub Releases API for the latest release."""
    mode = get_runtime_mode(is_loopback)
    if mode == "cloud":
        return {
            "mode": "cloud",
            "checked": True,
            "current_version": APP_VERSION,
            "latest_version": APP_VERSION,
            "update_available": False,
            "can_auto_install": False,
        }

    req = urllib.request.Request(
        GITHUB_API_LATEST,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"FirewallConfigReader/{APP_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "mode": mode,
                "checked": True,
                "current_version": APP_VERSION,
                "latest_version": APP_VERSION,
                "update_available": False,
                "can_auto_install": False,
            }
        return {
            "mode": mode,
            "checked": False,
            "current_version": APP_VERSION,
            "update_available": False,
            "error": f"GitHub API returned HTTP {exc.code}",
        }
    except Exception as exc:
        return {
            "mode": mode,
            "checked": False,
            "current_version": APP_VERSION,
            "update_available": False,
            "error": str(exc),
        }

    tag = str(data.get("tag_name") or "").strip()
    latest_ver = tag.lstrip("vV") or APP_VERSION
    html_url = str(data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases")
    body = str(data.get("body") or "").strip()

    installer_asset = None
    sums_asset = None
    for asset in data.get("assets") or []:
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if name.lower().startswith("firewallconfigreader-setup-") and name.lower().endswith(".exe"):
            installer_asset = {"name": name, "url": url, "size": int(asset.get("size") or 0)}
        elif name == "SHA256SUMS.txt":
            sums_asset = {"name": name, "url": url}

    newer = is_newer_version(latest_ver, APP_VERSION)
    can_install = False
    install_method = None
    if newer:
        if mode == "desktop" and installer_asset:
            can_install = True
            install_method = "installer"
        elif mode == "source" and is_local_git_checkout():
            can_install = True
            install_method = "git_pull"

    return {
        "mode": mode,
        "checked": True,
        "current_version": APP_VERSION,
        "latest_version": latest_ver,
        "update_available": newer,
        "release_url": html_url,
        "release_notes": body[:1000],
        "installer_asset": installer_asset,
        "sums_asset": sums_asset,
        "can_auto_install": can_install,
        "install_method": install_method,
    }


def _validate_github_url(url: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"Refusing to download update from untrusted host: {parsed.hostname}")


def _download_bytes(url: str, timeout: float = 60.0) -> bytes:
    _validate_github_url(url)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"FirewallConfigReader/{APP_VERSION}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _verify_sha256(file_bytes: bytes, filename: str, sums_text: str) -> bool:
    actual = hashlib.sha256(file_bytes).hexdigest().lower()
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].strip("*") == filename:
            expected = parts[0].strip().lower()
            return actual == expected
    return False


def _run_git_pull_update(latest_version: str) -> dict[str, Any]:
    """Pull latest changes via git fast-forward when running from a local git repository."""
    if not is_local_git_checkout():
        raise RuntimeError("Local directory is not a git repository.")
    res = subprocess.run(
        ["git", "pull", "--ff-only"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "git pull failed").strip()
        raise RuntimeError(f"git pull failed: {err}")
    return {
        "ok": True,
        "method": "git_pull",
        "latest_version": latest_version,
        "message": f"Updated local repository to v{latest_version} via git pull. Restart the local server to apply.",
    }


def download_and_trigger_install() -> dict[str, Any]:
    """Execute the appropriate update mechanism for the current runtime mode (desktop .exe vs local git source)."""
    info = check_for_updates(timeout=8.0, is_loopback=True)
    if not info.get("checked"):
        raise RuntimeError(info.get("error") or "Unable to reach GitHub Releases.")
    if not info.get("update_available"):
        raise RuntimeError(f"Already on the latest version (v{APP_VERSION}).")

    # Mode 2: Local website running from source checkout -> run git pull --ff-only
    if not is_frozen_desktop_exe():
        if is_local_git_checkout():
            return _run_git_pull_update(info["latest_version"])
        raise RuntimeError(
            "Running from unpacked source without git. Download the latest release from GitHub Releases."
        )

    # Mode 1: Packaged Desktop .exe -> download Inno Setup installer, verify SHA-256, and run silent upgrade
    installer = info.get("installer_asset")
    if not installer or not installer.get("url"):
        raise RuntimeError("No Windows Setup .exe asset found on the latest GitHub Release.")

    update_dir = Path(tempfile.gettempdir()) / "fw_config_reader_update"
    update_dir.mkdir(parents=True, exist_ok=True)
    exe_name = Path(installer["name"]).name
    exe_path = update_dir / exe_name

    exe_bytes = _download_bytes(installer["url"], timeout=120.0)
    if len(exe_bytes) < 1024 or not exe_bytes.startswith(b"MZ"):
        raise RuntimeError("Downloaded installer file is invalid or corrupted.")

    sums_asset = info.get("sums_asset")
    if sums_asset and sums_asset.get("url"):
        sums_bytes = _download_bytes(sums_asset["url"], timeout=15.0)
        sums_text = sums_bytes.decode("utf-8", errors="replace")
        if not _verify_sha256(exe_bytes, exe_name, sums_text):
            raise RuntimeError("SHA-256 checksum verification failed for downloaded installer.")

    exe_path.write_bytes(exe_bytes)

    current_exe = sys.executable
    batch_path = update_dir / "run_update.cmd"
    batch_contents = (
        "@echo off\r\n"
        "ping 127.0.0.1 -n 2 > nul\r\n"
        f'"{exe_path}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS\r\n'
        f'start "" "{current_exe}"\r\n'
    )
    batch_path.write_text(batch_contents, encoding="utf-8")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
        subprocess, "DETACHED_PROCESS", 0
    )
    subprocess.Popen(
        ["cmd.exe", "/c", str(batch_path)],
        creationflags=creationflags,
        close_fds=True,
    )

    threading.Timer(0.6, lambda: os._exit(0)).start()

    return {
        "ok": True,
        "method": "installer",
        "latest_version": info["latest_version"],
        "installer_path": str(exe_path),
        "message": f"Update v{info['latest_version']} verified and launched. The app will restart automatically.",
    }
