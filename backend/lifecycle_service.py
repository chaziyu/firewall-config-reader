"""
backend/lifecycle_service.py
Hybrid FortiGate hardware & FortiOS branch lifecycle auto-checker.

Combines:
1. Live branch EOS / EOES dates from https://endoflife.date/api/v1/products/fortios/
2. Live latest patch per branch from https://support.fortinet.com/rss/firmware.xml
3. Bundled offline snapshot (data/fortigate_lifecycle.json) for hardware EOS,
   Last Supported Firmware, and air-gapped/fallback branch metadata.
"""

from __future__ import annotations

from datetime import date
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any
import urllib.request
import xml.etree.ElementTree as ET

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "fortigate_lifecycle.json"
_PA_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "paloalto_lifecycle.json"
_ENDOFLIFE_URL = "https://endoflife.date/api/v1/products/fortios/"
_PA_ENDOFLIFE_URL = "https://endoflife.date/api/v1/products/pan-os/"
_FORTINET_RSS_URL = "https://support.fortinet.com/rss/firmware.xml"
_HTTP_TIMEOUT_SECONDS = 3.0
_LIVE_CACHE_TTL_SECONDS = 86400
_EOS_SOON_DAYS = 180
_USER_AGENT = "FirewallConfigReader/2.4.2"

_VARIANT_SUFFIXES = ("-POE", "-DSL", "-3G4G", "-5G", "-WIFI")
_RSS_TITLE_RE = re.compile(r"^FortiOS\s+(\d+\.\d+\.\d+)$")
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")
_PANOS_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)(?:-h(\d+))?", re.IGNORECASE)
_BRANCH_RE = re.compile(r"(\d+\.\d+)")

_catalog_lock = threading.Lock()
_catalog_cache: dict[str, Any] | None = None

_pa_catalog_lock = threading.Lock()
_pa_catalog_cache: dict[str, Any] | None = None

_live_lock = threading.Lock()
_live_cache: dict[str, Any] = {
    "fetched_at": 0.0,
    "endoflife": None,
    "rss": None,
}

_pa_live_lock = threading.Lock()
_pa_live_cache: dict[str, Any] = {
    "fetched_at": 0.0,
    "endoflife": None,
}


def clear_lifecycle_cache() -> None:
    """Reset in-memory catalog and live-check caches (primarily for tests)."""
    global _catalog_cache, _pa_catalog_cache
    with _catalog_lock:
        _catalog_cache = None
    with _pa_catalog_lock:
        _pa_catalog_cache = None
    with _live_lock:
        _live_cache["fetched_at"] = 0.0
        _live_cache["endoflife"] = None
        _live_cache["rss"] = None
    with _pa_live_lock:
        _pa_live_cache["fetched_at"] = 0.0
        _pa_live_cache["endoflife"] = None


def _load_bundled_catalog() -> dict[str, Any]:
    global _catalog_cache
    with _catalog_lock:
        if _catalog_cache is not None:
            return _catalog_cache
        if not _CATALOG_PATH.exists():
            _catalog_cache = {"updated_at": "", "branches": {}, "models": {}}
            return _catalog_cache
        data = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
        data.setdefault("updated_at", "")
        data.setdefault("branches", {})
        data.setdefault("models", {})
        _catalog_cache = data
        return _catalog_cache


def _parse_version_tuple(ver: str | None) -> tuple[int, ...] | None:
    if not ver:
        return None
    m = _VERSION_RE.search(str(ver).strip())
    if not m:
        return None
    return tuple(int(part) for part in m.group(1).split("."))


def _parse_iso_date(val: str | None) -> date | None:
    if not val:
        return None
    try:
        return date.fromisoformat(str(val).strip()[:10])
    except ValueError:
        return None


def _is_online_allowed(allow_online: bool | None) -> bool:
    if allow_online is not None:
        return bool(allow_online)
    disabled = os.environ.get("DISABLE_ONLINE_CHECKS", "").strip().lower()
    return disabled not in ("1", "true", "yes")


def _fetch_endoflife_branches() -> dict[str, dict[str, str | None]]:
    """Fetch FortiOS branch lifecycle dates from endoflife.date."""
    req = urllib.request.Request(
        _ENDOFLIFE_URL,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    releases = (payload.get("result") or {}).get("releases") or []
    out: dict[str, dict[str, str | None]] = {}
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        name = str(rel.get("name") or "").strip()
        if not name:
            continue
        latest_raw = rel.get("latest")
        latest_name: str | None = None
        if isinstance(latest_raw, dict):
            latest_name = str(latest_raw.get("name") or "").strip() or None
        elif isinstance(latest_raw, str):
            latest_name = latest_raw.strip() or None
        out[name] = {
            "release_date": rel.get("releaseDate"),
            "eoes": rel.get("eoasFrom"),
            "eos": rel.get("eolFrom"),
            "latest": latest_name,
        }
    return out


def _fetch_fortinet_rss_latest() -> dict[str, str]:
    """Fetch latest GA FortiOS patch versions per branch from Fortinet's firmware RSS."""
    req = urllib.request.Request(
        _FORTINET_RSS_URL,
        headers={"User-Agent": _USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as resp:
        raw_xml = resp.read().decode("utf-8", errors="replace")

    root = ET.fromstring(raw_xml)
    best: dict[str, tuple[tuple[int, ...], str]] = {}
    for item in root.findall(".//item"):
        title_el = item.find("title")
        if title_el is None or not title_el.text:
            continue
        title = title_el.text.strip()
        m = _RSS_TITLE_RE.match(title)
        if not m:
            continue
        ver = m.group(1)
        ver_tuple = _parse_version_tuple(ver)
        if ver_tuple is None:
            continue
        branch = ".".join(ver.split(".")[:2])
        prev = best.get(branch)
        if prev is None or ver_tuple > prev[0]:
            best[branch] = (ver_tuple, ver)

    return {branch: pair[1] for branch, pair in best.items()}


def is_live_cache_warm() -> bool:
    """Return True if the live lifecycle cache was fetched within the TTL window."""
    now = time.monotonic()
    with _live_lock:
        fetched_at = float(_live_cache["fetched_at"] or 0.0)
        return fetched_at > 0.0 and (now - fetched_at) < _LIVE_CACHE_TTL_SECONDS


def _get_live_data(
    allow_online: bool | None,
    *,
    cache_only: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if not _is_online_allowed(allow_online):
        return None, None

    now = time.monotonic()
    with _live_lock:
        fetched_at = float(_live_cache["fetched_at"] or 0.0)
        if fetched_at > 0.0 and (now - fetched_at) < _LIVE_CACHE_TTL_SECONDS:
            return _live_cache["endoflife"], _live_cache["rss"]
        if cache_only:
            return None, None

    eol_data: dict[str, Any] | None = None
    rss_data: dict[str, str] | None = None
    try:
        eol_data = _fetch_endoflife_branches()
    except Exception:
        eol_data = None
    try:
        rss_data = _fetch_fortinet_rss_latest()
    except Exception:
        rss_data = None

    with _live_lock:
        _live_cache["fetched_at"] = time.monotonic()
        _live_cache["endoflife"] = eol_data
        _live_cache["rss"] = rss_data

    return eol_data, rss_data


def _merge_branches(
    bundled_branches: dict[str, Any],
    eol_data: dict[str, Any] | None,
    rss_data: dict[str, str] | None,
) -> dict[str, dict[str, str | None]]:
    merged: dict[str, dict[str, str | None]] = {}
    for branch, meta in (bundled_branches or {}).items():
        if isinstance(meta, dict):
            merged[branch] = {
                "release_date": meta.get("release_date"),
                "eoes": meta.get("eoes"),
                "eos": meta.get("eos"),
                "latest": meta.get("latest"),
            }

    if eol_data:
        for branch, meta in eol_data.items():
            entry = merged.setdefault(
                branch,
                {"release_date": None, "eoes": None, "eos": None, "latest": None},
            )
            for field in ("release_date", "eoes", "eos"):
                if meta.get(field):
                    entry[field] = meta[field]
            live_latest = meta.get("latest")
            if live_latest:
                live_t = _parse_version_tuple(live_latest)
                cur_t = _parse_version_tuple(entry.get("latest"))
                if live_t is not None and (cur_t is None or live_t > cur_t):
                    entry["latest"] = live_latest

    if rss_data:
        for branch, rss_ver in rss_data.items():
            entry = merged.setdefault(
                branch,
                {"release_date": None, "eoes": None, "eos": None, "latest": None},
            )
            rss_t = _parse_version_tuple(rss_ver)
            cur_t = _parse_version_tuple(entry.get("latest"))
            if rss_t is not None and (cur_t is None or rss_t > cur_t):
                entry["latest"] = rss_ver

    return merged


def normalize_fortigate_model(raw_model: str | None) -> str:
    """Normalize raw FortiGate model tokens (e.g. 'FGT60F', 'FG100E') to canonical 'FG-60F'."""
    raw = str(raw_model or "").strip()
    if not raw or raw.lower() == "unknown":
        return ""

    upper = re.sub(r"[\s_]+", "-", raw.upper())
    upper = re.sub(r"-{2,}", "-", upper).strip("-")

    if upper.startswith(("FGVM", "FG-VM", "FORTIGATE-VM")):
        return "FG-VM"

    for prefix, canonical_prefix in (
        ("FORTIGATE-", "FG-"),
        ("FORTIGATE", "FG-"),
        ("FGT-", "FG-"),
        ("FGT", "FG-"),
        ("FG-", "FG-"),
        ("FG", "FG-"),
        ("FWF-", "FWF-"),
        ("FWF", "FWF-"),
        ("FGR-", "FGR-"),
        ("FGR", "FGR-"),
    ):
        if upper.startswith(prefix):
            rest = upper[len(prefix):].lstrip("-")
            if rest:
                return f"{canonical_prefix}{rest}"
            break

    return upper


def _lookup_model_entry(canonical_model: str, models: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    if not canonical_model:
        return "", None
    if canonical_model in models:
        return canonical_model, models[canonical_model]
    for suffix in _VARIANT_SUFFIXES:
        if canonical_model.endswith(suffix):
            base = canonical_model[: -len(suffix)]
            if base in models:
                return base, models[base]
    return canonical_model, None


def _format_source_label(
    eol_data: dict[str, Any] | None,
    rss_data: dict[str, str] | None,
    updated_at: str,
) -> str:
    if eol_data is not None and rss_data is not None:
        return "Live (endoflife.date + Fortinet RSS)"
    if eol_data is not None:
        return "Live (endoflife.date) · Snapshot fallback"
    if rss_data is not None:
        return "Live (Fortinet RSS) · Snapshot fallback"
    return f"Offline snapshot ({updated_at})" if updated_at else "Offline snapshot"


def evaluate_fortigate_lifecycle(
    model_raw: str | None,
    firmware_raw: str | None,
    *,
    allow_online: bool | None = None,
    cache_only: bool = False,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate FortiGate hardware & FortiOS branch lifecycle status."""
    ref_today = today or date.today()
    catalog = _load_bundled_catalog()
    updated_at = str(catalog.get("updated_at") or "")
    models = catalog.get("models") or {}

    needs_live_refresh = bool(cache_only and _is_online_allowed(allow_online) and not is_live_cache_warm())
    eol_data, rss_data = _get_live_data(allow_online, cache_only=cache_only)
    branches = _merge_branches(catalog.get("branches") or {}, eol_data, rss_data)
    source_label = _format_source_label(eol_data, rss_data, updated_at)

    canonical_model = normalize_fortigate_model(model_raw)
    matched_key, model_entry = _lookup_model_entry(canonical_model, models)
    is_vm = bool(model_entry.get("is_vm")) if model_entry else (canonical_model == "FG-VM")
    display_model = (
        str(model_entry.get("display_name") or matched_key)
        if model_entry
        else (canonical_model or str(model_raw or "Unknown"))
    )

    hw_eos_str = model_entry.get("eos") if model_entry else None
    hw_eos_date = _parse_iso_date(hw_eos_str)
    last_supported = str(model_entry.get("last_supported_firmware") or "") if model_entry else ""

    if is_vm:
        hw_status = "vm"
    elif model_entry is None:
        hw_status = "unknown"
    elif hw_eos_date is not None:
        days_left = (hw_eos_date - ref_today).days
        if days_left < 0:
            hw_status = "eos"
        elif days_left <= _EOS_SOON_DAYS:
            hw_status = "eos_soon"
        else:
            hw_status = "active"
    else:
        hw_status = "active"

    fw_str = str(firmware_raw or "").strip()
    fw_ver_match = _VERSION_RE.search(fw_str)
    fw_version = fw_ver_match.group(1) if fw_ver_match else (fw_str if fw_str and fw_str.lower() != "unknown" else "")
    fw_branch_match = _BRANCH_RE.search(fw_version or fw_str)
    fw_branch = fw_branch_match.group(1) if fw_branch_match else ""

    branch_meta = branches.get(fw_branch) if fw_branch else None
    eoes_str = branch_meta.get("eoes") if branch_meta else None
    branch_eos_str = branch_meta.get("eos") if branch_meta else None
    latest_in_branch = branch_meta.get("latest") if branch_meta else None

    eoes_date = _parse_iso_date(eoes_str)
    branch_eos_date = _parse_iso_date(branch_eos_str)

    if not branch_meta:
        branch_status = "unknown"
    elif branch_eos_date is not None and branch_eos_date < ref_today:
        branch_status = "eos"
    elif eoes_date is not None and eoes_date <= ref_today:
        branch_status = "eoes"
    else:
        branch_status = "supported"

    fw_tuple = _parse_version_tuple(fw_version)
    latest_tuple = _parse_version_tuple(latest_in_branch)
    if fw_tuple is None or latest_tuple is None:
        patch_status = "unknown"
    elif fw_tuple < latest_tuple:
        patch_status = "update_available"
    else:
        patch_status = "up_to_date"

    last_supported_capped_eos = False
    if last_supported and last_supported.lower() not in ("active", "unknown"):
        cap_branch_m = _BRANCH_RE.search(last_supported)
        if cap_branch_m:
            cap_meta = branches.get(cap_branch_m.group(1))
            cap_eos = _parse_iso_date(cap_meta.get("eos") if cap_meta else None)
            if cap_eos is not None and cap_eos < ref_today:
                last_supported_capped_eos = True

    if hw_status == "eos":
        badge_text = "Hardware EOS"
        badge_variant = "deny"
    elif branch_status == "eos":
        badge_text = "Branch EOS"
        badge_variant = "deny"
    elif hw_status == "eos_soon":
        badge_text = "Hardware EOS Soon"
        badge_variant = "warn"
    elif branch_status == "eoes":
        badge_text = "Branch EOES"
        badge_variant = "warn"
    elif patch_status == "update_available" and latest_in_branch:
        badge_text = f"Patch Available ({latest_in_branch})"
        badge_variant = "warn"
    elif branch_status == "supported" and patch_status == "up_to_date":
        badge_text = "Lifecycle OK · Up to Date"
        badge_variant = "allow"
    elif branch_status == "supported":
        badge_text = "Branch Supported"
        badge_variant = "allow"
    else:
        badge_text = "Lifecycle Unknown"
        badge_variant = "muted"

    return {
        "model_raw": str(model_raw or "Unknown"),
        "model_canonical": canonical_model or "Unknown",
        "model_display": display_model or "Unknown",
        "model_known": model_entry is not None,
        "is_vm": is_vm,
        "hw_eoo": model_entry.get("eoo") if model_entry else None,
        "hw_lsed": model_entry.get("lsed") if model_entry else None,
        "hw_eos": hw_eos_str,
        "hw_status": hw_status,
        "last_supported_firmware": last_supported or "Unknown",
        "last_supported_capped_eos": last_supported_capped_eos,
        "firmware_version": fw_version or "Unknown",
        "firmware_branch": fw_branch or "Unknown",
        "branch_eoes": eoes_str,
        "branch_eos": branch_eos_str,
        "branch_status": branch_status,
        "latest_in_branch": latest_in_branch,
        "patch_status": patch_status,
        "badge_text": badge_text,
        "badge_variant": badge_variant,
        "source_label": source_label,
        "snapshot_updated_at": updated_at,
        "needs_live_refresh": needs_live_refresh,
        "today": ref_today.isoformat(),
    }


def build_fortigate_lifecycle_blocks(result: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    """Build the Summary hero badge and Lifecycle & Firmware card from an evaluation result."""
    hero_badge: dict[str, str] = {
        "id": "fg_lifecycle_badge",
        "text": str(result.get("badge_text") or "Lifecycle Unknown"),
        "variant": str(result.get("badge_variant") or "muted"),
    }

    hw_status = result.get("hw_status")
    hw_eos = result.get("hw_eos")
    if result.get("is_vm"):
        hw_eos_val = "N/A (Virtual Appliance)"
    elif hw_status == "eos" and hw_eos:
        hw_eos_val = f"{hw_eos} (Reached)"
    elif hw_status == "eos_soon" and hw_eos:
        hw_eos_val = f"{hw_eos} (Within {_EOS_SOON_DAYS}d)"
    elif hw_eos:
        hw_eos_val = str(hw_eos)
    elif result.get("model_known"):
        hw_eos_val = "Not Announced (Active)"
    else:
        hw_eos_val = "Unknown Model"

    last_fw = str(result.get("last_supported_firmware") or "Unknown")
    if last_fw.lower() == "active":
        last_fw_val = "Active (No Cap Announced)"
    elif last_fw == "Unknown":
        last_fw_val = "Unknown"
    elif result.get("last_supported_capped_eos"):
        last_fw_val = f"{last_fw} (Capped on EOS branch)"
    else:
        last_fw_val = last_fw

    fw_ver = str(result.get("firmware_version") or "Unknown")
    fw_branch = str(result.get("firmware_branch") or "Unknown")
    current_fw_val = f"{fw_ver} (Branch {fw_branch})" if fw_branch != "Unknown" else fw_ver

    latest = result.get("latest_in_branch")
    patch_status = result.get("patch_status")
    if patch_status == "up_to_date" and latest:
        latest_val = f"{latest} (Up to Date)"
    elif patch_status == "update_available" and latest:
        latest_val = f"{latest} (Upgrade Available)"
    elif latest:
        latest_val = str(latest)
    else:
        latest_val = "Unknown"

    branch_eoes = result.get("branch_eoes") or "Unknown"
    branch_eos = result.get("branch_eos")
    branch_status = result.get("branch_status")
    if branch_status == "eos" and branch_eos:
        branch_eos_val = f"{branch_eos} (End of Support)"
    elif branch_status == "eoes" and branch_eos:
        branch_eos_val = f"{branch_eos} (Engineering Support Ended)"
    elif branch_eos:
        branch_eos_val = str(branch_eos)
    else:
        branch_eos_val = "Unknown"

    rows: list[dict[str, str]] = [
        {"label": "Hardware Model", "value": str(result.get("model_display") or "Unknown")},
        {"label": "Hardware End of Support (EOS)", "value": hw_eos_val},
        {"label": "Last Supported Firmware", "value": last_fw_val},
        {"label": "Current Firmware", "value": current_fw_val},
        {"label": "Latest Firmware in Branch", "value": latest_val},
        {"label": "Branch End of Engineering Support (EOES)", "value": str(branch_eoes)},
        {"label": "Branch End of Support (EOS)", "value": branch_eos_val},
    ]

    subtitle = f"Model & FortiOS branch support status · Source: {result.get('source_label', 'Offline snapshot')}"
    if result.get("needs_live_refresh"):
        snap_date = result.get("snapshot_updated_at")
        snap_note = f"showing snapshot {snap_date}" if snap_date else "showing snapshot"
        subtitle = f"Model & FortiOS branch support status · Fetching live data… ({snap_note})"

    card: dict[str, Any] = {
        "type": "card",
        "id": "fg_lifecycle_card",
        "title": "Lifecycle & Firmware",
        "subtitle": subtitle,
        "badge": hero_badge,
        "rows": rows,
    }
    if result.get("needs_live_refresh"):
        card["async_refresh_url"] = "/api/fg/lifecycle"
        card["async_badge_id"] = "fg_lifecycle_badge"
    return hero_badge, card


# ── Palo Alto PAN-OS Branch & Hotfix Patch Lifecycle ─────────────────────────

def _load_pa_bundled_catalog() -> dict[str, Any]:
    global _pa_catalog_cache
    with _pa_catalog_lock:
        if _pa_catalog_cache is not None:
            return _pa_catalog_cache
        if not _PA_CATALOG_PATH.exists():
            _pa_catalog_cache = {"updated_at": "", "branches": {}}
            return _pa_catalog_cache
        data = json.loads(_PA_CATALOG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
        data.setdefault("updated_at", "")
        data.setdefault("branches", {})
        _pa_catalog_cache = data
        return _pa_catalog_cache


def _parse_panos_version_tuple(ver: str | None) -> tuple[int, int, int, int] | None:
    """Parse PAN-OS version + optional hotfix (e.g. '10.2.7-h3' -> (10, 2, 7, 3))."""
    if not ver:
        return None
    m = _PANOS_VERSION_RE.search(str(ver).strip())
    if not m:
        return None
    major, minor, patch = (int(p) for p in m.group(1).split("."))
    hotfix = int(m.group(2)) if m.group(2) else 0
    return (major, minor, patch, hotfix)


def is_pa_live_cache_warm() -> bool:
    """Return True if the PAN-OS live lifecycle cache was fetched within the TTL window."""
    now = time.monotonic()
    with _pa_live_lock:
        fetched_at = float(_pa_live_cache["fetched_at"] or 0.0)
        return fetched_at > 0.0 and (now - fetched_at) < _LIVE_CACHE_TTL_SECONDS


def _fetch_panos_endoflife_branches() -> dict[str, dict[str, str | None]]:
    """Fetch PAN-OS branch EOL dates & latest hotfix patch from endoflife.date."""
    req = urllib.request.Request(
        _PA_ENDOFLIFE_URL,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    releases = (payload.get("result") or {}).get("releases") or []
    out: dict[str, dict[str, str | None]] = {}
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        name = str(rel.get("name") or "").strip()
        if not name:
            continue
        latest_raw = rel.get("latest")
        latest_name: str | None = None
        latest_date: str | None = None
        if isinstance(latest_raw, dict):
            latest_name = str(latest_raw.get("name") or "").strip() or None
            latest_date = str(latest_raw.get("date") or "").strip() or None
        elif isinstance(latest_raw, str):
            latest_name = latest_raw.strip() or None
        out[name] = {
            "release_date": rel.get("releaseDate"),
            "eos": rel.get("eolFrom"),
            "latest": latest_name,
            "latest_date": latest_date,
        }
    return out


def _get_pa_live_data(
    allow_online: bool | None,
    *,
    cache_only: bool = False,
) -> dict[str, dict[str, str | None]] | None:
    if not _is_online_allowed(allow_online):
        return None

    now = time.monotonic()
    with _pa_live_lock:
        fetched_at = float(_pa_live_cache["fetched_at"] or 0.0)
        if fetched_at > 0.0 and (now - fetched_at) < _LIVE_CACHE_TTL_SECONDS:
            return _pa_live_cache["endoflife"]
        if cache_only:
            return None

    eol_data: dict[str, dict[str, str | None]] | None = None
    try:
        eol_data = _fetch_panos_endoflife_branches()
    except Exception:
        eol_data = None

    with _pa_live_lock:
        _pa_live_cache["fetched_at"] = time.monotonic()
        _pa_live_cache["endoflife"] = eol_data

    return eol_data


def _merge_pa_branches(
    bundled_branches: dict[str, Any],
    live_data: dict[str, dict[str, str | None]] | None,
) -> dict[str, dict[str, str | None]]:
    merged: dict[str, dict[str, str | None]] = {}
    for branch, meta in (bundled_branches or {}).items():
        if isinstance(meta, dict):
            merged[branch] = {
                "release_date": meta.get("release_date"),
                "eos": meta.get("eos"),
                "latest": meta.get("latest"),
                "latest_date": meta.get("latest_date"),
            }

    if live_data:
        for branch, meta in live_data.items():
            entry = merged.setdefault(
                branch,
                {"release_date": None, "eos": None, "latest": None, "latest_date": None},
            )
            for field in ("release_date", "eos"):
                if meta.get(field):
                    entry[field] = meta[field]
            live_latest = meta.get("latest")
            if live_latest:
                live_t = _parse_panos_version_tuple(live_latest)
                cur_t = _parse_panos_version_tuple(entry.get("latest"))
                if live_t is not None and (cur_t is None or live_t >= cur_t):
                    entry["latest"] = live_latest
                    if meta.get("latest_date"):
                        entry["latest_date"] = meta["latest_date"]
    return merged


def evaluate_paloalto_lifecycle(
    version_raw: str | None,
    *,
    is_exact_version: bool = True,
    allow_online: bool | None = None,
    cache_only: bool = False,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate PAN-OS branch EOL & latest hotfix patch status."""
    ref_today = today or date.today()
    catalog = _load_pa_bundled_catalog()
    updated_at = str(catalog.get("updated_at") or "")

    needs_live_refresh = bool(cache_only and _is_online_allowed(allow_online) and not is_pa_live_cache_warm())
    live_data = _get_pa_live_data(allow_online, cache_only=cache_only)
    branches = _merge_pa_branches(catalog.get("branches") or {}, live_data)

    if live_data is not None:
        source_label = "Live (endoflife.date)"
    else:
        source_label = f"Offline snapshot ({updated_at})" if updated_at else "Offline snapshot"

    ver_str = str(version_raw or "").strip()
    ver_match = _PANOS_VERSION_RE.search(ver_str)
    panos_version = ver_match.group(0) if ver_match else (ver_str if ver_str and ver_str not in ("-", "Unknown") else "")
    branch_match = _BRANCH_RE.search(panos_version or ver_str)
    panos_branch = branch_match.group(1) if branch_match else ""

    branch_meta = branches.get(panos_branch) if panos_branch else None
    branch_eos_str = branch_meta.get("eos") if branch_meta else None
    latest_in_branch = branch_meta.get("latest") if branch_meta else None
    latest_date = branch_meta.get("latest_date") if branch_meta else None
    branch_eos_date = _parse_iso_date(branch_eos_str)

    if not branch_meta:
        branch_status = "unknown"
    elif branch_eos_date is not None:
        days_left = (branch_eos_date - ref_today).days
        if days_left < 0:
            branch_status = "eos"
        elif days_left <= _EOS_SOON_DAYS:
            branch_status = "eos_soon"
        else:
            branch_status = "supported"
    else:
        branch_status = "supported"

    ver_tuple = _parse_panos_version_tuple(panos_version)
    latest_tuple = _parse_panos_version_tuple(latest_in_branch)
    if ver_tuple is None or latest_tuple is None:
        patch_status = "unknown"
    elif ver_tuple < latest_tuple:
        patch_status = "update_available"
    else:
        patch_status = "up_to_date"

    if branch_status == "eos":
        badge_text = "Branch EOL"
        badge_variant = "deny"
    elif patch_status == "update_available" and latest_in_branch:
        badge_text = f"Patch Available ({latest_in_branch})"
        badge_variant = "warn"
    elif branch_status == "eos_soon":
        badge_text = "Branch EOL Soon"
        badge_variant = "warn"
    elif branch_status == "supported" and patch_status == "up_to_date":
        badge_text = "PAN-OS Up to Date"
        badge_variant = "allow"
    elif branch_status == "supported":
        badge_text = "Branch Supported"
        badge_variant = "allow"
    else:
        badge_text = "PAN-OS Lifecycle Unknown"
        badge_variant = "muted"

    return {
        "panos_version": panos_version or "Unknown",
        "panos_branch": panos_branch or "Unknown",
        "is_exact_version": bool(is_exact_version),
        "branch_eos": branch_eos_str,
        "branch_status": branch_status,
        "latest_in_branch": latest_in_branch,
        "latest_date": latest_date,
        "patch_status": patch_status,
        "badge_text": badge_text,
        "badge_variant": badge_variant,
        "source_label": source_label,
        "snapshot_updated_at": updated_at,
        "needs_live_refresh": needs_live_refresh,
        "today": ref_today.isoformat(),
    }


def build_paloalto_lifecycle_blocks(result: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    """Build the Dashboard hero badge and PAN-OS Firmware card from an evaluation result."""
    hero_badge: dict[str, str] = {
        "id": "pa_lifecycle_badge",
        "text": str(result.get("badge_text") or "PAN-OS Lifecycle Unknown"),
        "variant": str(result.get("badge_variant") or "muted"),
    }

    ver = str(result.get("panos_version") or "Unknown")
    branch = str(result.get("panos_branch") or "Unknown")
    if branch != "Unknown" and not result.get("is_exact_version", True):
        current_val = f"{ver} (Branch {branch} · XML schema version)"
    elif branch != "Unknown":
        current_val = f"{ver} (Branch {branch})"
    else:
        current_val = ver

    latest = result.get("latest_in_branch")
    patch_status = result.get("patch_status")
    if patch_status == "up_to_date" and latest:
        latest_val = f"{latest} (Up to Date)"
    elif patch_status == "update_available" and latest:
        latest_val = f"{latest} (Upgrade Available)"
    elif latest:
        latest_val = str(latest)
    else:
        latest_val = "Unknown"

    latest_date = str(result.get("latest_date") or "Unknown")

    branch_eos = result.get("branch_eos")
    branch_status = result.get("branch_status")
    if branch_status == "eos" and branch_eos:
        branch_eos_val = f"{branch_eos} (End of Life)"
    elif branch_status == "eos_soon" and branch_eos:
        branch_eos_val = f"{branch_eos} (Within {_EOS_SOON_DAYS}d)"
    elif branch_eos:
        branch_eos_val = str(branch_eos)
    else:
        branch_eos_val = "Unknown"

    rows: list[dict[str, str]] = [
        {"label": "Current PAN-OS", "value": current_val},
        {"label": "Latest Patch in Branch", "value": latest_val},
        {"label": "Latest Release Date", "value": latest_date},
        {"label": "Branch End of Life (EOL)", "value": branch_eos_val},
    ]

    subtitle = f"PAN-OS branch support & patch status · Source: {result.get('source_label', 'Offline snapshot')}"
    if result.get("needs_live_refresh"):
        snap_date = result.get("snapshot_updated_at")
        snap_note = f"showing snapshot {snap_date}" if snap_date else "showing snapshot"
        subtitle = f"PAN-OS branch support & patch status · Fetching live data… ({snap_note})"

    card: dict[str, Any] = {
        "type": "card",
        "id": "pa_lifecycle_card",
        "title": "PAN-OS Firmware",
        "subtitle": subtitle,
        "badge": hero_badge,
        "rows": rows,
    }
    if result.get("needs_live_refresh"):
        card["async_refresh_url"] = "/api/pa/lifecycle"
        card["async_badge_id"] = "pa_lifecycle_badge"
    return hero_badge, card
