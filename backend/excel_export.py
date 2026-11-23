"""
backend/excel_export.py
Exports all extracted firewall configuration data into a single .xlsx workbook.
Uses minimal styling: only header row fill color, leaving all other cells unstyled.
"""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import PatternFill
from openpyxl.utils import get_column_letter

from backend.view_models.fortigate import build_fortigate_section
from backend.view_models.paloalto import build_paloalto_section

PALO_ALTO_SECTIONS = ("Dashboard", "Policies", "Objects", "Network", "Device")
FORTIGATE_SECTIONS = (
    "Summary",
    "Interfaces",
    "Network",
    "Policy & Objects",
    "Security",
    "VPN",
    "User & Auth",
    "WiFi & Switch",
    "System",
    "Log & Report",
)

_HEADER_FILL = PatternFill(start_color="DCE6F1", end_color="DCE6F1", fill_type="solid")
_INVALID_SHEET_CHARS_RE = re.compile(r"[:\\/?*\[\]]")


def _sanitize_sheet_name(name: str, used: set[str]) -> str:
    clean = _INVALID_SHEET_CHARS_RE.sub("_", name).strip() or "Sheet"
    base = clean[:31]
    candidate = base
    idx = 2
    while candidate in used:
        suffix = f"_{idx}"
        candidate = f"{base[: 31 - len(suffix)]}{suffix}"
        idx += 1
    used.add(candidate)
    return candidate


def _collect_datasets(
    blocks: list[dict[str, Any]],
    prefix: str = "",
) -> list[tuple[str, list[str], list[list[str]]]]:
    """Recursively flatten declarative UI blocks into (title, columns, rows) tuples."""
    datasets: list[tuple[str, list[str], list[list[str]]]] = []

    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")

        if btype == "table":
            cols = [str(c) for c in (block.get("columns") or [])]
            raw_rows = block.get("rows") or []
            if not cols or not raw_rows:
                continue
            title = str(block.get("title") or "").strip()
            full_title = f"{prefix} — {title}" if (prefix and title) else (title or prefix)
            rows = [[str(r.get(c, "")) for c in cols] for r in raw_rows]
            datasets.append((full_title, cols, rows))

        elif btype == "kv_grid":
            items = block.get("items") or []
            if not items:
                continue
            rows = []
            for item in items:
                val = str(item.get("value", ""))
                sub = str(item.get("sub") or "").strip()
                if sub:
                    val = f"{val} ({sub})"
                rows.append([str(item.get("label", "")), val])
            datasets.append((prefix or "Summary", ["Property", "Value"], rows))

        elif btype == "card":
            card_rows = block.get("rows") or []
            if not card_rows:
                continue
            title = str(block.get("title") or "").strip()
            full_title = f"{prefix} — {title}" if (prefix and title) else (title or prefix)
            rows = [[str(r.get("label", "")), str(r.get("value", ""))] for r in card_rows]
            datasets.append((full_title, ["Property", "Value"], rows))

        elif btype == "tabs":
            for tab in block.get("tabs") or []:
                tab_label = str(tab.get("label") or "").strip()
                next_prefix = f"{prefix} - {tab_label}" if (prefix and tab_label) else (tab_label or prefix)
                datasets.extend(_collect_datasets(tab.get("blocks") or [], next_prefix))

        elif btype == "expander":
            exp_title = str(block.get("title") or "").strip()
            next_prefix = f"{prefix} - {exp_title}" if (prefix and exp_title) else (exp_title or prefix)
            datasets.extend(_collect_datasets(block.get("blocks") or [], next_prefix))

        elif btype == "profile_selector":
            for prof in block.get("profiles") or []:
                prof_label = str(prof.get("label") or "").strip()
                next_prefix = f"{prefix} - {prof_label}" if (prefix and prof_label) else (prof_label or prefix)
                datasets.extend(_collect_datasets(prof.get("blocks") or [], next_prefix))

    return datasets


def _measure_text_width(val: Any) -> int:
    text = "" if val is None else str(val)
    if not text:
        return 0
    return max((len(line) for line in text.splitlines()), default=0)


def _build_workbook(sections: list[tuple[str, dict[str, Any]]]) -> bytes:
    wb = Workbook()
    # Remove default sheet after creating section sheets
    default_ws = wb.active
    used_names: set[str] = set()

    for sec_name, payload in sections:
        ws = wb.create_sheet(title=_sanitize_sheet_name(sec_name, used_names))
        datasets = _collect_datasets(payload.get("blocks") or [])
        if not datasets:
            ws.append(["No data extracted."])
            ws.column_dimensions["A"].width = 24
            continue

        col_widths: dict[int, int] = {}
        for idx, (title, cols, rows) in enumerate(datasets):
            if idx > 0:
                ws.append([])
            if title:
                ws.append([title])
            ws.append(cols)
            header_row_idx = ws.max_row
            for col_idx, col_name in enumerate(cols, start=1):
                ws.cell(row=header_row_idx, column=col_idx).fill = _HEADER_FILL
                col_widths[col_idx] = max(col_widths.get(col_idx, 0), _measure_text_width(col_name))
            for row in rows:
                ws.append(row)
                for col_idx, val in enumerate(row, start=1):
                    col_widths[col_idx] = max(col_widths.get(col_idx, 0), _measure_text_width(val))

        for col_idx, max_len in col_widths.items():
            ws.column_dimensions[get_column_letter(col_idx)].width = min(max(max_len + 4, 12), 60)

    if default_ws is not None and len(wb.worksheets) > 1:
        wb.remove(default_ws)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def export_paloalto_excel(parsers: dict[str, Any]) -> bytes:
    sections = [(sec, build_paloalto_section(sec, parsers)) for sec in PALO_ALTO_SECTIONS]
    return _build_workbook(sections)


def export_fortigate_excel(parser: Any) -> bytes:
    sections = [(sec, build_fortigate_section(sec, parser)) for sec in FORTIGATE_SECTIONS]
    return _build_workbook(sections)


def get_downloads_dir() -> Path:
    """Return the user's Downloads directory (Windows Known Folder with Path.home fallback)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            # FOLDERID_Downloads = {374DE290-123F-4565-9164-39C4925E467B}
            downloads_guid = GUID(
                0x374DE290,
                0x123F,
                0x4565,
                (ctypes.c_ubyte * 8)(0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B),
            )
            path_ptr = ctypes.c_wchar_p()
            hr = ctypes.windll.shell32.SHGetKnownFolderPath(
                ctypes.byref(downloads_guid), 0, None, ctypes.byref(path_ptr)
            )
            if hr == 0 and path_ptr.value:
                result = Path(path_ptr.value)
                ctypes.windll.ole32.CoTaskMemFree(path_ptr)
                result.mkdir(parents=True, exist_ok=True)
                return result
        except Exception:
            pass
    fallback = Path.home() / "Downloads"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def unique_export_path(directory: Path, stem: str, ext: str = ".xlsx") -> Path:
    """Return a non-colliding path in *directory*, appending -1, -2, ... if needed."""
    candidate = directory / f"{stem}{ext}"
    if not candidate.exists():
        return candidate
    idx = 1
    while True:
        candidate = directory / f"{stem}-{idx}{ext}"
        if not candidate.exists():
            return candidate
        idx += 1

