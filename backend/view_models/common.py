"""
backend/view_models/common.py
Shared declarative UI block builders and standardized visual semantics
used across both FortiGate and Palo Alto view models.
"""

from __future__ import annotations

from typing import Any, Callable

POLICY_LEGEND: list[dict[str, str]] = [
    {"label": "Enabled (default)", "variant": "default"},
    {"label": "Disabled (red)", "variant": "danger"},
]

PA_POLICY_LEGEND: list[dict[str, str]] = [
    {"label": "Enabled (default)", "variant": "default"},
    {"label": "Disabled (red)", "variant": "danger"},
    {"label": "Panorama (purple)", "variant": "purple"},
]

ADMIN_LEGEND: list[dict[str, str]] = [
    {"label": "Full Privilege Admin (amber)", "variant": "warn"},
    {"label": "Scoped Admin (default)", "variant": "default"},
]


def is_truthy(val: Any) -> bool:
    """Return True if a config toggle/boolean-like value represents an enabled state."""
    return str(val or "").strip().lower() in (
        "enable",
        "enabled",
        "on",
        "yes",
        "true",
        "1",
        "✓",
        "all",
    )


def toggle_row(
    label: str,
    val: Any,
    *,
    on_label: str = "ON",
    off_label: str = "OFF",
) -> dict[str, str]:
    """Build a standardized ON/OFF key-value card row with tone badge."""
    on = is_truthy(val)
    return {
        "label": label,
        "value": on_label if on else off_label,
        "tone": "allow" if on else "muted",
    }


def table_block(
    rows: list[dict[str, Any]] | None,
    table_id: str,
    title: str = "",
    empty_text: str = "Not configured.",
    caption: str = "",
    export_filename: str | None = None,
    row_class_fn: Callable[[dict[str, Any]], str] | None = None,
    filter_col: str | None = None,
    drop_keys: set[str] | None = None,
    legend: list[dict[str, str] | str] | None = None,
) -> dict[str, Any]:
    """Build a declarative table block or an info alert when rows are empty."""
    if not rows:
        return {"type": "alert", "variant": "info", "text": empty_text}

    skip = drop_keys or set()
    cols = [k for k in rows[0].keys() if not str(k).startswith("_") and k not in skip]
    clean_rows = [{c: ("" if r.get(c) is None else str(r.get(c))) for c in cols} for r in rows]
    row_classes = [row_class_fn(r) if row_class_fn else "" for r in rows]

    blk: dict[str, Any] = {
        "type": "table",
        "id": table_id,
        "title": title,
        "columns": cols,
        "rows": clean_rows,
        "row_classes": row_classes,
        "caption": caption,
        "export_filename": export_filename or f"{table_id}.csv",
    }
    if filter_col and filter_col in cols:
        blk["filter_col"] = filter_col
    if legend:
        blk["legend"] = legend
    return blk


def kv_dict_blocks(
    data: dict[str, Any] | None,
    *,
    title: str = "",
    empty_text: str = "Not configured.",
    toggle_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert a single-object settings dict into compact kv_grid + toggle card blocks."""
    blocks: list[dict[str, Any]] = []
    if title:
        blocks.append({"type": "section_header", "title": title})
    if not data:
        blocks.append({"type": "alert", "variant": "info", "text": empty_text})
        return blocks

    tkeys = toggle_keys or set()
    kv_items: list[dict[str, Any]] = []
    toggle_rows: list[dict[str, str]] = []
    for k, v in data.items():
        if str(k).startswith("_"):
            continue
        if k in tkeys or v == "✓" or v == "":
            toggle_rows.append(toggle_row(str(k), v))
        else:
            val_str = "—" if v is None or str(v).strip() == "" else str(v)
            kv_items.append({"label": str(k), "value": val_str})

    if kv_items:
        blocks.append({"type": "kv_grid", "items": kv_items})
    if toggle_rows:
        blocks.append({"type": "card", "rows": toggle_rows})
    if not kv_items and not toggle_rows:
        blocks.append({"type": "alert", "variant": "info", "text": empty_text})
    return blocks


def policy_caption(total: int, disabled: int, panorama: int = 0) -> str:
    """Build a consistent summary caption for policy tables across vendors."""
    cap = f"Total: {total} · Enabled: {total - disabled} · Disabled: {disabled}"
    if panorama:
        cap += f" · Panorama: {panorama}"
    return cap
