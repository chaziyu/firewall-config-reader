"""
backend/routes/config_api.py
JSON API routes for Palo Alto and FortiGate sections + Policy Match / Policy Lookup.
"""

from __future__ import annotations

from pathlib import PurePath
import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from backend.auth import is_authenticated
from backend.session_store import SessionData, store

router = APIRouter(prefix="/api")


def _require_config_session(request: Request, expected_vendor: str) -> SessionData:
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or not sess.raw_content or sess.vendor != expected_vendor:
        raise HTTPException(status_code=404, detail=f"No active {expected_vendor} configuration loaded.")
    return sess


@router.get("/pa/{section}")
async def get_paloalto_section(section: str, request: Request):
    from backend.view_models.paloalto import build_paloalto_section

    sess = _require_config_session(request, "Palo Alto")
    try:
        parsers = store.get_palo_alto_parsers(sess.content_hash or "", sess.raw_content or b"")
        return build_paloalto_section(section, parsers)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error rendering section {section}: {exc}") from exc


class PaPolicyTestRequest(BaseModel):
    policy_type: str = "security"
    src_zone: str = "any"
    dst_zone: str = "any"
    src_interface: str = "any"
    dst_interface: str = "any"
    src_ip: str
    dst_ip: str
    src_user: str = "any"
    dst_port: str = "443"
    protocol: str = "tcp"


@router.post("/pa/policy-test")
async def pa_policy_test(body: PaPolicyTestRequest, request: Request):
    sess = _require_config_session(request, "Palo Alto")
    parsers = store.get_palo_alto_parsers(sess.content_hash or "", sess.raw_content or b"")
    pol_parser = parsers["Policies"]
    res = pol_parser.test_policy_match(
        body.policy_type,
        body.src_zone,
        body.dst_zone,
        body.src_interface,
        body.dst_interface,
        body.src_ip,
        body.dst_ip,
        body.src_user,
        body.dst_port,
        body.protocol,
    )
    payload: dict = {"matched": bool(res.get("matched")), "reason": res.get("reason", "")}
    rule = res.get("rule")
    if rule and isinstance(rule, dict):
        cols = [k for k in rule.keys() if not str(k).startswith("_")]
        payload["table"] = {
            "type": "table",
            "id": f"pa_match_{body.policy_type}",
            "columns": cols,
            "rows": [{c: str(rule.get(c, "")) for c in cols}],
            "row_classes": ["row-success"],
            "export_filename": f"pa_match_{body.policy_type}.csv",
        }
    return payload


@router.get("/fg/{section}")
async def get_fortigate_section(section: str, request: Request):
    from backend.view_models.fortigate import build_fortigate_section

    sess = _require_config_session(request, "FortiGate")
    try:
        fg = store.get_fortigate_parser(sess.content_hash or "", sess.raw_content or b"")
        return build_fortigate_section(section, fg)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error rendering section {section}: {exc}") from exc


class FgPolicyLookupRequest(BaseModel):
    src_iface: str = "any"
    dst_iface: str = "any"
    src_addr: str = ""
    dst_addr: str = ""
    protocol: str = "any"


@router.post("/fg/policy-lookup")
async def fg_policy_lookup(body: FgPolicyLookupRequest, request: Request):
    from backend.policy_lookup_service import evaluate_fortigate_lookup

    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser(sess.content_hash or "", sess.raw_content or b"")
    match = evaluate_fortigate_lookup(
        fg,
        src_iface=body.src_iface,
        dst_iface=body.dst_iface,
        src_addr=body.src_addr,
        dst_addr=body.dst_addr,
        protocol=body.protocol,
    )
    if match is None:
        return {
            "matched": False,
            "blocks": [
                {
                    "type": "alert",
                    "variant": "error",
                    "text": "No Matching Policy — Implicit DENY. Traffic would be dropped by the implicit deny rule.",
                }
            ],
        }

    action = str(match.get("Action", "-")).upper()
    cols = [k for k in match.keys() if not str(k).startswith("_")]
    return {
        "matched": True,
        "blocks": [
            {
                "type": "card",
                "title": f"First Matching Policy: #{match.get('ID', '?')} — {match.get('Name', '-')}",
                "badge": {"text": action, "variant": "allow" if action == "ACCEPT" else "deny"},
            },
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Policy ID", "value": f"#{match.get('ID', '?')}"},
                    {"label": "Action", "value": action},
                    {"label": "Src Interface", "value": match.get("Src Interface", "-")},
                    {"label": "Dst Interface", "value": match.get("Dst Interface", "-")},
                    {"label": "Service", "value": match.get("Service", "-")},
                    {"label": "NAT", "value": match.get("NAT", "-")},
                ],
            },
            {
                "type": "table",
                "id": "fg_lookup_match",
                "columns": cols,
                "rows": [{c: str(match.get(c, "")) for c in cols}],
                "row_classes": ["row-success" if action == "ACCEPT" else "row-danger"],
                "export_filename": "policy_lookup_result.csv",
            },
        ],
    }


@router.get("/export/excel")
def export_config_excel(request: Request):
    from backend.excel_export import export_fortigate_excel, export_paloalto_excel

    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or not sess.raw_content or sess.vendor not in ("Palo Alto", "FortiGate"):
        raise HTTPException(status_code=404, detail="No active firewall configuration loaded.")

    if sess.vendor == "Palo Alto":
        parsers = store.get_palo_alto_parsers(sess.content_hash or "", sess.raw_content)
        xlsx_bytes = export_paloalto_excel(parsers)
    else:
        fg = store.get_fortigate_parser(sess.content_hash or "", sess.raw_content)
        xlsx_bytes = export_fortigate_excel(fg)

    stem = PurePath(sess.filename or "firewall_config").stem
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("_") or "firewall_config"
    out_name = f"{safe_stem}_export.xlsx"

    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )
