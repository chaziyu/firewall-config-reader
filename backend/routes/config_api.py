"""
backend/routes/config_api.py
JSON API routes for Palo Alto and FortiGate sections + Policy Match / Policy Lookup.
"""

from __future__ import annotations

import gc
from pathlib import PurePath
import re

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from backend.auth import is_authenticated
from backend.session_store import SessionData, is_loopback_request, store

router = APIRouter(prefix="/api")


def _require_config_session(request: Request, expected_vendor: str) -> SessionData:
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or sess._sealed_content is None or sess.vendor != expected_vendor:
        raise HTTPException(status_code=404, detail=f"No active {expected_vendor} configuration loaded.")
    return sess


@router.get("/pa/lifecycle")
def get_paloalto_lifecycle(request: Request):
    from backend.lifecycle_service import (
        build_paloalto_lifecycle_blocks,
        evaluate_paloalto_lifecycle,
    )

    sess = _require_config_session(request, "Palo Alto")
    try:
        parsers = store.get_palo_alto_parsers_for_session(sess)
        info = parsers["Dashboard"].get_system_info()
        lifecycle = evaluate_paloalto_lifecycle(
            info.get("software_version"),
            is_exact_version=bool(info.get("software_version_exact", True)),
            cache_only=False,
        )
        badge, card = build_paloalto_lifecycle_blocks(lifecycle)
        return {"badge": badge, "card": card}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error checking PAN-OS lifecycle: {exc}") from exc


@router.get("/pa/{section}")
async def get_paloalto_section(section: str, request: Request):
    from backend.view_models.paloalto import build_paloalto_section

    sess = _require_config_session(request, "Palo Alto")
    try:
        parsers = store.get_palo_alto_parsers_for_session(sess)
        return build_paloalto_section(section, parsers, allow_probe=is_loopback_request(request))
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
    parsers = store.get_palo_alto_parsers_for_session(sess)
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
    rule = res.get("rule")
    shadowed = res.get("shadowed") or []
    if not res.get("matched") or not isinstance(rule, dict):
        reason = res.get("reason") or "No policy matched all criteria. Traffic hits Implicit Default Deny."
        return {
            "matched": False,
            "reason": reason,
            "blocks": [
                {
                    "type": "alert",
                    "variant": "error",
                    "text": f"No Matching Policy — Implicit DENY. {reason}",
                }
            ],
        }

    action = str(rule.get("Action", "ALLOW")).upper()
    is_allow = action in ("ALLOW", "ACCEPT", "PERMIT", "FORWARD")
    cols = [k for k in rule.keys() if not str(k).startswith("_")]
    table_blk = {
        "type": "table",
        "id": f"pa_match_{body.policy_type}",
        "columns": cols,
        "rows": [{c: str(rule.get(c, "")) for c in cols}],
        "row_classes": ["row-success" if is_allow else "row-danger"],
        "legend": [
            {"label": "Matched Allow Rule (green)", "variant": "success"},
            {"label": "Matched Deny/Drop Rule (red)", "variant": "danger"},
        ],
        "export_filename": f"pa_match_{body.policy_type}.csv",
    }

    rule_name = rule.get("Rule Name", "-")
    priority = rule.get("Priority (Index)", "-")
    blocks: list[dict] = [
        {
            "type": "card",
            "title": f"First Matching Rule: #{priority} — {rule_name}",
            "badge": {"text": action, "variant": "allow" if is_allow else "deny"},
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Rule Name", "value": str(rule_name)},
                {"label": "Priority (Index)", "value": f"#{priority}"},
                {"label": "Action", "value": action},
                {"label": "Zones", "value": f"{rule.get('Source Zone', 'any')} → {rule.get('Dest Zone', 'any')}"},
                {"label": "Service", "value": str(rule.get("Service", "any"))},
            ],
        },
        table_blk,
    ]

    if shadowed:
        blocks.append(
            {
                "type": "alert",
                "variant": "warn",
                "text": f"{len(shadowed)} subsequent shadowed rule(s) would also match this traffic after #{priority} ({rule_name}).",
            }
        )
        blocks.append(
            {
                "type": "expander",
                "title": f"Shadowed / Subsequent Matches ({len(shadowed)})",
                "open": False,
                "blocks": [
                    {
                        "type": "table",
                        "id": f"pa_match_{body.policy_type}_shadowed",
                        "columns": cols,
                        "rows": [{c: str(r.get(c, "")) for c in cols} for r in shadowed],
                        "row_classes": ["row-warn"] * len(shadowed),
                        "legend": [{"label": "Shadowed Rule (amber)", "variant": "warn"}],
                        "export_filename": f"pa_match_{body.policy_type}_shadowed.csv",
                    }
                ],
            }
        )

    return {
        "matched": True,
        "reason": res.get("reason", ""),
        "table": table_blk,
        "blocks": blocks,
    }


@router.get("/fg/lifecycle")
def get_fortigate_lifecycle(request: Request):
    from backend.lifecycle_service import (
        build_fortigate_lifecycle_blocks,
        evaluate_fortigate_lifecycle,
    )

    sess = _require_config_session(request, "FortiGate")
    try:
        fg = store.get_fortigate_parser_for_session(sess)
        model = fg.get_model()
        firmware = fg.get_firmware_version()
        lifecycle = evaluate_fortigate_lifecycle(model, firmware, cache_only=False)
        badge, card = build_fortigate_lifecycle_blocks(lifecycle)
        return {"badge": badge, "card": card}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error checking FortiGate lifecycle: {exc}") from exc


@router.get("/fg/{section}")
def get_fortigate_section(section: str, request: Request):
    from backend.view_models.fortigate import build_fortigate_section

    sess = _require_config_session(request, "FortiGate")
    try:
        fg = store.get_fortigate_parser_for_session(sess)
        return build_fortigate_section(section, fg, allow_probe=is_loopback_request(request))
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
    from backend.policy_lookup_service import evaluate_fortigate_lookup_detailed

    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser_for_session(sess)
    result = evaluate_fortigate_lookup_detailed(
        fg,
        src_iface=body.src_iface,
        dst_iface=body.dst_iface,
        src_addr=body.src_addr,
        dst_addr=body.dst_addr,
        protocol=body.protocol,
    )
    match = result.get("match")
    shadowed = result.get("shadowed") or []
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
    blocks: list[dict] = [
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
            "legend": [
                {"label": "Matched Allow Policy (green)", "variant": "success"},
                {"label": "Matched Deny Policy (red)", "variant": "danger"},
            ],
            "export_filename": "policy_lookup_result.csv",
        },
    ]

    if shadowed:
        blocks.append(
            {
                "type": "alert",
                "variant": "warn",
                "text": f"{len(shadowed)} subsequent shadowed policy(s) would also match this traffic after #{match.get('ID', '?')}.",
            }
        )
        blocks.append(
            {
                "type": "expander",
                "title": f"Shadowed / Subsequent Matches ({len(shadowed)})",
                "open": False,
                "blocks": [
                    {
                        "type": "table",
                        "id": "fg_lookup_shadowed",
                        "columns": cols,
                        "rows": [{c: str(r.get(c, "")) for c in cols} for r in shadowed],
                        "row_classes": ["row-warn"] * len(shadowed),
                        "legend": [{"label": "Shadowed Policy (amber)", "variant": "warn"}],
                        "export_filename": "policy_lookup_shadowed.csv",
                    }
                ],
            }
        )

    return {"matched": True, "blocks": blocks}


class FgRouteLookupRequest(BaseModel):
    dest_ip: str


class PaRouteLookupRequest(BaseModel):
    dest_ip: str
    virtual_router: str = "all"


def _build_route_lookup_response(res: dict, vendor_label: str) -> dict:
    if not res.get("valid"):
        return {
            "matched": False,
            "blocks": [{"type": "alert", "variant": "error", "text": res.get("error", "Invalid IP address.")}],
        }

    dest_ip = res["dest_ip"]
    winner = res.get("winner")
    candidates = res.get("candidates") or []
    active_pr = int(res.get("active_policy_routes") or 0)

    if winner is None:
        blocks: list[dict] = [
            {
                "type": "alert",
                "variant": "error",
                "text": f"No active connected or static route matched {dest_ip} ({vendor_label}).",
            }
        ]
        if active_pr > 0:
            blocks.append(
                {
                    "type": "alert",
                    "variant": "info",
                    "text": f"Note: {active_pr} active policy route(s) exist and are evaluated before static/connected routes.",
                }
            )
        return {"matched": False, "blocks": blocks}

    cols = list(winner.keys())
    next_hop = winner.get("Gateway") or winner.get("Next Hop") or "-"
    dist_val = winner.get("Distance") if "Distance" in winner else winner.get("AD", "-")
    metric_val = winner.get("Priority") if "Priority" in winner else winner.get("Metric", "-")
    row_classes = ["row-success"] + [""] * max(0, len(candidates) - 1)

    blocks = [
        {
            "type": "card",
            "title": f"Winning Route for {dest_ip}: {winner.get('Destination', '-')}",
            "subtitle": f"{winner.get('Type', 'Route')} via {winner.get('Interface', '-')}",
            "badge": {"text": winner.get("Type", "MATCH"), "variant": "allow"},
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Matched Prefix", "value": str(winner.get("Destination", "-"))},
                {"label": "Egress Interface", "value": str(winner.get("Interface", "-"))},
                {"label": "Next Hop / Gateway", "value": str(next_hop)},
                {"label": "Distance / Metric", "value": f"{dist_val} / {metric_val}"},
            ],
        },
        {
            "type": "table",
            "id": "route_lookup_candidates",
            "title": f"Matching Candidate Routes ({len(candidates)})",
            "columns": cols,
            "rows": [{c: str(r.get(c, "")) for c in cols} for r in candidates],
            "row_classes": row_classes,
            "legend": [
                {"label": "Winning Route (LPM)", "variant": "success"},
                {"label": "Less-Specific / Backup Route", "variant": "default"},
            ],
            "export_filename": "route_lookup_candidates.csv",
        },
    ]
    if active_pr > 0:
        blocks.append(
            {
                "type": "alert",
                "variant": "info",
                "text": f"Note: {active_pr} active policy route(s) exist and are evaluated before static/connected routes.",
            }
        )
    return {"matched": True, "blocks": blocks}


@router.post("/fg/route-lookup")
async def fg_route_lookup(body: FgRouteLookupRequest, request: Request):
    from backend.route_lookup_service import lookup_fortigate_route

    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser_for_session(sess)
    res = lookup_fortigate_route(fg, body.dest_ip)
    return _build_route_lookup_response(res, "FortiGate")


@router.post("/pa/route-lookup")
async def pa_route_lookup(body: PaRouteLookupRequest, request: Request):
    from backend.route_lookup_service import lookup_paloalto_route

    sess = _require_config_session(request, "Palo Alto")
    parsers = store.get_palo_alto_parsers_for_session(sess)
    res = lookup_paloalto_route(parsers["Network"], body.dest_ip, body.virtual_router)
    return _build_route_lookup_response(res, "Palo Alto")


class WhereUsedRequest(BaseModel):
    query: str = ""


@router.post("/fg/where-used")
async def fg_where_used(body: WhereUsedRequest, request: Request):
    from backend.where_used_service import build_where_used_blocks, search_fortigate_where_used

    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser_for_session(sess)
    res = search_fortigate_where_used(fg, body.query)
    found, blocks = build_where_used_blocks(res)
    return {"found": found, "blocks": blocks}


@router.post("/pa/where-used")
async def pa_where_used(body: WhereUsedRequest, request: Request):
    from backend.where_used_service import build_where_used_blocks, search_paloalto_where_used

    sess = _require_config_session(request, "Palo Alto")
    parsers = store.get_palo_alto_parsers_for_session(sess)
    res = search_paloalto_where_used(parsers, body.query)
    found, blocks = build_where_used_blocks(res)
    return {"found": found, "blocks": blocks}


@router.post("/fg/exposure-probe")
def fg_exposure_probe(request: Request):
    from backend.exposure_check import (
        build_exposure_probe_blocks,
        find_fortigate_public_mgmt_exposure,
        probe_exposure_targets,
    )

    if not is_loopback_request(request):
        raise HTTPException(
            status_code=403,
            detail="Live reachability probe is only available on direct local/desktop sessions.",
        )
    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser_for_session(sess)
    findings = find_fortigate_public_mgmt_exposure(fg)
    results = probe_exposure_targets(findings)
    return build_exposure_probe_blocks(results)


@router.post("/pa/exposure-probe")
def pa_exposure_probe(request: Request):
    from backend.exposure_check import (
        build_exposure_probe_blocks,
        find_paloalto_public_mgmt_exposure,
        probe_exposure_targets,
    )

    if not is_loopback_request(request):
        raise HTTPException(
            status_code=403,
            detail="Live reachability probe is only available on direct local/desktop sessions.",
        )
    sess = _require_config_session(request, "Palo Alto")
    parsers = store.get_palo_alto_parsers_for_session(sess)
    findings = find_paloalto_public_mgmt_exposure(
        parsers["Network"],
        device_parser=parsers.get("Device"),
        dashboard_parser=parsers.get("Dashboard"),
    )
    results = probe_exposure_targets(findings)
    return build_exposure_probe_blocks(results)


def _parse_diff_upload(filename: str, content: bytes, expected_vendor: str) -> bytes:
    from backend.upload_service import (
        UploadValidationError,
        sanitize_config_bytes,
        validate_content,
        validate_filename,
    )

    try:
        ext, is_tsf = validate_filename(filename)
        if is_tsf:
            raise UploadValidationError("Please upload a configuration file (.xml, .conf, or .txt), not a TSF .zip.")
        validate_content(content, is_tsf=False)
    except UploadValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    upload_vendor = "Palo Alto" if ext == ".xml" else "FortiGate"
    if upload_vendor != expected_vendor:
        raise HTTPException(
            status_code=400,
            detail=f"Expected a {expected_vendor} config file to compare against the active {expected_vendor} session.",
        )
    return sanitize_config_bytes(content, expected_vendor)


@router.post("/fg/config-diff")
def fg_config_diff(request: Request, file: UploadFile = File(...)):
    from backend.config_diff_service import build_config_diff_blocks, diff_fortigate_configs
    from parsers.fortigate import FortiGateParser

    sess = _require_config_session(request, "FortiGate")
    after_name = file.filename or "comparison.conf"
    raw_bytes = file.file.read()
    clean_bytes = _parse_diff_upload(after_name, raw_bytes, "FortiGate")
    try:
        after_fg = FortiGateParser(clean_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse FortiGate comparison config: {exc}") from exc

    before_fg = store.get_fortigate_parser_for_session(sess)
    diff_res = diff_fortigate_configs(before_fg, after_fg)
    return build_config_diff_blocks(diff_res, sess.filename or "Current Config", after_name)


@router.post("/pa/config-diff")
def pa_config_diff(request: Request, file: UploadFile = File(...)):
    import xml.etree.ElementTree as ET
    from backend.config_diff_service import build_config_diff_blocks, diff_paloalto_configs
    from parsers.paloalto import (
        PaloDashboardParser,
        PaloDeviceParser,
        PaloNetworkParser,
        PaloObjectsParser,
        PaloPoliciesParser,
    )

    sess = _require_config_session(request, "Palo Alto")
    after_name = file.filename or "comparison.xml"
    raw_bytes = file.file.read()
    clean_bytes = _parse_diff_upload(after_name, raw_bytes, "Palo Alto")
    try:
        root = ET.fromstring(clean_bytes.lstrip(b"\xef\xbb\xbf"))
        after_parsers = {
            "Dashboard": PaloDashboardParser(root),
            "Policies": PaloPoliciesParser(root),
            "Objects": PaloObjectsParser(root),
            "Network": PaloNetworkParser(root),
            "Device": PaloDeviceParser(root),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse Palo Alto comparison XML: {exc}") from exc

    before_parsers = store.get_palo_alto_parsers_for_session(sess)
    diff_res = diff_paloalto_configs(before_parsers, after_parsers)
    return build_config_diff_blocks(diff_res, sess.filename or "Current Config", after_name)


class PacketTraceRequest(BaseModel):
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: str = "443"
    protocol: str = "tcp"
    virtual_router: str = "all"
    check_return: bool = True


@router.post("/fg/packet-trace")
def fg_packet_trace(body: PacketTraceRequest, request: Request):
    from backend.packet_trace_service import build_packet_trace_blocks, trace_fortigate_packet

    sess = _require_config_session(request, "FortiGate")
    fg = store.get_fortigate_parser_for_session(sess)
    trace = trace_fortigate_packet(
        fg,
        body.src_ip,
        body.dst_ip,
        body.dst_port,
        body.protocol,
        check_return=body.check_return,
    )
    return build_packet_trace_blocks(trace)


@router.post("/pa/packet-trace")
def pa_packet_trace(body: PacketTraceRequest, request: Request):
    from backend.packet_trace_service import build_packet_trace_blocks, trace_paloalto_packet

    sess = _require_config_session(request, "Palo Alto")
    parsers = store.get_palo_alto_parsers_for_session(sess)
    trace = trace_paloalto_packet(
        parsers,
        body.src_ip,
        body.dst_ip,
        body.dst_port,
        body.protocol,
        body.virtual_router,
        check_return=body.check_return,
    )
    return build_packet_trace_blocks(trace)


@router.get("/export/report")
def export_audit_report(request: Request):
    from backend.excel_export import get_downloads_dir, unique_export_path
    from backend.report_export_service import (
        generate_fortigate_audit_report_html,
        generate_paloalto_audit_report_html,
    )
    from backend.update_service import is_frozen_desktop_exe

    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or sess._sealed_content is None or sess.vendor not in ("Palo Alto", "FortiGate"):
        raise HTTPException(status_code=404, detail="No active firewall configuration loaded.")

    fname = sess.filename or "firewall_config"
    if sess.vendor == "Palo Alto":
        parsers = store.get_palo_alto_parsers_for_session(sess)
        html_bytes = generate_paloalto_audit_report_html(parsers, fname)
    else:
        fg = store.get_fortigate_parser_for_session(sess)
        html_bytes = generate_fortigate_audit_report_html(fg, fname)

    stem = PurePath(fname).stem
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("_") or "firewall_config"
    out_stem = f"{safe_stem}_audit_report"

    if is_frozen_desktop_exe() and is_loopback_request(request):
        dest = unique_export_path(get_downloads_dir(), out_stem, ".html")
        dest.write_bytes(html_bytes)
        return JSONResponse({"saved": True, "filename": dest.name, "path": str(dest)})

    out_name = f"{out_stem}.html"
    return Response(
        content=html_bytes,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )


@router.get("/export/excel")
def export_config_excel(request: Request):
    from backend.excel_export import (
        export_fortigate_excel,
        export_paloalto_excel,
        get_downloads_dir,
        unique_export_path,
    )
    from backend.update_service import is_frozen_desktop_exe

    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or sess._sealed_content is None or sess.vendor not in ("Palo Alto", "FortiGate"):
        raise HTTPException(status_code=404, detail="No active firewall configuration loaded.")

    if sess.vendor == "Palo Alto":
        parsers = store.get_palo_alto_parsers_for_session(sess)
        xlsx_bytes = export_paloalto_excel(parsers)
    else:
        fg = store.get_fortigate_parser_for_session(sess)
        xlsx_bytes = export_fortigate_excel(fg)
    gc.collect()

    stem = PurePath(sess.filename or "firewall_config").stem
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("_") or "firewall_config"
    out_stem = f"{safe_stem}_export"

    if is_frozen_desktop_exe() and is_loopback_request(request):
        dest = unique_export_path(get_downloads_dir(), out_stem, ".xlsx")
        dest.write_bytes(xlsx_bytes)
        return JSONResponse({"saved": True, "filename": dest.name, "path": str(dest)})

    out_name = f"{out_stem}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )
