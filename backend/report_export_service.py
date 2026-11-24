"""
backend/report_export_service.py
One-Click Firewall Health & Security Audit Report Export (self-contained HTML / Print-to-PDF).
All untrusted configuration values are strictly escaped with html.escape().
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
from typing import Any

from backend.audit_service import run_fortigate_audit, run_paloalto_audit
from backend.cert_inspector_service import inspect_fortigate_certificates, inspect_paloalto_certificates
from backend.exposure_check import find_fortigate_public_mgmt_exposure, find_paloalto_public_mgmt_exposure
from backend.hygiene_service import analyze_fortigate_hygiene, analyze_paloalto_hygiene
from backend.lifecycle_service import (
    build_fortigate_lifecycle_blocks,
    build_paloalto_lifecycle_blocks,
    evaluate_fortigate_lifecycle,
    evaluate_paloalto_lifecycle,
)
from backend.posture_service import evaluate_fortigate_posture, evaluate_paloalto_posture
from backend.vpn_inspector_service import inspect_fortigate_vpns, inspect_paloalto_vpns


def _e(val: Any) -> str:
    return html.escape(str(val if val is not None else "-"), quote=True)


def _badge_html(text: str, tone: str = "muted") -> str:
    cls = {
        "allow": "b-allow",
        "success": "b-allow",
        "warn": "b-warn",
        "deny": "b-deny",
        "danger": "b-deny",
        "info": "b-info",
    }.get(tone, "b-muted")
    return f'<span class="badge {cls}">{_e(text)}</span>'


def _kv_table_html(items: list[tuple[str, str]]) -> str:
    cells = "".join(
        f'<div class="kv-box"><div class="kv-lbl">{_e(k)}</div><div class="kv-val">{_e(v)}</div></div>'
        for k, v in items
    )
    return f'<div class="kv-grid">{cells}</div>'


def _table_html(columns: list[str], rows: list[dict[str, Any]], row_tones: list[str] | None = None, empty_msg: str = "None") -> str:
    if not rows:
        return f'<p class="muted">{_e(empty_msg)}</p>'
    ths = "".join(f"<th>{_e(c)}</th>" for c in columns)
    trs: list[str] = []
    for idx, r in enumerate(rows):
        tone = row_tones[idx] if row_tones and idx < len(row_tones) else ""
        tr_cls = f' class="tr-{_e(tone)}"' if tone else ""
        tds = "".join(f"<td>{_e(r.get(c, '-'))}</td>" for c in columns)
        trs.append(f"<tr{tr_cls}>{tds}</tr>")
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


def _render_report_document(
    *,
    vendor: str,
    hostname: str,
    filename: str,
    overview_items: list[tuple[str, str]],
    lifecycle_rows: list[dict[str, Any]],
    exposure_findings: list[dict[str, Any]],
    certs: list[dict[str, Any]],
    vpn_inspections: list[dict[str, Any]],
    audit_result: dict[str, Any],
    hygiene_result: dict[str, Any],
) -> bytes:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Summary KPIs
    exp_crit = sum(1 for f in exposure_findings if f.get("severity") == "critical")
    cert_bad = sum(1 for c in certs if c.get("Status") in ("Expired", "Expiring Soon"))
    vpn_err = sum(1 for v in vpn_inspections if v.get("errors"))
    audit_high = int(audit_result.get("high_count", 0))
    audit_med = int(audit_result.get("med_count", 0))
    hyg_counts = hygiene_result.get("counts") or {}

    # 1. Lifecycle table
    lc_table = _table_html(
        ["Property", "Value"],
        [{"Property": r.get("label", "-"), "Value": r.get("value", "-")} for r in lifecycle_rows],
        empty_msg="No lifecycle data available.",
    )

    # 2. Exposure table
    exp_rows = [
        {
            "Interface / VIP": f.get("interface", "-"),
            "IP": f.get("ip", "-"),
            "Exposed Services": ", ".join(f.get("display_protocols") or f.get("protocols") or []),
            "Severity": "Critical" if f.get("severity") == "critical" else "Warning",
            "Notes": f.get("note", "-"),
        }
        for f in exposure_findings
    ]
    exp_tones = ["danger" if f.get("severity") == "critical" else "warn" for f in exposure_findings]
    exp_html = _table_html(
        ["Interface / VIP", "IP", "Exposed Services", "Severity", "Notes"],
        exp_rows,
        exp_tones,
        empty_msg="No public management or high-risk VIP exposures detected.",
    )

    # 3. Certificates (show flagged first, or summary if all valid)
    cert_flagged = [c for c in certs if c.get("Status") in ("Expired", "Expiring Soon")]
    cert_rows = cert_flagged if cert_flagged else certs[:25]
    cert_tones = [
        "danger" if c.get("Status") == "Expired" else ("warn" if c.get("Status") == "Expiring Soon" else "allow")
        for c in cert_rows
    ]
    cert_html = _table_html(
        ["Name", "Store", "Common Name", "Expires", "Days Left", "Status"],
        cert_rows,
        cert_tones,
        empty_msg="No certificates found in configuration.",
    )

    # 4. VPN Health
    vpn_rows = [
        {
            "Tunnel": v["name"],
            "Remote Peer": v["peer"],
            "Intf / Zone": v["intf_zone"],
            "Routes": str(v["active_route_count"]),
            "Allow Policies": str(v["allow_policy_count"]),
            "Status": f"Error ({len(v['errors'])})" if v["errors"] else (f"Warning ({len(v['warnings'])})" if v["warnings"] else "Healthy"),
            "Findings": "; ".join(v["errors"] + v["warnings"]) or "All 4 layers verified",
        }
        for v in vpn_inspections
    ]
    vpn_tones = [
        "danger" if v["errors"] else ("warn" if v["warnings"] else "allow")
        for v in vpn_inspections
    ]
    vpn_html = _table_html(
        ["Tunnel", "Remote Peer", "Intf / Zone", "Routes", "Allow Policies", "Status", "Findings"],
        vpn_rows,
        vpn_tones,
        empty_msg="No IPSec site-to-site tunnels configured.",
    )

    # 5. Quick Audit
    audit_findings = audit_result.get("findings") or []
    audit_tones = [
        "danger" if f.get("Severity") == "High" else ("warn" if f.get("Severity") == "Medium" else "info")
        for f in audit_findings
    ]
    audit_html = _table_html(
        ["Severity", "Category", "Count", "Details"],
        audit_findings,
        audit_tones,
        empty_msg="No quick audit findings.",
    )

    # 6. Hygiene Summary
    hyg_issues = hygiene_result.get("hygiene_issues") or []
    hyg_tones = ["danger" if r.get("_sev") == "danger" else "warn" for r in hyg_issues]
    hyg_html = _table_html(
        ["Finding", "Target", "Details", "Severity"],
        hyg_issues,
        hyg_tones,
        empty_msg="No rule or schedule hygiene issues detected.",
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_e(hostname)} — Firewall Audit Report</title>
  <style>
    :root {{ --ink:#0f172a; --muted:#475569; --border:#cbd5e1; --bg:#f8fafc; --card:#ffffff; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; padding:28px; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color:var(--ink); background:var(--bg); line-height:1.45; }}
    .wrap {{ max-width: 1080px; margin: 0 auto; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:flex-start; gap:16px; background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px 24px; margin-bottom:18px; }}
    .eyebrow {{ font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#2563eb; font-weight:700; }}
    h1 {{ margin:4px 0 6px; font-size:22px; }}
    .sub {{ color:var(--muted); font-size:13px; }}
    .print-btn {{ padding:8px 14px; border-radius:7px; border:1px solid #2563eb; background:#2563eb; color:#fff; font-weight:600; cursor:pointer; font-size:13px; }}
    .badges {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
    .badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; }}
    .b-allow {{ background:#dcfce7; color:#166534; }}
    .b-warn {{ background:#fef3c7; color:#92400e; }}
    .b-deny {{ background:#fee2e2; color:#991b1b; }}
    .b-info {{ background:#dbeafe; color:#1e40af; }}
    .b-muted {{ background:#e2e8f0; color:#334155; }}
    .section {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:18px 20px; margin-bottom:16px; page-break-inside:avoid; }}
    h2 {{ margin:0 0 12px; font-size:16px; border-bottom:1px solid #e2e8f0; padding-bottom:6px; }}
    .kv-grid {{ display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:10px; }}
    .kv-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:10px 12px; }}
    .kv-lbl {{ font-size:11px; text-transform:uppercase; color:var(--muted); font-weight:600; }}
    .kv-val {{ font-size:13.5px; font-weight:600; margin-top:2px; word-break:break-word; }}
    table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
    th, td {{ text-align:left; padding:7px 9px; border-bottom:1px solid #e2e8f0; vertical-align:top; }}
    th {{ background:#f1f5f9; font-size:11.5px; text-transform:uppercase; color:#334155; }}
    .tr-danger td {{ background:#fef2f2; color:#991b1b; }}
    .tr-warn td {{ background:#fffbeb; color:#92400e; }}
    .tr-allow td {{ background:#f0fdf4; color:#166534; }}
    .tr-info td {{ background:#eff6ff; color:#1e40af; }}
    .muted {{ color:var(--muted); font-size:13px; margin:0; }}
    @media print {{
      body {{ background:#fff; padding:0; }}
      .print-btn {{ display:none; }}
      .section, .topbar {{ border-color:#cbd5e1; box-shadow:none; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="topbar">
      <div>
        <div class="eyebrow">{_e(vendor)} Security &amp; Health Audit Report</div>
        <h1>{_e(hostname)}</h1>
        <div class="sub">Source File: {_e(filename)} &middot; Generated: {_e(generated_at)}</div>
        <div class="badges">
          {_badge_html(f"Audit: {audit_high} High / {audit_med} Med", "deny" if audit_high else ("warn" if audit_med else "allow"))}
          {_badge_html(f"Exposure: {len(exposure_findings)} ({exp_crit} Critical)", "deny" if exp_crit else ("warn" if exposure_findings else "allow"))}
          {_badge_html(f"Cert Alerts: {cert_bad}", "deny" if cert_bad else "allow")}
          {_badge_html(f"VPN Errors: {vpn_err}", "deny" if vpn_err else "allow")}
          {_badge_html(f"Unused Objects: {hyg_counts.get('unused', 0)}", "warn" if hyg_counts.get("unused", 0) else "allow")}
        </div>
      </div>
      <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
    </header>

    <section class="section">
      <h2>1. System Overview &amp; Posture</h2>
      {_kv_table_html(overview_items)}
    </section>

    <section class="section">
      <h2>2. Hardware &amp; Firmware Lifecycle</h2>
      {lc_table}
    </section>

    <section class="section">
      <h2>3. Public Management, VIP &amp; WAN Exposure ({len(exposure_findings)})</h2>
      {exp_html}
    </section>

    <section class="section">
      <h2>4. Certificate Expiry Status ({len(certs)} total)</h2>
      {cert_html}
    </section>

    <section class="section">
      <h2>5. Site-to-Site IPSec VPN Health ({len(vpn_inspections)} tunnel(s))</h2>
      {vpn_html}
    </section>

    <section class="section">
      <h2>6. Quick Security &amp; Hygiene Audit</h2>
      {audit_html}
    </section>

    <section class="section">
      <h2>7. Rule &amp; Object Cleanup Hygiene ({hyg_counts.get('unused', 0)} unused objects)</h2>
      {hyg_html}
    </section>
  </div>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def generate_fortigate_audit_report_html(fg: Any, filename: str) -> bytes:
    hostname = str(fg.get_hostname() or "FortiGate")
    model = str(fg.get_model() or "Unknown")
    firmware = str(fg.get_firmware_version() or "Unknown")
    serial = str(fg.get_serial_number() or "Unknown")
    wan_ip = str(fg.get_wan_ip() or "-")
    ha = fg.get_ha_config() or {}
    posture = evaluate_fortigate_posture(fg)
    _, lc_card = build_fortigate_lifecycle_blocks(evaluate_fortigate_lifecycle(model, firmware, cache_only=True))

    overview_items = [
        ("Hostname", hostname),
        ("Model", model),
        ("Serial Number", serial),
        ("Firmware Version", firmware),
        ("WAN IP / Netmask", wan_ip),
        ("HA Status", f"Enabled ({ha.get('mode', '-')})" if ha.get("enabled") else "Standalone"),
        ("Internet Connectivity", f"{posture['internet']} ({posture['internet_sub']})"),
        ("Local Hard Disk", f"{posture['disk']} ({posture['disk_sub']})"),
    ]
    return _render_report_document(
        vendor="FortiGate (FortiOS)",
        hostname=hostname,
        filename=filename,
        overview_items=overview_items,
        lifecycle_rows=lc_card.get("rows") or [],
        exposure_findings=find_fortigate_public_mgmt_exposure(fg),
        certs=inspect_fortigate_certificates(fg),
        vpn_inspections=inspect_fortigate_vpns(fg),
        audit_result=run_fortigate_audit(fg),
        hygiene_result=analyze_fortigate_hygiene(fg),
    )


def generate_paloalto_audit_report_html(parsers: dict[str, Any], filename: str) -> bytes:
    dash = parsers["Dashboard"]
    net = parsers.get("Network")
    dev = parsers.get("Device")
    pol = parsers.get("Policies")
    obj = parsers.get("Objects")

    info = dash.get_system_info() or {}
    ha = dash.get_ha_info() or {}
    hostname = str(info.get("hostname", "PaloAlto"))
    sw_ver = str(info.get("software_version", "-"))
    posture = evaluate_paloalto_posture(net, policies_parser=pol, dashboard_parser=dash, device_parser=dev)
    _, lc_card = build_paloalto_lifecycle_blocks(
        evaluate_paloalto_lifecycle(
            sw_ver,
            is_exact_version=bool(info.get("software_version_exact", True)),
            cache_only=True,
        )
    )

    overview_items = [
        ("Hostname", hostname),
        ("PAN-OS Version", sw_ver),
        ("Management IP", str(info.get("ip_address", "-"))),
        ("Default Gateway", str(info.get("default_gateway", "-") or "-")),
        ("Timezone", str(info.get("timezone", "-"))),
        ("HA Status", f"Enabled ({ha.get('mode', '-')})" if ha.get("enabled") else "Standalone"),
        ("Internet Connectivity", f"{posture['internet']} ({posture['internet_sub']})"),
        ("Local Hard Disk", f"{posture['disk']} ({posture['disk_sub']})"),
    ]
    return _render_report_document(
        vendor="Palo Alto Networks (PAN-OS)",
        hostname=hostname,
        filename=filename,
        overview_items=overview_items,
        lifecycle_rows=lc_card.get("rows") or [],
        exposure_findings=find_paloalto_public_mgmt_exposure(net, device_parser=dev, dashboard_parser=dash),
        certs=inspect_paloalto_certificates(dev),
        vpn_inspections=inspect_paloalto_vpns(net, pol) if net is not None else [],
        audit_result=run_paloalto_audit({"Policies": pol, "Objects": obj, "Network": net}),
        hygiene_result=analyze_paloalto_hygiene({"Policies": pol, "Objects": obj}),
    )
