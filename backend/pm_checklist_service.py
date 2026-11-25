"""
backend/pm_checklist_service.py
Backup-config Preventive Maintenance (PM) Lookup evaluator for FortiGate and Palo Alto.
Extracts and evaluates only items verifiable from the uploaded backup configuration
(omitting purely live/runtime items such as CPU, RAM, uptime, PSU, or license expiry).
"""

from __future__ import annotations

from datetime import date, timedelta
import re
from typing import Any

from backend.exposure_check import (
    find_fortigate_public_mgmt_exposure,
    find_paloalto_public_mgmt_exposure,
)
from backend.lifecycle_service import (
    evaluate_fortigate_lifecycle,
    evaluate_paloalto_lifecycle,
)
from backend.posture_service import (
    evaluate_fortigate_posture,
    evaluate_paloalto_posture,
)
from backend.view_models.common import table_block as _table_block
from backend.vpn_inspector_service import inspect_fortigate_vpns

# FortiOS `set timezone <code>` IDs for GMT+8
_FG_GMT8_CODES: dict[str, str] = {
    "55": "GMT+8 (Beijing, Hong Kong, Urumqi)",
    "56": "GMT+8 (Irkutsk, Ulaan Bataar)",
    "57": "GMT+8 (Kuala Lumpur, Singapore)",
    "58": "GMT+8 (Perth)",
    "59": "GMT+8 (Taipei)",
}

# Common PAN-OS IANA / POSIX timezone strings for GMT+8
_PA_GMT8_TOKENS = (
    "asia/singapore",
    "asia/kuala_lumpur",
    "asia/hong_kong",
    "asia/shanghai",
    "asia/taipei",
    "asia/manila",
    "asia/brunei",
    "asia/macau",
    "asia/kuching",
    "australia/perth",
    "etc/gmt-8",
    "gmt+8",
    "utc+8",
    "+08",
)

PM_LEGEND = [
    {"label": "Pass (green)", "variant": "success"},
    {"label": "Info (blue)", "variant": "info"},
    {"label": "Warn (amber)", "variant": "warn"},
    {"label": "Fail (red)", "variant": "danger"},
]


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _row(
    no: str,
    category: str,
    task: str,
    status: str,
    finding: str,
    guidance: str,
) -> dict[str, str]:
    return {
        "No.": no,
        "Category": category,
        "Task": task,
        "Status": status,
        "Config Finding": finding,
        "Recommendation / Follow-up": guidance,
    }


def _pm_row_class(row: dict[str, Any]) -> str:
    st = str(row.get("Status", "")).strip().lower()
    if st == "pass":
        return "row-success"
    if st == "fail":
        return "row-danger"
    if st == "warn":
        return "row-warn"
    if st == "info":
        return "row-info"
    return ""


def _summarize(rows: list[dict[str, str]]) -> dict[str, int]:
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0, "total": len(rows)}
    for r in rows:
        key = str(r.get("Status", "")).strip().lower()
        if key in counts:
            counts[key] += 1
    return counts


def _fg_extract_log_managers(fg: Any) -> list[str]:
    """Inspect FortiAnalyzer, FortiCloud (FortiGuard), and Syslog target settings."""
    extract = getattr(fg, "_extract_block", None)
    if extract is None:
        return []
    targets: list[str] = []
    specs = (
        ("log fortianalyzer setting", "FortiAnalyzer"),
        ("log fortianalyzer2 setting", "FortiAnalyzer 2"),
        ("log fortiguard setting", "FortiCloud"),
        ("log syslogd setting", "Syslog"),
        ("log syslogd2 setting", "Syslog 2"),
    )
    for keyword, label in specs:
        blk = extract(keyword)
        if not blk:
            continue
        if re.search(r"^\s*set status disable\b", blk, re.MULTILINE):
            continue
        enabled = bool(re.search(r"^\s*set status enable\b", blk, re.MULTILINE))
        srv_m = re.search(r'^\s*set server\s+"?([^"\r\n]+)"?', blk, re.MULTILINE)
        server = srv_m.group(1).strip() if srv_m else ""
        if enabled or server:
            targets.append(f"{label} ({server})" if server else label)
    return targets


def _fg_allowaccess_ifaces(fg: Any, proto: str) -> list[str]:
    """Return active non-zone interfaces whose allowaccess includes `proto`."""
    out: list[str] = []
    target = proto.lower()
    for row in _safe(fg.parse_interfaces, []) or []:
        if str(row.get("Type", "")).lower() == "zone":
            continue
        if str(row.get("Status", "Enable")).lower() == "disable":
            continue
        raw_access = str(row.get("Admin Access", row.get("Access", "")) or "")
        tokens = {t.strip().lower() for t in re.split(r"[,\s]+", raw_access) if t.strip()}
        if target in tokens:
            name = (
                str(row.get("Name", ""))
                .replace("\u00a0", "")
                .replace("\u2517", "")
                .replace("\U0001f4e6", "")
                .strip()
            )
            ip = str(row.get("IP/Netmask", "-")).strip()
            out.append(f"{name} ({ip})" if ip and ip != "-" else name)
    return out


# ── FortiGate PM Lookup ──────────────────────────────────────────────────────
def evaluate_fortigate_pm_checklist(
    fg: Any,
    *,
    lifecycle: dict[str, Any] | None = None,
    posture: dict[str, str] | None = None,
    exposure: list[dict[str, Any]] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the 15 config-verifiable Preventive Maintenance checks for FortiGate."""
    hostname = str(_safe(fg.get_hostname, "Unknown") or "Unknown")
    serial = str(_safe(fg.get_serial_number, "Unknown") or "Unknown")
    model = str(_safe(fg.get_model, "Unknown") or "Unknown")
    firmware = str(_safe(fg.get_firmware_version, "Unknown") or "Unknown")

    lc = lifecycle or evaluate_fortigate_lifecycle(model, firmware, cache_only=True, today=today)
    pos = posture or evaluate_fortigate_posture(fg)
    exp = exposure if exposure is not None else find_fortigate_public_mgmt_exposure(fg)
    sys_settings = _safe(fg.parse_system_settings, {}) or {}
    interfaces = _safe(fg.parse_interfaces, []) or []
    routes = _safe(fg.parse_static_routes, []) or []
    sdwan = _safe(fg.parse_sdwan, {}) or {}
    bgp = _safe(fg.parse_bgp, {}) or {}
    ospf = _safe(fg.parse_ospf, {}) or {}
    policy_routes = _safe(fg.parse_policy_routes, []) or []
    ha = _safe(fg.get_ha_config, {"enabled": False}) or {"enabled": False}
    log_settings = _safe(fg.parse_log_settings, {}) or {}
    vpn_tunnels = _safe(lambda: inspect_fortigate_vpns(fg), []) or []

    rows: list[dict[str, str]] = []

    # 1.1 Hard Disk Space
    disk_val = pos.get("disk", "Unknown")
    disk_sub = pos.get("disk_sub", "")
    disk_status = "Pass" if disk_val.startswith("Yes") else "Info"
    rows.append(
        _row(
            "1.1",
            "Hardware Status",
            "Hard Disk Space",
            disk_status,
            f"{disk_val} — {disk_sub}" if disk_sub else disk_val,
            "Verify live disk usage < 80% in Log & Report > Log Settings > Local Logs."
            if disk_status == "Pass"
            else "Diskless/memory-only model; confirm remote log manager (FAZ/FortiCloud/Syslog) is active.",
        )
    )

    # 1.4 Interface Monitoring
    non_zones = [r for r in interfaces if str(r.get("Type", "")).lower() != "zone"]
    enabled_if = [r for r in non_zones if str(r.get("Status", "Enable")).lower() != "disable"]
    disabled_if = len(non_zones) - len(enabled_if)
    vlans = sum(1 for r in non_zones if r.get("_is_sub") or "vlan" in str(r.get("Type", "")).lower())
    rows.append(
        _row(
            "1.4",
            "Hardware Status",
            "Interface Monitoring",
            "Pass" if enabled_if else "Warn",
            f"{len(enabled_if)} enabled, {disabled_if} disabled, {vlans} VLAN/sub-interfaces ({len(non_zones)} total).",
            "Confirm physical link state and port utilization in Network > Interfaces.",
        )
    )

    # 3.1 Firewall Firmware Version
    fw_ver = str(lc.get("firmware_version") or firmware)
    fw_branch = str(lc.get("firmware_branch") or "Unknown")
    latest_in_branch = lc.get("latest_in_branch")
    branch_status = str(lc.get("branch_status") or "unknown")
    patch_status = str(lc.get("patch_status") or "unknown")
    if branch_status == "eos":
        fw_status = "Fail"
        fw_finding = f"FortiOS {fw_ver} (Branch {fw_branch} is End-of-Support)."
        fw_guide = "Plan upgrade to a supported FortiOS branch following the Fortinet upgrade path."
    elif patch_status == "update_available" and latest_in_branch:
        fw_status = "Warn"
        fw_finding = f"FortiOS {fw_ver} (latest in {fw_branch} branch is {latest_in_branch})."
        fw_guide = f"Review release notes and schedule patch upgrade to {latest_in_branch}."
    elif branch_status == "supported":
        fw_status = "Pass"
        fw_finding = f"FortiOS {fw_ver} (Branch {fw_branch} supported" + (
            f", up to date with {latest_in_branch})." if latest_in_branch else ")."
        )
        fw_guide = "Installed firmware is on a supported branch."
    else:
        fw_status = "Info"
        fw_finding = f"FortiOS {fw_ver} (lifecycle metadata unavailable)."
        fw_guide = "Verify recommended FortiOS release on Fortinet Support Portal."
    rows.append(_row("3.1", "Product Life Cycle", "Firewall Firmware Version", fw_status, fw_finding, fw_guide))

    # 3.2 Final Firmware Release (FFR)
    last_sup = str(lc.get("last_supported_firmware") or "Unknown")
    capped_eos = bool(lc.get("last_supported_capped_eos"))
    if last_sup.lower() == "unknown":
        ffr_status = "Info"
        ffr_finding = f"Model {lc.get('model_display', model)} — FFR not listed in offline catalog."
        ffr_guide = "Check Last Supported Firmware at support.fortinet.com/welcome/#/lifecycle."
    elif capped_eos:
        ffr_status = "Fail"
        ffr_finding = f"Model {lc.get('model_display', model)} capped at {last_sup} (EOS branch)."
        ffr_guide = "Hardware can no longer run a supported FortiOS branch; plan hardware refresh."
    elif last_sup.lower() == "active":
        ffr_status = "Pass"
        ffr_finding = f"Model {lc.get('model_display', model)} — Active (no Final Firmware Release cap announced)."
        ffr_guide = "No FFR restriction."
    else:
        ffr_status = "Warn"
        ffr_finding = f"Model {lc.get('model_display', model)} — Final Firmware Release: {last_sup}."
        ffr_guide = f"Track lifecycle; hardware will not upgrade beyond {last_sup}."
    rows.append(_row("3.2", "Product Life Cycle", "Final Firmware Release (FFR)", ffr_status, ffr_finding, ffr_guide))

    # 3.3 End of Support (EOS)
    hw_status = str(lc.get("hw_status") or "unknown")
    hw_eos = lc.get("hw_eos") or "Not announced / Unknown"
    branch_eos = lc.get("branch_eos") or "Unknown"
    if hw_status == "eos" or branch_status == "eos":
        eos_status = "Fail"
    elif hw_status == "eos_soon" or branch_status == "eoes":
        eos_status = "Warn"
    elif hw_status in ("supported", "active") or branch_status == "supported":
        eos_status = "Pass"
    else:
        eos_status = "Info"
    rows.append(
        _row(
            "3.3",
            "Product Life Cycle",
            "End of Support (EOS)",
            eos_status,
            f"Hardware EoS: {hw_eos} · FortiOS {fw_branch} EoS: {branch_eos}.",
            "Plan hardware/firmware replacement before EoS."
            if eos_status in ("Fail", "Warn")
            else "Within active support lifecycle.",
        )
    )

    # 4.1 VPN Tunnels
    if not vpn_tunnels:
        vpn_status = "Info"
        vpn_finding = "No IPSec site-to-site tunnels configured."
        vpn_guide = "N/A unless VPN tunnels are expected."
    else:
        vpn_issues = sum(
            1
            for t in vpn_tunnels
            if str(t.get("status", "")).lower() in ("error", "fail", "critical", "warn", "warning")
        )
        vpn_status = "Warn" if vpn_issues else "Pass"
        vpn_finding = f"{len(vpn_tunnels)} IPSec tunnel(s) configured" + (
            f" ({vpn_issues} with config/health warnings)." if vpn_issues else " (no config issues detected)."
        )
        vpn_guide = "Verify live tunnel up/down stats via CLI: get vpn ipsec tunnel summary."
    rows.append(_row("4.1", "VPN", "VPN Tunnels", vpn_status, vpn_finding, vpn_guide))

    # 5.1 Firewall Routing Table
    active_routes = [r for r in routes if str(r.get("Status", "Enable")).lower() != "disable"]
    has_default = any(
        str(r.get("Destination", "")).strip() in ("0.0.0.0/0", "0.0.0.0/0.0.0.0") for r in active_routes
    )
    extras = []
    if sdwan and sdwan.get("members"):
        extras.append(f"SD-WAN ({len(sdwan.get('members', []))} members)")
    if policy_routes:
        extras.append(f"{len(policy_routes)} policy route(s)")
    if bgp and (bgp.get("as") or bgp.get("neighbors")):
        extras.append("BGP")
    if ospf and (ospf.get("router_id") or ospf.get("areas")):
        extras.append("OSPF")
    rt_finding = (
        f"{len(active_routes)} active static route(s) ({len(routes) - len(active_routes)} disabled), "
        f"default route: {'Yes' if has_default else 'No'}."
    )
    if extras:
        rt_finding += " Also: " + ", ".join(extras) + "."
    rows.append(
        _row(
            "5.1",
            "Routing Table",
            "Firewall Routing Table",
            "Pass" if (active_routes or extras) else "Warn",
            rt_finding,
            "Review active routing table and gateway reachability in Network > Static Routes.",
        )
    )

    # 6.2 GUI Accessibility
    https_port = str(sys_settings.get("https_port") or "443")
    http_port = str(sys_settings.get("http_port") or "80")
    https_ifs = _fg_allowaccess_ifaces(fg, "https")
    http_ifs = _fg_allowaccess_ifaces(fg, "http")
    pub_gui = [
        f
        for f in exp
        if f.get("category", "mgmt") == "mgmt" and any(p in ("HTTP", "HTTPS") for p in f.get("protocols", []))
    ]
    if any(f.get("severity") == "critical" for f in pub_gui):
        gui_status = "Fail"
        gui_guide = (
            "Restrict public GUI access with admin trusthosts or move management behind VPN/internal interface; disable HTTP."
        )
    elif pub_gui or http_ifs:
        gui_status = "Warn"
        gui_guide = "Prefer HTTPS-only management and restrict public interfaces with trusthosts."
    elif https_ifs:
        gui_status = "Pass"
        gui_guide = "Verify live web GUI login on management interface."
    else:
        gui_status = "Info"
        gui_guide = "No interface explicitly lists HTTPS allowaccess; verify GUI access method."
    gui_parts = [f"Ports: HTTPS {https_port} / HTTP {http_port}"]
    if https_ifs:
        gui_parts.append(f"HTTPS on {', '.join(https_ifs[:4])}")
    if http_ifs:
        gui_parts.append(f"HTTP on {', '.join(http_ifs[:4])}")
    rows.append(_row("6.2", "Configuration", "GUI Accessibility", gui_status, "; ".join(gui_parts) + ".", gui_guide))

    # 6.3 CLI/SSH Accessibility
    ssh_port = str(sys_settings.get("ssh_port") or "22")
    ssh_ifs = _fg_allowaccess_ifaces(fg, "ssh")
    pub_ssh = [
        f
        for f in exp
        if f.get("category", "mgmt") == "mgmt" and "SSH" in f.get("protocols", [])
    ]
    if any(f.get("severity") == "critical" for f in pub_ssh):
        ssh_status = "Fail"
        ssh_guide = "Restrict public SSH access with admin trusthosts or disable SSH on WAN."
    elif pub_ssh:
        ssh_status = "Warn"
        ssh_guide = "SSH is on a public interface (trusthost restricted); verify authorized IPs."
    elif ssh_ifs:
        ssh_status = "Pass"
        ssh_guide = "Verify CLI/SSH login (`get system status`)."
    else:
        ssh_status = "Info"
        ssh_guide = "SSH allowaccess not explicitly enabled on any interface (use GUI CLI console if needed)."
    ssh_finding = (
        f"SSH port {ssh_port}; enabled on {', '.join(ssh_ifs[:4])}."
        if ssh_ifs
        else f"SSH port {ssh_port}; not enabled on any interface."
    )
    rows.append(_row("6.3", "Configuration", "CLI/SSH Accessibility", ssh_status, ssh_finding, ssh_guide))

    # 6.5 Firewall Date & Time (GMT+8 + NTP)
    tz_code = str(sys_settings.get("timezone") or "-").strip()
    ntp = sys_settings.get("ntp") or {}
    ntp_enabled = bool(ntp) and str(ntp.get("status", "enable")).lower() != "disable"
    ntp_servers = ", ".join(ntp.get("servers") or []) if ntp else "Not configured"
    is_gmt8 = tz_code in _FG_GMT8_CODES
    tz_label = _FG_GMT8_CODES.get(tz_code, f"Code {tz_code}" if tz_code != "-" else "Not explicitly set (default)")
    if is_gmt8 and ntp_enabled:
        dt_status = "Pass"
        dt_guide = "Timezone is GMT+8 and NTP sync is enabled."
    elif not ntp_enabled and not is_gmt8:
        dt_status = "Warn"
        dt_guide = "Set timezone to GMT+8 (e.g. code 57 Kuala Lumpur/Singapore) and enable NTP sync."
    elif not is_gmt8:
        dt_status = "Warn"
        dt_guide = "Confirm timezone matches GMT+8 requirement in System > Settings."
    else:
        dt_status = "Warn"
        dt_guide = "Enable NTP synchronization in System > Settings (`config system ntp`)."
    rows.append(
        _row(
            "6.5",
            "Configuration",
            "Firewall Date & Time",
            dt_status,
            f"Timezone: {tz_label} · NTP: {'Enabled' if ntp_enabled else 'Disabled/Default'} ({ntp_servers}).",
            dt_guide,
        )
    )

    # 6.6 Firewall Internet Access
    inet_val = pos.get("internet", "Unknown")
    inet_sub = pos.get("internet_sub", "")
    inet_status = "Pass" if inet_val.startswith("Connected") else "Info"
    rows.append(
        _row(
            "6.6",
            "Configuration",
            "Firewall Internet Access",
            inet_status,
            f"{inet_val} ({inet_sub})." if inet_sub else inet_val,
            "Matches expected connectivity posture."
            if inet_status == "Pass"
            else "Config indicates internal/air-gapped posture; confirm against site design.",
        )
    )

    # 6.7 High Availability
    if ha.get("enabled"):
        hb = ", ".join(ha.get("heartbeat_interfaces") or []) or "—"
        ha_status = "Pass"
        ha_finding = (
            f"HA Enabled ({ha.get('mode', 'Cluster')}, group '{ha.get('group_name', '—')}', "
            f"priority {ha.get('priority', '—')}, heartbeat: {hb})."
        )
        ha_guide = "Verify HA cluster sync status and secondary member health in System > HA."
    else:
        ha_status = "Info"
        ha_finding = "Standalone mode (HA not configured)."
        ha_guide = "No HA cluster configured; skip HA sync check."
    rows.append(_row("6.7", "Configuration", "High Availability", ha_status, ha_finding, ha_guide))

    # 6.8 Logging (Event Log)
    local_log_on = disk_val.startswith("Yes") or str(log_settings.get("memory_status", "")).lower() == "enable"
    rows.append(
        _row(
            "6.8",
            "Configuration",
            "Logging (Event Log)",
            "Pass" if local_log_on else "Warn",
            f"Local storage: {disk_val}. Implicit policy log: {log_settings.get('uuid_traffic', '-')}.",
            "Review critical errors/warnings from past 3 months in Log & Report > System Events.",
        )
    )

    # 6.9 Log Manager
    log_mgrs = _fg_extract_log_managers(fg)
    rows.append(
        _row(
            "6.9",
            "Configuration",
            "Log Manager",
            "Pass" if log_mgrs else "Warn",
            "Configured: " + ", ".join(log_mgrs) + "." if log_mgrs else "No FortiAnalyzer, FortiCloud, or Syslog server enabled.",
            "Confirm log transmission status in Log & Report > Log Settings."
            if log_mgrs
            else "Configure FortiAnalyzer, FortiCloud, or Syslog for centralized log retention.",
        )
    )

    # 6.10 Backup Configurations
    rows.append(
        _row(
            "6.10",
            "Configuration",
            "Backup Configurations",
            "Pass",
            f"Valid FortiOS backup parsed — Hostname: {hostname}, Model: {lc.get('model_display', model)}, S/N: {serial}, Firmware: {firmware}.",
            "Archive this sanitized backup snapshot per change-management policy.",
        )
    )

    return {
        "vendor": "FortiGate",
        "hostname": hostname,
        "subtitle": f"{lc.get('model_display', model)} · FortiOS {firmware} · S/N {serial}",
        "rows": rows,
        "summary": _summarize(rows),
    }


# ── Palo Alto PM Lookup ──────────────────────────────────────────────────────
def evaluate_paloalto_pm_checklist(
    parsers: dict[str, Any],
    *,
    lifecycle: dict[str, Any] | None = None,
    posture: dict[str, str] | None = None,
    exposure: list[dict[str, Any]] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the 10 config-verifiable Preventive Maintenance checks for Palo Alto."""
    dash = parsers.get("Dashboard")
    net = parsers.get("Network")
    dev = parsers.get("Device")
    pol = parsers.get("Policies")
    obj = parsers.get("Objects")

    info = _safe(dash.get_system_info, {}) if dash is not None else {}
    ha = _safe(dash.get_ha_info, {"enabled": False}) if dash is not None else {"enabled": False}
    hostname = str(info.get("hostname", "Unknown") or "Unknown")
    sw_version = str(info.get("software_version", "Unknown") or "Unknown")
    timezone = str(info.get("timezone", "-") or "-")

    ref_today = today or date.today()
    lc = lifecycle or evaluate_paloalto_lifecycle(
        sw_version,
        is_exact_version=bool(info.get("software_version_exact", True)),
        cache_only=True,
        today=ref_today,
    )
    pos = posture or evaluate_paloalto_posture(
        net,
        policies_parser=pol,
        dashboard_parser=dash,
        device_parser=dev,
    )
    exp = (
        exposure
        if exposure is not None
        else find_paloalto_public_mgmt_exposure(net, device_parser=dev, dashboard_parser=dash)
    )

    mgmt_if = _safe(dev.get_mgmt_interface, {}) if dev is not None else {}
    mgmt_svc = _safe(dev.get_mgmt_services, {}) if dev is not None else {}
    ntp = _safe(dev.get_ntp, {}) if dev is not None else {}
    syslog_profs = _safe(dev.get_syslog_profiles, []) if dev is not None else []
    log_fwd = _safe(obj.get_log_forwarding_profiles, []) if obj is not None else []

    rows: list[dict[str, str]] = []

    # 1.1 Hard Disk Space
    rows.append(
        _row(
            "1.1",
            "Hardware Status",
            "Hard Disk Space",
            "Pass",
            f"{pos.get('disk', 'Yes (PAN-OS Local Disk)')} — {pos.get('disk_sub', '')}".strip(" —"),
            "Verify all disk partitions < 90% via CLI: show system disk-space.",
        )
    )

    # 1.4 Firewall Port Monitoring
    eth_ifs = _safe(net.get_ethernet_interfaces, []) if net is not None else []
    ae_ifs = _safe(net.get_ae_interfaces, []) if net is not None and hasattr(net, "get_ae_interfaces") else []
    zones = _safe(net.get_zones, []) if net is not None and hasattr(net, "get_zones") else []
    active_eth = [i for i in eth_ifs if not i.get("_disabled")]
    rows.append(
        _row(
            "1.4",
            "Hardware Status",
            "Firewall Port Monitoring",
            "Pass" if active_eth else "Warn",
            f"{len(active_eth)} active Ethernet interface(s) ({len(eth_ifs) - len(active_eth)} disabled), {len(ae_ifs)} AE interface(s), {len(zones)} zone(s).",
            "Verify physical link state in Network > Interfaces > Ethernet.",
        )
    )

    # 4.2 GUI Accessibility
    mgmt_ip = str(mgmt_if.get("IP Address") or info.get("ip_address") or "Not configured")
    permitted = str(mgmt_if.get("Permitted IPs") or "Any (Unrestricted)")
    https_on = str(mgmt_svc.get("disable_https", "no")).lower() != "yes"
    http_on = str(mgmt_svc.get("disable_http", "no")).lower() != "yes"
    pub_gui = [f for f in exp if any(p in ("HTTP", "HTTPS") for p in f.get("protocols", []))]
    if any(f.get("severity") == "critical" for f in pub_gui):
        gui_status = "Fail"
        gui_guide = "Restrict public management GUI with permitted-ip and disable HTTP."
    elif http_on or pub_gui or permitted.startswith("Any"):
        gui_status = "Warn"
        gui_guide = "Disable HTTP if enabled and configure Permitted IP Addresses on management interface."
    elif https_on:
        gui_status = "Pass"
        gui_guide = "HTTPS enabled with Permitted IPs restricted; verify live web login."
    else:
        gui_status = "Info"
        gui_guide = "HTTPS is disabled on management interface; verify GUI access path."
    rows.append(
        _row(
            "4.2",
            "Configuration",
            "GUI Accessibility",
            gui_status,
            f"Mgmt IP: {mgmt_ip} · HTTPS: {'Enabled' if https_on else 'Disabled'}, HTTP: {'Enabled' if http_on else 'Disabled'} · Permitted IPs: {permitted}.",
            gui_guide,
        )
    )

    # 4.3 CLI/SSH Accessibility
    ssh_on = str(mgmt_svc.get("disable_ssh", "no")).lower() != "yes"
    pub_ssh = [f for f in exp if "SSH" in f.get("protocols", [])]
    if any(f.get("severity") == "critical" for f in pub_ssh):
        ssh_status = "Fail"
        ssh_guide = "Restrict public SSH management with permitted-ip."
    elif pub_ssh or (ssh_on and permitted.startswith("Any")):
        ssh_status = "Warn"
        ssh_guide = "Configure Permitted IP Addresses on management interface to limit SSH exposure."
    elif ssh_on:
        ssh_status = "Pass"
        ssh_guide = "SSH enabled with Permitted IPs restricted; verify SSH login."
    else:
        ssh_status = "Info"
        ssh_guide = "SSH is disabled on management interface."
    rows.append(
        _row(
            "4.3",
            "Configuration",
            "CLI/SSH Accessibility",
            ssh_status,
            f"SSH: {'Enabled' if ssh_on else 'Disabled'} on {mgmt_ip} · Permitted IPs: {permitted}.",
            ssh_guide,
        )
    )

    # 4.4 Firewall Firmware Version
    pa_branch = str(lc.get("panos_branch") or "Unknown")
    branch_status = str(lc.get("branch_status") or "unknown")
    patch_status = str(lc.get("patch_status") or "unknown")
    latest_in_branch = lc.get("latest_in_branch")
    branch_eos = lc.get("branch_eos") or "Unknown"
    if branch_status == "eos":
        fw_status = "Fail"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} reached EOL on {branch_eos})."
        fw_guide = "Plan upgrade to a supported PAN-OS release."
    elif patch_status == "update_available" and latest_in_branch:
        fw_status = "Warn"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} EoS: {branch_eos}; latest: {latest_in_branch})."
        fw_guide = f"Check Preferred release in Device > Software (latest in branch: {latest_in_branch})."
    elif branch_status == "supported":
        fw_status = "Pass"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} supported until {branch_eos})."
        fw_guide = "Confirm preferred release via `request system software info preferred`."
    else:
        fw_status = "Info"
        fw_finding = f"PAN-OS {sw_version} (lifecycle metadata unavailable)."
        fw_guide = "Verify PAN-OS version & preferred release in Device > Software."
    rows.append(_row("4.4", "Configuration", "Firewall Firmware Version", fw_status, fw_finding, fw_guide))

    # 4.5 Firewall Date & Time (GMT+8 + NTP)
    p_ntp = str(ntp.get("primary") or "-").strip()
    s_ntp = str(ntp.get("secondary") or "-").strip()
    has_ntp = (p_ntp not in ("", "-")) or (s_ntp not in ("", "-"))
    is_gmt8 = any(tok in timezone.lower() for tok in _PA_GMT8_TOKENS)
    if is_gmt8 and has_ntp:
        dt_status = "Pass"
        dt_guide = "Timezone is GMT+8 and NTP server(s) configured; verify live sync with `show ntp`."
    elif not has_ntp:
        dt_status = "Warn"
        dt_guide = "Configure primary/secondary NTP servers and confirm GMT+8 timezone (`show clock` / `show ntp`)."
    else:
        dt_status = "Warn"
        dt_guide = "Confirm timezone matches GMT+8 requirement (`show clock`)."
    ntp_txt = ", ".join(x for x in (p_ntp, s_ntp) if x and x != "-") or "Not configured"
    rows.append(
        _row(
            "4.5",
            "Configuration",
            "Firewall Date & Time",
            dt_status,
            f"Timezone: {timezone} · NTP Servers: {ntp_txt}.",
            dt_guide,
        )
    )

    # 4.6 Firewall Internet Access
    inet_val = pos.get("internet", "Unknown")
    inet_sub = pos.get("internet_sub", "")
    inet_status = "Pass" if inet_val.startswith("Connected") else "Info"
    rows.append(
        _row(
            "4.6",
            "Configuration",
            "Firewall Internet Access",
            inet_status,
            f"{inet_val} ({inet_sub})." if inet_sub else inet_val,
            "Verify external connectivity via CLI: ping host 8.8.8.8.",
        )
    )

    # 4.7 High Availability
    if ha.get("enabled"):
        mode_lbl = "Active-Passive" if ha.get("mode", "active-passive") == "active-passive" else "Active-Active"
        ha_status = "Pass"
        ha_finding = (
            f"HA Enabled ({mode_lbl}, Group {ha.get('group_id', '—')}, "
            f"Peer {ha.get('peer_ip', '—')}, HA1 {ha.get('ha1_port', '—')})."
        )
        ha_guide = "Verify HA peer state and config sync in Main Dashboard > HA."
    else:
        ha_status = "Info"
        ha_finding = "Standalone mode (HA not configured)."
        ha_guide = "No HA configured; skip HA sync check."
    rows.append(_row("4.7", "Configuration", "High Availability (if any)", ha_status, ha_finding, ha_guide))

    # 4.8 Event Logging (+ dynamic 3-month PAN-OS log filter)
    three_months_ago = (ref_today - timedelta(days=90)).strftime("%Y/%m/%d")
    pa_filter = (
        f"(receive_time geq '{three_months_ago} 00:00:00') and "
        "((severity eq critical) or (severity eq high) or (severity eq medium))"
    )
    has_log_ext = bool(syslog_profs or log_fwd)
    rows.append(
        _row(
            "4.8",
            "Configuration",
            "Event Logging",
            "Pass" if has_log_ext else "Info",
            f"{len(syslog_profs)} Syslog profile(s), {len(log_fwd)} Log Forwarding profile(s).",
            f"Monitor > Logs > System filter (past 90 days): {pa_filter}",
        )
    )

    # 4.9 Backup Configurations
    rows.append(
        _row(
            "4.9",
            "Configuration",
            "Backup Configurations",
            "Pass",
            f"Valid PAN-OS XML backup parsed — Hostname: {hostname}, PAN-OS: {sw_version}.",
            "Archive this backup snapshot per change-management policy.",
        )
    )

    return {
        "vendor": "Palo Alto",
        "hostname": hostname,
        "subtitle": f"PAN-OS {sw_version} · {timezone}",
        "rows": rows,
        "summary": _summarize(rows),
    }


def build_pm_lookup_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Build declarative UI blocks (hero + filterable PM table + legend) for PM Lookup."""
    summary = result["summary"]
    badges = [
        {"text": f"Pass: {summary['pass']}", "variant": "allow"},
        {"text": f"Warn: {summary['warn']}", "variant": "warn" if summary["warn"] else "muted"},
        {"text": f"Fail: {summary['fail']}", "variant": "deny" if summary["fail"] else "muted"},
        {"text": f"Info: {summary['info']}", "variant": "info" if summary["info"] else "muted"},
    ]
    vendor_slug = "fg" if result["vendor"] == "FortiGate" else "pa"
    return [
        {
            "type": "hero",
            "eyebrow": "PM Lookup (Backup Config)",
            "title": result["hostname"],
            "subtitle": result["subtitle"],
            "badges": badges,
        },
        {
            "type": "alert",
            "variant": "info",
            "text": (
                f"Evaluated {summary['total']} backup-config verifiable Preventive Maintenance checks "
                "(live-only metrics such as CPU, memory, uptime, PSU, and license expiry are omitted)."
            ),
        },
        _table_block(
            result["rows"],
            table_id=f"{vendor_slug}_pm_lookup",
            title="Preventive Maintenance (PM) Checklist Evaluation",
            caption=(
                f"{summary['total']} config-verifiable checks · {summary['pass']} pass · "
                f"{summary['warn']} warn · {summary['fail']} fail · {summary['info']} info"
            ),
            export_filename=f"{vendor_slug}_pm_lookup.csv",
            filter_col="Status",
            row_class_fn=_pm_row_class,
            legend=PM_LEGEND,
        ),
    ]
