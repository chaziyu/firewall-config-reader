"""
backend/posture_service.py
Infers firewall Internet Connectivity posture and Local Hard Disk / log storage
availability strictly from static configuration signals (FortiGate & Palo Alto).
"""

from __future__ import annotations

import re
from typing import Any

from backend.exposure_check import _bare_ip, is_public_ip


def _split_csv(val: str) -> list[str]:
    return [p.strip() for p in str(val or "").split(",") if p.strip() and p.strip() != "-"]


def _fg_has_default_route(fg: Any) -> tuple[bool, bool]:
    """Return (has_default_route, is_sdwan_default)."""
    has_default = False
    is_sdwan = False
    for rt in fg.parse_static_routes() or []:
        if str(rt.get("Status", "Enable")).lower() == "disable":
            continue
        dst = str(rt.get("Destination", "-")).strip()
        if dst in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "-"):
            has_default = True
            if str(rt.get("Interface", "")).lower() in ("virtual-wan-link", "sdwan"):
                is_sdwan = True

    extract = getattr(fg, "_extract_block", None)
    if extract is not None:
        raw_rt = extract("router static") or ""
        entries = re.findall(r"^\s*edit \d+(.*?)^\s*next", raw_rt, re.DOTALL | re.MULTILINE)
        for body in entries:
            if re.search(r"^\s*set status disable", body, re.MULTILINE):
                continue
            has_dst = bool(re.search(r"^\s*set dst\s+", body, re.MULTILINE))
            sdwan_m = re.search(r"^\s*set sdwan(?:-zone)?\s+", body, re.MULTILINE)
            if sdwan_m and not has_dst:
                has_default = True
                is_sdwan = True
    return has_default, is_sdwan


def _fg_has_dhcp_or_pppoe_wan(fg: Any) -> bool:
    extract = getattr(fg, "_extract_block", None)
    if extract is None:
        return False
    raw_if = extract("system interface") or ""
    entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', raw_if, re.DOTALL | re.MULTILINE)
    for _, body in entries:
        if re.search(r"^\s*set status disable", body, re.MULTILINE):
            continue
        if re.search(r"^\s*set mode (?:dhcp|pppoe)\b", body, re.MULTILINE):
            return True
    return False


def _fg_block_enabled(fg: Any, keyword: str) -> tuple[bool, bool]:
    """Return (block_present, explicitly_enabled)."""
    extract = getattr(fg, "_extract_block", None)
    if extract is None:
        return False, False
    blk = extract(keyword)
    if not blk:
        return False, False
    if re.search(r"^\s*set status disable\b", blk, re.MULTILINE):
        return True, False
    if re.search(r"^\s*set status enable\b", blk, re.MULTILINE):
        return True, True
    return True, True


def evaluate_fortigate_posture(fg: Any) -> dict[str, str]:
    # 1. Internet Connectivity signals
    has_default, is_sdwan_def = _fg_has_default_route(fg)
    has_dhcp_pppoe = _fg_has_dhcp_or_pppoe_wan(fg)

    has_public_wan = False
    for row in fg.parse_interfaces() or []:
        if str(row.get("Type", "")).lower() == "zone":
            continue
        if str(row.get("Status", "Enable")).lower() == "disable":
            continue
        for part in _split_csv(str(row.get("IP/Netmask", ""))):
            if is_public_ip(part):
                has_public_wan = True
                break

    has_outbound_nat = any(
        str(p.get("Status", "Enable")).lower() != "disable"
        and str(p.get("Action", "")).upper() == "ACCEPT"
        and str(p.get("NAT", "")).lower() == "enable"
        for p in (fg.parse_policies() or [])
    )

    has_public_vip = any(
        is_public_ip(_bare_ip(str(v.get("Mapped From", ""))))
        for v in (fg.parse_vip() or [])
    )

    has_public_vpn = any(
        str(p1.get("status", "Enable")).lower() != "disable"
        and is_public_ip(str(p1.get("remote_gw", "")))
        for p1 in (fg.parse_ipsec_phase1() or [])
    )

    has_public_dns = False
    try:
        dns = fg.get_dns() or {}
        has_public_dns = is_public_ip(dns.get("primary")) or is_public_ip(dns.get("secondary"))
    except Exception:
        pass

    signals: list[str] = []
    if has_default:
        signals.append("SD-WAN default route" if is_sdwan_def else "0.0.0.0/0 route")
    if has_public_wan:
        signals.append("public WAN IP")
    elif has_dhcp_pppoe:
        signals.append("DHCP/PPPoE WAN")
    if has_outbound_nat:
        signals.append("outbound NAT")
    if has_public_vip:
        signals.append("public VIPs")
    if has_public_vpn:
        signals.append("public IPSec peer")
    if has_public_dns:
        signals.append("public DNS")

    if (has_default or has_dhcp_pppoe) and (has_public_wan or has_dhcp_pppoe):
        internet = "Connected (Direct Public IP)"
    elif has_default and (has_outbound_nat or has_public_vip or has_public_vpn or has_public_dns):
        internet = "Connected (Behind Upstream NAT)"
    elif has_public_wan or has_public_vip or has_public_vpn:
        internet = "Likely Connected (Public Peers / VIPs)"
    else:
        internet = "Internal / Air-Gapped"

    internet_sub = ", ".join(signals[:4]) if signals else "No default route, public WAN IP, or outbound NAT"

    # 2. Local Hard Disk & Log Storage
    model = str(fg.get_model() or "Unknown")
    disk_present, disk_enabled = _fg_block_enabled(fg, "log disk setting")
    extract = getattr(fg, "_extract_block", None)
    has_sys_storage = bool(extract and extract("system storage"))

    remote_log_targets: list[str] = []
    for kw, label in (
        ("log syslogd setting", "Syslog"),
        ("log fortianalyzer setting", "FortiAnalyzer"),
        ("log fortiguard setting", "FortiCloud"),
    ):
        pres, en = _fg_block_enabled(fg, kw)
        if pres and en:
            remote_log_targets.append(label)

    m_num = re.search(r"(\d+)(?:[A-Z]|$)", model.upper())
    last_digit = m_num.group(1)[-1] if m_num else ""

    if "VM" in model.upper():
        disk = "Yes (Virtual Disk)"
        disk_sub = "Disk logging enabled" if (disk_present and disk_enabled) else "Virtual appliance storage"
    elif last_digit == "1":
        disk = "Yes (Onboard SSD)"
        if disk_present and disk_enabled:
            disk_sub = "Disk logging enabled"
        elif disk_present:
            disk_sub = "Disk logging disabled"
        else:
            disk_sub = "Hardware SSD model (*1 series)"
    elif disk_present or has_sys_storage:
        disk = "Yes (Log Disk Configured)"
        disk_sub = "Disk logging enabled" if disk_enabled else "Disk logging disabled"
    elif last_digit == "0":
        disk = "No (Diskless Model)"
        if remote_log_targets:
            disk_sub = f"Remote logging: {', '.join(remote_log_targets)}"
        else:
            disk_sub = "Memory-only logs (no Syslog/FAZ)"
    else:
        disk = "Unknown"
        disk_sub = f"Remote logging: {', '.join(remote_log_targets)}" if remote_log_targets else "No disk config block"

    return {
        "internet": internet,
        "internet_sub": internet_sub,
        "disk": disk,
        "disk_sub": disk_sub,
    }


def evaluate_paloalto_posture(
    network_parser: Any,
    policies_parser: Any = None,
    dashboard_parser: Any = None,
    device_parser: Any = None,
) -> dict[str, str]:
    has_default = False
    has_bgp = False
    has_public_intf = False
    has_public_vpn = False
    has_outbound_nat = False

    if network_parser is not None:
        for vr in network_parser.get_virtual_routers() or []:
            if str(vr.get("BGP", "no")).lower() == "yes":
                has_bgp = True
            vr_el = vr.get("_vr_el")
            if vr_el is None:
                continue
            detail = network_parser.get_vr_detail(vr_el)
            for rt in detail.get("static_v4", []) or []:
                if str(rt.get("Destination", "")).strip() == "0.0.0.0/0":
                    has_default = True

        for getter in (
            "get_ethernet_interfaces",
            "get_vlan_interfaces",
            "get_loopback_interfaces",
            "get_tunnel_interfaces",
        ):
            fn = getattr(network_parser, getter, None)
            if fn is None:
                continue
            for row in fn() or []:
                if row.get("_disabled"):
                    continue
                for part in _split_csv(str(row.get("IP Address", ""))):
                    if is_public_ip(part):
                        has_public_intf = True
                        break

        for tun in network_parser.get_ipsec_tunnels() or []:
            if is_public_ip(str(tun.get("IKE Peer IP", ""))):
                has_public_vpn = True

    if policies_parser is not None:
        for nr in policies_parser.get_nat_rules() or []:
            if nr.get("_disabled"):
                continue
            if str(nr.get("Src Translation", "None")) != "None":
                has_outbound_nat = True
                break

    if dashboard_parser is not None and hasattr(dashboard_parser, "get_system_info"):
        info = dashboard_parser.get_system_info() or {}
        if is_public_ip(info.get("ip_address")):
            has_public_intf = True

    signals: list[str] = []
    if has_default:
        signals.append("0.0.0.0/0 route")
    elif has_bgp:
        signals.append("BGP enabled")
    if has_public_intf:
        signals.append("public interface IP")
    if has_outbound_nat:
        signals.append("source NAT")
    if has_public_vpn:
        signals.append("public IPSec peer")

    if (has_default or has_bgp) and has_public_intf:
        internet = "Connected (Direct Public IP)"
    elif (has_default or has_bgp) and (has_outbound_nat or has_public_vpn):
        internet = "Connected (Behind Upstream NAT)"
    elif has_public_intf or has_public_vpn:
        internet = "Likely Connected (Public Peers / IP)"
    else:
        internet = "Internal / Air-Gapped"

    internet_sub = ", ".join(signals[:4]) if signals else "No default route, public interface IP, or source NAT"

    syslog_count = 0
    if device_parser is not None and hasattr(device_parser, "get_syslog_profiles"):
        try:
            syslog_count = len(device_parser.get_syslog_profiles() or [])
        except Exception:
            syslog_count = 0

    disk = "Yes (PAN-OS Local Disk)"
    disk_sub = f"Local disk + {syslog_count} Syslog profile(s)" if syslog_count else "Local log storage (no Syslog profiles)"

    return {
        "internet": internet,
        "internet_sub": internet_sub,
        "disk": disk,
        "disk_sub": disk_sub,
    }
