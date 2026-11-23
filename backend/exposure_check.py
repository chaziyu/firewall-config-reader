"""
backend/exposure_check.py
Detects active firewall interfaces configured with a public IP address that also
enable HTTP, HTTPS, or SSH administrative management access, and builds the
shared Option B declarative UI blocks for Overview pages.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_MGMT_PROTOCOLS = ("HTTP", "HTTPS", "SSH")
_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")
_TREE_PREFIX_RE = re.compile(r"^[\s\u00a0]*(?:\u2517|\u2514)?[\s\u00a0]*")


def _clean_interface_name(name: str) -> str:
    return _TREE_PREFIX_RE.sub("", str(name or "")).strip()


def is_public_ip(ip_str: str | None) -> bool:
    """Return True if ip_str (optionally with /mask or /prefix) is a routable public IP."""
    if not ip_str:
        return False
    raw = str(ip_str).strip()
    if not raw or raw.lower() in ("-", "none", "dhcp", "pppoe", "unknown"):
        return False
    addr_part = raw.split("/", 1)[0].strip()
    if not addr_part:
        return False
    try:
        ip = ipaddress.ip_address(addr_part)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NET:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return bool(ip.is_global)


def _extract_public_ips(ip_field: str | None) -> list[str]:
    if not ip_field:
        return []
    out: list[str] = []
    for part in str(ip_field).split(","):
        candidate = part.strip()
        if is_public_ip(candidate):
            out.append(candidate)
    return out


def find_fortigate_public_mgmt_exposure(parser: Any) -> list[dict[str, Any]]:
    """Return active FortiGate interfaces with a public IP and HTTP/HTTPS/SSH access."""
    try:
        rows = parser.parse_interfaces() or []
    except Exception:
        return []

    settings: dict[str, Any] = {}
    if hasattr(parser, "parse_system_settings"):
        try:
            settings = parser.parse_system_settings() or {}
        except Exception:
            settings = {}

    port_map = {
        "HTTP": str(settings.get("http_port") or "80"),
        "HTTPS": str(settings.get("https_port") or "443"),
        "SSH": str(settings.get("ssh_port") or "22"),
    }

    findings: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("Type", "")).strip().lower() == "zone":
            continue
        if str(row.get("Status", "Enable")).strip().lower() == "disable":
            continue

        public_ips = _extract_public_ips(row.get("IP/Netmask"))
        if not public_ips:
            continue

        raw_access = str(row.get("Admin Access", "") or "")
        tokens = {t.strip().upper() for t in re.split(r"[,\s]+", raw_access) if t.strip()}
        protocols = [p for p in _MGMT_PROTOCOLS if p in tokens]
        if not protocols:
            continue

        findings.append(
            {
                "interface": _clean_interface_name(row.get("Name", "")),
                "ip": ", ".join(public_ips),
                "protocols": protocols,
                "display_protocols": [f"{p} ({port_map[p]})" for p in protocols],
                "note": "",
            }
        )
    return findings


def _pa_mgt_exposure(
    network_parser: Any,
    device_parser: Any | None = None,
    dashboard_parser: Any | None = None,
) -> list[dict[str, Any]]:
    sys_info: dict[str, Any] = {}
    info_source = dashboard_parser or device_parser or network_parser
    if info_source is not None and hasattr(info_source, "get_system_info"):
        try:
            sys_info = info_source.get_system_info() or {}
        except Exception:
            sys_info = {}

    mgt_ips: list[str] = []
    for key in ("ip_address", "ipv6_address"):
        val = sys_info.get(key)
        if is_public_ip(val):
            mgt_ips.append(str(val).strip())

    if not mgt_ips:
        return []

    mgmt_svc: dict[str, str] = {}
    if device_parser is not None and hasattr(device_parser, "get_mgmt_services"):
        try:
            mgmt_svc = device_parser.get_mgmt_services() or {}
        except Exception:
            mgmt_svc = {}
    else:
        dev = getattr(info_source, "dev", None)
        sys_el = dev.find("deviceconfig/system") if dev is not None else None
        svc_el = sys_el.find("service") if sys_el is not None else None
        if svc_el is not None:
            mgmt_svc = {
                "disable_http": svc_el.findtext("disable-http") or "no",
                "disable_https": svc_el.findtext("disable-https") or "no",
                "disable_ssh": svc_el.findtext("disable-ssh") or "no",
            }

    # In PAN-OS, MGT HTTP/HTTPS/SSH default to enabled unless disable-* is "yes".
    enabled_protos: list[str] = []
    for proto, flag_key in (("HTTP", "disable_http"), ("HTTPS", "disable_https"), ("SSH", "disable_ssh")):
        if str(mgmt_svc.get(flag_key, "no")).strip().lower() not in ("yes", "true", "1"):
            enabled_protos.append(proto)

    if not enabled_protos:
        return []

    dev = getattr(info_source, "dev", None)
    sys_el = dev.find("deviceconfig/system") if dev is not None else None
    permitted: list[str] = []
    if sys_el is not None:
        permitted = [e.get("name", "").strip() for e in sys_el.findall("permitted-ip/entry") if e.get("name")]
    note = f"Permitted IPs: {', '.join(permitted)}" if permitted else "Permitted IPs: any"

    return [
        {
            "interface": "Management (MGT)",
            "ip": ", ".join(mgt_ips),
            "protocols": enabled_protos,
            "note": note,
        }
    ]


def find_paloalto_public_mgmt_exposure(
    network_parser: Any,
    device_parser: Any | None = None,
    dashboard_parser: Any | None = None,
) -> list[dict[str, Any]]:
    """Return active Palo Alto MGT and dataplane interfaces with a public IP and HTTP/HTTPS/SSH."""
    findings = _pa_mgt_exposure(
        network_parser,
        device_parser=device_parser,
        dashboard_parser=dashboard_parser,
    )
    if network_parser is None:
        return findings

    try:
        profiles_list = network_parser.get_intf_mgmt_profiles() or []
    except Exception:
        profiles_list = []

    profile_map: dict[str, tuple[list[str], str]] = {}
    for prof in profiles_list:
        pname = str(prof.get("Name", "")).strip()
        if not pname:
            continue
        protos = [p for p in _MGMT_PROTOCOLS if prof.get(p) == "✓"]
        permitted = str(prof.get("Permitted IPs", "any") or "any").strip()
        if protos:
            profile_map[pname] = (protos, permitted)

    if not profile_map:
        return findings

    iface_getters = (
        "get_ethernet_interfaces",
        "get_vlan_interfaces",
        "get_loopback_interfaces",
        "get_tunnel_interfaces",
    )
    seen_ifaces: set[str] = set()
    for getter in iface_getters:
        fn = getattr(network_parser, getter, None)
        if fn is None:
            continue
        try:
            rows = fn() or []
        except Exception:
            continue
        for row in rows:
            if row.get("_disabled"):
                continue
            if str(row.get("Status", "")).strip().lower() == "disable":
                continue

            prof_name = str(row.get("Mgmt Profile", "-") or "-").strip()
            if prof_name not in profile_map:
                continue

            public_ips = _extract_public_ips(row.get("IP Address"))
            if not public_ips:
                continue

            iface_name = _clean_interface_name(row.get("Interface", ""))
            seen_ifaces.add(iface_name)
            protos, permitted = profile_map[prof_name]
            findings.append(
                {
                    "interface": iface_name,
                    "ip": ", ".join(public_ips),
                    "protocols": protos,
                    "note": f"Profile: {prof_name} · Permitted IPs: {permitted}",
                }
            )

    # Also check ethernet L3 sub-interfaces (<ethernet><entry><layer3><units><entry>),
    # which PaloNetworkParser.get_ethernet_interfaces() does not list.
    dev = getattr(network_parser, "dev", None)
    eth_el = dev.find("network/interface/ethernet") if dev is not None else None
    if eth_el is not None:
        for eth_entry in eth_el.findall("entry"):
            if (eth_entry.findtext("link-state") or "").strip().lower() == "down":
                continue
            l3 = eth_entry.find("layer3")
            if l3 is None:
                continue
            for unit in l3.findall("units/entry"):
                uname = _clean_interface_name(unit.get("name", ""))
                if not uname or uname in seen_ifaces:
                    continue
                prof_name = (unit.findtext("interface-management-profile") or "").strip()
                if prof_name not in profile_map:
                    continue
                ips = [x.get("name", "") for x in unit.findall("ip/entry") if x.get("name")]
                public_ips = [ip for ip in ips if is_public_ip(ip)]
                if not public_ips:
                    continue
                protos, permitted = profile_map[prof_name]
                findings.append(
                    {
                        "interface": uname,
                        "ip": ", ".join(public_ips),
                        "protocols": protos,
                        "note": f"Profile: {prof_name} · Permitted IPs: {permitted}",
                    }
                )

    return findings


def build_exposure_overview_blocks(findings: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, Any] | None]:
    """Return (hero_badge, optional_detail_card) following the Option B UI design."""
    if not findings:
        return ({"text": "No Public Mgmt Exposure", "variant": "allow"}, None)

    any_http = any("HTTP" in f.get("protocols", []) for f in findings)
    severity = "deny" if any_http else "warn"
    badge = {"text": f"Public Mgmt Exposed ({len(findings)})", "variant": severity}
    card = {
        "type": "card",
        "title": "Public Interface Management Exposure",
        "subtitle": "Active interfaces with a public IP enabling HTTP, HTTPS, or SSH management access.",
        "badge": {"text": f"{len(findings)} Exposed", "variant": severity},
        "rows": [
            {
                "label": f"{f['interface']} ({f['ip']})" + (f" · {f['note']}" if f.get("note") else ""),
                "value": ", ".join(f.get("display_protocols") or f["protocols"]),
                "tone": "deny" if "HTTP" in f.get("protocols", []) else "warn",
            }
            for f in findings
        ],
    }
    return badge, card
