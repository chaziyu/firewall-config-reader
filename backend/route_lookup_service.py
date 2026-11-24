"""
backend/route_lookup_service.py
Longest Prefix Match (LPM) route lookup for FortiGate and Palo Alto configs.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_TREE_PREFIX_RE = re.compile(r"^[\s\u00a0]*(?:\u2517|\u2514)?[\s\u00a0]*")


def _clean_iface(name: str) -> str:
    return _TREE_PREFIX_RE.sub("", str(name or "")).strip()


def _parse_int(val: Any, default: int) -> int:
    try:
        return int(str(val).strip())
    except Exception:
        return default


def _parse_network(cidr_or_mask: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    raw = str(cidr_or_mask or "").strip()
    if not raw or raw in ("-", "none"):
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def lookup_fortigate_route(parser: Any, dest_ip: str) -> dict[str, Any]:
    raw_ip = (dest_ip or "").strip()
    try:
        target = ipaddress.ip_address(raw_ip)
    except ValueError:
        return {"valid": False, "error": f"Invalid IP address: '{raw_ip}'."}

    candidates: list[dict[str, Any]] = []

    # 1. Connected routes from active interfaces
    for row in parser.parse_interfaces() or []:
        if str(row.get("Type", "")).strip().lower() == "zone":
            continue
        if str(row.get("Status", "Enable")).strip().lower() == "disable":
            continue
        ip_field = str(row.get("IP/Netmask", "") or "")
        for part in ip_field.split(","):
            net = _parse_network(part)
            if net is None or net.version != target.version:
                continue
            if target in net:
                candidates.append(
                    {
                        "Type": "Connected",
                        "Destination": str(net),
                        "Prefix Len": net.prefixlen,
                        "Gateway": "Directly Connected",
                        "Interface": _clean_iface(row.get("Name", "-")),
                        "Distance": 0,
                        "Priority": 0,
                        "Comment": row.get("Alias", "-") or "-",
                        "_sort": (-net.prefixlen, 0, 0),
                    }
                )

    # 2. Active Static Routes
    for row in parser.parse_static_routes() or []:
        if str(row.get("Status", "Enable")).strip().lower() == "disable":
            continue
        net = _parse_network(row.get("Destination", ""))
        if net is None or net.version != target.version:
            continue
        if target in net:
            dist = _parse_int(row.get("Distance"), 10)
            prio = _parse_int(row.get("Priority"), 0)
            candidates.append(
                {
                    "Type": "Static",
                    "Destination": str(net),
                    "Prefix Len": net.prefixlen,
                    "Gateway": str(row.get("Gateway", "-") or "-"),
                    "Interface": str(row.get("Interface", "-") or "-"),
                    "Distance": dist,
                    "Priority": prio,
                    "Comment": str(row.get("Comment", "-") or "-"),
                    "_sort": (-net.prefixlen, dist, prio),
                }
            )

    candidates.sort(key=lambda c: c["_sort"])
    for c in candidates:
        c.pop("_sort", None)

    policy_routes = parser.parse_policy_routes() if hasattr(parser, "parse_policy_routes") else []
    active_pr = sum(
        1 for pr in (policy_routes or []) if str(pr.get("Status", "Enable")).strip().lower() != "disable"
    )

    return {
        "valid": True,
        "dest_ip": str(target),
        "winner": candidates[0] if candidates else None,
        "candidates": candidates,
        "active_policy_routes": active_pr,
    }


def _pa_interface_networks(network_parser: Any) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    iface_nets: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}

    def _add(iface_name: str, ip_str: str) -> None:
        cleaned = _clean_iface(iface_name)
        if not cleaned:
            return
        net = _parse_network(ip_str)
        if net is not None:
            iface_nets.setdefault(cleaned, []).append(net)

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
            if str(row.get("Status", "")).strip().lower() == "disable":
                continue
            iname = _clean_iface(row.get("Interface", ""))
            for part in str(row.get("IP Address", "") or "").split(","):
                _add(iname, part)

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
                uname = _clean_iface(unit.get("name", ""))
                for ip_el in unit.findall("ip/entry"):
                    _add(uname, ip_el.get("name", ""))

    return iface_nets


def lookup_paloalto_route(
    network_parser: Any,
    dest_ip: str,
    virtual_router: str = "all",
) -> dict[str, Any]:
    raw_ip = (dest_ip or "").strip()
    try:
        target = ipaddress.ip_address(raw_ip)
    except ValueError:
        return {"valid": False, "error": f"Invalid IP address: '{raw_ip}'."}

    iface_nets = _pa_interface_networks(network_parser)
    vrs = network_parser.get_virtual_routers() or []
    vr_filter = (virtual_router or "all").strip()

    candidates: list[dict[str, Any]] = []
    for vr_row in vrs:
        vr_name = str(vr_row.get("Name", "default"))
        if vr_filter.lower() != "all" and vr_name != vr_filter:
            continue
        vr_el = vr_row.get("_vr_el")
        if vr_el is None:
            continue
        detail = network_parser.get_vr_detail(vr_el)

        # Connected interface routes inside this VR
        for iname in detail.get("interfaces", []) or []:
            cleaned = _clean_iface(iname)
            for net in iface_nets.get(cleaned, []):
                if net.version == target.version and target in net:
                    candidates.append(
                        {
                            "Virtual Router": vr_name,
                            "Type": "Connected",
                            "Route Name": f"connected ({cleaned})",
                            "Destination": str(net),
                            "Prefix Len": net.prefixlen,
                            "Next Hop": "Directly Connected",
                            "Interface": cleaned,
                            "AD": 0,
                            "Metric": 0,
                            "_sort": (-net.prefixlen, 0, 0),
                        }
                    )

        # Static routes inside this VR
        ad_map = detail.get("ad", {}) or {}
        static_ad = _parse_int(ad_map.get("static"), 10)
        for sr in detail.get("static_v4", []) or []:
            net = _parse_network(sr.get("Destination", ""))
            if net is None or net.version != target.version:
                continue
            if target in net:
                metric = _parse_int(sr.get("Metric"), 10)
                nh_type = str(sr.get("NH Type", "-") or "-")
                nh_val = str(sr.get("NH Value", "-") or "-")
                nh_display = f"{nh_type}: {nh_val}" if nh_type not in ("-", "none") else nh_val
                candidates.append(
                    {
                        "Virtual Router": vr_name,
                        "Type": "Static",
                        "Route Name": str(sr.get("Name", "-") or "-"),
                        "Destination": str(net),
                        "Prefix Len": net.prefixlen,
                        "Next Hop": nh_display,
                        "Interface": str(sr.get("Interface", "-") or "-"),
                        "AD": static_ad,
                        "Metric": metric,
                        "_sort": (-net.prefixlen, static_ad, metric),
                    }
                )

    candidates.sort(key=lambda c: c["_sort"])
    for c in candidates:
        c.pop("_sort", None)

    return {
        "valid": True,
        "dest_ip": str(target),
        "winner": candidates[0] if candidates else None,
        "candidates": candidates,
    }
