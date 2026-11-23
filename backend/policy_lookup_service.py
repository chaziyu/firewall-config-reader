"""
backend/policy_lookup_service.py
Pure-Python FortiGate top-to-bottom policy match evaluator.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def _ip_int(ip: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address(ip.strip()))
    except Exception:
        return None


def _ip_in_net(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip.strip()) in net
    except Exception:
        return False


def _ip_in_range(ip: str, start_int: int, end_int: int) -> bool:
    tip = _ip_int(ip)
    return tip is not None and start_int <= tip <= end_int


def _resolve_addr_match(ip_str: str, addr_objects: list[dict[str, Any]], obj_name: str) -> bool:
    if obj_name.lower() in ("all", "any", ""):
        return True
    if ip_str.strip().lower() == obj_name.strip().lower():
        return True
    for obj in addr_objects:
        if obj.get("Name", "") != obj_name:
            continue
        t = str(obj.get("Type", "")).lower()
        if t == "subnet":
            net = obj.get("network_obj")
            if net and _ip_in_net(ip_str, net):
                return True
        elif t == "ip range":
            s = obj.get("start_int")
            e = obj.get("end_int")
            if s is not None and e is not None and _ip_in_range(ip_str, s, e):
                return True
    return False


def _iface_ok(pol_val: str, user_val: str) -> bool:
    if not user_val or user_val.lower() == "any":
        return True
    pl = [x.strip().lower() for x in pol_val.split(",")]
    return "any" in pl or user_val.lower() in pl


def evaluate_fortigate_lookup(
    parser: Any,
    src_iface: str = "any",
    dst_iface: str = "any",
    src_addr: str = "",
    dst_addr: str = "",
    protocol: str = "any",
) -> dict[str, Any] | None:
    """
    Evaluate FortiGate firewall policies top-to-bottom with AND logic across:
    src_iface, dst_iface, src_addr, dst_addr, protocol.
    Returns the first matching policy dict, or None (implicit deny).
    """
    policies = parser.parse_policies()
    if not policies:
        return None

    addresses = parser.parse_addresses()
    addr_objs = list(addresses.get("subnet", [])) + list(addresses.get("iprange", []))
    for obj in addr_objs:
        if str(obj.get("Type", "")).lower() == "subnet" and "network_obj" not in obj:
            try:
                obj["network_obj"] = ipaddress.IPv4Network(
                    obj.get("Details", "0.0.0.0/0"), strict=False
                )
            except Exception:
                pass

    src_q = (src_addr or "").strip()
    dst_q = (dst_addr or "").strip()
    proto_q = (protocol or "any").strip().lower()

    for pol in policies:
        if str(pol.get("Status", "Enable")).lower() == "disable":
            continue

        if not _iface_ok(str(pol.get("Src Interface", "any")), src_iface):
            continue

        if not _iface_ok(str(pol.get("Dst Interface", "any")), dst_iface):
            continue

        if src_q and src_q.lower() not in ("any", "all"):
            pol_src = str(pol.get("Source", "all"))
            src_names = [n.strip() for n in pol_src.split(",")]
            if not any(
                n.lower() in ("all", "any") or _resolve_addr_match(src_q, addr_objs, n)
                for n in src_names
            ):
                continue

        if dst_q and dst_q.lower() not in ("any", "all"):
            pol_dst = str(pol.get("Destination", "all"))
            dst_names = [n.strip() for n in pol_dst.split(",")]
            if not any(
                n.lower() in ("all", "any") or _resolve_addr_match(dst_q, addr_objs, n)
                for n in dst_names
            ):
                continue

        if proto_q not in ("any", "ip", ""):
            pol_svc = str(pol.get("Service", "ALL")).upper()
            if not any(x in pol_svc for x in ("ALL", "ANY", proto_q.upper())):
                continue

        return pol

    return None
