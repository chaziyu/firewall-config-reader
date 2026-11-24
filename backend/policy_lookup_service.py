"""
backend/policy_lookup_service.py
Pure-Python FortiGate top-to-bottom policy match evaluator with recursive
Address Group, VIP/DNAT, Service Group, and port/protocol resolution.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# Built-in FortiGate well-known service definitions:
# SERVICE_NAME -> list of (protocol, port_start, port_end) where 0..65535 means any port
_WELL_KNOWN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "ALL": [("ALL", 0, 65535)],
    "ANY": [("ALL", 0, 65535)],
    "ALL_TCP": [("TCP", 1, 65535)],
    "TCP": [("TCP", 1, 65535)],
    "ALL_UDP": [("UDP", 1, 65535)],
    "UDP": [("UDP", 1, 65535)],
    "ALL_ICMP": [("ICMP", 0, 65535)],
    "ICMP": [("ICMP", 0, 65535)],
    "PING": [("ICMP", 0, 65535)],
    "HTTP": [("TCP", 80, 80)],
    "HTTPS": [("TCP", 443, 443)],
    "SSH": [("TCP", 22, 22)],
    "TELNET": [("TCP", 23, 23)],
    "DNS": [("TCP", 53, 53), ("UDP", 53, 53)],
    "RDP": [("TCP", 3389, 3389)],
    "SMTP": [("TCP", 25, 25)],
    "SMTPS": [("TCP", 465, 465)],
    "SUBMISSION": [("TCP", 587, 587)],
    "FTP": [("TCP", 21, 21)],
    "NTP": [("UDP", 123, 123)],
    "SNMP": [("UDP", 161, 161), ("UDP", 162, 162)],
    "SYSLOG": [("UDP", 514, 514)],
    "SMB": [("TCP", 445, 445)],
    "LDAP": [("TCP", 389, 389)],
    "LDAPS": [("TCP", 636, 636)],
    "DHCP": [("UDP", 67, 68)],
    "RADIUS": [("UDP", 1812, 1813)],
    "IKE": [("UDP", 500, 500), ("UDP", 4500, 4500)],
}


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


def _strip_port(val: str) -> str:
    s = str(val or "").strip()
    if ":" in s and not s.startswith("["):
        return s.split(":", 1)[0].strip()
    return s


def _build_address_index(
    addresses: dict[str, Any],
    vips: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]], dict[str, dict[str, Any]]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for bucket in ("subnet", "iprange", "ipmask", "fqdn", "other"):
        for obj in addresses.get(bucket, []) or []:
            name = str(obj.get("Name", "")).strip()
            if not name:
                continue
            item = dict(obj)
            t = str(item.get("Type", "")).lower()
            if t in ("subnet", "interface subnet") and "network_obj" not in item:
                details = str(item.get("Details", "")).strip()
                if details and details != "-":
                    try:
                        item["network_obj"] = ipaddress.IPv4Network(details, strict=False)
                    except Exception:
                        pass
            by_name.setdefault(name, []).append(item)

    groups: dict[str, list[str]] = {}
    for grp in addresses.get("groups", []) or []:
        gname = str(grp.get("Name", "")).strip()
        raw_members = str(grp.get("Members", "") or "")
        if gname:
            groups[gname] = [m.strip() for m in raw_members.split(",") if m.strip() and m.strip() != "-"]

    vip_map: dict[str, dict[str, Any]] = {}
    for vip in vips or []:
        vname = str(vip.get("Name", "")).strip()
        if vname:
            vip_map[vname] = vip

    return by_name, groups, vip_map


def _resolve_addr_match(
    query: str,
    by_name: dict[str, list[dict[str, Any]]],
    groups: dict[str, list[str]],
    vip_map: dict[str, dict[str, Any]] | None,
    obj_name: str,
    visited: set[str] | None = None,
) -> bool:
    name = str(obj_name or "").strip()
    low = name.lower()
    if low in ("all", "any", ""):
        return True
    q_clean = query.strip()
    if q_clean.lower() == low:
        return True

    seen = visited if visited is not None else set()
    if name in seen:
        return False
    seen.add(name)

    if vip_map and name in vip_map:
        vip = vip_map[name]
        mapped_from = _strip_port(vip.get("Mapped From", ""))
        mapped_to = _strip_port(vip.get("Mapped To", ""))
        if q_clean in (mapped_from, mapped_to) and q_clean not in ("", "-"):
            return True

    if name in groups:
        for member in groups[name]:
            if _resolve_addr_match(q_clean, by_name, groups, vip_map, member, seen):
                return True

    for obj in by_name.get(name, []):
        t = str(obj.get("Type", "")).lower()
        if t in ("subnet", "interface subnet"):
            net = obj.get("network_obj")
            if net and _ip_in_net(q_clean, net):
                return True
        elif t == "ip range":
            s = obj.get("start_int")
            e = obj.get("end_int")
            if s is not None and e is not None and _ip_in_range(q_clean, s, e):
                return True
        elif t == "fqdn":
            fqdn = str(obj.get("FQDN", "")).strip().lower()
            if fqdn and fqdn != "-" and q_clean.lower() == fqdn:
                return True
    return False


def _parse_port_specs(spec_str: str, proto: str) -> list[tuple[str, int, int]]:
    """Parse FortiGate portrange tokens like '8080-8090 8443:1024-65535' into (proto, lo, hi)."""
    out: list[tuple[str, int, int]] = []
    for token in spec_str.strip().split():
        # Strip optional ':srcport[-srcend]'
        dst_part = token.split(":", 1)[0].strip()
        if not dst_part:
            continue
        if "-" in dst_part:
            parts = dst_part.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
                out.append((proto, min(lo, hi), max(lo, hi)))
            except ValueError:
                continue
        else:
            try:
                p = int(dst_part)
                out.append((proto, p, p))
            except ValueError:
                continue
    return out


def _build_service_index(
    services_data: dict[str, Any],
) -> tuple[dict[str, list[tuple[str, int, int]]], dict[str, list[str]]]:
    svc_specs: dict[str, list[tuple[str, int, int]]] = {
        k: list(v) for k, v in _WELL_KNOWN_SERVICES.items()
    }
    for svc in services_data.get("services", []) or []:
        name = str(svc.get("Name", "")).strip()
        if not name:
            continue
        details = str(svc.get("Details", "") or "")
        proto_field = str(svc.get("Protocol", "TCP/UDP")).upper()
        specs: list[tuple[str, int, int]] = []
        for part in details.split("|"):
            p = part.strip()
            if p.upper().startswith("TCP:"):
                specs.extend(_parse_port_specs(p.split(":", 1)[1], "TCP"))
            elif p.upper().startswith("UDP:"):
                specs.extend(_parse_port_specs(p.split(":", 1)[1], "UDP"))
            elif p.upper().startswith("ICMP"):
                specs.append(("ICMP", 0, 65535))
        if not specs:
            if "ICMP" in proto_field:
                specs.append(("ICMP", 0, 65535))
            elif proto_field == "ALL":
                specs.append(("ALL", 0, 65535))
        svc_specs[name.upper()] = specs

    svc_groups: dict[str, list[str]] = {}
    for grp in services_data.get("groups", []) or []:
        gname = str(grp.get("Name", "")).strip()
        raw_members = str(grp.get("Members", "") or "")
        if gname:
            svc_groups[gname.upper()] = [
                m.strip() for m in raw_members.split(",") if m.strip() and m.strip() != "-"
            ]
    return svc_specs, svc_groups


def _parse_query_specs(
    query: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
) -> tuple[str, list[tuple[str, int, int]]]:
    """Return (upper_query_name, parsed_proto_port_specs)."""
    q = query.strip().upper()
    if q in ("", "ANY", "ALL", "IP"):
        return q, [("ALL", 0, 65535)]

    # Check proto/port e.g. tcp/443, udp/53, tcp/8080-8090
    m = re.match(r"^(TCP|UDP)/(\d+)(?:-(\d+))?$", q)
    if m:
        proto = m.group(1)
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        return q, [(proto, min(lo, hi), max(lo, hi))]

    # Bare port number e.g. 443 -> matches TCP or UDP on that port
    if q.isdigit():
        p = int(q)
        return q, [("TCP", p, p), ("UDP", p, p)]

    if q in svc_specs:
        return q, svc_specs[q]
    if q in svc_groups:
        return q, _expand_service_specs(q, svc_specs, svc_groups, set())

    return q, []


def _expand_service_specs(
    svc_name: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
    visited: set[str],
) -> list[tuple[str, int, int]]:
    key = svc_name.strip().upper()
    if not key or key in visited:
        return []
    visited.add(key)
    if key in svc_groups:
        out: list[tuple[str, int, int]] = []
        for member in svc_groups[key]:
            out.extend(_expand_service_specs(member, svc_specs, svc_groups, visited))
        return out
    return list(svc_specs.get(key, []))


def _specs_overlap(
    pol_specs: list[tuple[str, int, int]],
    q_specs: list[tuple[str, int, int]],
) -> bool:
    for p_proto, p_lo, p_hi in pol_specs:
        if p_proto == "ALL":
            return True
        for q_proto, q_lo, q_hi in q_specs:
            if q_proto == "ALL":
                return True
            if p_proto == q_proto and max(p_lo, q_lo) <= min(p_hi, q_hi):
                return True
    return False


def _service_matches(
    pol_svc_str: str,
    proto_query: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
) -> bool:
    q_upper, q_specs = _parse_query_specs(proto_query, svc_specs, svc_groups)
    if q_upper in ("", "ANY", "ALL", "IP"):
        return True

    pol_tokens = [t.strip() for t in pol_svc_str.split(",") if t.strip()]
    for token in pol_tokens:
        tok_upper = token.upper()
        if tok_upper in ("ALL", "ANY", q_upper):
            return True
        if tok_upper in svc_groups:
            # Check direct member name match inside group too
            members = _collect_group_names(tok_upper, svc_groups, set())
            if q_upper in members or "ALL" in members or "ANY" in members:
                return True
        pol_specs = _expand_service_specs(tok_upper, svc_specs, svc_groups, set())
        if pol_specs and q_specs and _specs_overlap(pol_specs, q_specs):
            return True
        if not q_specs and q_upper in tok_upper:
            return True
    return False


def _collect_group_names(
    grp_name: str,
    svc_groups: dict[str, list[str]],
    visited: set[str],
) -> set[str]:
    key = grp_name.upper()
    if key in visited:
        return set()
    visited.add(key)
    names: set[str] = {key}
    for m in svc_groups.get(key, []):
        mu = m.upper()
        names.add(mu)
        if mu in svc_groups:
            names.update(_collect_group_names(mu, svc_groups, visited))
    return names


def _iface_ok(pol_val: str, user_val: str) -> bool:
    if not user_val or user_val.lower() == "any":
        return True
    pl = [x.strip().lower() for x in pol_val.split(",")]
    return "any" in pl or user_val.lower() in pl


def evaluate_fortigate_lookup_detailed(
    parser: Any,
    src_iface: str = "any",
    dst_iface: str = "any",
    src_addr: str = "",
    dst_addr: str = "",
    protocol: str = "any",
) -> dict[str, Any]:
    """
    Evaluate FortiGate firewall policies top-to-bottom with AND logic across:
    src_iface, dst_iface, src_addr, dst_addr, protocol.
    Returns {"match": first_policy_or_None, "shadowed": subsequent_matching_policies}.
    """
    policies = parser.parse_policies()
    if not policies:
        return {"match": None, "shadowed": []}

    addresses = parser.parse_addresses() if hasattr(parser, "parse_addresses") else {}
    vips = parser.parse_vip() if hasattr(parser, "parse_vip") else []
    services_data = parser.parse_services() if hasattr(parser, "parse_services") else {}

    by_name, addr_groups, vip_map = _build_address_index(addresses, vips)
    svc_specs, svc_groups = _build_service_index(services_data)

    src_q = (src_addr or "").strip()
    dst_q = (dst_addr or "").strip()
    proto_q = (protocol or "any").strip()

    matches: list[dict[str, Any]] = []
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
                _resolve_addr_match(src_q, by_name, addr_groups, None, n)
                for n in src_names
            ):
                continue

        if dst_q and dst_q.lower() not in ("any", "all"):
            pol_dst = str(pol.get("Destination", "all"))
            dst_names = [n.strip() for n in pol_dst.split(",")]
            if not any(
                _resolve_addr_match(dst_q, by_name, addr_groups, vip_map, n)
                for n in dst_names
            ):
                continue

        if not _service_matches(str(pol.get("Service", "ALL")), proto_q, svc_specs, svc_groups):
            continue

        matches.append(pol)

    if not matches:
        return {"match": None, "shadowed": []}
    return {"match": matches[0], "shadowed": matches[1:]}


def evaluate_fortigate_lookup(
    parser: Any,
    src_iface: str = "any",
    dst_iface: str = "any",
    src_addr: str = "",
    dst_addr: str = "",
    protocol: str = "any",
) -> dict[str, Any] | None:
    """Backwards-compatible wrapper returning the first matching policy or None."""
    return evaluate_fortigate_lookup_detailed(
        parser,
        src_iface=src_iface,
        dst_iface=dst_iface,
        src_addr=src_addr,
        dst_addr=dst_addr,
        protocol=protocol,
    )["match"]
