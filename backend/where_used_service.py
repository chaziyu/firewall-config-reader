"""
backend/where_used_service.py
Global IP / CIDR / Object "Where-Used" reference search for FortiGate and Palo Alto configs.
Resolves IP containment, CIDR overlap, IP ranges, VIPs/NATs, and nested address groups.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def _parse_query(query: str) -> tuple[str, ipaddress.IPv4Address | None, ipaddress.IPv4Network | None]:
    q = (query or "").strip()
    if not q:
        return "", None, None
    q_ip: ipaddress.IPv4Address | None = None
    q_net: ipaddress.IPv4Network | None = None
    try:
        if "/" in q:
            q_net = ipaddress.IPv4Network(q, strict=False)
        else:
            q_ip = ipaddress.IPv4Address(q)
    except Exception:
        pass
    return q, q_ip, q_net


def _split_csv(val: str) -> list[str]:
    out: list[str] = []
    for part in str(val or "").split(","):
        tok = part.strip()
        if not tok or tok == "-":
            continue
        if tok.startswith("!"):
            tok = tok[1:].strip()
        if tok:
            out.append(tok)
    return out


def _strip_port(val: str) -> str:
    s = str(val or "").strip()
    if ":" in s and not s.startswith("["):
        return s.split(":", 1)[0].strip()
    return s


def _parse_network_or_ip(target: str) -> ipaddress.IPv4Network | None:
    s = _strip_port(target)
    if not s or s in ("-", "none", "any", "all"):
        return None
    # Handle "IP/netmask" or "IP netmask" or "IP/prefix" or bare "IP"
    if " " in s and "/" not in s:
        s = s.replace(" ", "/", 1)
    try:
        return ipaddress.IPv4Network(s, strict=False)
    except Exception:
        return None


def _parse_ip_range_ints(target: str) -> tuple[int, int] | None:
    s = str(target or "").strip()
    if "-" not in s:
        return None
    parts = s.split("-", 1)
    try:
        a = int(ipaddress.IPv4Address(parts[0].strip()))
        b = int(ipaddress.IPv4Address(parts[1].strip()))
        return (min(a, b), max(a, b))
    except Exception:
        return None


def _ip_or_net_matches(
    q_ip: ipaddress.IPv4Address | None,
    q_net: ipaddress.IPv4Network | None,
    target_str: str,
    *,
    skip_default_route: bool = False,
) -> bool:
    if q_ip is None and q_net is None:
        return False
    t = str(target_str or "").strip()
    if not t or t == "-":
        return False

    net = _parse_network_or_ip(t)
    if net is not None:
        if skip_default_route and net.prefixlen == 0:
            return False
        if q_ip is not None:
            return q_ip in net
        if q_net is not None:
            return q_net.overlaps(net)

    rng = _parse_ip_range_ints(t)
    if rng is not None:
        lo, hi = rng
        if q_ip is not None:
            q_int = int(q_ip)
            return lo <= q_int <= hi
        if q_net is not None:
            return lo <= int(q_net.broadcast_address) and hi >= int(q_net.network_address)
    return False


def _propagate_groups(
    groups_raw: list[dict[str, Any]],
    matched_names: set[str],
    q_low: str,
    member_key: str = "Members",
    name_key: str = "Name",
) -> list[dict[str, Any]]:
    """Iteratively resolve nested groups containing any matched object or matching query directly."""
    group_entries: list[tuple[str, list[str], dict[str, Any]]] = []
    for g in groups_raw:
        gname = str(g.get(name_key, "")).strip()
        if not gname:
            continue
        members = _split_csv(str(g.get(member_key, "")))
        group_entries.append((gname, members, g))

    matched_groups: dict[str, dict[str, Any]] = {}
    changed = True
    while changed:
        changed = False
        for gname, members, g in group_entries:
            reasons: list[str] = []
            if q_low in gname.lower():
                reasons.append("Group name match")
            hit_members = [m for m in members if m in matched_names]
            if hit_members:
                reasons.append(f"Contains {', '.join(hit_members[:4])}" + ("..." if len(hit_members) > 4 else ""))
            if reasons and gname not in matched_groups:
                matched_groups[gname] = {
                    "Name": gname,
                    "Type": str(g.get("Type", "Address Group")),
                    "Members": str(g.get(member_key, "-")),
                    "Match Reason": "; ".join(reasons),
                }
                if gname not in matched_names:
                    matched_names.add(gname)
                    changed = True
    return list(matched_groups.values())


def _is_wildcard_query(q_low: str) -> bool:
    return q_low in ("all", "any")


def search_fortigate_where_used(fg: Any, query: str) -> dict[str, Any]:
    q, q_ip, q_net = _parse_query(query)
    if not q:
        return {"valid": False, "error": "Please enter an IP address, CIDR subnet, or object name."}

    q_low = q.lower()
    is_default_query = q in ("0.0.0.0", "0.0.0.0/0")
    allow_wildcard = _is_wildcard_query(q_low)

    addresses = fg.parse_addresses() or {}
    vips = fg.parse_vip() or []
    ip_pools = fg.parse_ip_pools() or []
    policies = fg.parse_policies() or []
    static_routes = fg.parse_static_routes() or []
    p1_list = fg.parse_ipsec_phase1() or []
    p2_list = fg.parse_ipsec_phase2() or []
    interfaces = fg.parse_interfaces() or []

    matched_names: set[str] = set()
    addr_rows: list[dict[str, Any]] = []

    # 1. Address Objects
    for bucket in ("subnet", "iprange", "ipmask", "fqdn", "other"):
        for obj in addresses.get(bucket, []) or []:
            name = str(obj.get("Name", "")).strip()
            if not name:
                continue
            atype = str(obj.get("Type", "-"))
            reasons: list[str] = []

            if q_low in name.lower():
                reasons.append("Name match")

            if bucket == "iprange":
                s_int = obj.get("start_int")
                e_int = obj.get("end_int")
                val_display = "-"
                if s_int is not None and e_int is not None:
                    s_ip = str(ipaddress.IPv4Address(s_int))
                    e_ip = str(ipaddress.IPv4Address(e_int))
                    val_display = f"{s_ip} - {e_ip}"
                    if q_ip is not None and s_int <= int(q_ip) <= e_int:
                        reasons.append("IP in range")
                    elif q_net is not None and s_int <= int(q_net.broadcast_address) and e_int >= int(q_net.network_address):
                        reasons.append("Subnet overlaps range")
            elif bucket == "fqdn":
                val_display = str(obj.get("FQDN", "-"))
                if q_low in val_display.lower():
                    reasons.append("FQDN match")
            else:
                val_display = str(obj.get("Details", "-"))
                if _ip_or_net_matches(q_ip, q_net, val_display):
                    reasons.append("IP / CIDR match")
                elif q_low in val_display.lower():
                    reasons.append("Value match")

            if reasons:
                matched_names.add(name)
                addr_rows.append(
                    {
                        "Name": name,
                        "Type": atype,
                        "Value": val_display,
                        "Interface": str(obj.get("Interface", "any")),
                        "Match Reason": "; ".join(reasons),
                    }
                )

    # 2. Address Groups (recursive upward propagation)
    grp_rows = _propagate_groups(addresses.get("groups", []) or [], matched_names, q_low)

    # 3. VIPs & IP Pools
    nat_rows: list[dict[str, Any]] = []
    for vip in vips:
        vname = str(vip.get("Name", "")).strip()
        ext = str(vip.get("Mapped From", "-"))
        mapped = str(vip.get("Mapped To", "-"))
        reasons = []
        if q_low in vname.lower():
            reasons.append("VIP name match")
        if _ip_or_net_matches(q_ip, q_net, ext) or q_low in ext.lower():
            reasons.append("External IP match")
        if _ip_or_net_matches(q_ip, q_net, mapped) or q_low in mapped.lower():
            reasons.append("Mapped-to IP match")
        if reasons:
            if vname:
                matched_names.add(vname)
            nat_rows.append(
                {
                    "Kind": "VIP (DNAT)",
                    "Name": vname or "-",
                    "Interface": str(vip.get("Interface", "any")),
                    "External / Pool": ext,
                    "Mapped To": mapped,
                    "Match Reason": "; ".join(reasons),
                }
            )

    for pool in ip_pools:
        pname = str(pool.get("Name", "")).strip()
        rng_str = str(pool.get("External IP Range", "-"))
        reasons = []
        if q_low in pname.lower():
            reasons.append("Pool name match")
        if _ip_or_net_matches(q_ip, q_net, rng_str) or q_low in rng_str.lower():
            reasons.append("Pool range match")
        if reasons:
            nat_rows.append(
                {
                    "Kind": f"IP Pool ({pool.get('Type', 'Overload')})",
                    "Name": pname or "-",
                    "Interface": "-",
                    "External / Pool": rng_str,
                    "Mapped To": "-",
                    "Match Reason": "; ".join(reasons),
                }
            )

    # 4. Firewall Policies
    policy_rows: list[dict[str, Any]] = []
    for pol in policies:
        hits: list[str] = []
        if q_low in str(pol.get("Name", "")).lower():
            hits.append("Policy Name")
        for field_label, key in (("Source", "Source"), ("Destination", "Destination")):
            tokens = _split_csv(str(pol.get(key, "")))
            for tok in tokens:
                tok_low = tok.lower()
                if tok_low in ("all", "any") and not allow_wildcard:
                    continue
                if tok in matched_names or q_low == tok_low or _ip_or_net_matches(q_ip, q_net, tok):
                    hits.append(f"{field_label} ({tok})")
        for if_label, if_key in (("Src Interface", "Src Interface"), ("Dst Interface", "Dst Interface")):
            for tok in _split_csv(str(pol.get(if_key, ""))):
                if tok.lower() == q_low:
                    hits.append(f"{if_label} ({tok})")
        if hits:
            policy_rows.append(
                {
                    "ID": str(pol.get("ID", "-")),
                    "Name": str(pol.get("Name", "-")),
                    "Src Interface": str(pol.get("Src Interface", "-")),
                    "Dst Interface": str(pol.get("Dst Interface", "-")),
                    "Source": str(pol.get("Source", "-")),
                    "Destination": str(pol.get("Destination", "-")),
                    "Service": str(pol.get("Service", "-")),
                    "Action": str(pol.get("Action", "-")),
                    "NAT": str(pol.get("NAT", "-")),
                    "Status": str(pol.get("Status", "Enable")),
                    "Matched In": "; ".join(dict.fromkeys(hits)),
                    "_disabled": str(pol.get("Status", "Enable")).lower() == "disable",
                }
            )

    # 5. Static Routes
    route_rows: list[dict[str, Any]] = []
    for rt in static_routes:
        dst = str(rt.get("Destination", "-"))
        gw = str(rt.get("Gateway", "-"))
        iface = str(rt.get("Interface", "-"))
        comment = str(rt.get("Comment", "-"))
        reasons = []
        if _ip_or_net_matches(q_ip, q_net, dst, skip_default_route=not is_default_query):
            reasons.append("Destination prefix match")
        if _ip_or_net_matches(q_ip, q_net, gw):
            reasons.append("Gateway match")
        if q_low in iface.lower() and iface != "-":
            reasons.append("Interface match")
        if q_low in comment.lower() and comment != "-":
            reasons.append("Comment match")
        if reasons:
            route_rows.append(
                {
                    "Seq": str(rt.get("Seq", "-")),
                    "Destination": dst,
                    "Gateway": gw,
                    "Interface": iface,
                    "Distance": str(rt.get("Distance", "-")),
                    "Status": str(rt.get("Status", "Enable")),
                    "Match Reason": "; ".join(reasons),
                }
            )

    # 6. VPN & Interfaces
    vpn_iface_rows: list[dict[str, Any]] = []
    for p1 in p1_list:
        tname = str(p1.get("name", "-"))
        rgw = str(p1.get("remote_gw", "-"))
        lgw = str(p1.get("local_gw", "-"))
        intf = str(p1.get("interface", "-"))
        reasons = []
        if q_low in tname.lower():
            reasons.append("Tunnel name match")
        if _ip_or_net_matches(q_ip, q_net, rgw) or (rgw != "-" and q_low == rgw.lower()):
            reasons.append("Remote GW match")
        if _ip_or_net_matches(q_ip, q_net, lgw) or (lgw != "-" and q_low == lgw.lower()):
            reasons.append("Local GW match")
        if intf != "-" and q_low == intf.lower():
            reasons.append("Bound interface match")
        if reasons:
            vpn_iface_rows.append(
                {
                    "Kind": "IPSec Phase 1",
                    "Name": tname,
                    "Details": f"Peer: {rgw} · Intf: {intf}",
                    "Status": str(p1.get("status", "Enable")),
                    "Match Reason": "; ".join(reasons),
                }
            )

    for p2 in p2_list:
        p2name = str(p2.get("name", "-"))
        p1name = str(p2.get("phase1name", "-"))
        src_val = str(p2.get("src_name") if p2.get("src_addr_type") == "name" else p2.get("src_subnet", "-"))
        dst_val = str(p2.get("dst_name") if p2.get("dst_addr_type") == "name" else p2.get("dst_subnet", "-"))
        reasons = []
        if q_low in p2name.lower() or q_low in p1name.lower():
            reasons.append("Phase 2 / Phase 1 name match")
        if src_val in matched_names or _ip_or_net_matches(q_ip, q_net, src_val, skip_default_route=not is_default_query):
            reasons.append(f"Local selector ({src_val})")
        if dst_val in matched_names or _ip_or_net_matches(q_ip, q_net, dst_val, skip_default_route=not is_default_query):
            reasons.append(f"Remote selector ({dst_val})")
        if reasons:
            vpn_iface_rows.append(
                {
                    "Kind": "IPSec Phase 2",
                    "Name": f"{p1name} / {p2name}",
                    "Details": f"{src_val} → {dst_val}",
                    "Status": "Configured",
                    "Match Reason": "; ".join(reasons),
                }
            )

    for iface in interfaces:
        raw_name = str(iface.get("Name", "")).replace("\u00a0", "").replace("\u2517 ", "").strip()
        ip_net = str(iface.get("IP/Netmask", "-"))
        itype = str(iface.get("Type", "-"))
        reasons = []
        if q_low in raw_name.lower():
            reasons.append("Interface name match")
        if _ip_or_net_matches(q_ip, q_net, ip_net):
            reasons.append("Interface subnet match")
        if reasons:
            vpn_iface_rows.append(
                {
                    "Kind": f"Interface ({itype})",
                    "Name": raw_name,
                    "Details": f"IP: {ip_net} · Zone: {iface.get('Zone', '-')}",
                    "Status": str(iface.get("Status", "Enable")),
                    "Match Reason": "; ".join(reasons),
                }
            )

    return {
        "valid": True,
        "vendor": "FortiGate",
        "query": q,
        "addresses_and_groups": addr_rows + grp_rows,
        "nat_rules": nat_rows,
        "policies": policy_rows,
        "routes": route_rows,
        "vpn_and_interfaces": vpn_iface_rows,
    }


def search_paloalto_where_used(parsers: dict[str, Any], query: str) -> dict[str, Any]:
    q, q_ip, q_net = _parse_query(query)
    if not q:
        return {"valid": False, "error": "Please enter an IP address, CIDR subnet, or object name."}

    q_low = q.lower()
    is_default_query = q in ("0.0.0.0", "0.0.0.0/0")
    allow_wildcard = _is_wildcard_query(q_low)

    obj_p = parsers["Objects"]
    pol_p = parsers["Policies"]
    net_p = parsers["Network"]

    matched_names: set[str] = set()
    addr_rows: list[dict[str, Any]] = []

    # 1. Address Objects
    for obj in obj_p.get_addresses() or []:
        name = str(obj.get("Name", "")).strip()
        val = str(obj.get("Value", "-"))
        atype = str(obj.get("Type", "-"))
        if not name:
            continue
        reasons: list[str] = []
        if q_low in name.lower():
            reasons.append("Name match")
        if _ip_or_net_matches(q_ip, q_net, val):
            reasons.append("IP / CIDR / Range match")
        elif q_low in val.lower():
            reasons.append("Value match")
        if reasons:
            matched_names.add(name)
            addr_rows.append(
                {
                    "Name": name,
                    "Type": atype,
                    "Value": val,
                    "Tags": str(obj.get("Tags", "None")),
                    "Match Reason": "; ".join(reasons),
                }
            )

    # 2. Address Groups
    grp_rows = _propagate_groups(obj_p.get_address_groups() or [], matched_names, q_low)

    # 3. Security Policies
    policy_rows: list[dict[str, Any]] = []
    for rule in pol_p.get_security_rules() or []:
        hits: list[str] = []
        if q_low in str(rule.get("Name", "")).lower():
            hits.append("Rule Name")
        for field_label, key in (("Source", "Source Addr"), ("Destination", "Dest Addr")):
            for tok in _split_csv(str(rule.get(key, ""))):
                tok_low = tok.lower()
                if tok_low in ("any", "all") and not allow_wildcard:
                    continue
                if tok in matched_names or q_low == tok_low or _ip_or_net_matches(q_ip, q_net, tok):
                    hits.append(f"{field_label} ({tok})")
        if hits:
            policy_rows.append(
                {
                    "Name": str(rule.get("Name", "-")),
                    "Source Zone": str(rule.get("Source Zone", "-")),
                    "Source Addr": str(rule.get("Source Addr", "-")),
                    "Dest Zone": str(rule.get("Dest Zone", "-")),
                    "Dest Addr": str(rule.get("Dest Addr", "-")),
                    "Application": str(rule.get("Application", "-")),
                    "Service": str(rule.get("Service", "-")),
                    "Action": str(rule.get("Action", "-")),
                    "Matched In": "; ".join(dict.fromkeys(hits)),
                    "_disabled": bool(rule.get("_disabled")),
                }
            )

    # 4. NAT Rules
    nat_rows: list[dict[str, Any]] = []
    for nr in pol_p.get_nat_rules() or []:
        hits = []
        if q_low in str(nr.get("Name", "")).lower():
            hits.append("Rule Name")
        for field_label, key in (("Source", "Source Addr"), ("Destination", "Dest Addr")):
            for tok in _split_csv(str(nr.get(key, ""))):
                tok_low = tok.lower()
                if tok_low in ("any", "all") and not allow_wildcard:
                    continue
                if tok in matched_names or q_low == tok_low or _ip_or_net_matches(q_ip, q_net, tok):
                    hits.append(f"{field_label} ({tok})")
        src_t = str(nr.get("Src Translation", "None"))
        dst_t = str(nr.get("Dst Translation", "None"))
        for t_label, t_val in (("Src Translation", src_t), ("Dst Translation", dst_t)):
            if t_val != "None":
                if q_low in t_val.lower() or any(m in t_val for m in matched_names):
                    hits.append(t_label)
                elif q_ip is not None and str(q_ip) in t_val:
                    hits.append(t_label)
        if hits:
            nat_rows.append(
                {
                    "Kind": "NAT Policy",
                    "Name": str(nr.get("Name", "-")),
                    "Zones": f"{nr.get('Source Zone', '-')} → {nr.get('Dest Zone', '-')}",
                    "Original": f"{nr.get('Source Addr', '-')} → {nr.get('Dest Addr', '-')}",
                    "Translated": f"Src: {src_t} | Dst: {dst_t}",
                    "Match Reason": "; ".join(dict.fromkeys(hits)),
                    "_disabled": bool(nr.get("_disabled")),
                }
            )

    # 5. Static Routes across Virtual Routers
    route_rows: list[dict[str, Any]] = []
    for vr in net_p.get_virtual_routers() or []:
        vr_el = vr.get("_vr_el")
        if vr_el is None:
            continue
        detail = net_p.get_vr_detail(vr_el)
        vr_name = detail.get("name", vr.get("Name", "default"))
        for rt in detail.get("static_v4", []) or []:
            dst = str(rt.get("Destination", "-"))
            nh = str(rt.get("NH Value", "-"))
            iface = str(rt.get("Interface", "-"))
            rname = str(rt.get("Name", "-"))
            reasons = []
            if q_low in rname.lower():
                reasons.append("Route name match")
            if _ip_or_net_matches(q_ip, q_net, dst, skip_default_route=not is_default_query):
                reasons.append("Destination prefix match")
            if _ip_or_net_matches(q_ip, q_net, nh):
                reasons.append("Next-hop match")
            if iface != "-" and q_low == iface.lower():
                reasons.append("Interface match")
            if reasons:
                route_rows.append(
                    {
                        "Virtual Router": vr_name,
                        "Name": rname,
                        "Destination": dst,
                        "Interface": iface,
                        "NH Value": nh,
                        "Metric": str(rt.get("Metric", "-")),
                        "Match Reason": "; ".join(reasons),
                    }
                )

    # 6. VPN & Interfaces
    vpn_iface_rows: list[dict[str, Any]] = []
    for tun in net_p.get_ipsec_tunnels() or []:
        tname = str(tun.get("Name", "-"))
        peer = str(tun.get("IKE Peer IP", "-"))
        loc = str(tun.get("IKE Local IP", "-"))
        tint = str(tun.get("Tunnel Intf", "-"))
        gw = str(tun.get("IKE GW", "-"))
        reasons = []
        if q_low in tname.lower() or q_low in gw.lower():
            reasons.append("Tunnel / IKE GW match")
        if _ip_or_net_matches(q_ip, q_net, peer) or (peer != "-" and q_low == peer.lower()):
            reasons.append("Peer IP match")
        if _ip_or_net_matches(q_ip, q_net, loc) or (loc != "-" and q_low == loc.lower()):
            reasons.append("Local IP match")
        if tint != "-" and q_low == tint.lower():
            reasons.append("Tunnel interface match")
        if reasons:
            vpn_iface_rows.append(
                {
                    "Kind": "IPSec Tunnel",
                    "Name": tname,
                    "Details": f"GW: {gw} ({peer}) · Intf: {tint} · Zone: {tun.get('Zone', '-')}",
                    "Match Reason": "; ".join(reasons),
                }
            )

    for gw in net_p.get_ike_gateways() or []:
        gname = str(gw.get("Name", "-"))
        peer = str(gw.get("Peer Address", "-"))
        loc = str(gw.get("Local IP", "-"))
        reasons = []
        if q_low in gname.lower():
            reasons.append("IKE GW name match")
        if _ip_or_net_matches(q_ip, q_net, peer) or (peer != "-" and q_low == peer.lower()):
            reasons.append("Peer IP match")
        if _ip_or_net_matches(q_ip, q_net, loc) or (loc != "-" and q_low == loc.lower()):
            reasons.append("Local IP match")
        if reasons:
            vpn_iface_rows.append(
                {
                    "Kind": "IKE Gateway",
                    "Name": gname,
                    "Details": f"Peer: {peer} · Local Intf: {gw.get('Local Intf', '-')}",
                    "Match Reason": "; ".join(reasons),
                }
            )

    for kind, rows in (
        ("Ethernet", net_p.get_ethernet_interfaces() or []),
        ("VLAN", net_p.get_vlan_interfaces() or []),
        ("Loopback", net_p.get_loopback_interfaces() or []),
        ("Tunnel", net_p.get_tunnel_interfaces() or []),
    ):
        for iface in rows:
            iname = str(iface.get("Interface", "")).replace("\u2514 ", "").strip()
            ip_str = str(iface.get("IP Address", "-"))
            reasons = []
            if q_low in iname.lower():
                reasons.append("Interface name match")
            for ip_part in _split_csv(ip_str):
                if _ip_or_net_matches(q_ip, q_net, ip_part):
                    reasons.append("Interface subnet match")
                    break
            if reasons:
                vpn_iface_rows.append(
                    {
                        "Kind": f"Interface ({kind})",
                        "Name": iname,
                        "Details": f"IP: {ip_str} · Zone: {iface.get('Zone', '-')}",
                        "Match Reason": "; ".join(reasons),
                    }
                )

    return {
        "valid": True,
        "vendor": "Palo Alto",
        "query": q,
        "addresses_and_groups": addr_rows + grp_rows,
        "nat_rules": nat_rows,
        "policies": policy_rows,
        "routes": route_rows,
        "vpn_and_interfaces": vpn_iface_rows,
    }


def _strip_internal_rows(rows: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, str]], list[str]]:
    if not rows:
        return [], [], []
    cols = [k for k in rows[0].keys() if not str(k).startswith("_")]
    clean = [{c: str(r.get(c, "")) for c in cols} for r in rows]
    classes = ["row-danger" if r.get("_disabled") else "" for r in rows]
    return cols, clean, classes


def build_where_used_blocks(result: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    if not result.get("valid"):
        return False, [{"type": "alert", "variant": "error", "text": result.get("error", "Invalid search query.")}]

    query = result["query"]
    addr_grp = result.get("addresses_and_groups") or []
    nat_rules = result.get("nat_rules") or []
    policies = result.get("policies") or []
    routes = result.get("routes") or []
    vpn_ifaces = result.get("vpn_and_interfaces") or []

    total = len(addr_grp) + len(nat_rules) + len(policies) + len(routes) + len(vpn_ifaces)
    if total == 0:
        return False, [
            {
                "type": "alert",
                "variant": "info",
                "text": f'No references found for "{query}".',
            }
        ]

    blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": f'Where-Used Results for "{query}"',
            "subtitle": f"Found {total} reference(s) across {result.get('vendor', '')} configuration",
            "badge": {"text": f"{total} Match(es)", "variant": "allow"},
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Addresses & Groups", "value": str(len(addr_grp))},
                {"label": "NAT / VIP / Pools", "value": str(len(nat_rules))},
                {"label": "Policies", "value": str(len(policies))},
                {"label": "Static Routes", "value": str(len(routes))},
                {"label": "VPN & Interfaces", "value": str(len(vpn_ifaces))},
            ],
        },
    ]

    sections = [
        ("Addresses & Groups", "wu_addrs", addr_grp, "where_used_addresses.csv", False),
        ("NAT / VIP / IP Pools", "wu_nats", nat_rules, "where_used_nat.csv", True),
        ("Firewall / Security Policies", "wu_policies", policies, "where_used_policies.csv", True),
        ("Static Routes", "wu_routes", routes, "where_used_routes.csv", False),
        ("VPN & Interfaces", "wu_vpn_ifaces", vpn_ifaces, "where_used_vpn_interfaces.csv", False),
    ]

    for title, tbl_id, rows, fname, has_disabled_flag in sections:
        if not rows:
            continue
        cols, clean_rows, row_classes = _strip_internal_rows(rows)
        tbl: dict[str, Any] = {
            "type": "table",
            "id": tbl_id,
            "columns": cols,
            "rows": clean_rows,
            "export_filename": fname,
        }
        if has_disabled_flag and any(row_classes):
            tbl["row_classes"] = row_classes
            tbl["legend"] = [
                {"label": "Active Rule (default)", "variant": "default"},
                {"label": "Disabled Rule (red)", "variant": "danger"},
            ]
        blocks.append(
            {
                "type": "expander",
                "title": f"{title} ({len(rows)})",
                "open": True,
                "blocks": [tbl],
            }
        )

    return True, blocks
