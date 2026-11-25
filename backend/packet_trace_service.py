"""
backend/packet_trace_service.py
End-to-End Packet Flow Simulator ("Trace Packet") for FortiGate and Palo Alto.
Unifies Ingress/RPF, Pre-NAT/DNAT, Egress Route (LPM), Security/Firewall Policy,
and Outbound SNAT into a single step-by-step packet trace.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from backend.exposure_check import _bare_ip
from backend.policy_lookup_service import evaluate_fortigate_lookup_detailed
from backend.route_lookup_service import lookup_fortigate_route, lookup_paloalto_route


def _validate_ipv4(ip_str: str, label: str) -> tuple[str | None, str | None]:
    s = str(ip_str or "").strip()
    if not s:
        return None, f"Please enter a {label} IPv4 address."
    try:
        return str(ipaddress.IPv4Address(s)), None
    except ValueError:
        return None, f"Invalid {label} IPv4 address: '{s}'."


def _split_csv(val: str) -> list[str]:
    return [p.strip() for p in str(val or "").split(",") if p.strip() and p.strip() != "-"]


def _fg_interface_aliases(fg: Any) -> dict[str, list[str]]:
    """Map interface name -> [iface, parent_zone, sdwan_zone] for policy lookup."""
    aliases: dict[str, list[str]] = {}
    for row in fg.parse_interfaces() or []:
        if str(row.get("Type", "")).lower() == "zone":
            zname = str(row.get("Zone", "")).strip()
            for m in _split_csv(str(row.get("Members", ""))):
                bucket = aliases.setdefault(m, [m])
                if zname and zname != "-" and zname not in bucket:
                    bucket.append(zname)
        else:
            cname = str(row.get("Name", "")).replace("\u00a0", "").replace("\u2517 ", "").strip()
            z = str(row.get("Zone", "-")).strip()
            if cname:
                bucket = aliases.setdefault(cname, [cname])
                if z and z != "-" and z not in bucket:
                    bucket.append(z)

    if hasattr(fg, "parse_sdwan"):
        try:
            sdwan = fg.parse_sdwan() or {}
            for m in sdwan.get("members", []) or []:
                m_intf = str(m.get("Interface", "")).strip()
                m_zone = str(m.get("Zone", "virtual-wan-link") or "virtual-wan-link").strip()
                if m_intf and m_intf != "-":
                    bucket = aliases.setdefault(m_intf, [m_intf])
                    if m_zone not in bucket:
                        bucket.append(m_zone)
                    if "virtual-wan-link" not in bucket:
                        bucket.append("virtual-wan-link")
        except Exception:
            pass
    return aliases


def _build_return_path_step(
    vendor: str,
    s_ip: str,
    post_dst_ip: str,
    src_iface: str,
    dst_iface: str,
    ing_winner: dict[str, Any] | None,
    eg_winner: dict[str, Any] | None,
    *,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    active_policy_routes: int = 0,
    step_num: str = "6",
) -> tuple[str, dict[str, Any], str | None]:
    """Evaluate return-path routing symmetry (dst -> src) and RPF consistency."""
    if src_iface == "-" or ing_winner is None:
        summary = "No Return Route (RPF / Drop Risk)"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): no connected or static route back to source {s_ip}; "
            "reply traffic will be blackholed or dropped by Strict RPF."
        )
        step = {
            "Step": step_num,
            "Stage": "Return Path & Symmetry Check",
            "Outcome": summary,
            "Details": f"Reverse LPM lookup for {s_ip} found no active route. Reply packets from {post_dst_ip} cannot return.",
            "_tone": "danger",
        }
        return summary, step, warn

    ing_vr = str(ing_winner.get("Virtual Router") or "").strip()
    eg_vr = str(eg_winner.get("Virtual Router") or "").strip() if eg_winner else ""
    if vendor == "Palo Alto" and ing_vr and eg_vr and ing_vr != eg_vr:
        summary = f"Cross-VR Asymmetry ({eg_vr} ≠ {ing_vr})"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): forward egress is in VR '{eg_vr}' via {dst_iface}, "
            f"while reverse route to {s_ip} is in VR '{ing_vr}' via {src_iface}."
        )
        step = {
            "Step": step_num,
            "Stage": "Return Path & Symmetry Check",
            "Outcome": summary,
            "Details": f"Return prefix {ing_winner.get('Destination', '-')} resolves in VR '{ing_vr}' ({src_iface}), different from egress VR '{eg_vr}'.",
            "_tone": "warn",
        }
        return summary, step, warn

    if src_iface == dst_iface:
        summary = f"Asymmetric / Hairpin ({dst_iface})"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): forward egress and reverse route both use '{dst_iface}'. "
            "Verify hosts do not bypass the firewall on the return leg (hairpin / asymmetric routing)."
        )
        step = {
            "Step": step_num,
            "Stage": "Return Path & Symmetry Check",
            "Outcome": summary,
            "Details": f"Return lookup for {s_ip} resolves back out {src_iface} ({ing_winner.get('Destination', '-')}).",
            "_tone": "warn",
        }
        return summary, step, warn

    ret_gw = ing_winner.get("Gateway") or ing_winner.get("Next Hop") or "Directly Connected"
    if dst_zone and src_zone:
        flow_label = f"{dst_iface} ({dst_zone}) → {src_iface} ({src_zone})"
    else:
        flow_label = f"{dst_iface} → {src_iface}"
    summary = f"Symmetric ({flow_label})"
    extra = f" Note: {active_policy_routes} active policy route(s) may override static return LPM." if active_policy_routes > 0 else ""
    step = {
        "Step": step_num,
        "Stage": "Return Path & Symmetry Check",
        "Outcome": summary,
        "Details": (
            f"Reverse LPM for {s_ip} matches {ing_winner.get('Destination', '-')} via {src_iface} "
            f"(Next Hop: {ret_gw}, {ing_winner.get('Type', 'Route')}).{extra}"
        ),
        "_tone": "success",
    }
    return summary, step, None


def trace_fortigate_packet(
    fg: Any,
    src_ip: str,
    dst_ip: str,
    dst_port: str = "443",
    protocol: str = "tcp",
    *,
    check_return: bool = True,
) -> dict[str, Any]:
    s_ip, err = _validate_ipv4(src_ip, "Source")
    if err or s_ip is None:
        return {"valid": False, "error": err}
    d_ip, err = _validate_ipv4(dst_ip, "Destination")
    if err or d_ip is None:
        return {"valid": False, "error": err}

    proto_clean = str(protocol or "tcp").strip().lower()
    port_clean = str(dst_port or "").strip()
    if proto_clean in ("icmp", "any"):
        svc_query = proto_clean
    elif port_clean:
        svc_query = f"{proto_clean}/{port_clean}"
    else:
        svc_query = proto_clean

    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    # Step 1: Ingress & Reverse Path Check
    ing_res = lookup_fortigate_route(fg, s_ip)
    ing_winner = ing_res.get("winner")
    src_iface = str(ing_winner.get("Interface", "-")) if ing_winner else "-"
    if src_iface == "-":
        warnings.append(f"No route back to Source IP {s_ip} — Strict RPF would drop return/ingress packets.")
        steps.append(
            {
                "Step": "1",
                "Stage": "Ingress & RPF Check",
                "Outcome": "Unknown (RPF Drop Risk)",
                "Details": f"No connected or static route matched {s_ip}.",
                "_tone": "warn",
            }
        )
    else:
        steps.append(
            {
                "Step": "1",
                "Stage": "Ingress & RPF Check",
                "Outcome": src_iface,
                "Details": f"Source {s_ip} arrives via {src_iface} (matched {ing_winner.get('Destination', '-')}, {ing_winner.get('Type', '-')}).",
                "_tone": "info",
            }
        )

    # Step 2: Pre-NAT / DNAT (VIPs)
    vip_name: str | None = None
    post_dst_ip = d_ip
    post_dst_port = port_clean
    for vip in fg.parse_vip() or []:
        mapped_from = str(vip.get("Mapped From", "-") or "").strip()
        if _bare_ip(mapped_from) != d_ip:
            continue
        ext_port = mapped_from.split(":", 1)[1].strip() if ":" in mapped_from else ""
        if ext_port and port_clean and ext_port != port_clean:
            continue
        vip_name = str(vip.get("Name", "")).strip() or None
        mapped_to = str(vip.get("Mapped To", "-") or "").strip()
        post_dst_ip = _bare_ip(mapped_to) or d_ip
        if ":" in mapped_to:
            post_dst_port = mapped_to.split(":", 1)[1].strip()
        break

    if vip_name:
        steps.append(
            {
                "Step": "2",
                "Stage": "Pre-NAT / DNAT (VIP)",
                "Outcome": f"DNAT via {vip_name}",
                "Details": f"{d_ip}:{port_clean or '*'} → {post_dst_ip}:{post_dst_port or '*'}",
                "_tone": "info",
            }
        )
    else:
        steps.append(
            {
                "Step": "2",
                "Stage": "Pre-NAT / DNAT (VIP)",
                "Outcome": "No DNAT",
                "Details": f"Destination remains {d_ip}",
                "_tone": "info",
            }
        )

    # Check if destination IP is one of the firewall's own active interface IPs (Local-In)
    if not vip_name:
        own_ip_map: dict[str, tuple[str, str]] = {}
        for row in fg.parse_interfaces() or []:
            if str(row.get("Type", "")).lower() == "zone" or str(row.get("Status", "Enable")).lower() == "disable":
                continue
            iname = str(row.get("Name", "")).replace("\u00a0", "").replace("\u2517 ", "").strip()
            acc = str(row.get("Admin Access", "-") or "-")
            for part in _split_csv(str(row.get("IP/Netmask", ""))):
                b = _bare_ip(part)
                if b and b != "-":
                    own_ip_map[b] = (iname, acc)
        if post_dst_ip in own_ip_map:
            own_iface, own_acc = own_ip_map[post_dst_ip]
            steps.append(
                {
                    "Step": "3",
                    "Stage": "Local-In (To Firewall)",
                    "Outcome": f"Firewall Interface ({own_iface})",
                    "Details": f"Destination {post_dst_ip} is the firewall's own interface IP. Governed by allowaccess ({own_acc}) & local-in-policy, not forwarding policies.",
                    "_tone": "info",
                }
            )
            return {
                "valid": True,
                "vendor": "FortiGate",
                "verdict": "LOCAL-IN",
                "src": s_ip,
                "dst": f"{d_ip}:{port_clean or proto_clean}",
                "ingress": src_iface,
                "egress": f"{own_iface} (Local-In)",
                "policy": f"Local-In ({own_acc})",
                "nat": "None",
                "steps": steps,
                "warnings": warnings,
            }

    # Step 3: Egress Route (LPM)
    eg_res = lookup_fortigate_route(fg, post_dst_ip)
    eg_winner = eg_res.get("winner")
    dst_iface = str(eg_winner.get("Interface", "-")) if eg_winner else "-"
    active_pr = int(eg_res.get("active_policy_routes") or 0)
    if active_pr > 0:
        warnings.append(f"{active_pr} active Policy Route(s) exist and are evaluated before static/connected routes.")

    if dst_iface == "-":
        warnings.append(f"No route to destination {post_dst_ip} — traffic dropped at routing stage.")
        steps.append(
            {
                "Step": "3",
                "Stage": "Egress Route (LPM)",
                "Outcome": "No Route (Drop)",
                "Details": f"No active connected or static route matched {post_dst_ip}.",
                "_tone": "danger",
            }
        )
        return {
            "valid": True,
            "vendor": "FortiGate",
            "verdict": "DROP",
            "src": f"{s_ip}",
            "dst": f"{d_ip}:{port_clean or proto_clean}",
            "ingress": src_iface,
            "egress": "No Route",
            "policy": "Not evaluated (no route)",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    gw = eg_winner.get("Gateway") or "-"
    steps.append(
        {
            "Step": "3",
            "Stage": "Egress Route (LPM)",
            "Outcome": dst_iface,
            "Details": f"Matched {eg_winner.get('Destination', '-')} via {dst_iface} (GW: {gw}, {eg_winner.get('Type', '-')}).",
            "_tone": "info",
        }
    )

    if src_iface != "-" and src_iface == dst_iface:
        warnings.append(f"Ingress and egress both resolve to '{src_iface}' (hairpin / potential asymmetric path).")

    # Step 4: Firewall Policy Evaluation
    aliases = _fg_interface_aliases(fg)
    src_candidates = aliases.get(src_iface, [src_iface]) if src_iface != "-" else ["any"]
    dst_candidates = aliases.get(dst_iface, [dst_iface])
    dst_lookup_addr = vip_name or d_ip

    best_match = None
    best_shadowed: list[dict[str, Any]] = []
    for s_cand in src_candidates:
        for d_cand in dst_candidates:
            res = evaluate_fortigate_lookup_detailed(
                fg,
                src_iface=s_cand,
                dst_iface=d_cand,
                src_addr=s_ip,
                dst_addr=dst_lookup_addr,
                protocol=svc_query,
            )
            m = res.get("match")
            if m is not None:
                if best_match is None:
                    best_match = m
                    best_shadowed = res.get("shadowed") or []

    if best_match is None:
        same_connected = (
            ing_winner is not None
            and eg_winner is not None
            and ing_winner.get("Type") == "Connected"
            and eg_winner.get("Type") == "Connected"
            and src_iface != "-"
            and src_iface == dst_iface
            and ing_winner.get("Destination") == eg_winner.get("Destination")
        )
        if same_connected:
            steps.append(
                {
                    "Step": "4",
                    "Stage": "Firewall Policy",
                    "Outcome": "L2 Direct (Bypasses L3 Policy)",
                    "Details": f"Both {s_ip} and {post_dst_ip} belong to directly connected subnet {eg_winner.get('Destination')} on {dst_iface}; hosts communicate at L2 unless hairpinned.",
                    "_tone": "info",
                }
            )
            return {
                "valid": True,
                "vendor": "FortiGate",
                "verdict": "L2 DIRECT",
                "src": s_ip,
                "dst": f"{d_ip}:{port_clean or proto_clean}",
                "ingress": src_iface,
                "egress": dst_iface,
                "policy": "N/A — L2 Switched (Same Connected Subnet)",
                "nat": "None",
                "steps": steps,
                "warnings": warnings,
            }

        steps.append(
            {
                "Step": "4",
                "Stage": "Firewall Policy",
                "Outcome": "Implicit DENY",
                "Details": f"No policy matched ({', '.join(src_candidates)} → {', '.join(dst_candidates)}).",
                "_tone": "danger",
            }
        )
        return {
            "valid": True,
            "vendor": "FortiGate",
            "verdict": "DENY",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean or proto_clean}",
            "ingress": src_iface,
            "egress": dst_iface,
            "policy": "Implicit DENY",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    pol_id = best_match.get("ID", "?")
    pol_name = best_match.get("Name", "-")
    action = str(best_match.get("Action", "DENY")).upper()
    is_allow = action in ("ACCEPT", "ALLOW", "IPSEC")
    if best_shadowed:
        warnings.append(f"{len(best_shadowed)} subsequent shadowed policy(s) also match after #{pol_id}.")

    steps.append(
        {
            "Step": "4",
            "Stage": "Firewall Policy",
            "Outcome": f"#{pol_id} {pol_name} ({action})",
            "Details": f"{best_match.get('Src Interface', '-')} → {best_match.get('Dst Interface', '-')} | Service: {best_match.get('Service', '-')}",
            "_tone": "success" if is_allow else "danger",
        }
    )

    # Step 5: Outbound SNAT
    nat_flag = str(best_match.get("NAT", "-")).lower()
    if is_allow and nat_flag == "enable":
        nat_summary = f"SNAT Enabled (Masquerade / Pool on {dst_iface})"
        steps.append(
            {
                "Step": "5",
                "Stage": "Outbound SNAT",
                "Outcome": "SNAT Applied",
                "Details": f"Source {s_ip} translated via egress interface {dst_iface} / policy IP Pool.",
                "_tone": "info",
            }
        )
    else:
        nat_summary = "No SNAT"
        steps.append(
            {
                "Step": "5",
                "Stage": "Outbound SNAT",
                "Outcome": "No SNAT",
                "Details": "Source IP is preserved (policy NAT disabled).",
                "_tone": "info",
            }
        )

    ret_summary: str | None = None
    if check_return:
        ret_summary, ret_step, ret_warn = _build_return_path_step(
            "FortiGate",
            s_ip,
            post_dst_ip,
            src_iface,
            dst_iface,
            ing_winner,
            eg_winner,
            active_policy_routes=active_pr,
            step_num="6",
        )
        steps.append(ret_step)
        if ret_warn and not (src_iface == dst_iface and any("hairpin" in w for w in warnings)):
            warnings.append(ret_warn)

    res: dict[str, Any] = {
        "valid": True,
        "vendor": "FortiGate",
        "verdict": "ALLOW" if is_allow else "DENY",
        "src": s_ip,
        "dst": f"{d_ip}:{port_clean or proto_clean}",
        "ingress": src_iface,
        "egress": dst_iface,
        "policy": f"#{pol_id} — {pol_name} ({action})",
        "nat": nat_summary if not vip_name else f"DNAT ({vip_name}) + {nat_summary}",
        "steps": steps,
        "warnings": warnings,
    }
    if ret_summary is not None:
        res["return_path"] = ret_summary
    return res


def trace_paloalto_packet(
    parsers: dict[str, Any],
    src_ip: str,
    dst_ip: str,
    dst_port: str = "443",
    protocol: str = "tcp",
    virtual_router: str = "all",
    *,
    check_return: bool = True,
) -> dict[str, Any]:
    s_ip, err = _validate_ipv4(src_ip, "Source")
    if err or s_ip is None:
        return {"valid": False, "error": err}
    d_ip, err = _validate_ipv4(dst_ip, "Destination")
    if err or d_ip is None:
        return {"valid": False, "error": err}

    net_p = parsers["Network"]
    pol_p = parsers["Policies"]
    zone_map = net_p._build_zone_map() if hasattr(net_p, "_build_zone_map") else {}

    proto_clean = str(protocol or "tcp").strip().lower()
    port_clean = str(dst_port or "443").strip()

    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    # Step 1: Ingress & RPF
    ing_res = lookup_paloalto_route(net_p, s_ip, virtual_router)
    ing_w = ing_res.get("winner")
    src_iface = str(ing_w.get("Interface", "-")) if ing_w else "-"
    src_zone = zone_map.get(src_iface, "any") if src_iface != "-" else "any"
    if src_iface == "-":
        warnings.append(f"No reverse route to {s_ip} — check asymmetric routing or Strict RPF.")
        steps.append(
            {
                "Step": "1",
                "Stage": "Ingress & RPF Check",
                "Outcome": "Unknown (No Reverse Route)",
                "Details": f"No route matched {s_ip}; Security policy will evaluate with zone 'any'.",
                "_tone": "warn",
            }
        )
    else:
        steps.append(
            {
                "Step": "1",
                "Stage": "Ingress & RPF Check",
                "Outcome": f"{src_iface} (Zone: {src_zone})",
                "Details": f"Matched {ing_w.get('Destination', '-')} via {src_iface}.",
                "_tone": "info",
            }
        )

    # Check if destination is one of Palo Alto's own active interface IPs (Local-In)
    pa_own_ips: dict[str, tuple[str, str]] = {}
    for getter in (
        "get_ethernet_interfaces",
        "get_vlan_interfaces",
        "get_loopback_interfaces",
        "get_tunnel_interfaces",
    ):
        fn = getattr(net_p, getter, None)
        if fn is None:
            continue
        for row in fn() or []:
            if row.get("_disabled"):
                continue
            iname = str(row.get("Interface", "")).replace("\u2514 ", "").strip()
            mprof = str(row.get("Mgmt Profile", "-") or "-")
            for part in _split_csv(str(row.get("IP Address", ""))):
                b = _bare_ip(part)
                if b and b != "-":
                    pa_own_ips[b] = (iname, mprof)
    dash_p = parsers.get("Dashboard")
    if dash_p is not None and hasattr(dash_p, "get_system_info"):
        mgt_ip = _bare_ip(str((dash_p.get_system_info() or {}).get("ip_address", "")))
        if mgt_ip and mgt_ip not in ("-", "Unknown"):
            pa_own_ips[mgt_ip] = ("Management (MGT)", "MGT Services")

    if d_ip in pa_own_ips:
        own_iface, own_prof = pa_own_ips[d_ip]
        steps.append(
            {
                "Step": "2",
                "Stage": "Local-In (To Firewall)",
                "Outcome": f"Firewall Interface ({own_iface})",
                "Details": f"Destination {d_ip} is the firewall's own interface IP. Governed by Interface Mgmt Profile ({own_prof}).",
                "_tone": "info",
            }
        )
        return {
            "valid": True,
            "vendor": "Palo Alto",
            "verdict": "LOCAL-IN",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean}",
            "ingress": f"{src_iface} ({src_zone})",
            "egress": f"{own_iface} (Local-In)",
            "policy": f"Local-In ({own_prof})",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    # Step 2: Egress Route
    eg_res = lookup_paloalto_route(net_p, d_ip, virtual_router)
    eg_w = eg_res.get("winner")
    dst_iface = str(eg_w.get("Interface", "-")) if eg_w else "-"
    dst_zone = zone_map.get(dst_iface, "any") if dst_iface != "-" else "any"
    if dst_iface == "-":
        warnings.append(f"No route matched destination {d_ip} — packet dropped at routing lookup.")
        steps.append(
            {
                "Step": "2",
                "Stage": "Egress Route (LPM)",
                "Outcome": "No Route (Drop)",
                "Details": f"No active connected or static route matched {d_ip}.",
                "_tone": "danger",
            }
        )
        return {
            "valid": True,
            "vendor": "Palo Alto",
            "verdict": "DROP",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean}",
            "ingress": f"{src_iface} ({src_zone})",
            "egress": "No Route",
            "policy": "Not evaluated (no route)",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    nh = eg_w.get("Next Hop") or "-"
    steps.append(
        {
            "Step": "2",
            "Stage": "Egress Route (LPM)",
            "Outcome": f"{dst_iface} (Zone: {dst_zone})",
            "Details": f"Matched {eg_w.get('Destination', '-')} via {dst_iface} (Next Hop: {nh}).",
            "_tone": "info",
        }
    )

    # Step 3: NAT Policy Match
    nat_res = pol_p.test_policy_match(
        "nat",
        src_zone,
        dst_zone,
        src_iface if src_iface != "-" else "any",
        dst_iface,
        s_ip,
        d_ip,
        "any",
        port_clean,
        proto_clean,
    )
    nat_rule_meta = nat_res.get("rule") if nat_res.get("matched") else None
    if nat_rule_meta:
        nat_name = str(nat_rule_meta.get("Rule Name") or nat_rule_meta.get("Name") or "-")
        full_nat = next((r for r in (pol_p.get_nat_rules() or []) if r.get("Name") == nat_name), {})
        src_t = full_nat.get("Src Translation", "Configured")
        dst_t = full_nat.get("Dst Translation", "None")
        nat_summary = f"{nat_name}: Src={src_t} | Dst={dst_t}"
        steps.append(
            {
                "Step": "3",
                "Stage": "NAT Rule Evaluation",
                "Outcome": f"Matched: {nat_name}",
                "Details": f"Src Translation: {src_t} · Dst Translation: {dst_t}",
                "_tone": "info",
            }
        )
    else:
        nat_summary = "No NAT Rule Matched"
        steps.append(
            {
                "Step": "3",
                "Stage": "NAT Rule Evaluation",
                "Outcome": "No NAT",
                "Details": "No NAT rule matched this 5-tuple and zone pair.",
                "_tone": "info",
            }
        )

    # Step 4: Security Policy Match (PAN-OS matches pre-NAT IP + post-NAT zone)
    sec_res = pol_p.test_policy_match(
        "security",
        src_zone,
        dst_zone,
        src_iface if src_iface != "-" else "any",
        dst_iface,
        s_ip,
        d_ip,
        "any",
        port_clean,
        proto_clean,
    )
    sec_rule_meta = sec_res.get("rule") if sec_res.get("matched") else None
    if sec_rule_meta:
        sec_name = str(sec_rule_meta.get("Rule Name") or sec_rule_meta.get("Name") or "-")
        full_sec = next((r for r in (pol_p.get_security_rules() or []) if r.get("Name") == sec_name), {})
        action = str(sec_rule_meta.get("Action") or full_sec.get("Action") or "allow").lower()
        is_allow = action == "allow"
        verdict = "ALLOW" if is_allow else "DENY"
        pol_summary = f"{sec_name} ({action.upper()})"
        steps.append(
            {
                "Step": "4",
                "Stage": "Security Policy",
                "Outcome": pol_summary,
                "Details": f"Zones: {full_sec.get('Source Zone', src_zone)} → {full_sec.get('Dest Zone', dst_zone)} | App: {full_sec.get('Application', '-')}",
                "_tone": "success" if is_allow else "danger",
            }
        )
    else:
        same_connected = (
            ing_w is not None
            and eg_w is not None
            and ing_w.get("Type") == "Connected"
            and eg_w.get("Type") == "Connected"
            and src_iface != "-"
            and src_iface == dst_iface
            and ing_w.get("Destination") == eg_w.get("Destination")
        )
        if same_connected:
            verdict = "L2 DIRECT"
            pol_summary = "N/A — L2 Switched (Same Connected Subnet)"
            steps.append(
                {
                    "Step": "4",
                    "Stage": "Security Policy",
                    "Outcome": "L2 Direct (Bypasses L3 Policy)",
                    "Details": f"Both {s_ip} and {d_ip} belong to directly connected subnet {eg_w.get('Destination')} on {dst_iface}; hosts communicate at L2.",
                    "_tone": "info",
                }
            )
        elif src_zone != "any" and src_zone == dst_zone:
            verdict = "ALLOW"
            pol_summary = "intrazone-default (ALLOW)"
            steps.append(
                {
                    "Step": "4",
                    "Stage": "Security Policy",
                    "Outcome": pol_summary,
                    "Details": f"No explicit rule matched, so traffic within same zone '{src_zone}' hits PAN-OS default intrazone-default (allow).",
                    "_tone": "success",
                }
            )
        else:
            verdict = "DENY"
            pol_summary = "Implicit Deny / interzone-default"
            steps.append(
                {
                    "Step": "4",
                    "Stage": "Security Policy",
                    "Outcome": "No Rule Matched (Deny)",
                    "Details": str(sec_res.get("reason", "No matching security rule.")),
                    "_tone": "danger",
                }
            )

    ret_summary: str | None = None
    if check_return and verdict != "L2 DIRECT":
        ret_summary, ret_step, ret_warn = _build_return_path_step(
            "Palo Alto",
            s_ip,
            d_ip,
            src_iface,
            dst_iface,
            ing_w,
            eg_w,
            src_zone=src_zone,
            dst_zone=dst_zone,
            step_num="5",
        )
        steps.append(ret_step)
        if ret_warn:
            warnings.append(ret_warn)

    res: dict[str, Any] = {
        "valid": True,
        "vendor": "Palo Alto",
        "verdict": verdict,
        "src": s_ip,
        "dst": f"{d_ip}:{port_clean}",
        "ingress": f"{src_iface} ({src_zone})",
        "egress": f"{dst_iface} ({dst_zone})",
        "policy": pol_summary,
        "nat": nat_summary,
        "steps": steps,
        "warnings": warnings,
    }
    if ret_summary is not None:
        res["return_path"] = ret_summary
    return res


def build_packet_trace_blocks(trace: dict[str, Any]) -> dict[str, Any]:
    if not trace.get("valid"):
        return {
            "ok": False,
            "blocks": [{"type": "alert", "variant": "error", "text": trace.get("error", "Invalid trace input.")}],
        }

    verdict = trace["verdict"]
    badge_variant = (
        "allow"
        if verdict == "ALLOW"
        else ("info" if verdict in ("L2 DIRECT", "LOCAL-IN") else "deny")
    )
    kv_items = [
        {"label": "Ingress", "value": trace["ingress"]},
        {"label": "Egress", "value": trace["egress"]},
        {"label": "Policy Decision", "value": trace["policy"]},
        {"label": "NAT", "value": trace["nat"]},
    ]
    if trace.get("return_path"):
        kv_items.append({"label": "Return Path", "value": trace["return_path"]})

    blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": f"Packet Trace Verdict: {verdict}",
            "subtitle": f"{trace['vendor']} · {trace['src']} → {trace['dst']}",
            "badge": {"text": verdict, "variant": badge_variant},
        },
        {
            "type": "kv_grid",
            "items": kv_items,
        },
    ]

    for w in trace.get("warnings") or []:
        blocks.append({"type": "alert", "variant": "warn", "text": w})

    step_rows = [
        {
            "Step": s["Step"],
            "Stage": s["Stage"],
            "Outcome": s["Outcome"],
            "Details": s["Details"],
        }
        for s in trace["steps"]
    ]
    tone_map = {
        "success": "row-success",
        "info": "row-info",
        "warn": "row-warn",
        "danger": "row-danger",
    }
    row_classes = [tone_map.get(s.get("_tone", ""), "") for s in trace["steps"]]

    blocks.append(
        {
            "type": "table",
            "id": "fw_packet_trace_steps",
            "title": "Pipeline Evaluation Steps",
            "columns": ["Step", "Stage", "Outcome", "Details"],
            "rows": step_rows,
            "row_classes": row_classes,
            "legend": [
                {"label": "Allowed / Matched (green)", "variant": "success"},
                {"label": "Pipeline Stage Resolved (blue)", "variant": "info"},
                {"label": "Warning / RPF Risk (amber)", "variant": "warn"},
                {"label": "Denied / Dropped (red)", "variant": "danger"},
            ],
            "export_filename": "packet_trace_steps.csv",
        }
    )

    return {"ok": True, "verdict": verdict, "blocks": blocks}
