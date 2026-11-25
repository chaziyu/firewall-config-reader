"""
backend/vpn_inspector_service.py
Site-to-Site IPSec VPN "All-in-One" Inspector for FortiGate and Palo Alto.
Stitches Phase 1 / Phase 2 (or IKE / IPSec Crypto), Tunnel Interface & Zone,
Static Routes, and Firewall / Security Policies with automated misconfiguration checks.
"""

from __future__ import annotations

import re
from typing import Any


_WEAK_CIPHER_TOKENS = ("des", "3des", "md5", "sha1", "null")
_WEAK_DH_GROUPS = {"1", "2", "5", "group1", "group2", "group5"}


def _split_csv(val: str) -> list[str]:
    return [p.strip() for p in str(val or "").split(",") if p.strip() and p.strip() != "-"]


def _find_weak_crypto(proposal_str: str, dh_str: str) -> list[str]:
    findings: list[str] = []
    tokens = [t.lower() for t in re.split(r"[\s,;|]+", str(proposal_str or "")) if t]
    for tok in tokens:
        parts = [p for p in re.split(r"[-_/]", tok) if p]
        for p in parts:
            if p in _WEAK_CIPHER_TOKENS:
                findings.append(p.upper())
    dh_tokens = [t.lower() for t in re.split(r"[\s,;|]+", str(dh_str or "")) if t and t != "-"]
    for dt in dh_tokens:
        if dt in _WEAK_DH_GROUPS:
            findings.append(f"DH {dt}")
    return list(dict.fromkeys(findings))


def _clean_fg_iface_name(name: str) -> str:
    return str(name or "").replace("\u00a0", "").replace("\u2517 ", "").strip()


def _format_nat_summary(items: list[str], noun_singular: str, noun_plural: str, max_show: int = 2) -> str:
    """Format a concise NAT finding tag with bounded policy/rule enumeration."""
    if len(items) == 1:
        return f"NAT on {noun_singular} {items[0]}"
    if len(items) <= max_show:
        return f"NAT on {len(items)} {noun_plural} ({', '.join(items)})"
    return f"NAT on {len(items)} {noun_plural} ({', '.join(items[:max_show])}, +{len(items) - max_show})"


def format_vpn_findings_summary(ins: dict[str, Any]) -> str:
    """Build a concise, scannable single-line Findings summary for tables and reports."""
    s_errs = ins.get("summary_errors", ins.get("errors", []))
    s_warns = ins.get("summary_warnings", ins.get("warnings", []))
    combined = list(s_errs) + list(s_warns)
    return " | ".join(combined) if combined else "OK"


def inspect_fortigate_vpns(fg: Any) -> list[dict[str, Any]]:
    phase1_list = fg.parse_ipsec_phase1() or []
    if not phase1_list:
        return []
    phase2_list = fg.parse_ipsec_phase2() or []
    interfaces = fg.parse_interfaces() or []
    static_routes = fg.parse_static_routes() or []
    policies = fg.parse_policies() or []

    iface_map: dict[str, dict[str, Any]] = {}
    iface_to_zone: dict[str, str] = {}
    for row in interfaces:
        if str(row.get("Type", "")).lower() == "zone":
            zname = str(row.get("Zone", "")).strip()
            for m in _split_csv(str(row.get("Members", ""))):
                if zname and zname != "-":
                    iface_to_zone[m] = zname
        else:
            cname = _clean_fg_iface_name(str(row.get("Name", "")))
            if cname:
                iface_map[cname] = row
                z = str(row.get("Zone", "-")).strip()
                if z and z != "-":
                    iface_to_zone[cname] = z

    inspections: list[dict[str, Any]] = []
    for p1 in phase1_list:
        tname = str(p1.get("name", "-"))
        rgw = str(p1.get("remote_gw", "-"))
        is_dialup = rgw in ("-", "", "0.0.0.0")
        iface_row = iface_map.get(tname, {})
        zone = iface_to_zone.get(tname, "-")
        tun_ip = str(iface_row.get("IP/Netmask", "-")) if iface_row else "-"
        tun_status = str(iface_row.get("Status", p1.get("status", "Enable")))

        p2_matches = [p2 for p2 in phase2_list if p2.get("phase1name") == tname]
        p2_rows: list[dict[str, Any]] = []
        weak_p2_selectors: list[str] = []
        weak_p2_tokens: list[str] = []
        for p2 in p2_matches:
            weak_p2 = _find_weak_crypto(str(p2.get("proposal", "")), str(p2.get("dhgrp", "")))
            sel_name = str(p2.get("name", "-"))
            if weak_p2:
                weak_p2_selectors.append(sel_name)
                weak_p2_tokens.extend(weak_p2)
            p2_rows.append(
                {
                    "Selector": sel_name,
                    "Local": str(p2.get("src_name") if p2.get("src_addr_type") == "name" else p2.get("src_subnet", "-")),
                    "Remote": str(p2.get("dst_name") if p2.get("dst_addr_type") == "name" else p2.get("dst_subnet", "-")),
                    "Proposal": str(p2.get("proposal", "-")),
                    "DH Group": str(p2.get("dhgrp", "-")),
                    "PFS": str(p2.get("pfs", "-")),
                    "Auto-Neg": str(p2.get("auto_negotiate", "-")),
                    "_weak": bool(weak_p2),
                }
            )

        match_targets = {tname}
        if zone != "-":
            match_targets.add(zone)

        routes_for_tun = [
            {
                "Seq": str(r.get("Seq", "-")),
                "Destination": str(r.get("Destination", "-")),
                "Gateway": str(r.get("Gateway", "-")),
                "Interface": str(r.get("Interface", "-")),
                "Distance": str(r.get("Distance", "-")),
                "Status": str(r.get("Status", "Enable")),
            }
            for r in static_routes
            if str(r.get("Interface", "")).strip() == tname
        ]
        active_routes = [r for r in routes_for_tun if r["Status"].lower() != "disable"]

        policies_for_tun: list[dict[str, Any]] = []
        for pol in policies:
            src_ifs = set(_split_csv(str(pol.get("Src Interface", ""))))
            dst_ifs = set(_split_csv(str(pol.get("Dst Interface", ""))))
            if src_ifs & match_targets or dst_ifs & match_targets:
                policies_for_tun.append(
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
                        "_disabled": str(pol.get("Status", "Enable")).lower() == "disable",
                    }
                )

        enabled_accept_pols = [
            p for p in policies_for_tun if not p["_disabled"] and p["Action"].upper() == "ACCEPT"
        ]
        nat_enabled_pols = [p for p in enabled_accept_pols if p["NAT"].lower() == "enable"]

        errors: list[str] = []
        warnings: list[str] = []
        summary_errors: list[str] = []
        summary_warnings: list[str] = []

        if str(p1.get("status", "Enable")).lower() == "disable":
            errors.append("Phase 1 tunnel is administratively disabled.")
            summary_errors.append("P1 disabled")
        if not p2_rows:
            errors.append("No Phase 2 selectors configured for this tunnel.")
            summary_errors.append("No P2 selectors")
        if not active_routes and not (is_dialup and str(p1.get("add_route", "enable")).lower() == "enable"):
            errors.append(f"No active static route points to tunnel interface '{tname}'.")
            summary_errors.append("No static route")
        if not enabled_accept_pols:
            target_desc = f"'{tname}'" if zone == "-" else f"'{tname}' or zone '{zone}'"
            errors.append(f"No enabled ACCEPT firewall policy references {target_desc}.")
            summary_errors.append("No allow policy")

        if nat_enabled_pols:
            pol_ids = [f"#{p['ID']}" for p in nat_enabled_pols]
            warnings.append(f"NAT is enabled on site-to-site allow policy {', '.join(pol_ids)} (verify if SNAT is intentional).")
            summary_warnings.append(_format_nat_summary(pol_ids, "policy", "policies"))
        if str(p1.get("ike_version", "1")) == "1":
            warnings.append("Uses legacy IKEv1; consider upgrading to IKEv2 if peer supports it.")
            summary_warnings.append("IKEv1")
        weak_p1 = _find_weak_crypto(str(p1.get("proposal", "")), str(p1.get("dhgrp", "")))
        if weak_p1:
            weak_p1_str = ", ".join(weak_p1)
            warnings.append(f"Weak Phase 1 crypto/DH detected: {weak_p1_str}.")
            summary_warnings.append(f"Weak P1 ({weak_p1_str})")
        if weak_p2_selectors:
            sel_count = len(weak_p2_selectors)
            total_p2 = len(p2_matches)
            tokens_str = ", ".join(dict.fromkeys(weak_p2_tokens))
            if sel_count == 1:
                warnings.append(f"Weak Phase 2 crypto/DH in '{weak_p2_selectors[0]}': {tokens_str}.")
                summary_warnings.append(f"Weak P2 (1 selector: {tokens_str})")
            else:
                sample = ", ".join(f"'{s}'" for s in weak_p2_selectors[:3])
                if sel_count > 3:
                    sample += f" (+{sel_count - 3} more)"
                warnings.append(f"Weak Phase 2 crypto/DH in {sel_count}/{total_p2} selectors ({sample}): {tokens_str}.")
                scope = f"{sel_count} selectors" if sel_count == total_p2 else f"{sel_count}/{total_p2} selectors"
                summary_warnings.append(f"Weak P2 ({scope}: {tokens_str})")

        inspections.append(
            {
                "name": tname,
                "peer": "Dial-Up / Any" if is_dialup else rgw,
                "intf_zone": f"{tname}" + (f" ({zone})" if zone != "-" else ""),
                "layer1_items": [
                    {"label": "Remote Gateway", "value": "Dial-Up / Any" if is_dialup else rgw},
                    {"label": "Underlay Interface", "value": str(p1.get("interface", "-"))},
                    {"label": "IKE Version", "value": f"IKEv{p1.get('ike_version', '1')}"},
                    {"label": "Auth Method", "value": str(p1.get("authmethod", "psk")).upper()},
                    {"label": "Phase 1 Proposal", "value": str(p1.get("proposal", "-"))},
                    {"label": "Phase 1 DH Group", "value": str(p1.get("dhgrp", "-"))},
                    {"label": "NAT Traversal", "value": str(p1.get("nattraversal", "-"))},
                    {"label": "DPD", "value": str(p1.get("dpd", "-"))},
                ],
                "phase2_rows": p2_rows,
                "layer2_items": [
                    {"label": "Tunnel Interface", "value": tname},
                    {"label": "Zone", "value": zone},
                    {"label": "Tunnel IP / Netmask", "value": tun_ip},
                    {"label": "Interface Status", "value": tun_status},
                ],
                "routes": routes_for_tun,
                "active_route_count": len(active_routes),
                "policies": policies_for_tun,
                "allow_policy_count": len(enabled_accept_pols),
                "errors": errors,
                "warnings": warnings,
                "summary_errors": summary_errors,
                "summary_warnings": summary_warnings,
            }
        )
    return inspections


def inspect_paloalto_vpns(network_parser: Any, policies_parser: Any = None) -> list[dict[str, Any]]:
    tunnels = network_parser.get_ipsec_tunnels() or []
    if not tunnels:
        return []

    ike_gws = {g.get("Name"): g for g in (network_parser.get_ike_gateways() or [])}
    ike_cryptos = {c.get("Name"): c for c in (network_parser.get_ike_crypto_profiles() or [])}
    ipsec_cryptos = {c.get("Name"): c for c in (network_parser.get_ipsec_crypto_profiles() or [])}
    tun_intfs = {t.get("Interface"): t for t in (network_parser.get_tunnel_interfaces() or [])}

    all_routes: list[dict[str, Any]] = []
    for vr in network_parser.get_virtual_routers() or []:
        vr_el = vr.get("_vr_el")
        if vr_el is None:
            continue
        detail = network_parser.get_vr_detail(vr_el)
        vr_name = detail.get("name", vr.get("Name", "default"))
        for rt in detail.get("static_v4", []) or []:
            all_routes.append({**rt, "Virtual Router": vr_name})

    sec_rules = (policies_parser.get_security_rules() or []) if policies_parser is not None else []
    nat_rules = (policies_parser.get_nat_rules() or []) if policies_parser is not None else []

    inspections: list[dict[str, Any]] = []
    for tun in tunnels:
        tname = str(tun.get("Name", "-"))
        gw_name = str(tun.get("IKE GW", "-"))
        gw = ike_gws.get(gw_name, {})
        ike_prof_name = str(gw.get("Crypto Profile", "-"))
        ike_prof = ike_cryptos.get(ike_prof_name, {})
        ipsec_prof_name = str(tun.get("Crypto", "-"))
        ipsec_prof = ipsec_cryptos.get(ipsec_prof_name, {})

        tun_intf = str(tun.get("Tunnel Intf", "-"))
        tun_info = tun_intfs.get(tun_intf, {})
        zone = str(tun.get("Zone", "-") or "-")
        vr_name = str(tun.get("VR", "-") or "-")
        peer_ip = str(tun.get("IKE Peer IP", gw.get("Peer Address", "-")))
        ike_ver = str(gw.get("Version", "ikev2"))

        routes_for_tun = [
            {
                "Virtual Router": str(r.get("Virtual Router", "-")),
                "Name": str(r.get("Name", "-")),
                "Destination": str(r.get("Destination", "-")),
                "Interface": str(r.get("Interface", "-")),
                "NH Value": str(r.get("NH Value", "-")),
                "Metric": str(r.get("Metric", "-")),
            }
            for r in all_routes
            if tun_intf != "-" and str(r.get("Interface", "")).strip() == tun_intf
        ]

        policies_for_tun: list[dict[str, Any]] = []
        if zone != "-" and sec_rules:
            for sr in sec_rules:
                src_z = set(_split_csv(str(sr.get("Source Zone", ""))))
                dst_z = set(_split_csv(str(sr.get("Dest Zone", ""))))
                if zone in src_z or zone in dst_z:
                    policies_for_tun.append(
                        {
                            "Name": str(sr.get("Name", "-")),
                            "Source Zone": str(sr.get("Source Zone", "-")),
                            "Source Addr": str(sr.get("Source Addr", "-")),
                            "Dest Zone": str(sr.get("Dest Zone", "-")),
                            "Dest Addr": str(sr.get("Dest Addr", "-")),
                            "Application": str(sr.get("Application", "-")),
                            "Service": str(sr.get("Service", "-")),
                            "Action": str(sr.get("Action", "-")),
                            "Status": "Disabled" if sr.get("_disabled") else "Enabled",
                            "_disabled": bool(sr.get("_disabled")),
                        }
                    )

        enabled_allow_pols = [
            p for p in policies_for_tun if not p["_disabled"] and p["Action"].lower() == "allow"
        ]

        nat_hits = []
        if zone != "-" and nat_rules:
            for nr in nat_rules:
                if nr.get("_disabled"):
                    continue
                src_z = set(_split_csv(str(nr.get("Source Zone", ""))))
                dst_z = set(_split_csv(str(nr.get("Dest Zone", ""))))
                if zone in src_z or zone in dst_z:
                    if str(nr.get("Src Translation", "None")) != "None" or str(nr.get("Dst Translation", "None")) != "None":
                        nat_hits.append(str(nr.get("Name", "-")))

        errors: list[str] = []
        warnings: list[str] = []
        summary_errors: list[str] = []
        summary_warnings: list[str] = []

        if tun_intf == "-":
            errors.append("No tunnel interface assigned to IPSec tunnel.")
            summary_errors.append("No tunnel intf")
        if zone == "-":
            errors.append(f"Tunnel interface '{tun_intf}' is not assigned to a Security Zone.")
            summary_errors.append("No zone")
        if vr_name == "-":
            warnings.append(f"Tunnel interface '{tun_intf}' is not assigned to a Virtual Router.")
            summary_warnings.append("No VR")
        if not routes_for_tun:
            errors.append(f"No static route points to tunnel interface '{tun_intf}'.")
            summary_errors.append("No static route")
        if policies_parser is not None and zone != "-" and not enabled_allow_pols:
            errors.append(f"No enabled 'allow' security policy references zone '{zone}'.")
            summary_errors.append("No allow policy")

        if "ikev1" in ike_ver.lower():
            warnings.append("IKE Gateway uses legacy IKEv1; consider IKEv2 if peer supports it.")
            summary_warnings.append("IKEv1")
        if nat_hits:
            warnings.append(f"NAT rule(s) {', '.join(nat_hits)} translate traffic in tunnel zone '{zone}' (verify if intentional).")
            summary_warnings.append(_format_nat_summary(nat_hits, "rule", "rules"))

        weak_ike = _find_weak_crypto(
            f"{ike_prof.get('Encryption', '')} {ike_prof.get('Authentication', '')}",
            str(ike_prof.get("DH Group", "")),
        )
        if weak_ike:
            weak_ike_str = ", ".join(weak_ike)
            warnings.append(f"Weak IKE Crypto ({ike_prof_name}): {weak_ike_str}.")
            summary_warnings.append(f"Weak IKE ({weak_ike_str})")

        weak_ipsec = _find_weak_crypto(
            f"{ipsec_prof.get('Encryption', '')} {ipsec_prof.get('Authentication', '')}",
            str(ipsec_prof.get("DH Group", "")),
        )
        if weak_ipsec:
            weak_ipsec_str = ", ".join(weak_ipsec)
            warnings.append(f"Weak IPSec Crypto ({ipsec_prof_name}): {weak_ipsec_str}.")
            summary_warnings.append(f"Weak IPSec ({weak_ipsec_str})")

        inspections.append(
            {
                "name": tname,
                "peer": peer_ip,
                "intf_zone": f"{tun_intf}" + (f" ({zone})" if zone != "-" else ""),
                "layer1_items": [
                    {"label": "IKE Gateway", "value": gw_name},
                    {"label": "Peer Address", "value": peer_ip},
                    {"label": "Local Intf / IP", "value": f"{tun.get('IKE Interface', '-')} ({tun.get('IKE Local IP', '-')})"},
                    {"label": "IKE Version", "value": ike_ver},
                    {"label": "Auth Method", "value": str(gw.get("Auth Method", "-"))},
                    {"label": "NAT Traversal", "value": str(gw.get("NAT Traversal", "-"))},
                    {"label": "IKE Crypto Profile", "value": ike_prof_name},
                    {"label": "IPSec Crypto Profile", "value": ipsec_prof_name},
                ],
                "phase2_rows": [
                    {
                        "Profile": ipsec_prof_name,
                        "Type": str(ipsec_prof.get("Type", "-")),
                        "Encryption": str(ipsec_prof.get("Encryption", "-")),
                        "Authentication": str(ipsec_prof.get("Authentication", "-")),
                        "DH Group": str(ipsec_prof.get("DH Group", "-")),
                        "Lifetime": str(ipsec_prof.get("Lifetime", "-")),
                        "_weak": bool(weak_ipsec),
                    }
                ]
                if ipsec_prof
                else [],
                "layer2_items": [
                    {"label": "Tunnel Interface", "value": tun_intf},
                    {"label": "Security Zone", "value": zone},
                    {"label": "Virtual Router", "value": vr_name},
                    {"label": "Tunnel IP", "value": str(tun_info.get("IP Address", "-"))},
                ],
                "routes": routes_for_tun,
                "active_route_count": len(routes_for_tun),
                "policies": policies_for_tun,
                "allow_policy_count": len(enabled_allow_pols),
                "errors": errors,
                "warnings": warnings,
                "summary_errors": summary_errors,
                "summary_warnings": summary_warnings,
            }
        )
    return inspections


def build_vpn_inspector_blocks(inspections: list[dict[str, Any]], vendor: str) -> list[dict[str, Any]]:
    if not inspections:
        return [{"type": "alert", "variant": "info", "text": "No IPSec tunnels configured to inspect."}]

    overview_rows: list[dict[str, str]] = []
    overview_classes: list[str] = []
    for ins in inspections:
        errs = ins["errors"]
        warns = ins["warnings"]
        if errs:
            status_str = f"Error ({len(errs)})"
            row_cls = "row-danger"
        elif warns:
            status_str = f"Warning ({len(warns)})"
            row_cls = "row-warn"
        else:
            status_str = "Healthy"
            row_cls = "row-success"
        overview_classes.append(row_cls)
        findings_text = format_vpn_findings_summary(ins)
        overview_rows.append(
            {
                "Tunnel": ins["name"],
                "Remote Peer": ins["peer"],
                "Tunnel Intf / Zone": ins["intf_zone"],
                "Routes": str(ins["active_route_count"]),
                "Allow Policies": str(ins["allow_policy_count"]),
                "Status": status_str,
                "Findings": findings_text,
            }
        )

    overview_cols = list(overview_rows[0].keys())
    overview_table = {
        "type": "table",
        "id": f"{vendor}_vpn_inspector_overview",
        "title": f"Site-to-Site VPN Health Summary ({len(inspections)} tunnel(s))",
        "columns": overview_cols,
        "rows": overview_rows,
        "row_classes": overview_classes,
        "legend": [
            {"label": "Healthy — All 4 Layers Wired (green)", "variant": "success"},
            {"label": "Warning — Review Crypto / NAT / IKEv1 (amber)", "variant": "warn"},
            {"label": "Error — Missing Route, Policy, or Disabled (red)", "variant": "danger"},
        ],
        "export_filename": f"{vendor}_vpn_health_summary.csv",
    }

    options: list[dict[str, Any]] = []
    for idx, ins in enumerate(inspections):
        errs = ins["errors"]
        warns = ins["warnings"]
        if errs:
            badge = {"text": f"{len(errs)} Error(s)", "variant": "deny"}
        elif warns:
            badge = {"text": f"{len(warns)} Warning(s)", "variant": "warn"}
        else:
            badge = {"text": "Healthy", "variant": "allow"}

        detail_blocks: list[dict[str, Any]] = [
            {
                "type": "card",
                "title": f"Tunnel: {ins['name']}",
                "subtitle": f"Peer: {ins['peer']} · Intf/Zone: {ins['intf_zone']}",
                "badge": badge,
            }
        ]
        for e in errs:
            detail_blocks.append({"type": "alert", "variant": "error", "text": e})
        for w in warns:
            detail_blocks.append({"type": "alert", "variant": "warn", "text": w})
        if not errs and not warns:
            detail_blocks.append(
                {
                    "type": "alert",
                    "variant": "success",
                    "text": "Tunnel, interface/zone binding, static route, and allow policy are all configured.",
                }
            )

        detail_blocks.append({"type": "section_header", "title": "1. Phase 1 / IKE & Crypto Parameters"})
        detail_blocks.append({"type": "kv_grid", "items": ins["layer1_items"]})
        if ins["phase2_rows"]:
            p2_cols = [k for k in ins["phase2_rows"][0].keys() if not str(k).startswith("_")]
            has_weak_p2 = any(r.get("_weak") for r in ins["phase2_rows"])
            p2_block: dict[str, Any] = {
                "type": "table",
                "id": f"{vendor}_vpn_insp_p2_{idx}",
                "title": "Phase 2 / IPSec Crypto Details",
                "columns": p2_cols,
                "rows": [{c: str(r.get(c, "")) for c in p2_cols} for r in ins["phase2_rows"]],
                "export_filename": f"{vendor}_vpn_{idx}_phase2.csv",
            }
            if has_weak_p2:
                p2_block["row_classes"] = ["row-warn" if r.get("_weak") else "" for r in ins["phase2_rows"]]
                p2_block["legend"] = [{"label": "Weak Phase 2 Crypto / DH Group (amber)", "variant": "warn"}]
            detail_blocks.append(p2_block)

        detail_blocks.append({"type": "section_header", "title": "2. Tunnel Interface & Zone Binding"})
        detail_blocks.append({"type": "kv_grid", "items": ins["layer2_items"]})

        detail_blocks.append({"type": "section_header", "title": f"3. Static Routes Pointing to Tunnel ({len(ins['routes'])})"})
        if ins["routes"]:
            r_cols = list(ins["routes"][0].keys())
            detail_blocks.append(
                {
                    "type": "table",
                    "id": f"{vendor}_vpn_insp_rt_{idx}",
                    "columns": r_cols,
                    "rows": [{c: str(r.get(c, "")) for c in r_cols} for r in ins["routes"]],
                    "export_filename": f"{vendor}_vpn_{idx}_routes.csv",
                }
            )
        else:
            detail_blocks.append(
                {
                    "type": "alert",
                    "variant": "warn",
                    "text": "No static routes point to this tunnel interface (check dynamic routing/BGP or dial-up add-route if applicable).",
                }
            )

        detail_blocks.append({"type": "section_header", "title": f"4. Firewall / Security Policies ({len(ins['policies'])})"})
        if ins["policies"]:
            pol_cols = [k for k in ins["policies"][0].keys() if not str(k).startswith("_")]
            pol_classes: list[str] = []
            for p in ins["policies"]:
                if p.get("_disabled"):
                    pol_classes.append("row-danger")
                elif str(p.get("Action", "")).lower() in ("accept", "allow"):
                    pol_classes.append("row-success")
                else:
                    pol_classes.append("row-danger")
            detail_blocks.append(
                {
                    "type": "table",
                    "id": f"{vendor}_vpn_insp_pol_{idx}",
                    "columns": pol_cols,
                    "rows": [{c: str(p.get(c, "")) for c in pol_cols} for p in ins["policies"]],
                    "row_classes": pol_classes,
                    "legend": [
                        {"label": "Allow / Accept Policy (green)", "variant": "success"},
                        {"label": "Deny / Drop / Disabled Policy (red)", "variant": "danger"},
                    ],
                    "export_filename": f"{vendor}_vpn_{idx}_policies.csv",
                }
            )
        else:
            detail_blocks.append(
                {
                    "type": "alert",
                    "variant": "error",
                    "text": "No firewall/security policies reference this tunnel interface or zone.",
                }
            )

        options.append({"name": ins["name"], "blocks": detail_blocks})

    return [
        overview_table,
        {
            "type": "profile_selector",
            "id": f"{vendor}_vpn_inspector_sel",
            "label": "Inspect Tunnel End-to-End",
            "options": options,
        },
    ]
