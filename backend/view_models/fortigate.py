"""
backend/view_models/fortigate.py
Builds structured UI block payloads for all 10 FortiGate FortiOS sections:
  - Summary
  - Interfaces
  - Network
  - Policy & Objects (incl. Policy Lookup)
  - Security
  - VPN
  - User & Auth
  - WiFi & Switch
  - System
  - Log & Report
"""

from __future__ import annotations

from typing import Any, Callable

from backend.audit_service import build_audit_overview_blocks, run_fortigate_audit
from backend.cert_inspector_service import (
    build_cert_inspector_blocks,
    build_cert_overview_blocks,
    inspect_fortigate_certificates,
)
from backend.exposure_check import (
    build_exposure_overview_blocks,
    find_fortigate_public_mgmt_exposure,
)
from backend.hygiene_service import analyze_fortigate_hygiene, build_hygiene_blocks
from backend.lifecycle_service import (
    build_fortigate_lifecycle_blocks,
    evaluate_fortigate_lifecycle,
)
from backend.posture_service import evaluate_fortigate_posture
from backend.ssl_to_ipsec_service import (
    analyze_fortigate_ssl_to_ipsec,
    build_ssl_to_ipsec_blocks,
)
from backend.view_models.common import (
    ADMIN_LEGEND,
    POLICY_LEGEND,
    policy_caption,
    table_block as _table_block,
    toggle_row as _toggle_row,
)
from backend.vpn_inspector_service import build_vpn_inspector_blocks, inspect_fortigate_vpns

_INTERNAL_ADDR_KEYS = {
    "network_obj",
    "network",
    "broadcast",
    "prefixlen",
    "start_int",
    "end_int",
}


# ── 1. Summary & Security/Health ─────────────────────────────────────────────
def _safe_fg_call(fn, default="Unknown"):
    try:
        return fn()
    except Exception:
        return default


def _eval_fortigate_health(parser: Any, *, allow_probe: bool = False) -> dict[str, Any]:
    hostname = parser.get_hostname()
    serial = _safe_fg_call(parser.get_serial_number)
    model = _safe_fg_call(parser.get_model)
    firmware = _safe_fg_call(parser.get_firmware_version)

    lifecycle = evaluate_fortigate_lifecycle(model, firmware, cache_only=True)
    lifecycle_badge, lifecycle_card = build_fortigate_lifecycle_blocks(lifecycle)
    exposure_findings = find_fortigate_public_mgmt_exposure(parser)
    exposure_badge, exposure_card = build_exposure_overview_blocks(
        exposure_findings,
        allow_probe=allow_probe,
        probe_endpoint="/api/fg/exposure-probe",
    )
    audit_result = run_fortigate_audit(parser)
    audit_badge, audit_expander = build_audit_overview_blocks(audit_result)
    cert_list = inspect_fortigate_certificates(parser)
    cert_badge, cert_card = build_cert_overview_blocks(cert_list)

    subtitle_parts = [f"Firmware {firmware}", f"S/N {serial}"]
    if model and model != "Unknown":
        subtitle_parts.insert(0, str(lifecycle.get("model_display") or model))

    return {
        "hostname": hostname,
        "serial": serial,
        "model": model,
        "firmware": firmware,
        "subtitle": " · ".join(subtitle_parts),
        "lifecycle": lifecycle,
        "lifecycle_badge": lifecycle_badge,
        "lifecycle_card": lifecycle_card,
        "exposure_badge": exposure_badge,
        "exposure_card": exposure_card,
        "audit_badge": audit_badge,
        "audit_expander": audit_expander,
        "cert_badge": cert_badge,
        "cert_card": cert_card,
    }


def build_overview(parser: Any, *, allow_probe: bool = False) -> dict[str, Any]:
    health = _eval_fortigate_health(parser, allow_probe=allow_probe)
    hostname = health["hostname"]
    serial = health["serial"]
    model = health["model"]
    firmware = health["firmware"]
    lifecycle = health["lifecycle"]

    try:
        dns = parser.get_dns()
        dns_primary = dns.get("primary", "Unknown")
        dns_secondary = dns.get("secondary", "Unknown")
    except Exception:
        dns_primary, dns_secondary = "Unknown", "Unknown"

    wan_ip = _safe_fg_call(parser.get_wan_ip)
    mgmt_info = _safe_fg_call(parser.get_management_ip, {"ip": "Not configured", "sub": ""})
    if not isinstance(mgmt_info, dict):
        mgmt_info = {"ip": str(mgmt_info), "sub": ""}
    sys_settings = _safe_fg_call(parser.parse_system_settings, {}) or {}
    http_port = str(sys_settings.get("http_port") or "80")
    https_port = str(sys_settings.get("https_port") or "443")
    ssh_port = str(sys_settings.get("ssh_port") or "22")
    ha = _safe_fg_call(parser.get_ha_config, {"enabled": False})

    ha_badge = (
        {"text": f"HA Enabled · {ha.get('mode', 'Cluster')}", "variant": "allow"}
        if ha.get("enabled")
        else {"text": "Standalone", "variant": "muted"}
    )
    posture = evaluate_fortigate_posture(parser)

    mgmt_item: dict[str, Any] = {"label": "Management IP", "value": mgmt_info.get("ip", "Not configured")}
    if mgmt_info.get("sub"):
        mgmt_item["sub"] = mgmt_info["sub"]

    hero_badges = [
        ha_badge,
        health["lifecycle_badge"],
        health["exposure_badge"],
        health["audit_badge"],
    ]
    if health["cert_badge"] is not None:
        hero_badges.append(health["cert_badge"])

    blocks: list[dict[str, Any]] = [
        {
            "type": "hero",
            "eyebrow": "FortiGate Appliance",
            "title": str(hostname),
            "subtitle": health["subtitle"],
            "badges": hero_badges,
        },
        {"type": "section_header", "title": "System Overview"},
        {
            "type": "kv_grid",
            "items": [
                {"label": "Hostname", "value": hostname},
                {"label": "Model", "value": lifecycle.get("model_display", model) if model != "Unknown" else "Unknown"},
                mgmt_item,
                {"label": "WAN IP / Netmask", "value": wan_ip},
                {"label": "Admin Ports", "value": f"HTTPS {https_port} · SSH {ssh_port}", "sub": f"HTTP {http_port}"},
                {"label": "Primary DNS", "value": dns_primary, "sub": f"Secondary: {dns_secondary}"},
                {"label": "Serial Number", "value": serial},
                {"label": "Firmware Version", "value": firmware},
                {"label": "Internet Connectivity", "value": posture["internet"], "sub": posture["internet_sub"]},
                {"label": "Local Hard Disk", "value": posture["disk"], "sub": posture["disk_sub"]},
            ],
        },
        {"type": "section_header", "title": "High Availability"},
    ]

    if not ha.get("enabled"):
        blocks.append(
            {
                "type": "card",
                "title": "Standalone Mode",
                "subtitle": "High Availability is not enabled in this FortiOS configuration.",
                "badge": {"text": "Not Enabled", "variant": "muted"},
            }
        )
    else:
        blocks.append(
            {
                "type": "card",
                "title": f"{ha.get('mode', 'HA')} Cluster",
                "subtitle": f"Group: {ha.get('group_name', '—')}",
                "badge": {"text": "HA Enabled", "variant": "allow"},
            }
        )
        blocks.append(
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Mode", "value": ha.get("mode", "—")},
                    {"label": "Group Name", "value": ha.get("group_name", "—")},
                    {"label": "Priority", "value": ha.get("priority", "—")},
                    {"label": "Session Pickup", "value": ha.get("session_pickup", "disable")},
                    {"label": "Heartbeat Interfaces", "value": ", ".join(ha.get("heartbeat_interfaces", [])) or "—"},
                ],
            }
        )

    blocks.extend(
        [
            {"type": "where_used_lookup", "vendor": "fg"},
            {"type": "packet_trace", "vendor": "fg"},
            {"type": "config_diff", "vendor": "fg"},
        ]
    )
    return {"section": "Overview", "blocks": blocks}


def build_summary(parser: Any, *, allow_probe: bool = False) -> dict[str, Any]:
    return build_overview(parser, allow_probe=allow_probe)


def build_security_health(parser: Any, *, allow_probe: bool = False) -> dict[str, Any]:
    """Build the Security & Health overview page for FortiGate."""
    health = _eval_fortigate_health(parser, allow_probe=allow_probe)
    hero_badges = [
        health["lifecycle_badge"],
        health["exposure_badge"],
        health["audit_badge"],
    ]
    if health["cert_badge"] is not None:
        hero_badges.append(health["cert_badge"])

    blocks: list[dict[str, Any]] = [
        {
            "type": "hero",
            "eyebrow": "Security & Health",
            "title": str(health["hostname"]),
            "subtitle": health["subtitle"],
            "badges": hero_badges,
        },
        health["lifecycle_card"],
    ]
    if health["exposure_card"] is not None:
        blocks.append(health["exposure_card"])
    if health["cert_card"] is not None:
        blocks.append(health["cert_card"])
    blocks.append(health["audit_expander"])
    return {"section": "Security & Health", "blocks": blocks}


# ── 2. Interfaces ────────────────────────────────────────────────────────────
def build_interfaces(parser: Any) -> dict[str, Any]:
    rows = parser.parse_interfaces()
    if not rows:
        return {
            "section": "Interfaces",
            "blocks": [{"type": "alert", "variant": "warn", "text": "No interface data found."}],
        }

    def _iface_cls(r: dict[str, Any]) -> str:
        status = str(r.get("Status", "Enable")).lower()
        itype = str(r.get("Type", "")).lower()
        if itype == "zone":
            return "row-zone"
        if status == "disable":
            return "row-danger"
        if itype in ("hardware switch", "hardwareswitch", "hard-switch", "software switch", "aggregate", "redundant"):
            return "row-info"
        if r.get("_is_sub") or "vlan" in itype:
            return "row-sub"
        return ""

    total = len([r for r in rows if str(r.get("Type", "")).lower() != "zone"])
    enabled = len(
        [
            r
            for r in rows
            if str(r.get("Status", "")).lower() == "enable"
            and str(r.get("Type", "")).lower() != "zone"
        ]
    )
    zones = len([r for r in rows if str(r.get("Type", "")).lower() == "zone"])

    optional_cols = ("Secondary IPs", "IPv6", "VRF", "MTU", "Description")
    empty_optional = {
        col
        for col in optional_cols
        if all(str(r.get(col, "-")) in ("-", "") for r in rows)
    }

    blocks = [
        {
            "type": "legend",
            "items": [
                {"label": "Zone (muted)", "variant": "muted"},
                {"label": "Hardware / Aggregate Switch (blue)", "variant": "info"},
                {"label": "Sub-interface / VLAN (purple)", "variant": "purple"},
                {"label": "Disabled (red)", "variant": "danger"},
            ],
        },
        _table_block(
            rows,
            "fg_interfaces",
            caption=f"{enabled} enabled · {total - enabled} disabled · {zones} zones",
            export_filename="fortigate_interfaces.csv",
            row_class_fn=_iface_cls,
            drop_keys=empty_optional,
        ),
    ]
    return {"section": "Interfaces", "blocks": blocks}


# ── 3. Network ───────────────────────────────────────────────────────────────
def build_network(parser: Any) -> dict[str, Any]:
    # SD-WAN
    sdwan = parser.parse_sdwan()
    if not sdwan:
        sdwan_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No SD-WAN configuration found."}]
    else:
        status = str(sdwan.get("status", "-"))
        zones = sdwan.get("zones", [])
        members_raw = sdwan.get("members", [])
        zone_rows = []
        for z in zones:
            zname = z["Zone Name"]
            zmembers = [m for m in members_raw if m["Zone"] == zname]
            if zmembers:
                for m in zmembers:
                    zone_rows.append(
                        {
                            "Zone": zname,
                            "Seq": m["Seq"],
                            "Interface": m["Interface"],
                            "Gateway": m["Gateway"],
                            "Cost": m["Cost"],
                            "Priority": m["Priority"],
                            "Status": m["Status"],
                        }
                    )
            else:
                zone_rows.append(
                    {
                        "Zone": zname,
                        "Seq": "-",
                        "Interface": "(no members)",
                        "Gateway": "-",
                        "Cost": "-",
                        "Priority": "-",
                        "Status": "-",
                    }
                )
        sdwan_blocks = [
            {
                "type": "card",
                "title": "SD-WAN Status",
                "badge": {"text": status, "variant": "allow" if status.lower() == "enable" else "deny"},
            },
            {"type": "section_header", "title": "SD-WAN Zones / Members"},
            _table_block(zone_rows, "fg_sdwan_zones", empty_text="No SD-WAN zones."),
            {"type": "section_header", "title": "SD-WAN Rules"},
            _table_block(
                sdwan.get("services", []),
                "fg_sdwan_rules",
                empty_text="No SD-WAN rules.",
                row_class_fn=lambda r: "row-danger" if str(r.get("Status", "")).lower() == "disable" else "",
                legend=[
                    {"label": "Enabled (default)", "variant": "default"},
                    {"label": "Disabled Rule (red)", "variant": "danger"},
                ],
            ),
            {"type": "section_header", "title": "Performance SLA"},
            _table_block(sdwan.get("health_checks", []), "fg_sdwan_sla", empty_text="No health checks configured."),
        ]

    # Static & Policy routes
    static_rows = parser.parse_static_routes()
    st_en = len([r for r in static_rows if str(r.get("Status", "")).lower() != "disable"])
    pr_rows = parser.parse_policy_routes()
    pr_en = len([r for r in pr_rows if str(r.get("Status", "")).lower() != "disable"])
    _dis_cls = lambda r: "row-danger" if str(r.get("Status", "")).lower() == "disable" else ""
    _route_legend = [
        {"label": "Active Route (default)", "variant": "default"},
        {"label": "Disabled Route (red)", "variant": "danger"},
    ]

    # RIP
    rip = parser.parse_rip()
    if not rip:
        rip_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No RIP configuration found."}]
    else:
        rip_nets = [{"Network": n} for n in rip.get("networks", [])]
        rip_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Version", "value": rip.get("version", "-")},
                    {"label": "Default Metric", "value": rip.get("default_metric", "-")},
                    {"label": "Originate Default", "value": rip.get("default_info", "-")},
                ],
            },
            _table_block(rip_nets, "fg_rip_nets", title="Networks", empty_text="No networks configured."),
            _table_block(rip.get("interfaces", []), "fg_rip_ifaces", title="Interfaces", empty_text="No RIP interfaces."),
        ]

    # OSPF
    ospf = parser.parse_ospf()
    if not ospf:
        ospf_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No OSPF configuration found."}]
    else:
        ospf_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Router ID", "value": ospf.get("router_id", "-")},
                    {"label": "ABR Type", "value": ospf.get("abr_type", "-")},
                    {"label": "Auto Cost Ref", "value": ospf.get("auto_cost", "-")},
                    {"label": "Default Originate", "value": ospf.get("default_info", "-")},
                ],
            },
            _table_block(ospf.get("areas", []), "fg_ospf_areas", title="Areas", empty_text="No OSPF areas."),
            _table_block(ospf.get("interfaces", []), "fg_ospf_ifaces", title="OSPF Interfaces", empty_text="No OSPF interfaces."),
            _table_block(ospf.get("networks", []), "fg_ospf_nets", title="Networks", empty_text="No OSPF networks."),
        ]

    # BGP
    bgp = parser.parse_bgp()
    if not bgp:
        bgp_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No BGP configuration found."}]
    else:
        bgp_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Local AS", "value": bgp.get("local_as", "-")},
                    {"label": "Router ID", "value": bgp.get("router_id", "-")},
                    {"label": "Keepalive", "value": f"{bgp.get('keepalive', '-')}s"},
                    {"label": "Hold Time", "value": f"{bgp.get('holdtime', '-')}s"},
                ],
            },
            _table_block(bgp.get("neighbors", []), "fg_bgp_nbrs", title="Neighbors", empty_text="No BGP neighbors."),
            _table_block(bgp.get("networks", []), "fg_bgp_nets", title="Advertised Networks", empty_text="No BGP networks."),
        ]

    # Routing objects
    robj = parser.parse_routing_objects()
    robj_blocks = [
        _table_block(robj.get("prefix_lists", []), "fg_prefix_lists", title="Prefix Lists", empty_text="No prefix lists."),
        _table_block(robj.get("route_maps", []), "fg_route_maps", title="Route Maps", empty_text="No route maps."),
        _table_block(robj.get("aspath_lists", []), "fg_aspath", title="AS Path Lists", empty_text="No AS path lists."),
    ]

    # Multicast
    mcast = parser.parse_multicast()
    if not mcast:
        mcast_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No Multicast configuration found."}]
    else:
        ok = str(mcast.get("enabled", "")).lower() == "enable"
        mcast_blocks = [
            {
                "type": "card",
                "title": "Multicast Routing",
                "badge": {"text": str(mcast.get("enabled", "-")), "variant": "allow" if ok else "deny"},
            },
            _table_block(mcast.get("interfaces", []), "fg_mcast_ifaces", title="PIM Interfaces", empty_text="No multicast interfaces."),
        ]
        pim_sm = mcast.get("pim_sm", {})
        if pim_sm:
            mcast_blocks.append(
                _table_block(
                    pim_sm.get("rp_list", []),
                    "fg_pim_rp",
                    title="PIM-SM Rendezvous Points",
                    empty_text="No RP configured.",
                )
            )

    ipam_rows = parser.parse_ipam()
    fext_rows = parser.parse_fortiextender()
    robj_count = (
        len(robj.get("prefix_lists", []))
        + len(robj.get("route_maps", []))
        + len(robj.get("aspath_lists", []))
    )

    tabs = [
        {"label": "SD-WAN", "count": len(sdwan.get("services", [])) if sdwan else 0, "blocks": sdwan_blocks},
        {
            "label": "Static Routes",
            "count": len(static_rows),
            "blocks": [
                {"type": "route_lookup", "vendor": "fg"},
                _table_block(static_rows, "fg_static_routes", empty_text="No static routes configured.", row_class_fn=_dis_cls, legend=_route_legend, caption=f"{st_en} active · {len(static_rows) - st_en} disabled"),
            ],
        },
        {"label": "Policy Routes", "count": len(pr_rows), "blocks": [_table_block(pr_rows, "fg_policy_routes", empty_text="No policy routes configured.", row_class_fn=_dis_cls, legend=_route_legend, caption=f"{pr_en} active · {len(pr_rows) - pr_en} disabled")]},
        {"label": "RIP", "count": len(rip.get("networks", [])) if rip else 0, "blocks": rip_blocks},
        {"label": "OSPF", "count": len(ospf.get("areas", [])) if ospf else 0, "blocks": ospf_blocks},
        {"label": "BGP", "count": len(bgp.get("neighbors", [])) if bgp else 0, "blocks": bgp_blocks},
        {"label": "Routing Objects", "count": robj_count, "blocks": robj_blocks},
        {"label": "Multicast", "count": len(mcast.get("interfaces", [])) if mcast else 0, "blocks": mcast_blocks},
        {"label": "IPAM", "count": len(ipam_rows), "blocks": [_table_block(ipam_rows, "fg_ipam", empty_text="No IPAM configuration found.")]},
        {"label": "FortiExtender", "count": len(fext_rows), "blocks": [_table_block(fext_rows, "fg_fortiext", empty_text="No FortiExtender configuration found.")]},
    ]
    return {"section": "Network", "blocks": [{"type": "tabs", "id": "fg_network_tabs", "tabs": tabs}]}


def build_interfaces_network(parser: Any) -> dict[str, Any]:
    iface_res = build_interfaces(parser)
    iface_rows = parser.parse_interfaces() or []
    net_res = build_network(parser)
    net_tabs = net_res["blocks"][0]["tabs"] if net_res.get("blocks") else []
    tabs = [
        {"label": "Interfaces", "count": len(iface_rows), "blocks": iface_res.get("blocks", [])},
        *net_tabs,
    ]
    return {"section": "Interfaces & Network", "blocks": [{"type": "tabs", "id": "fg_iface_net_tabs", "tabs": tabs}]}


# ── 4. Policy & Objects ──────────────────────────────────────────────────────
def _split_tokens(val: Any) -> list[str]:
    s = str(val or "").strip()
    if not s or s == "-":
        return []
    return [tok.strip() for tok in s.split(",") if tok.strip()]


def _format_policy_nat_label(p: dict[str, Any], central_nat: bool) -> str:
    if central_nat:
        return "Central NAT"
    tags: list[str] = []
    if p.get("_nat64"):
        tags.append("NAT64")
    if p.get("_nat46"):
        tags.append("NAT46")
    if p.get("_natinbound") or p.get("_natoutbound") or p.get("_natip"):
        tags.append("IPsec NAT")
    if tags:
        prefix = "Enable" if str(p.get("NAT", "")).lower() == "enable" else "Special"
        return f"{prefix} ({', '.join(tags)})"
    if str(p.get("NAT", "")).lower() == "enable":
        pools = p.get("_poolname") or []
        if p.get("_ippool") or pools:
            pool_txt = ", ".join(pools) if pools else "IP Pool"
            base = f"Enable (Pool: {pool_txt})"
        else:
            base = "Enable (Interface IP)"
        if p.get("_fixedport"):
            base += " · Fixed Port"
        return base
    return str(p.get("NAT", "-"))


def _resolve_egress_ips(
    dst_iface_str: str,
    iface_ip_map: dict[str, str],
    sdwan_zone_members: dict[str, list[str]],
) -> str:
    tokens = _split_tokens(dst_iface_str)
    if not tokens:
        return "-"
    resolved: list[str] = []
    for tok in tokens:
        members = sdwan_zone_members.get(tok)
        if members:
            member_ips = [f"{m}: {iface_ip_map[m]}" for m in members if m in iface_ip_map]
            if member_ips:
                resolved.append(f"{tok} [{', '.join(member_ips)}]")
            else:
                resolved.append(f"{tok} (SD-WAN)")
        elif tok in iface_ip_map:
            resolved.append(f"{tok}: {iface_ip_map[tok]}")
        elif tok.lower() == "any":
            resolved.append("Any Egress IP")
        else:
            resolved.append(f"{tok} (Dynamic / Unconfigured)")
    return ", ".join(resolved)


def _build_fg_nat_blocks(parser: Any, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    central_nat = bool(parser.is_central_nat_enabled()) if hasattr(parser, "is_central_nat_enabled") else False
    central_snat = parser.parse_central_snat() if hasattr(parser, "parse_central_snat") else []
    vips = parser.parse_vip() or []
    vip_groups = parser.parse_vip_groups() if hasattr(parser, "parse_vip_groups") else []
    ip_pools = parser.parse_ip_pools() or []

    # Interface, Zone & SD-WAN lookups for resolving egress interface SNAT IPs
    iface_ip_map: dict[str, str] = {}
    sdwan_zone_members: dict[str, list[str]] = {}
    for row in parser.parse_interfaces() or []:
        if str(row.get("Type", "")).lower() == "zone":
            zname = str(row.get("Zone", "")).strip()
            zmembers = _split_tokens(row.get("Members", ""))
            if zname and zmembers:
                sdwan_zone_members[zname] = zmembers
            continue
        raw_name = str(row.get("Name", "")).replace("\u00a0", "").replace("┗", "").strip()
        ip_val = str(row.get("IP/Netmask", "")).strip()
        if raw_name and ip_val and ip_val not in ("-", "0.0.0.0 0.0.0.0", "0.0.0.0/0", "dhcp", "pppoe"):
            iface_ip_map[raw_name] = ip_val

    sdwan = parser.parse_sdwan() or {}
    for m in sdwan.get("members", []) or []:
        zname = str(m.get("Zone") or m.get("zone") or "").strip()
        iname = str(m.get("Interface") or m.get("interface") or "").strip()
        if zname and iname and iname != "-":
            sdwan_zone_members.setdefault(zname, []).append(iname)

    pool_range_map: dict[str, str] = {
        str(p.get("Name", "")): str(p.get("External IP Range", "-"))
        for p in ip_pools
        if p.get("Name")
    }

    # Policy usage indexes
    dst_policy_refs: dict[str, list[str]] = {}
    pool_policy_refs: dict[str, list[str]] = {}
    for p in policies:
        pid = str(p.get("ID", "?"))
        pname = str(p.get("Name", "")).strip()
        plabel = f"#{pid}" + (f" ({pname})" if pname and pname != "-" else "")
        for tok in _split_tokens(p.get("Destination")):
            dst_policy_refs.setdefault(tok, []).append(plabel)
        for pool_name in p.get("_poolname") or []:
            pool_policy_refs.setdefault(pool_name, []).append(f"Policy {plabel}")

    for cs in central_snat:
        cid = str(cs.get("ID", "?"))
        for pool_name in cs.get("_pool_list") or []:
            pool_policy_refs.setdefault(pool_name, []).append(f"Central SNAT #{cid}")

    vip_group_refs: dict[str, list[str]] = {}
    vip_grp_rows: list[dict[str, Any]] = []
    for vg in vip_groups:
        vg_name = str(vg.get("Name", ""))
        direct_refs = dst_policy_refs.get(vg_name, [])
        for mem in vg.get("_member_list") or []:
            vip_group_refs.setdefault(mem, []).extend(direct_refs or [f"Group: {vg_name}"])
        vip_grp_rows.append(
            {
                **vg,
                "Used By Policies": ", ".join(dict.fromkeys(direct_refs)) if direct_refs else "Unused",
            }
        )

    # ── Sub-tab 1: Outbound SNAT ──────────────────────────────────────────────
    snat_blocks: list[dict[str, Any]] = []
    if central_snat or central_nat:
        snat_blocks.append({"type": "section_header", "title": "Central SNAT Rules"})
        snat_legend = [
            {"label": "IP Pool SNAT (blue)", "variant": "info"},
            {"label": "No-NAT / Excluded (muted)", "variant": "muted"},
            {"label": "Disabled Rule (red)", "variant": "danger"},
        ]
        snat_blocks.append(
            _table_block(
                central_snat,
                "fg_central_snat",
                empty_text="Central NAT is enabled, but no Central SNAT rules are configured.",
                export_filename="fg_central_snat.csv",
                row_class_fn=lambda r: (
                    "row-danger"
                    if str(r.get("Status", "")).lower() == "disable"
                    else (
                        "row-muted"
                        if str(r.get("NAT", "")).lower() == "disable"
                        else ("row-info" if str(r.get("IP Pool", "-")) != "-" else "")
                    )
                ),
                legend=snat_legend,
                caption=f"{len(central_snat)} central SNAT rules",
            )
        )

    resolved_snat_rows: list[dict[str, Any]] = []
    for p in policies:
        nat_on = str(p.get("NAT", "")).lower() == "enable"
        special = bool(p.get("_nat64") or p.get("_nat46") or p.get("_natinbound") or p.get("_natoutbound") or p.get("_natip"))
        if not nat_on and not special:
            continue

        pools = p.get("_poolname") or []
        if p.get("_nat64"):
            nat_type = "NAT64"
        elif p.get("_nat46"):
            nat_type = "NAT46"
        elif p.get("_natinbound") or p.get("_natoutbound") or p.get("_natip"):
            nat_type = "IPsec NAT"
        elif p.get("_ippool") or pools:
            nat_type = "IP Pool"
        else:
            nat_type = "Interface IP"

        if nat_type in ("IP Pool", "NAT64", "NAT46") and pools:
            pool_display = ", ".join(pools)
            trans_ips = ", ".join(f"{pn} ({pool_range_map.get(pn, 'Missing Pool')})" for pn in pools)
        elif p.get("_natip"):
            pool_display = "-"
            trans_ips = str(p.get("_natip"))
        else:
            pool_display = "-"
            trans_ips = _resolve_egress_ips(str(p.get("Dst Interface", "")), iface_ip_map, sdwan_zone_members)

        if p.get("_fixedport"):
            port_mode = "Fixed Port (No PAT)"
        elif p.get("_port_preserve") == "enable":
            port_mode = "Port Preserve"
        else:
            port_mode = "Dynamic PAT"

        resolved_snat_rows.append(
            {
                "Policy ID": p.get("ID", "-"),
                "Policy Name": p.get("Name", "-"),
                "Src → Dst Interface": f"{p.get('Src Interface', '-')} → {p.get('Dst Interface', '-')}",
                "Source": p.get("Source", "-"),
                "Destination": p.get("Destination", "-"),
                "NAT Type": nat_type,
                "Pool Name": pool_display,
                "Translated IP(s)": trans_ips,
                "Port Behavior": port_mode,
                "Status": p.get("Status", "Enable"),
                "_nat_type": nat_type,
                "_fixed": bool(p.get("_fixedport")),
            }
        )

    if not central_nat:
        snat_blocks.append({"type": "section_header", "title": "Policy-Based Outbound SNAT"})
        pol_snat_legend = [
            {"label": "Interface IP SNAT (default)", "variant": "default"},
            {"label": "IP Pool SNAT (blue)", "variant": "info"},
            {"label": "Fixed Port / Special NAT (amber)", "variant": "warn"},
            {"label": "Disabled Policy (red)", "variant": "danger"},
        ]
        snat_blocks.append(
            _table_block(
                resolved_snat_rows,
                "fg_policy_snat",
                empty_text="No NAT-enabled firewall policies found.",
                export_filename="fg_policy_snat.csv",
                row_class_fn=lambda r: (
                    "row-danger"
                    if str(r.get("Status", "")).lower() == "disable"
                    else (
                        "row-warn"
                        if r.get("_fixed") or r.get("_nat_type") in ("NAT64", "NAT46", "IPsec NAT")
                        else ("row-info" if r.get("_nat_type") == "IP Pool" else "")
                    )
                ),
                legend=pol_snat_legend,
                caption=f"{len(resolved_snat_rows)} NAT-enabled policies",
            )
        )
    elif resolved_snat_rows:
        snat_blocks.append(
            {
                "type": "expander",
                "title": f"Legacy Per-Policy NAT Flags ({len(resolved_snat_rows)} ignored under Central NAT)",
                "open": False,
                "blocks": [
                    _table_block(
                        resolved_snat_rows,
                        "fg_policy_snat_ignored",
                        export_filename="fg_policy_snat_ignored.csv",
                    )
                ],
            }
        )

    # ── Sub-tab 2: Virtual IPs (DNAT) ─────────────────────────────────────────
    enriched_vips: list[dict[str, Any]] = []
    for v in vips:
        vname = str(v.get("Name", ""))
        refs = list(dst_policy_refs.get(vname, []))
        refs.extend(vip_group_refs.get(vname, []))
        used_str = ", ".join(dict.fromkeys(refs)) if refs else "Unused"
        enriched_vips.append({**v, "Used By Policies": used_str})

    vip_legend = [
        {"label": "Active & Referenced (default)", "variant": "default"},
        {"label": "Unused by Any Policy (muted)", "variant": "muted"},
        {"label": "Disabled VIP (red)", "variant": "danger"},
    ]
    vip_blocks: list[dict[str, Any]] = [
        _table_block(
            enriched_vips,
            "fg_vips",
            empty_text="No Virtual IPs found.",
            export_filename="fg_virtual_ips.csv",
            row_class_fn=lambda r: (
                "row-danger"
                if str(r.get("_status", "Enable")).lower() == "disable"
                else ("row-muted" if r.get("Used By Policies") == "Unused" else "")
            ),
            legend=vip_legend,
            caption=f"{len(enriched_vips)} Virtual IPs",
        )
    ]
    if vip_grp_rows:
        vip_blocks.append({"type": "section_header", "title": "VIP Groups"})
        vip_blocks.append(
            _table_block(
                vip_grp_rows,
                "fg_vip_groups",
                export_filename="fg_vip_groups.csv",
                row_class_fn=lambda r: "row-muted" if r.get("Used By Policies") == "Unused" else "",
                legend=[
                    {"label": "Referenced Group (default)", "variant": "default"},
                    {"label": "Unused Group (muted)", "variant": "muted"},
                ],
                caption=f"{len(vip_grp_rows)} VIP groups",
            )
        )

    # ── Sub-tab 3: IP Pools (SNAT) ────────────────────────────────────────────
    enriched_pools: list[dict[str, Any]] = []
    for pool in ip_pools:
        pname = str(pool.get("Name", ""))
        refs = pool_policy_refs.get(pname, [])
        used_str = ", ".join(dict.fromkeys(refs)) if refs else "Unused"
        enriched_pools.append({**pool, "Used By Policies": used_str})

    pool_blocks = [
        _table_block(
            enriched_pools,
            "fg_ip_pools",
            empty_text="No IP pools found.",
            export_filename="fg_ip_pools.csv",
            row_class_fn=lambda r: "row-muted" if r.get("Used By Policies") == "Unused" else "",
            legend=[
                {"label": "Referenced Pool (default)", "variant": "default"},
                {"label": "Unused Pool (muted)", "variant": "muted"},
            ],
            caption=f"{len(enriched_pools)} IP pools",
        )
    ]

    mode_banner = (
        {
            "type": "alert",
            "variant": "warn",
            "text": "Central NAT mode is enabled (set central-nat enable). Outbound SNAT is controlled by Central SNAT rules rather than per-policy NAT settings.",
        }
        if central_nat
        else {
            "type": "alert",
            "variant": "info",
            "text": "Policy-Based NAT mode is active. Outbound SNAT is configured per firewall policy (egress interface IP or IP Pools); inbound DNAT uses Virtual IPs.",
        }
    )

    return [
        mode_banner,
        {
            "type": "tabs",
            "id": "fg_nat_sub",
            "tabs": [
                {"label": "Outbound SNAT", "blocks": snat_blocks},
                {"label": "Virtual IPs / DNAT", "blocks": vip_blocks},
                {"label": "IP Pools", "blocks": pool_blocks},
            ],
        },
    ]


def build_policies_nat(parser: Any) -> dict[str, Any]:
    policies = parser.parse_policies()
    central_nat = bool(parser.is_central_nat_enabled()) if hasattr(parser, "is_central_nat_enabled") else False
    display_policies = [
        {**p, "NAT": _format_policy_nat_label(p, central_nat)}
        for p in policies
    ]
    iface_names = parser.get_interface_names() if hasattr(parser, "get_interface_names") else []
    iface_opts = ["any"] + iface_names

    _dis_cls = lambda r: "row-danger" if str(r.get("Status", "")).lower() == "disable" else ""
    fw_dis = sum(1 for r in display_policies if str(r.get("Status", "")).lower() == "disable")
    proxy_pols = parser.parse_proxy_policy()
    px_dis = sum(1 for r in proxy_pols if str(r.get("Status", "")).lower() == "disable")
    auth_rules = parser.parse_auth_rules()

    nat_blocks = _build_fg_nat_blocks(parser, policies)
    # Count NAT items: Outbound SNAT + VIPs + IP Pools
    snat_cnt = len(parser.parse_central_snat()) if central_nat and hasattr(parser, "parse_central_snat") else sum(
        1 for p in policies if str(p.get("NAT", "")).lower() == "enable"
    )
    nat_total = snat_cnt + len(parser.parse_vip() or []) + len(parser.parse_ip_pools() or [])

    tabs = [
        {
            "label": "Firewall Policy",
            "count": len(display_policies),
            "blocks": [
                {"type": "policy_simulator", "vendor": "fg", "interfaces": iface_opts},
                _table_block(
                    display_policies,
                    "fg_fw_policies",
                    empty_text="No firewall policies found.",
                    row_class_fn=_dis_cls,
                    legend=POLICY_LEGEND,
                    export_filename="fg_firewall_policies.csv",
                    caption=policy_caption(len(display_policies), fw_dis),
                ),
            ],
        },
        {"label": "NAT", "count": nat_total, "blocks": nat_blocks},
        {
            "label": "Proxy Policy",
            "count": len(proxy_pols),
            "blocks": [
                _table_block(
                    proxy_pols,
                    "fg_proxy_pol",
                    empty_text="No proxy policies found.",
                    row_class_fn=_dis_cls,
                    legend=POLICY_LEGEND,
                    export_filename="fg_proxy_policies.csv",
                    caption=policy_caption(len(proxy_pols), px_dis),
                )
            ],
        },
        {"label": "Auth Rules", "count": len(auth_rules), "blocks": [_table_block(auth_rules, "fg_auth_rules", empty_text="No authentication rules found.")]},
        {"label": "Cleanup & Hygiene", "blocks": build_hygiene_blocks(analyze_fortigate_hygiene(parser), "fg")},
    ]
    return {"section": "Policies & NAT", "blocks": [{"type": "tabs", "id": "fg_po_tabs", "tabs": tabs}]}


def build_objects(parser: Any) -> dict[str, Any]:
    addr = parser.parse_addresses()
    addr_tabs = [
        {
            "label": label,
            "count": len(addr.get(data_key, [])),
            "blocks": [
                _table_block(
                    addr.get(data_key, []),
                    f"fg_addr_{sfx}",
                    empty_text=f"No {label} addresses.",
                    drop_keys=_INTERNAL_ADDR_KEYS,
                )
            ],
        }
        for data_key, sfx, label in [
            ("subnet", "subnet", "Subnet / IP Mask"),
            ("iprange", "iprange", "IP Range"),
            ("fqdn", "fqdn", "FQDN"),
            ("ipmask", "ipmask", "Interface Subnet"),
            ("groups", "groups", "Address Groups"),
            ("regex", "regex", "Host Regex"),
        ]
    ]
    addr_total = sum(len(addr.get(k, [])) for k in ("subnet", "iprange", "fqdn", "ipmask", "groups", "regex"))

    svc_data = parser.parse_services()
    services = svc_data.get("services", [])
    schedules = parser.parse_schedules()
    proto_rows = parser.parse_protocol_options()
    shaping = parser.parse_traffic_shaping()
    vservers = parser.parse_virtual_servers()
    hchecks = parser.parse_health_check()

    tabs = [
        {"label": "Addresses", "count": addr_total, "blocks": [{"type": "tabs", "id": "fg_addr_sub", "tabs": addr_tabs}]},
        {"label": "Services", "count": len(services), "blocks": [_table_block(services, "fg_services", empty_text="No custom services found.", filter_col="Category")]},
        {"label": "Schedules", "count": len(schedules), "blocks": [_table_block(schedules, "fg_schedules", empty_text="No schedules found.")]},
        {"label": "Protocol Options", "count": len(proto_rows), "blocks": [_table_block(proto_rows, "fg_proto_opts", empty_text="No protocol options profiles found.", filter_col="Profile")]},
        {"label": "Traffic Shaping", "count": len(shaping), "blocks": [_table_block(shaping, "fg_traffic_shaping", empty_text="No traffic shapers found.")]},
        {"label": "Virtual Servers", "count": len(vservers), "blocks": [_table_block(vservers, "fg_vservers", empty_text="No virtual servers found.")]},
        {"label": "Health Check", "count": len(hchecks), "blocks": [_table_block(hchecks, "fg_health_checks", empty_text="No health check monitors found.")]},
    ]
    return {"section": "Objects", "blocks": [{"type": "tabs", "id": "fg_obj_tabs", "tabs": tabs}]}


def build_policy_objects(parser: Any) -> dict[str, Any]:
    pol_tabs = build_policies_nat(parser)["blocks"][0]["tabs"]
    obj_tabs = build_objects(parser)["blocks"][0]["tabs"]
    # Keep Cleanup & Hygiene at the end for legacy Policy & Objects callers
    hyg = [t for t in pol_tabs if t["label"] == "Cleanup & Hygiene"]
    pol_core = [t for t in pol_tabs if t["label"] != "Cleanup & Hygiene"]
    return {"section": "Policy & Objects", "blocks": [{"type": "tabs", "id": "fg_po_tabs", "tabs": [*pol_core, *obj_tabs, *hyg]}]}


# ── 5. Security ──────────────────────────────────────────────────────────────
def _sec_profile_selector(
    profiles: list[dict[str, Any]],
    sel_id: str,
    detail_builder: Callable[[dict[str, Any], int], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if not profiles:
        return [{"type": "alert", "variant": "info", "text": "No profiles configured."}]
    return [
        {
            "type": "profile_selector",
            "id": sel_id,
            "label": "Select Profile",
            "options": [
                {"name": p.get("name", f"Profile {i+1}"), "blocks": detail_builder(p, i)}
                for i, p in enumerate(profiles)
            ],
        }
    ]


def build_security(parser: Any) -> dict[str, Any]:
    def _av(p, i):
        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Inspection Mode", "value": p.get("feature_set", "flow")},
                    {"label": "Comment", "value": p.get("comment", "-")},
                ],
            },
            _table_block(p.get("protocols", []), f"fg_av_{i}", empty_text="No protocol scan settings configured."),
        ]

    def _wf(p, i):
        blks: list[dict[str, Any]] = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Inspection Mode", "value": p.get("feature_set", "flow")},
                    {"label": "URL Filter Table", "value": p.get("urlfilter_name", p.get("urlfilter_table", "-"))},
                    {"label": "Safe Search", "value": p.get("safe_search", "-")},
                    {"label": "Block Invalid URLs", "value": p.get("block_invalid_url", "disable")},
                ],
            }
        ]
        entries = p.get("urlfilter_entries", [])
        if entries:
            blks.append(
                _table_block(
                    entries,
                    f"fg_wf_urls_{i}",
                    title=f"Static URL Filter ({len(entries)} entries)",
                    row_class_fn=lambda r: "row-danger" if str(r.get("Action", "")).lower() == "block" else "row-success",
                    legend=[
                        {"label": "Allow / Exempt / Monitor (green)", "variant": "success"},
                        {"label": "Block (red)", "variant": "danger"},
                    ],
                )
            )
        cats = p.get("categories", [])
        blks.append(
            _table_block(
                cats,
                f"fg_wf_cats_{i}",
                title="Categories",
                empty_text="No category filters configured.",
                row_class_fn=lambda r: "row-danger" if str(r.get("Action", "")).lower() == "block" else "",
                legend=[
                    {"label": "Allow / Monitor / Authenticate (default)", "variant": "default"},
                    {"label": "Block (red)", "variant": "danger"},
                ],
            )
        )
        return blks

    def _dns(p, i):
        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Inspection Mode", "value": p.get("feature_set", "flow")},
                    {"label": "Block Botnet", "value": p.get("block_botnet", "-")},
                    {"label": "Safe Search", "value": p.get("safe_search", "-")},
                ],
            },
            _table_block(
                p.get("categories", []),
                f"fg_dns_cats_{i}",
                title="DNS Categories",
                empty_text="No DNS category filters configured.",
                row_class_fn=lambda r: "row-danger" if str(r.get("Action", "")).lower() == "block" else "",
                legend=[
                    {"label": "Allow / Monitor (default)", "variant": "default"},
                    {"label": "Block / Redirect (red)", "variant": "danger"},
                ],
            ),
        ]

    def _app(p, i):
        def _act(r):
            a = str(r.get("Action", "")).lower()
            if a == "block":
                return "row-danger"
            if a == "pass":
                return "row-success"
            return ""

        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Options", "value": p.get("options", "-")},
                    {"label": "Deep Inspection", "value": p.get("deep_inspection", "-")},
                    {"label": "Unknown App Action", "value": p.get("unknown_action", "-")},
                ],
            },
            _table_block(
                p.get("entries", []),
                f"fg_app_{i}",
                title="Application & Filter Overrides",
                empty_text="No entries configured.",
                row_class_fn=_act,
                legend=[
                    {"label": "Pass (green)", "variant": "success"},
                    {"label": "Monitor (default)", "variant": "default"},
                    {"label": "Block (red)", "variant": "danger"},
                ],
            ),
        ]

    def _ips(p, i):
        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Comment", "value": p.get("comment", "-")},
                    {"label": "Block Malicious URL", "value": p.get("block_malicious_url", "-")},
                ],
            },
            _table_block(p.get("entries", []), f"fg_ips_{i}", title="IPS Entries", empty_text="No IPS entries configured."),
        ]

    def _ff(p, i):
        return [
            {"type": "kv_grid", "items": [{"label": "Inspection Mode", "value": p.get("feature_set", "flow")}, {"label": "Comment", "value": p.get("comment", "-")}]},
            _table_block(p.get("rules", []), f"fg_ff_{i}", empty_text="No file filter rules configured."),
        ]

    def _ef(p, i):
        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Inspection Mode", "value": p.get("feature_set", "flow")},
                    {"label": "Spam Filtering", "value": p.get("spam_filtering", "-")},
                    {"label": "BWL Table", "value": p.get("spam_bwl_table", "-")},
                ],
            },
            _table_block(p.get("protocols", []), f"fg_ef_{i}", empty_text="No specific protocol settings."),
        ]

    def _voip(p, i):
        blks: list[dict[str, Any]] = []
        sip = p.get("sip", {})
        sccp = p.get("sccp", {})
        if sip:
            blks.append({"type": "kv_grid", "items": [{"label": "SIP Status", "value": sip.get("status", "-")}, {"label": "SIP RTP", "value": sip.get("rtp", "-")}, {"label": "SIP Port", "value": sip.get("port", "-")}]})
        if sccp:
            blks.append({"type": "kv_grid", "items": [{"label": "SCCP Status", "value": sccp.get("status", "-")}, {"label": "SCCP Port", "value": sccp.get("port", "-")}]})
        if not blks:
            blks.append({"type": "alert", "variant": "info", "text": "No SIP/SCCP configuration found."})
        return blks

    def _waf(p, i):
        def _sig_cls(r):
            if str(r.get("Status", "")).lower() == "enable":
                return "row-danger" if str(r.get("Action", "")).lower() == "block" else "row-warn"
            return "row-muted"

        blks = [
            _table_block(
                p.get("signatures", []),
                f"fg_waf_sig_{i}",
                title="Signature Classes",
                empty_text="No signature classes.",
                row_class_fn=_sig_cls,
                legend=[
                    {"label": "Enabled + Block (red)", "variant": "danger"},
                    {"label": "Enabled + Log/Warning (amber)", "variant": "warn"},
                    {"label": "Disabled (muted)", "variant": "muted"},
                ],
            )
        ]
        if p.get("constraints"):
            blks.append(_table_block(p["constraints"], f"fg_waf_con_{i}", title="Constraints"))
        return blks

    def _ssl(p, i):
        return [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "CA Certificate", "value": p.get("ca_cert", "-")},
                    {"label": "Untrusted CA Cert", "value": p.get("untrusted_cert", "-")},
                    {"label": "Comment", "value": p.get("comment", "-")},
                ],
            },
            _table_block(p.get("protocols", []), f"fg_ssl_{i}", empty_text="No protocol configurations found."),
        ]

    av_list = parser.parse_antivirus()
    wf_list = parser.parse_webfilter()
    dns_list = parser.parse_dnsfilter()
    app_list = parser.parse_appcontrol()
    ips_list = parser.parse_ips()
    ff_list = parser.parse_filefilter()
    ef_list = parser.parse_emailfilter()
    voip_list = parser.parse_voip()
    waf_list = parser.parse_waf()
    ssl_list = parser.parse_ssl_inspection()
    wro_list = parser.parse_web_rating_override()
    wpo_list = parser.parse_web_profile_override()

    tabs = [
        {"label": "Antivirus", "count": len(av_list), "blocks": _sec_profile_selector(av_list, "fg_sel_av", _av)},
        {"label": "Web Filter", "count": len(wf_list), "blocks": _sec_profile_selector(wf_list, "fg_sel_wf", _wf)},
        {"label": "DNS Filter", "count": len(dns_list), "blocks": _sec_profile_selector(dns_list, "fg_sel_dns", _dns)},
        {"label": "App Control", "count": len(app_list), "blocks": _sec_profile_selector(app_list, "fg_sel_app", _app)},
        {"label": "IPS", "count": len(ips_list), "blocks": _sec_profile_selector(ips_list, "fg_sel_ips", _ips)},
        {"label": "File Filter", "count": len(ff_list), "blocks": _sec_profile_selector(ff_list, "fg_sel_ff", _ff)},
        {"label": "Email Filter", "count": len(ef_list), "blocks": _sec_profile_selector(ef_list, "fg_sel_ef", _ef)},
        {"label": "VoIP", "count": len(voip_list), "blocks": _sec_profile_selector(voip_list, "fg_sel_voip", _voip)},
        {"label": "WAF", "count": len(waf_list), "blocks": _sec_profile_selector(waf_list, "fg_sel_waf", _waf)},
        {"label": "SSL Inspection", "count": len(ssl_list), "blocks": _sec_profile_selector(ssl_list, "fg_sel_ssl", _ssl)},
        {"label": "Web Rating Overrides", "count": len(wro_list), "blocks": [_table_block(wro_list, "fg_wro", empty_text="No web rating overrides configured.", filter_col="Category Name")]},
        {"label": "Web Profile Overrides", "count": len(wpo_list), "blocks": [_table_block(wpo_list, "fg_wpo", empty_text="No web profile overrides configured.")]},
    ]
    return {"section": "Security Profiles", "blocks": [{"type": "tabs", "id": "fg_sec_tabs", "tabs": tabs}]}


# ── 6. VPN ───────────────────────────────────────────────────────────────────
def build_vpn(parser: Any) -> dict[str, Any]:
    phase1_list = parser.parse_ipsec_phase1()
    phase2_list = parser.parse_ipsec_phase2()

    if not phase1_list:
        ipsec_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No IPSec tunnels configured."}]
    else:
        summary = [
            {
                "Tunnel": p["name"],
                "Interface Binding": p["interface"],
                "Remote Gateway": p["remote_gw"],
                "IKE Version": f"IKEv{p['ike_version']}",
                "Status": p["status"],
                "Comment": p["comments"],
            }
            for p in phase1_list
        ]

        def _p1_detail(p, idx):
            props = [x for x in str(p.get("proposal", "-")).split() if x != "-"]
            prop_rows = [
                {
                    "Encryption": pr.split("-")[0].upper(),
                    "Authentication": pr.split("-")[1].upper() if "-" in pr else "-",
                }
                for pr in props
            ]
            blks: list[dict[str, Any]] = [
                {
                    "type": "kv_grid",
                    "items": [
                        {"label": "Remote Gateway", "value": p.get("remote_gw", "-")},
                        {"label": "Interface", "value": p.get("interface", "-")},
                        {"label": "IKE Version", "value": f"IKEv{p.get('ike_version', '1')}"},
                        {"label": "Auth Method", "value": p.get("authmethod", "psk").upper()},
                        {"label": "NAT Traversal", "value": p.get("nattraversal", "-")},
                        {"label": "DPD", "value": f"{p.get('dpd', '-')} ({p.get('dpd_retrycount', '-')}x / {p.get('dpd_retryinterval', '-')}s)"},
                        {"label": "DH Group", "value": p.get("dhgrp", "-")},
                        {"label": "Key Lifetime", "value": f"{p.get('keylifetime', '86400')}s"},
                    ],
                },
                _table_block(prop_rows, f"fg_p1_prop_{idx}", title="Phase 1 Proposal", empty_text="No proposal configured."),
            ]
            tunnel_p2 = [p2 for p2 in phase2_list if p2.get("phase1name") == p.get("name")]
            for j, p2 in enumerate(tunnel_p2):
                src_val = p2.get("src_name", "-") if p2.get("src_addr_type") == "name" else p2.get("src_subnet", "-")
                dst_val = p2.get("dst_name", "-") if p2.get("dst_addr_type") == "name" else p2.get("dst_subnet", "-")
                blks.append(
                    {
                        "type": "expander",
                        "title": f"Phase 2 Selector: {p2.get('name', '-')}",
                        "open": len(tunnel_p2) == 1,
                        "blocks": [
                            {
                                "type": "kv_grid",
                                "items": [
                                    {"label": "Local Address", "value": src_val},
                                    {"label": "Remote Address", "value": dst_val},
                                    {"label": "Proposal", "value": p2.get("proposal", "-")},
                                    {"label": "DH Group", "value": p2.get("dhgrp", "-")},
                                    {"label": "Key Lifetime", "value": f"{p2.get('keylifeseconds', '43200')}s"},
                                    {"label": "PFS", "value": p2.get("pfs", "-")},
                                    {"label": "Auto Negotiate", "value": p2.get("auto_negotiate", "-")},
                                    {"label": "Keepalive", "value": p2.get("keepalive", "-")},
                                ],
                            }
                        ],
                    }
                )
            return blks

        ipsec_blocks = [
            _table_block(summary, "fg_ipsec_summary", title="IPSec Tunnels", export_filename="fg_ipsec_tunnels.csv"),
            {
                "type": "profile_selector",
                "id": "fg_ipsec_detail_sel",
                "label": "Inspect Tunnel Details",
                "options": [{"name": p["name"], "blocks": _p1_detail(p, i)} for i, p in enumerate(phase1_list)],
            },
        ]

    # SSL-VPN Portals
    portals = parser.parse_ssl_portals()
    if not portals:
        portal_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No SSL-VPN portals configured."}]
    else:
        p_summary = [
            {
                "Name": p["name"],
                "Tunnel Mode": p["tunnel_mode"],
                "Web Mode": p["web_mode"],
                "IP Pools": p["ip_pools"],
                "Split Tunneling": p["split_tunneling"],
            }
            for p in portals
        ]
        portal_blocks = [
            _table_block(p_summary, "fg_ssl_portals", title="SSL-VPN Portals"),
            {
                "type": "profile_selector",
                "id": "fg_ssl_portal_sel",
                "label": "Inspect Portal Details",
                "options": [
                    {
                        "name": p["name"],
                        "blocks": [
                            {
                                "type": "kv_grid",
                                "items": [
                                    {"label": "Tunnel Mode", "value": p.get("tunnel_mode", "-")},
                                    {"label": "Web Mode", "value": p.get("web_mode", "-")},
                                    {"label": "Split Tunneling", "value": p.get("split_tunneling", "-")},
                                    {"label": "IP Pools", "value": p.get("ip_pools", "-")},
                                    {"label": "Host Check", "value": p.get("host_check", "-")},
                                    {"label": "FortiClient Download", "value": p.get("forticlient_download", "-")},
                                ],
                            },
                            _table_block(p.get("bookmarks", []), f"fg_ssl_bm_{i}", title="Predefined Bookmarks", empty_text="No predefined bookmarks configured."),
                        ],
                    }
                    for i, p in enumerate(portals)
                ],
            },
        ]

    # SSL-VPN Settings
    settings = parser.parse_ssl_settings()
    if not settings:
        ssl_set_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No SSL-VPN settings configured."}]
    else:
        auth_rules = settings.get("auth_rules") or [
            {"Users/Groups": "All Other Users/Groups", "Portal": settings.get("default_portal", "full-access")}
        ]
        ssl_set_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Status", "value": settings.get("enabled", "-")},
                    {"label": "Port", "value": settings.get("port", "443")},
                    {"label": "Certificate", "value": settings.get("servercert", "-")},
                    {"label": "Listen Interfaces", "value": ", ".join(settings.get("listen_interfaces", [])) or "-"},
                    {"label": "Idle Timeout", "value": f"{settings.get('idle_timeout', '-')}s"},
                    {"label": "Default Portal", "value": settings.get("default_portal", "-")},
                    {"label": "DNS Server 1", "value": settings.get("dns_server1", "Same as client")},
                    {"label": "Address Range", "value": settings.get("ip_range", "-")},
                ],
            },
            _table_block(auth_rules, "fg_ssl_auth_rules", title="Authentication / Portal Mapping"),
        ]
        if str(settings.get("enabled", "enable")).lower() != "disable":
            ssl_set_blocks.insert(
                0,
                {
                    "type": "alert",
                    "variant": "info",
                    "text": "Planning a migration from SSL-VPN? Open the 'SSL-to-IPSec Migration' tab for a readiness audit, certificate check, and draft Dial-up IPSec IKEv2 CLI.",
                },
            )

    inspector_blocks = build_vpn_inspector_blocks(inspect_fortigate_vpns(parser), "fg")
    ssl_mig_blocks = build_ssl_to_ipsec_blocks(analyze_fortigate_ssl_to_ipsec(parser))

    conc_list = parser.parse_ipsec_concentrator()
    client_list = parser.parse_ssl_clients()
    tabs = [
        {"label": "Site-to-Site Inspector", "count": len(phase1_list), "blocks": inspector_blocks},
        {"label": "IPSec Tunnels", "count": len(phase1_list), "blocks": ipsec_blocks},
        {"label": "IPSec Concentrator", "count": len(conc_list), "blocks": [_table_block(conc_list, "fg_ipsec_conc", empty_text="No IPSec concentrators configured.")]},
        {"label": "SSL-VPN Portals", "count": len(portals), "blocks": portal_blocks},
        {"label": "SSL-VPN Settings", "blocks": ssl_set_blocks},
        {"label": "SSL-VPN Clients", "count": len(client_list), "blocks": [_table_block(client_list, "fg_ssl_clients", empty_text="No SSL-VPN client configurations found.")]},
        {"label": "SSL-to-IPSec Migration", "blocks": ssl_mig_blocks},
    ]
    return {"section": "VPN", "blocks": [{"type": "tabs", "id": "fg_vpn_tabs", "tabs": tabs}]}


# ── 7. User & Auth ───────────────────────────────────────────────────────────
def build_user_auth(parser: Any) -> dict[str, Any]:
    auth = parser.parse_auth_settings()
    if not auth:
        auth_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No authentication settings found."}]
    else:
        active = {p.strip().upper() for p in str(auth.get("auth_type", "http https")).split()}
        auth_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Auth Certificate", "value": auth.get("auth_cert", "-")},
                    {"label": "Auth Timeout", "value": f"{auth.get('auth_timeout', '5')} minutes"},
                ],
            },
            {
                "type": "badge_grid",
                "items": [
                    {"label": proto, "value": "ON" if proto in active else "OFF", "variant": "allow" if proto in active else "deny"}
                    for proto in ("HTTP", "HTTPS", "TELNET", "SSH")
                ],
            },
            {"type": "card", "rows": [_toggle_row("HTTP Redirect to Auth Portal", auth.get("http_redirect", "disable"))]},
        ]

    users_local = parser.parse_user_local()
    user_groups = parser.parse_user_groups()
    guest_users = parser.parse_guest_users()
    ldap_list = parser.parse_ldap()
    radius_list = parser.parse_radius()
    fsso_list = parser.parse_fsso()
    token_list = parser.parse_fortitoken()

    tabs = [
        {
            "label": "User Definition",
            "count": len(users_local),
            "blocks": [
                _table_block(
                    users_local,
                    "fg_users",
                    empty_text="No local users configured.",
                    row_class_fn=lambda r: "row-danger" if str(r.get("Status", "")).lower() == "disable" else "",
                    legend=[
                        {"label": "Enabled User (default)", "variant": "default"},
                        {"label": "Disabled User (red)", "variant": "danger"},
                    ],
                )
            ],
        },
        {"label": "User Groups", "count": len(user_groups), "blocks": [_table_block(user_groups, "fg_user_groups", empty_text="No user groups configured.")]},
        {"label": "Guest Management", "count": len(guest_users), "blocks": [_table_block(guest_users, "fg_guest_users", empty_text="No guest users configured.")]},
        {"label": "LDAP Servers", "count": len(ldap_list), "blocks": [_table_block(ldap_list, "fg_ldap", empty_text="No LDAP servers configured.", export_filename="fg_ldap_servers.csv")]},
        {"label": "RADIUS Servers", "count": len(radius_list), "blocks": [_table_block(radius_list, "fg_radius", empty_text="No RADIUS servers configured.", export_filename="fg_radius_servers.csv")]},
        {"label": "Single Sign-On", "count": len(fsso_list), "blocks": [_table_block(fsso_list, "fg_fsso", empty_text="No FSSO agents configured.")]},
        {"label": "FortiToken", "count": len(token_list), "blocks": [_table_block(token_list, "fg_fortitoken", empty_text="No FortiTokens configured.", export_filename="fg_fortitokens.csv")]},
        {"label": "Auth Settings", "blocks": auth_blocks},
    ]
    return {"section": "Users & Auth", "blocks": [{"type": "tabs", "id": "fg_user_tabs", "tabs": tabs}]}


# ── 8. WiFi & Switch ─────────────────────────────────────────────────────────
def build_wifi(parser: Any) -> dict[str, Any]:
    aps = parser.parse_managed_fortiaps()
    ssids = parser.parse_ssids()
    ap_profs = parser.parse_fortiap_profiles()
    wids = parser.parse_wids_profiles()
    switches = parser.parse_managed_switches()
    port_pols = parser.parse_switch_port_policies()
    nac_pols = parser.parse_nac_policies()

    tabs = [
        {"label": "Managed FortiAPs", "count": len(aps), "blocks": [_table_block(aps, "fg_managed_aps", empty_text="No managed FortiAPs configured.", export_filename="fg_managed_fortiaps.csv")]},
        {
            "label": "SSIDs",
            "count": len(ssids),
            "blocks": [
                _table_block(
                    ssids,
                    "fg_ssids",
                    empty_text="No SSIDs configured.",
                    row_class_fn=lambda r: "row-danger" if str(r.get("Status", "")).lower() == "disable" else "",
                    legend=[
                        {"label": "Enabled SSID (default)", "variant": "default"},
                        {"label": "Disabled SSID (red)", "variant": "danger"},
                    ],
                )
            ],
        },
        {"label": "FortiAP Profiles", "count": len(ap_profs), "blocks": [_table_block(ap_profs, "fg_ap_profiles", empty_text="No FortiAP profiles configured.", export_filename="fg_fortiap_profiles.csv")]},
        {"label": "WIDS Profiles", "count": len(wids), "blocks": [_table_block(wids, "fg_wids", empty_text="No WIDS profiles configured.", export_filename="fg_wids_profiles.csv")]},
        {"label": "Managed FortiSwitches", "count": len(switches), "blocks": [_table_block(switches, "fg_switches", empty_text="No managed FortiSwitches configured.", export_filename="fg_managed_switches.csv")]},
        {"label": "Port Policies", "count": len(port_pols), "blocks": [_table_block(port_pols, "fg_port_policies", empty_text="No port policies configured.")]},
        {"label": "NAC Policies", "count": len(nac_pols), "blocks": [_table_block(nac_pols, "fg_nac", empty_text="No NAC policies configured.", export_filename="fg_nac_policies.csv")]},
    ]
    return {"section": "WiFi & Switch", "blocks": [{"type": "tabs", "id": "fg_wifi_tabs", "tabs": tabs}]}


# ── 9. System ────────────────────────────────────────────────────────────────
def build_system(parser: Any) -> dict[str, Any]:
    admins = parser.parse_admins()
    if admins:
        admins = sorted(admins, key=lambda x: (0 if x.get("Profile") == "super_admin" else 1, x.get("Name", "")))

    profiles = parser.parse_accprofiles()
    perm_cols = [
        "Security Fabric", "FortiView", "User & Device", "Firewall", "Log & Report",
        "Network", "System", "Security Profile", "VPN", "WiFi & Switch",
    ]
    prof_blocks: list[dict[str, Any]] = (
        [{"type": "alert", "variant": "info", "text": "No admin profiles configured."}]
        if not profiles
        else [
            {
                "type": "expander",
                "title": p.get("name", "Profile"),
                "blocks": [
                    {
                        "type": "badge_grid",
                        "items": [
                            {
                                "label": perm,
                                "value": p.get(perm, "None"),
                                "variant": "allow" if p.get(perm) == "Read/Write" else ("info" if p.get(perm) == "Read" else "muted"),
                            }
                            for perm in perm_cols
                        ],
                    }
                ],
            }
            for p in profiles
        ]
    )

    s = parser.parse_system_settings()
    if not s:
        settings_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No system settings found."}]
    else:
        tz_map = {
            "57": "Asia/Kuala_Lumpur (UTC+8)",
            "0": "UTC",
            "4": "America/New_York (UTC-5)",
            "12": "America/Los_Angeles (UTC-8)",
            "26": "Europe/London (UTC+0)",
            "28": "Europe/Paris (UTC+1)",
            "55": "Asia/Singapore (UTC+8)",
            "29": "Asia/Tokyo (UTC+9)",
        }
        tz_raw = str(s.get("timezone", ""))
        thresh = str(s.get("admin_lockout_threshold", "-"))
        dur = str(s.get("admin_lockout_duration", "60"))
        lockout_display = "Disabled" if thresh == "0" else (f"{thresh} attempts / {dur}s" if thresh != "-" else "-")
        pp = parser.parse_password_policy() if hasattr(parser, "parse_password_policy") else {"status": "disable"}
        pp_enabled = str(pp.get("status", "disable")).lower() == "enable" or str(s.get("passwd_policy", "disable")).lower() == "enable"

        settings_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Hostname", "value": s.get("hostname", "-")},
                    {"label": "Time Zone", "value": tz_map.get(tz_raw, f"TZ {tz_raw}")},
                    {"label": "VDOM Mode", "value": s.get("vdom_status", "disable")},
                    {"label": "Idle Timeout", "value": f"{s.get('idle_timeout', '5')} min"},
                    {"label": "Admin Lockout Threshold", "value": lockout_display},
                ],
            },
            {
                "type": "card",
                "rows": [
                    _toggle_row("FortiGuard Updates", s.get("fgd_alert_subscription", "disable")),
                    _toggle_row("Revision Backup on Upgrade", s.get("revision_backup_on_upgrade", "disable")),
                ],
            },
            {"type": "section_header", "title": "Password Policy"},
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Minimum Length", "value": str(pp.get("minimum_length", "-")) if pp_enabled else "Disabled"},
                    {"label": "Apply To", "value": str(pp.get("apply_to", "-")) if pp_enabled else "—"},
                    {"label": "Min Uppercase / Lowercase", "value": f"{pp.get('min_upper_case_letter', '0')} / {pp.get('min_lower_case_letter', '0')}" if pp_enabled else "—"},
                    {"label": "Min Numbers / Special", "value": f"{pp.get('min_number', '0')} / {pp.get('min_non_alphanumeric', '0')}" if pp_enabled else "—"},
                    {"label": "Expiry Days", "value": f"{pp.get('expire_day', '90')} days" if str(pp.get("expire_status", "disable")).lower() == "enable" else "Disabled"},
                ],
            },
            {
                "type": "card",
                "rows": [
                    _toggle_row("Admin Password Policy", "enable" if pp_enabled else "disable"),
                    _toggle_row("Password Expiration", pp.get("expire_status", "disable")),
                    _toggle_row("Allow Password Reuse", pp.get("reuse_password", "enable")),
                ],
            },
        ]

    ha = parser.get_ha_config()
    if not ha.get("enabled"):
        ha_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "HA is not configured (Standalone mode)."}]
    else:
        ha_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Mode", "value": ha.get("mode", "-")},
                    {"label": "Group Name", "value": ha.get("group_name", "-")},
                    {"label": "Priority", "value": ha.get("priority", "-")},
                    {"label": "Session Pickup", "value": ha.get("session_pickup", "disable")},
                    {"label": "Heartbeat Interfaces", "value": ", ".join(ha.get("heartbeat_interfaces", [])) or "—"},
                    {"label": "Monitor Interfaces", "value": ", ".join(ha.get("monitor_interfaces", [])) or "—"},
                ],
            },
            {
                "type": "card",
                "rows": [
                    _toggle_row("Override", ha.get("override", "disable")),
                    _toggle_row("HA Management Reservation", ha.get("ha_mgmt_status", "disable")),
                ],
            },
        ]
        if ha.get("ha_mgmt_interfaces"):
            ha_blocks.append(_table_block(ha["ha_mgmt_interfaces"], "fg_ha_mgmt", title="HA Management Interfaces"))

    try:
        snmp = parser.parse_snmp()
    except AttributeError:
        snmp = {}
    if not snmp:
        snmp_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No SNMP configuration found."}]
    else:
        snmp_blocks = [
            {"type": "kv_grid", "items": [{"label": "Sys Contact", "value": snmp.get("contact", "-")}, {"label": "Sys Location", "value": snmp.get("location", "-")}]},
            _table_block(snmp.get("communities", []), "fg_snmp_communities", title="Communities", empty_text="No SNMP communities."),
            _table_block(snmp.get("users", []), "fg_snmpv3_users", title="SNMPv3 Users", empty_text="No SNMPv3 users."),
        ]

    certs = inspect_fortigate_certificates(parser)
    tabs = [
        {
            "label": "Administrators",
            "count": len(admins or []),
            "blocks": [
                _table_block(
                    admins,
                    "fg_admins",
                    empty_text="No administrators configured.",
                    row_class_fn=lambda r: "row-warn" if r.get("Profile") == "super_admin" else "",
                    legend=ADMIN_LEGEND,
                    export_filename="fg_administrators.csv",
                )
            ],
        },
        {"label": "Admin Profiles", "count": len(profiles or []), "blocks": prof_blocks},
        {"label": "Settings", "blocks": settings_blocks},
        {"label": "HA", "blocks": ha_blocks},
        {"label": "SNMP", "blocks": snmp_blocks},
        {"label": "Certificates", "count": len(certs), "blocks": build_cert_inspector_blocks(certs, "fg")},
    ]
    return {"section": "System", "blocks": [{"type": "tabs", "id": "fg_sys_tabs", "tabs": tabs}]}


# ── 10. Log & Report ─────────────────────────────────────────────────────────
def build_log_settings(parser: Any) -> dict[str, Any]:
    log = parser.parse_log_settings()
    log_rows = [
        {"Section": "Global", "Setting": "UUIDs in Traffic Logs", "Value": log.get("uuid_traffic", "disable")},
        {"Section": "Global", "Setting": "Event Logging", "Value": log.get("event_logging", "disable")},
        {"Section": "Global", "Setting": "Local Traffic Logging", "Value": log.get("local_traffic", "disable")},
        {"Section": "Global", "Setting": "Syslog Logging", "Value": log.get("syslog", "disable")},
        {"Section": "GUI Prefs", "Setting": "Resolve Hostnames", "Value": log.get("resolve_hosts", "enable")},
        {"Section": "GUI Prefs", "Setting": "Resolve Unknown Applications", "Value": log.get("resolve_apps", "enable")},
        {"Section": "Local Logs", "Setting": "Memory Logging", "Value": log.get("memory", "enable")},
    ]

    log_tab_blocks = [
        {
            "type": "card",
            "title": "Global & Local Log Settings",
            "rows": [_toggle_row(f"{r['Section']} — {r['Setting']}", r["Value"]) for r in log_rows],
        },
        _table_block(log_rows, "fg_log_settings", title="Exportable Table", export_filename="fg_log_settings.csv"),
    ]

    tw = parser.parse_threat_weight()
    if not tw:
        tw_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No config log threat-weight block found in this configuration."}]
    else:
        tw_rows: list[dict[str, Any]] = [{"Section": "Master", "Item": "Log Threat Weight", "Level": tw.get("status", "enable")}]
        for name in ("P2P", "Proxy"):
            tw_rows.append({"Section": "Application", "Item": name, "Level": tw.get("application", {}).get(name, "Off")})
        ips = tw.get("ips_score", {})
        for label, key in [("Informational", "info"), ("Low", "low"), ("Medium", "medium"), ("High", "high"), ("Critical", "critical")]:
            tw_rows.append({"Section": "IPS Severity", "Item": label, "Level": ips.get(key, "Off")})
        tw_rows.append({"Section": "Botnet", "Item": "Botnet Communication", "Level": tw.get("botnet_connection", "Off")})
        for item, key in [("Blocked Connection", "blocked_connection"), ("Failed Connection", "failed_connection")]:
            tw_rows.append({"Section": "Packet", "Item": item, "Level": tw.get(key, "Off")})
        for k, v in (tw.get("web") or {}).items():
            tw_rows.append({"Section": "Web Activity", "Item": k, "Level": v})

        lmap = tw.get("level", {})
        tw_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Status", "value": tw.get("status", "enable")},
                    {"label": "Low Risk Score", "value": lmap.get("low", "5")},
                    {"label": "Medium Risk Score", "value": lmap.get("medium", "10")},
                    {"label": "High Risk Score", "value": lmap.get("high", "30")},
                    {"label": "Critical Risk Score", "value": lmap.get("critical", "50")},
                ],
            },
            _table_block(
                tw_rows,
                "fg_threat_weight",
                title="Threat Weight Rules",
                export_filename="fg_threat_weight.csv",
                row_class_fn=lambda r: "row-danger" if str(r.get("Level", "")).lower() == "critical" else ("row-warn" if str(r.get("Level", "")).lower() == "high" else ""),
                legend=[
                    {"label": "Critical Severity (red)", "variant": "danger"},
                    {"label": "High Severity (amber)", "variant": "warn"},
                    {"label": "Medium / Low / Off (default)", "variant": "default"},
                ],
            ),
        ]

    tabs = [
        {"label": "Log Settings", "blocks": log_tab_blocks},
        {"label": "Threat Weight", "blocks": tw_blocks},
    ]
    return {"section": "Log & Report", "blocks": [{"type": "tabs", "id": "fg_log_tabs", "tabs": tabs}]}


def build_system_logs(parser: Any) -> dict[str, Any]:
    sys_tabs = build_system(parser)["blocks"][0]["tabs"]
    log_tabs = build_log_settings(parser)["blocks"][0]["tabs"]
    return {"section": "System & Logs", "blocks": [{"type": "tabs", "id": "fg_sys_tabs", "tabs": [*sys_tabs, *log_tabs]}]}


def build_fortigate_section(section: str, parser: Any, *, allow_probe: bool = False) -> dict[str, Any]:
    builders = {
        "Overview": lambda: build_overview(parser, allow_probe=allow_probe),
        "Security & Health": lambda: build_security_health(parser, allow_probe=allow_probe),
        "Policies & NAT": lambda: build_policies_nat(parser),
        "Objects": lambda: build_objects(parser),
        "Interfaces & Network": lambda: build_interfaces_network(parser),
        "Security Profiles": lambda: build_security(parser),
        "VPN": lambda: build_vpn(parser),
        "Users & Auth": lambda: build_user_auth(parser),
        "WiFi & Switch": lambda: build_wifi(parser),
        "System & Logs": lambda: build_system_logs(parser),
        # Backward-compatible legacy section aliases
        "Summary": lambda: build_summary(parser, allow_probe=allow_probe),
        "Interfaces": lambda: build_interfaces(parser),
        "Network": lambda: build_network(parser),
        "Policy & Objects": lambda: build_policy_objects(parser),
        "Security": lambda: build_security(parser),
        "User & Auth": lambda: build_user_auth(parser),
        "System": lambda: build_system_logs(parser),
        "Log & Report": lambda: build_log_settings(parser),
    }
    if section not in builders:
        raise KeyError(f"Unknown FortiGate section: {section}")
    res = builders[section]()
    res["section"] = section
    return res
