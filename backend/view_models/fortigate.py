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
from backend.exposure_check import (
    build_exposure_overview_blocks,
    find_fortigate_public_mgmt_exposure,
)

_INTERNAL_ADDR_KEYS = {
    "network_obj",
    "network",
    "broadcast",
    "prefixlen",
    "start_int",
    "end_int",
}


def _table_block(
    rows: list[dict[str, Any]] | None,
    table_id: str,
    title: str = "",
    empty_text: str = "Not configured.",
    caption: str = "",
    export_filename: str | None = None,
    row_class_fn: Callable[[dict[str, Any]], str] | None = None,
    filter_col: str | None = None,
    drop_keys: set[str] | None = None,
    legend: list[dict[str, str] | str] | None = None,
) -> dict[str, Any]:
    if not rows:
        return {"type": "alert", "variant": "info", "text": empty_text}

    skip = drop_keys or set()
    cols = [k for k in rows[0].keys() if not str(k).startswith("_") and k not in skip]
    clean_rows = [{c: ("" if r.get(c) is None else str(r.get(c))) for c in cols} for r in rows]
    row_classes = [row_class_fn(r) if row_class_fn else "" for r in rows]

    blk: dict[str, Any] = {
        "type": "table",
        "id": table_id,
        "title": title,
        "columns": cols,
        "rows": clean_rows,
        "row_classes": row_classes,
        "caption": caption,
        "export_filename": export_filename or f"{table_id}.csv",
    }
    if filter_col and filter_col in cols:
        blk["filter_col"] = filter_col
    if legend:
        blk["legend"] = legend
    return blk


def _on(v: Any) -> bool:
    return str(v or "disable").lower() in ("enable", "on", "all", "enabled", "yes", "1", "true")


def _toggle_row(label: str, val: Any) -> dict[str, str]:
    on = _on(val)
    return {"label": label, "value": "ON" if on else "OFF", "tone": "allow" if on else "muted"}


# ── 1. Summary ───────────────────────────────────────────────────────────────
def build_summary(parser: Any) -> dict[str, Any]:
    hostname = parser.get_hostname()
    try:
        dns = parser.get_dns()
        dns_primary = dns.get("primary", "Unknown")
        dns_secondary = dns.get("secondary", "Unknown")
    except Exception:
        dns_primary, dns_secondary = "Unknown", "Unknown"

    def _safe(fn, default="Unknown"):
        try:
            return fn()
        except Exception:
            return default

    wan_ip = _safe(parser.get_wan_ip)
    mgmt_info = _safe(parser.get_management_ip, {"ip": "Not configured", "sub": ""})
    if not isinstance(mgmt_info, dict):
        mgmt_info = {"ip": str(mgmt_info), "sub": ""}
    sys_settings = _safe(parser.parse_system_settings, {}) or {}
    http_port = str(sys_settings.get("http_port") or "80")
    https_port = str(sys_settings.get("https_port") or "443")
    ssh_port = str(sys_settings.get("ssh_port") or "22")
    serial = _safe(parser.get_serial_number)
    firmware = _safe(parser.get_firmware_version)
    ha = _safe(parser.get_ha_config, {"enabled": False})

    ha_badge = (
        {"text": f"HA Enabled · {ha.get('mode', 'Cluster')}", "variant": "allow"}
        if ha.get("enabled")
        else {"text": "Standalone", "variant": "muted"}
    )
    exposure_findings = find_fortigate_public_mgmt_exposure(parser)
    exposure_badge, exposure_card = build_exposure_overview_blocks(exposure_findings)
    audit_result = run_fortigate_audit(parser)
    audit_badge, audit_expander = build_audit_overview_blocks(audit_result)

    blocks: list[dict[str, Any]] = [
        {
            "type": "hero",
            "eyebrow": "FortiGate Appliance",
            "title": str(hostname),
            "subtitle": f"Firmware {firmware} · S/N {serial}",
            "badges": [ha_badge, exposure_badge, audit_badge],
        },
    ]
    if exposure_card is not None:
        blocks.append(exposure_card)
    blocks.append(audit_expander)

    mgmt_item: dict[str, Any] = {"label": "Management IP", "value": mgmt_info.get("ip", "Not configured")}
    if mgmt_info.get("sub"):
        mgmt_item["sub"] = mgmt_info["sub"]

    blocks.extend([
        {"type": "section_header", "title": "System Overview"},
        {
            "type": "kv_grid",
            "items": [
                {"label": "Hostname", "value": hostname},
                mgmt_item,
                {"label": "WAN IP / Netmask", "value": wan_ip},
                {"label": "Admin Ports", "value": f"HTTPS {https_port} · SSH {ssh_port}", "sub": f"HTTP {http_port}"},
                {"label": "Primary DNS", "value": dns_primary, "sub": f"Secondary: {dns_secondary}"},
                {"label": "Serial Number", "value": serial},
                {"label": "Firmware Version", "value": firmware},
            ],
        },
    ])
    return {"section": "Summary", "blocks": blocks}


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

    tabs = [
        {"label": "IPAM", "blocks": [_table_block(parser.parse_ipam(), "fg_ipam", empty_text="No IPAM configuration found.")]},
        {"label": "FortiExtender", "blocks": [_table_block(parser.parse_fortiextender(), "fg_fortiext", empty_text="No FortiExtender configuration found.")]},
        {"label": "SD-WAN", "blocks": sdwan_blocks},
        {
            "label": "Static Routes",
            "blocks": [
                {"type": "route_lookup", "vendor": "fg"},
                _table_block(static_rows, "fg_static_routes", empty_text="No static routes configured.", row_class_fn=_dis_cls, legend=_route_legend, caption=f"{st_en} active · {len(static_rows) - st_en} disabled"),
            ],
        },
        {"label": "Policy Routes", "blocks": [_table_block(pr_rows, "fg_policy_routes", empty_text="No policy routes configured.", row_class_fn=_dis_cls, legend=_route_legend, caption=f"{pr_en} active · {len(pr_rows) - pr_en} disabled")]},
        {"label": "RIP", "blocks": rip_blocks},
        {"label": "OSPF", "blocks": ospf_blocks},
        {"label": "BGP", "blocks": bgp_blocks},
        {"label": "Routing Objects", "blocks": robj_blocks},
        {"label": "Multicast", "blocks": mcast_blocks},
    ]
    return {"section": "Network", "blocks": [{"type": "tabs", "id": "fg_network_tabs", "tabs": tabs}]}


# ── 4. Policy & Objects ──────────────────────────────────────────────────────
def build_policy_objects(parser: Any) -> dict[str, Any]:
    policies = parser.parse_policies()
    iface_names = parser.get_interface_names() if hasattr(parser, "get_interface_names") else []
    iface_opts = ["any"] + iface_names

    _dis_warn = lambda r: "row-warn" if str(r.get("Status", "")).lower() == "disable" else ""
    _pol_legend = [
        {"label": "Enabled Policy (default)", "variant": "default"},
        {"label": "Disabled Policy (amber)", "variant": "warn"},
    ]

    addr = parser.parse_addresses()
    addr_tabs = [
        {
            "label": label,
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

    svc_data = parser.parse_services()
    services = svc_data.get("services", [])

    proto_rows = parser.parse_protocol_options()

    tabs = [
        {
            "label": "Firewall Policy",
            "blocks": [
                {
                    "type": "expander",
                    "title": "🔍 Policy Lookup (Traffic Simulator)",
                    "blocks": [{"type": "fg_policy_lookup", "interfaces": iface_opts}],
                },
                _table_block(
                    policies,
                    "fg_fw_policies",
                    empty_text="No firewall policies found.",
                    row_class_fn=_dis_warn,
                    legend=_pol_legend,
                    export_filename="fg_firewall_policies.csv",
                    caption=f"{len(policies)} policies",
                ),
            ],
        },
        {"label": "Proxy Policy", "blocks": [_table_block(parser.parse_proxy_policy(), "fg_proxy_pol", empty_text="No proxy policies found.", row_class_fn=_dis_warn, legend=_pol_legend, export_filename="fg_proxy_policies.csv")]},
        {"label": "Auth Rules", "blocks": [_table_block(parser.parse_auth_rules(), "fg_auth_rules", empty_text="No authentication rules found.")]},
        {"label": "Addresses", "blocks": [{"type": "tabs", "id": "fg_addr_sub", "tabs": addr_tabs}]},
        {"label": "Services", "blocks": [_table_block(services, "fg_services", empty_text="No custom services found.", filter_col="Category")]},
        {"label": "Schedules", "blocks": [_table_block(parser.parse_schedules(), "fg_schedules", empty_text="No schedules found.")]},
        {"label": "Virtual IPs", "blocks": [_table_block(parser.parse_vip(), "fg_vips", empty_text="No Virtual IPs found.", export_filename="fg_virtual_ips.csv")]},
        {"label": "IP Pools", "blocks": [_table_block(parser.parse_ip_pools(), "fg_ip_pools", empty_text="No IP pools found.")]},
        {"label": "Protocol Options", "blocks": [_table_block(proto_rows, "fg_proto_opts", empty_text="No protocol options profiles found.", filter_col="Profile")]},
        {"label": "Traffic Shaping", "blocks": [_table_block(parser.parse_traffic_shaping(), "fg_traffic_shaping", empty_text="No traffic shapers found.")]},
        {"label": "Virtual Servers", "blocks": [_table_block(parser.parse_virtual_servers(), "fg_vservers", empty_text="No virtual servers found.")]},
        {"label": "Health Check", "blocks": [_table_block(parser.parse_health_check(), "fg_health_checks", empty_text="No health check monitors found.")]},
    ]
    return {"section": "Policy & Objects", "blocks": [{"type": "tabs", "id": "fg_po_tabs", "tabs": tabs}]}


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

    tabs = [
        {"label": "Antivirus", "blocks": _sec_profile_selector(parser.parse_antivirus(), "fg_sel_av", _av)},
        {"label": "Web Filter", "blocks": _sec_profile_selector(parser.parse_webfilter(), "fg_sel_wf", _wf)},
        {"label": "DNS Filter", "blocks": _sec_profile_selector(parser.parse_dnsfilter(), "fg_sel_dns", _dns)},
        {"label": "App Control", "blocks": _sec_profile_selector(parser.parse_appcontrol(), "fg_sel_app", _app)},
        {"label": "IPS", "blocks": _sec_profile_selector(parser.parse_ips(), "fg_sel_ips", _ips)},
        {"label": "File Filter", "blocks": _sec_profile_selector(parser.parse_filefilter(), "fg_sel_ff", _ff)},
        {"label": "Email Filter", "blocks": _sec_profile_selector(parser.parse_emailfilter(), "fg_sel_ef", _ef)},
        {"label": "VoIP", "blocks": _sec_profile_selector(parser.parse_voip(), "fg_sel_voip", _voip)},
        {"label": "WAF", "blocks": _sec_profile_selector(parser.parse_waf(), "fg_sel_waf", _waf)},
        {"label": "SSL Inspection", "blocks": _sec_profile_selector(parser.parse_ssl_inspection(), "fg_sel_ssl", _ssl)},
        {"label": "Web Rating Overrides", "blocks": [_table_block(parser.parse_web_rating_override(), "fg_wro", empty_text="No web rating overrides configured.", filter_col="Category Name")]},
        {"label": "Web Profile Overrides", "blocks": [_table_block(parser.parse_web_profile_override(), "fg_wpo", empty_text="No web profile overrides configured.")]},
    ]
    return {"section": "Security", "blocks": [{"type": "tabs", "id": "fg_sec_tabs", "tabs": tabs}]}


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

    tabs = [
        {"label": "IPSec Tunnels", "blocks": ipsec_blocks},
        {"label": "IPSec Concentrator", "blocks": [_table_block(parser.parse_ipsec_concentrator(), "fg_ipsec_conc", empty_text="No IPSec concentrators configured.")]},
        {"label": "SSL-VPN Portals", "blocks": portal_blocks},
        {"label": "SSL-VPN Settings", "blocks": ssl_set_blocks},
        {"label": "SSL-VPN Clients", "blocks": [_table_block(parser.parse_ssl_clients(), "fg_ssl_clients", empty_text="No SSL-VPN client configurations found.")]},
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

    tabs = [
        {
            "label": "User Definition",
            "blocks": [
                _table_block(
                    parser.parse_user_local(),
                    "fg_users",
                    empty_text="No local users configured.",
                    row_class_fn=lambda r: "row-warn" if str(r.get("Status", "")).lower() == "disable" else "",
                    legend=[
                        {"label": "Enabled User (default)", "variant": "default"},
                        {"label": "Disabled User (amber)", "variant": "warn"},
                    ],
                )
            ],
        },
        {"label": "User Groups", "blocks": [_table_block(parser.parse_user_groups(), "fg_user_groups", empty_text="No user groups configured.")]},
        {"label": "Guest Management", "blocks": [_table_block(parser.parse_guest_users(), "fg_guest_users", empty_text="No guest users configured.")]},
        {"label": "LDAP Servers", "blocks": [_table_block(parser.parse_ldap(), "fg_ldap", empty_text="No LDAP servers configured.", export_filename="fg_ldap_servers.csv")]},
        {"label": "RADIUS Servers", "blocks": [_table_block(parser.parse_radius(), "fg_radius", empty_text="No RADIUS servers configured.", export_filename="fg_radius_servers.csv")]},
        {"label": "Single Sign-On", "blocks": [_table_block(parser.parse_fsso(), "fg_fsso", empty_text="No FSSO agents configured.")]},
        {"label": "FortiToken", "blocks": [_table_block(parser.parse_fortitoken(), "fg_fortitoken", empty_text="No FortiTokens configured.", export_filename="fg_fortitokens.csv")]},
        {"label": "Auth Settings", "blocks": auth_blocks},
    ]
    return {"section": "User & Auth", "blocks": [{"type": "tabs", "id": "fg_user_tabs", "tabs": tabs}]}


# ── 8. WiFi & Switch ─────────────────────────────────────────────────────────
def build_wifi(parser: Any) -> dict[str, Any]:
    tabs = [
        {"label": "Managed FortiAPs", "blocks": [_table_block(parser.parse_managed_fortiaps(), "fg_managed_aps", empty_text="No managed FortiAPs configured.", export_filename="fg_managed_fortiaps.csv")]},
        {
            "label": "SSIDs",
            "blocks": [
                _table_block(
                    parser.parse_ssids(),
                    "fg_ssids",
                    empty_text="No SSIDs configured.",
                    row_class_fn=lambda r: "row-warn" if str(r.get("Status", "")).lower() == "disable" else "",
                    legend=[
                        {"label": "Enabled SSID (default)", "variant": "default"},
                        {"label": "Disabled SSID (amber)", "variant": "warn"},
                    ],
                )
            ],
        },
        {"label": "FortiAP Profiles", "blocks": [_table_block(parser.parse_fortiap_profiles(), "fg_ap_profiles", empty_text="No FortiAP profiles configured.", export_filename="fg_fortiap_profiles.csv")]},
        {"label": "WIDS Profiles", "blocks": [_table_block(parser.parse_wids_profiles(), "fg_wids", empty_text="No WIDS profiles configured.", export_filename="fg_wids_profiles.csv")]},
        {"label": "Managed FortiSwitches", "blocks": [_table_block(parser.parse_managed_switches(), "fg_switches", empty_text="No managed FortiSwitches configured.", export_filename="fg_managed_switches.csv")]},
        {"label": "Port Policies", "blocks": [_table_block(parser.parse_switch_port_policies(), "fg_port_policies", empty_text="No port policies configured.")]},
        {"label": "NAC Policies", "blocks": [_table_block(parser.parse_nac_policies(), "fg_nac", empty_text="No NAC policies configured.", export_filename="fg_nac_policies.csv")]},
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
        settings_blocks = [
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Hostname", "value": s.get("hostname", "-")},
                    {"label": "Time Zone", "value": tz_map.get(tz_raw, f"TZ {tz_raw}")},
                    {"label": "VDOM Mode", "value": s.get("vdom_status", "disable")},
                    {"label": "Admin Lockout Threshold", "value": s.get("admin_lockout_threshold", "-")},
                ],
            },
            {
                "type": "card",
                "rows": [
                    _toggle_row("FortiGuard Updates", s.get("fgd_alert_subscription", "disable")),
                    _toggle_row("Revision Backup on Upgrade", s.get("revision_backup_on_upgrade", "disable")),
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

    tabs = [
        {
            "label": "Administrators",
            "blocks": [
                _table_block(
                    admins,
                    "fg_admins",
                    empty_text="No administrators configured.",
                    row_class_fn=lambda r: "row-warn" if r.get("Profile") == "super_admin" else "",
                    legend=[
                        {"label": "super_admin Full Privilege (amber)", "variant": "warn"},
                        {"label": "Scoped Admin Profile (default)", "variant": "default"},
                    ],
                    export_filename="fg_administrators.csv",
                )
            ],
        },
        {"label": "Admin Profiles", "blocks": prof_blocks},
        {"label": "Settings", "blocks": settings_blocks},
        {"label": "HA", "blocks": ha_blocks},
        {"label": "SNMP", "blocks": snmp_blocks},
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


def build_fortigate_section(section: str, parser: Any) -> dict[str, Any]:
    builders = {
        "Summary": lambda: build_summary(parser),
        "Interfaces": lambda: build_interfaces(parser),
        "Network": lambda: build_network(parser),
        "Policy & Objects": lambda: build_policy_objects(parser),
        "Security": lambda: build_security(parser),
        "VPN": lambda: build_vpn(parser),
        "User & Auth": lambda: build_user_auth(parser),
        "WiFi & Switch": lambda: build_wifi(parser),
        "System": lambda: build_system(parser),
        "Log & Report": lambda: build_log_settings(parser),
    }
    if section not in builders:
        raise KeyError(f"Unknown FortiGate section: {section}")
    return builders[section]()
