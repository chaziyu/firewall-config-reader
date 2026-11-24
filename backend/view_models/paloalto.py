"""
backend/view_models/paloalto.py
Builds structured UI block payloads for all 5 Palo Alto PAN-OS sections:
  - Dashboard
  - Policies (incl. Test Policy Match metadata)
  - Objects
  - Network
  - Device
"""

from __future__ import annotations

from typing import Any, Callable

from backend.audit_service import build_audit_overview_blocks, run_paloalto_audit
from backend.exposure_check import (
    build_exposure_overview_blocks,
    find_paloalto_public_mgmt_exposure,
)
from backend.lifecycle_service import (
    build_paloalto_lifecycle_blocks,
    evaluate_paloalto_lifecycle,
)
from backend.vpn_inspector_service import build_vpn_inspector_blocks, inspect_paloalto_vpns


def _table_block(
    rows: list[dict[str, Any]] | None,
    table_id: str,
    title: str = "",
    empty_text: str = "Not configured.",
    caption: str = "",
    export_filename: str | None = None,
    row_class_fn: Callable[[dict[str, Any]], str] | None = None,
    filter_col: str | None = None,
    legend: list[dict[str, str] | str] | None = None,
) -> dict[str, Any]:
    if not rows:
        return {"type": "alert", "variant": "info", "text": empty_text}

    cols = [k for k in rows[0].keys() if not str(k).startswith("_")]
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


def _dict_table_block(d: dict[str, Any] | None, table_id: str, fname: str, title: str = "") -> dict[str, Any]:
    if not d:
        return {"type": "alert", "variant": "info", "text": "No data."}
    rows = [{"Setting": str(k), "Value": str(v)} for k, v in d.items()]
    return _table_block(rows, table_id=table_id, title=title, export_filename=fname)


def _policy_row_class(r: dict[str, Any]) -> str:
    if r.get("_disabled"):
        return "row-danger"
    if r.get("_panorama"):
        return "row-purple"
    return ""


_PA_POLICY_LEGEND = [
    {"label": "Enabled (default)", "variant": "default"},
    {"label": "Disabled (red)", "variant": "danger"},
    {"label": "Panorama (purple)", "variant": "purple"},
]


def _policy_block(rows: list[dict[str, Any]] | None, key: str, label: str) -> dict[str, Any]:
    if not rows:
        return {"type": "alert", "variant": "info", "text": f"No {label} configured."}
    dis = sum(1 for r in rows if r.get("_disabled"))
    pan = sum(1 for r in rows if r.get("_panorama"))
    cap = f"Total: {len(rows)} | Enabled: {len(rows) - dis} | Disabled: {dis}"
    if pan:
        cap += f" | Panorama: {pan}"
    return _table_block(
        rows,
        table_id=key,
        caption=cap,
        export_filename=f"{key}.csv",
        row_class_fn=_policy_row_class,
        legend=_PA_POLICY_LEGEND,
    )


# ── 1. Dashboard ─────────────────────────────────────────────────────────────
def build_dashboard(
    parser: Any,
    network_parser: Any = None,
    device_parser: Any = None,
    policies_parser: Any = None,
    objects_parser: Any = None,
) -> dict[str, Any]:
    info = parser.get_system_info()
    ha = parser.get_ha_info()

    hostname = str(info.get("hostname", "Unknown"))
    sw_version = str(info.get("software_version", "—"))
    timezone = str(info.get("timezone", "—"))
    adv_routing = str(info.get("adv_routing", "Off"))
    dup_ip = str(info.get("dup_ip", "Disable"))

    lifecycle = evaluate_paloalto_lifecycle(
        sw_version,
        is_exact_version=bool(info.get("software_version_exact", True)),
        cache_only=True,
    )
    lifecycle_badge, lifecycle_card = build_paloalto_lifecycle_blocks(lifecycle)
    exposure_findings = find_paloalto_public_mgmt_exposure(
        network_parser,
        device_parser=device_parser,
        dashboard_parser=parser,
    )
    exposure_badge, exposure_card = build_exposure_overview_blocks(exposure_findings)
    audit_result = run_paloalto_audit(
        {
            "Policies": policies_parser,
            "Objects": objects_parser,
            "Network": network_parser,
        }
    )
    audit_badge, audit_expander = build_audit_overview_blocks(audit_result)

    blocks: list[dict[str, Any]] = [
        {
            "type": "hero",
            "eyebrow": "PAN-OS Appliance",
            "title": hostname,
            "subtitle": f"PAN-OS {sw_version} · {timezone}",
            "badges": [
                {
                    "text": f"Advanced Routing: {adv_routing}",
                    "variant": "allow" if adv_routing == "On" else "muted",
                },
                {
                    "text": f"Duplicate IP: {dup_ip}",
                    "variant": "info" if dup_ip == "Enable" else "muted",
                },
                lifecycle_badge,
                exposure_badge,
                audit_badge,
            ],
        },
    ]

    blocks.extend([
        {"type": "section_header", "title": "Management & Network Identity"},
        {
            "type": "kv_grid",
            "items": [
                {"label": "Management IP", "value": info.get("ip_address", "—")},
                {"label": "Netmask", "value": info.get("netmask", "—")},
                {"label": "Default Gateway", "value": info.get("default_gateway", "") or "—"},
                {"label": "IPv6 Address", "value": info.get("ipv6_address", "Unknown")},
                {"label": "IPv6 Link-Local", "value": info.get("ipv6_link_local", "Unknown")},
                {"label": "IPv6 Default GW", "value": info.get("ipv6_gateway", "") or "—"},
                {"label": "Software Version", "value": sw_version},
                {"label": "Timezone", "value": timezone},
            ],
        },
        {"type": "section_header", "title": "High Availability"},
    ])

    if not ha.get("enabled"):
        blocks.append(
            {
                "type": "card",
                "title": "Standalone Mode",
                "subtitle": "High Availability is not enabled in this PAN-OS configuration.",
                "badge": {"text": "Not Enabled", "variant": "muted"},
            }
        )
    else:
        mode = ha.get("mode", "active-passive")
        mode_label = "Active-Passive" if mode == "active-passive" else "Active-Active"
        local_state = "Active" if mode == "active-passive" else "Active-Primary"
        blocks.append(
            {
                "type": "card",
                "title": f"{mode_label} Cluster",
                "subtitle": f"Group ID: {ha.get('group_id', '—')}",
                "badge": {
                    "text": "HA Enabled",
                    "variant": "allow" if mode == "active-passive" else "info",
                },
            }
        )
        blocks.append(
            {
                "type": "kv_grid",
                "items": [
                    {"label": "Local State", "value": local_state},
                    {"label": "Peer IP", "value": ha.get("peer_ip", "—")},
                    {"label": "HA1 Interface", "value": ha.get("ha1_port", "—")},
                    {"label": "HA1 IP", "value": ha.get("ha1_ip", "—")},
                ],
            }
        )

    blocks.append(lifecycle_card)
    if exposure_card is not None:
        blocks.append(exposure_card)
    blocks.append({"type": "where_used_lookup", "vendor": "pa"})
    blocks.append(audit_expander)

    return {"section": "Dashboard", "blocks": blocks}


# ── 2. Policies ──────────────────────────────────────────────────────────────
def build_policies(parser: Any) -> dict[str, Any]:
    zones = ["any"] + (parser.get_zones_list() if hasattr(parser, "get_zones_list") else [])
    intfs = ["any"] + (parser.get_interfaces_list() if hasattr(parser, "get_interfaces_list") else [])

    def _pol_tab(title: str, ptype: str | None, rows: list, key: str, label: str) -> dict[str, Any]:
        blks: list[dict[str, Any]] = []
        if ptype:
            blks.append(
                {
                    "type": "pa_policy_test",
                    "policy_type": ptype,
                    "zones": zones,
                    "interfaces": intfs,
                }
            )
        blks.append(_policy_block(rows, key, label))
        return {"label": title, "blocks": blks}

    tabs = [
        _pol_tab("Security", "security", parser.get_security_rules(), "pa_security_rules", "Security rules"),
        _pol_tab("NAT", "nat", parser.get_nat_rules(), "pa_nat_rules", "NAT rules"),
        _pol_tab("QoS", None, parser.get_qos_rules(), "pa_qos_rules", "QoS rules"),
        _pol_tab("Policy Based Forwarding", "pbf", parser.get_pbf_rules(), "pa_pbf_rules", "PBF rules"),
        _pol_tab("Decryption", "decryption", parser.get_decryption_rules(), "pa_decrypt_rules", "Decryption rules"),
        _pol_tab("Tunnel Inspection", None, parser.get_tunnel_inspection_rules(), "pa_tunnel_rules", "Tunnel inspection rules"),
        _pol_tab("App Override", None, parser.get_app_override_rules(), "pa_appov_rules", "App override rules"),
        _pol_tab("Authentication", "auth", parser.get_auth_rules(), "pa_auth_rules", "Authentication rules"),
        _pol_tab("DoS Protection", "dos", parser.get_dos_rules(), "pa_dos_rules", "DoS rules"),
        _pol_tab("SD-WAN", None, parser.get_sdwan_rules(), "pa_sdwan_rules", "SD-WAN rules"),
    ]

    return {"section": "Policies", "blocks": [{"type": "tabs", "id": "pa_policies_tabs", "tabs": tabs}]}


# ── 3. Objects ───────────────────────────────────────────────────────────────
def _sev_row_class(r: dict[str, Any]) -> str:
    s = str(r.get("Severity", "")).lower()
    if "critical" in s:
        return "row-danger"
    if "high" in s:
        return "row-warn"
    return ""


def _url_cat_row_class(r: dict[str, Any]) -> str:
    sa = str(r.get("Site Access", "")).lower()
    if sa == "block":
        return "row-danger"
    if sa == "alert":
        return "row-warn"
    if sa == "allow":
        return "row-success"
    return ""


def _sdwan_dist_row_class(r: dict[str, Any]) -> str:
    d = str(r.get("Traffic Distribution", "")).lower()
    if "top" in d:
        return "row-info"
    if "weighted" in d:
        return "row-purple"
    return ""


def _sched_row_class(r: dict[str, Any]) -> str:
    return "row-warn" if str(r.get("Recurrence", "")).lower() == "one-time" else ""


def build_objects(parser: Any) -> dict[str, Any]:
    # Security profile groups as expanders
    sp_blocks: list[dict[str, Any]] = []
    pg_rows = parser.get_security_profile_groups()
    if pg_rows:
        sp_blocks.append({"type": "section_header", "title": "Profile Groups"})
        for row in pg_rows:
            items = [
                {
                    "label": k,
                    "value": str(v),
                    "variant": "allow" if str(v) != "None" else "muted",
                }
                for k, v in row.items()
                if k != "Name"
            ]
            sp_blocks.append(
                {
                    "type": "expander",
                    "title": str(row.get("Name", "Profile Group")),
                    "blocks": [{"type": "badge_grid", "items": items}],
                }
            )

    url_profiles = parser.get_url_filtering_profiles()
    if url_profiles:
        url_block: dict[str, Any] = {
            "type": "profile_selector",
            "id": "pa_url_filtering",
            "label": "Select URL Filtering Profile",
            "options": [
                {
                    "name": p["name"],
                    "blocks": [
                        _table_block(
                            p.get("categories", []),
                            table_id=f"pa_url_cat_{i}",
                            empty_text="No category overrides configured.",
                            row_class_fn=_url_cat_row_class,
                            legend=[
                                {"label": "Allow (green)", "variant": "success"},
                                {"label": "Alert (amber)", "variant": "warn"},
                                {"label": "Block (red)", "variant": "danger"},
                            ],
                            caption=f"{len(p.get('categories', []))} categories",
                            export_filename=f"pa_url_{p['name']}.csv",
                        )
                    ],
                }
                for i, p in enumerate(url_profiles)
            ],
        }
    else:
        url_block = {"type": "alert", "variant": "info", "text": "No custom URL filtering profiles."}

    _sev_legend = [
        {"label": "Includes Critical Severity (red)", "variant": "danger"},
        {"label": "Includes High Severity (amber)", "variant": "warn"},
        {"label": "Medium / Low / Info (default)", "variant": "default"},
    ]

    sp_blocks.append(
        {
            "type": "tabs",
            "id": "pa_sec_prof_tabs",
            "tabs": [
                {"label": "Antivirus", "blocks": [_table_block(parser.get_av_profiles(), "pa_av_profs", empty_text="No custom antivirus profiles.")]},
                {"label": "Anti-Spyware", "blocks": [_table_block(parser.get_spyware_profiles(), "pa_spyware_profs", empty_text="No custom anti-spyware profiles.", row_class_fn=_sev_row_class, legend=_sev_legend)]},
                {"label": "Vulnerability", "blocks": [_table_block(parser.get_vulnerability_profiles(), "pa_vuln_profs", empty_text="No custom vulnerability profiles.", row_class_fn=_sev_row_class, legend=_sev_legend)]},
                {"label": "URL Filtering", "blocks": [url_block]},
                {"label": "File Blocking", "blocks": [_table_block(parser.get_file_blocking_profiles(), "pa_fileblock_profs", empty_text="No custom file blocking profiles.")]},
                {"label": "WildFire", "blocks": [_table_block(parser.get_wildfire_profiles(), "pa_wildfire_profs", empty_text="No custom WildFire profiles.")]},
                {"label": "Data Filtering", "blocks": [_table_block(parser.get_data_filtering_profiles(), "pa_datafilt_profs", empty_text="No custom data filtering profiles.")]},
                {"label": "DoS Protection", "blocks": [_table_block(parser.get_dos_protection_profiles(), "pa_dos_profs", empty_text="No custom DoS protection profiles.")]},
            ],
        }
    )

    # Decryption profiles
    dec_rows = parser.get_decryption_profiles()
    if not dec_rows:
        dec_blocks = [{"type": "alert", "variant": "info", "text": "No decryption profiles configured."}]
    else:
        dec_blocks = []
        for row in dec_rows:
            sfp_rows = [
                {
                    "label": k.replace("SFP - ", ""),
                    "value": str(row[k]),
                    "tone": "deny" if str(row[k]).lower() == "yes" else "allow",
                }
                for k in row
                if k.startswith("SFP")
            ]
            proto_rows = [
                {"label": k, "value": str(row.get(k, "-"))}
                for k in ("Min TLS Version", "Max TLS Version", "Allow SHA1", "Allow 3DES", "Allow RC4")
            ]
            proto_rows.append({"label": "No Decryption — Block Untrusted", "value": str(row.get("ND - Block Untrusted", "-"))})
            proto_rows.append({"label": "No Decryption — Block Expired", "value": str(row.get("ND - Block Expired", "-"))})
            dec_blocks.append(
                {
                    "type": "expander",
                    "title": str(row.get("Name", "Decryption Profile")),
                    "blocks": [
                        {"type": "card", "title": "SSL Forward Proxy", "rows": sfp_rows},
                        {"type": "card", "title": "SSL Protocol & No Decryption", "rows": proto_rows},
                    ],
                }
            )

    tabs = [
        {
            "label": "Addresses",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_addr_sub",
                    "tabs": [
                        {"label": "Addresses", "blocks": [_table_block(parser.get_addresses(), "pa_addresses", empty_text="No addresses configured.", filter_col="Type")]},
                        {"label": "Address Groups", "blocks": [_table_block(parser.get_address_groups(), "pa_address_groups", empty_text="No address groups configured.")]},
                        {"label": "Application Groups", "blocks": [_table_block(parser.get_application_groups(), "pa_application_groups", empty_text="No application groups configured.")]},
                    ],
                }
            ],
        },
        {
            "label": "Services",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_svc_sub",
                    "tabs": [
                        {"label": "Services", "blocks": [_table_block(parser.get_services(), "pa_services", empty_text="No services configured.")]},
                        {"label": "Service Groups", "blocks": [_table_block(parser.get_service_groups(), "pa_service_groups", empty_text="No service groups configured.")]},
                    ],
                }
            ],
        },
        {"label": "Tags", "blocks": [_table_block(parser.get_tags(), "pa_tags", empty_text="No tags configured.")]},
        {"label": "Regions", "blocks": [_table_block(parser.get_regions(), "pa_regions", empty_text="No regions configured.")]},
        {"label": "Dynamic User Groups", "blocks": [_table_block(parser.get_dynamic_user_groups(), "pa_dynamic_groups", empty_text="No dynamic user groups configured.")]},
        {"label": "Devices", "blocks": [_table_block(parser.get_devices(), "pa_devices", empty_text="No device objects configured.")]},
        {
            "label": "GlobalProtect HIP",
            "blocks": [
                {"type": "section_header", "title": "HIP Objects"},
                _table_block(parser.get_hip_objects(), "pa_hip_objects", empty_text="No HIP objects configured."),
                {"type": "section_header", "title": "HIP Profiles"},
                _table_block(parser.get_hip_profiles(), "pa_hip_profiles", empty_text="No HIP profiles configured."),
            ],
        },
        {"label": "External Dynamic Lists", "blocks": [_table_block(parser.get_external_dynamic_lists(), "pa_edl", empty_text="No custom external dynamic lists configured.", export_filename="pa_external_dynamic_lists.csv", filter_col="Type")]},
        {
            "label": "Custom Objects",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_custom_obj_sub",
                    "tabs": [
                        {"label": "Data Patterns", "blocks": [_table_block(parser.get_data_patterns(), "pa_data_patterns", empty_text="No custom data patterns configured.")]},
                        {"label": "Spyware", "blocks": [_table_block(parser.get_custom_spyware(), "pa_custom_spyware", empty_text="No custom spyware objects configured.")]},
                        {"label": "Vulnerability", "blocks": [_table_block(parser.get_custom_vulnerability(), "pa_custom_vulnerability", empty_text="No custom vulnerability objects configured.")]},
                        {"label": "URL Categories", "blocks": [_table_block(parser.get_custom_url_categories(), "pa_custom_url_categories", empty_text="No custom URL categories configured.")]},
                    ],
                }
            ],
        },
        {"label": "Security Profiles", "blocks": sp_blocks},
        {"label": "Log Forwarding", "blocks": [_table_block(parser.get_log_forwarding_profiles(), "pa_log_forwarding", empty_text="No log forwarding profiles configured.")]},
        {
            "label": "Authentication",
            "blocks": [
                {"type": "section_header", "title": "Authentication Profiles"},
                _table_block(parser.get_auth_profiles(), "pa_auth_profiles", empty_text="No authentication profiles configured."),
                {"type": "section_header", "title": "Authentication Sequences"},
                _table_block(parser.get_auth_sequences(), "pa_auth_sequences", empty_text="No authentication sequences configured."),
            ],
        },
        {"label": "Decryption Profiles", "blocks": dec_blocks},
        {
            "label": "SD-WAN Link Mgmt",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_sdwan_obj_sub",
                    "tabs": [
                        {"label": "Path Quality", "blocks": [_table_block(parser.get_sdwan_path_quality(), "pa_sdwan_path_quality", empty_text="No path quality profiles configured.")]},
                        {
                            "label": "Traffic Distribution",
                            "blocks": [
                                _table_block(
                                    parser.get_sdwan_traffic_dist(),
                                    "pa_sdwan_dist",
                                    empty_text="No traffic distribution profiles configured.",
                                    row_class_fn=_sdwan_dist_row_class,
                                    legend=[
                                        {"label": "Top Down Priority (blue)", "variant": "info"},
                                        {"label": "Weighted Session (purple)", "variant": "purple"},
                                        {"label": "Best Available Path (default)", "variant": "default"},
                                    ],
                                )
                            ],
                        },
                        {"label": "SaaS Quality", "blocks": [_table_block(parser.get_sdwan_saas_quality(), "pa_sdwan_saas", empty_text="No SaaS quality profiles configured.")]},
                        {"label": "Error Correction", "blocks": [_table_block(parser.get_sdwan_error_correction(), "pa_sdwan_error", empty_text="No error correction profiles configured.")]},
                    ],
                }
            ],
        },
        {
            "label": "Schedules",
            "blocks": [
                _table_block(
                    parser.get_schedules(),
                    "pa_schedules",
                    empty_text="No schedules configured.",
                    row_class_fn=_sched_row_class,
                    legend=[
                        {"label": "Recurring Schedule (default)", "variant": "default"},
                        {"label": "One-Time Schedule (amber)", "variant": "warn"},
                    ],
                )
            ],
        },
    ]

    return {"section": "Objects", "blocks": [{"type": "tabs", "id": "pa_objects_tabs", "tabs": tabs}]}


# ── 4. Network ───────────────────────────────────────────────────────────────
def _eth_row_class(r: dict[str, Any]) -> str:
    t = str(r.get("Type", ""))
    if t == "HA":
        return "row-warn"
    if "Aggregate (Parent)" in t:
        return "row-info"
    if "Sub-Interface" in t:
        return "row-muted"
    if t == "Virtual Wire":
        return "row-purple"
    return ""


def _qos_row_class(r: dict[str, Any]) -> str:
    pri = str(r.get("Priority", "")).lower()
    if pri == "real-time":
        return "row-danger"
    if pri == "high":
        return "row-warn"
    if pri == "medium":
        return "row-success"
    return ""


def build_network(parser: Any, policies_parser: Any = None) -> dict[str, Any]:
    # Virtual Routers
    vrs = parser.get_virtual_routers()
    if not vrs:
        vr_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No virtual routers."}]
    else:
        vr_summary = [{k: v for k, v in r.items() if k != "_vr_el"} for r in vrs]
        vr_blocks = [
            {
                "type": "route_lookup",
                "vendor": "pa",
                "virtual_routers": ["all"] + [str(v.get("Name", "default")) for v in vrs],
            },
            _table_block(vr_summary, "pa_vr_list", export_filename="pa_virtual_routers.csv", caption=f"{len(vrs)} virtual routers"),
        ]
        for i, vr_row in enumerate(vrs):
            detail = parser.get_vr_detail(vr_row["_vr_el"])
            ecmp = detail.get("ecmp", {})
            ecmp_enabled = ecmp.get("enabled") == "yes"
            ad = detail.get("ad", {})
            ad_rows = [{"Metric": k.replace("-", " ").title(), "Distance": v} for k, v in ad.items() if v != "-"]

            gen_blocks: list[dict[str, Any]] = [
                {
                    "type": "card",
                    "title": f"Interfaces ({len(detail.get('interfaces', []))})",
                    "subtitle": ", ".join(detail.get("interfaces", [])) or "None",
                    "badge": {"text": "ECMP Enabled" if ecmp_enabled else "ECMP Disabled", "variant": "allow" if ecmp_enabled else "muted"},
                }
            ]
            if ecmp_enabled:
                gen_blocks.append(
                    {
                        "type": "kv_grid",
                        "items": [
                            {"label": "ECMP Method", "value": ecmp.get("method", "-")},
                            {"label": "Symmetric Return", "value": ecmp.get("symmetric_return", "-")},
                            {"label": "Strict Source", "value": ecmp.get("strict_source", "-")},
                        ],
                    }
                )
            if ad_rows:
                gen_blocks.append(_table_block(ad_rows, f"pa_vr_{i}_ad", title="Admin Distances", export_filename=f"pa_vr_{detail['name']}_ad.csv"))

            sr = detail.get("static_v4", [])
            sr_block = _table_block(
                sr,
                f"pa_vr_{i}_routes",
                empty_text="No static routes.",
                export_filename=f"pa_vr_{detail['name']}_static_routes.csv",
                caption=f"{len(sr)} IPv4 routes",
                row_class_fn=lambda r: "row-success" if r.get("Path Mon") == "yes" else "",
                legend=[
                    {"label": "Path Monitoring Enabled (green)", "variant": "success"},
                    {"label": "Standard Static Route (default)", "variant": "default"},
                ],
            )

            bgp = detail.get("bgp", {})
            if bgp:
                bgp_blocks = [
                    {
                        "type": "kv_grid",
                        "items": [
                            {"label": "Enabled", "value": bgp.get("Enabled", "-")},
                            {"label": "Local AS", "value": bgp.get("Local AS", "-")},
                            {"label": "Graceful Restart", "value": bgp.get("Graceful Restart", "-")},
                        ],
                    }
                ]
            else:
                bgp_blocks = [{"type": "alert", "variant": "info", "text": "BGP not configured."}]

            vr_blocks.append(
                {
                    "type": "expander",
                    "title": f"{detail['name']} — Details",
                    "blocks": [
                        {
                            "type": "tabs",
                            "id": f"pa_vr_{i}_tabs",
                            "tabs": [
                                {"label": "General / ECMP", "blocks": gen_blocks},
                                {"label": "Static Routes", "blocks": [sr_block]},
                                {"label": "BGP", "blocks": bgp_blocks},
                            ],
                        }
                    ],
                }
            )

    # QoS Profiles
    qos_profiles = parser.get_qos_profiles()
    if not qos_profiles:
        qos_prof_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No QoS profiles."}]
    else:
        _qos_legend = [
            {"label": "Real-Time Priority (red)", "variant": "danger"},
            {"label": "High Priority (amber)", "variant": "warn"},
            {"label": "Medium Priority (green)", "variant": "success"},
            {"label": "Low Priority (default)", "variant": "default"},
        ]
        qos_prof_blocks = [
            {
                "type": "expander",
                "title": p["name"],
                "blocks": [
                    _table_block(
                        p.get("classes", []),
                        f"pa_qos_{i}",
                        empty_text="No classes.",
                        row_class_fn=_qos_row_class,
                        legend=_qos_legend,
                        export_filename=f"pa_qos_{p['name']}.csv",
                    )
                ],
            }
            for i, p in enumerate(qos_profiles)
        ]

    np_defs = [
        ("GP-IPSec Crypto", "get_gp_ipsec_crypto", "pa_gp_ipsec_c", "pa_gp_ipsec_crypto.csv", "No GP IPSec crypto profiles."),
        ("IKE Gateways", "get_ike_gateways", "pa_ike_gw", "pa_ike_gateways.csv", "No IKE gateways."),
        ("IKE Crypto", "get_ike_crypto_profiles", "pa_ike_c", "pa_ike_crypto.csv", "No IKE crypto profiles."),
        ("IPSec Crypto", "get_ipsec_crypto_profiles", "pa_ipsec_c", "pa_ipsec_crypto.csv", "No IPSec crypto profiles."),
        ("Monitor", "get_monitor_profiles", "pa_mon_p", "pa_monitor_profiles.csv", "No monitor profiles."),
        ("Interface Mgmt", "get_intf_mgmt_profiles", "pa_intf_mgmt", "pa_intf_mgmt_profiles.csv", "No interface management profiles."),
        ("Zone Protection", "get_zone_protection_profiles", "pa_zp_p", "pa_zone_protection_profiles.csv", "No zone protection profiles."),
        ("LLDP Profiles", "get_lldp_profiles", "pa_lldp_p", "pa_lldp_profiles.csv", "No LLDP profiles."),
        ("BFD Profiles", "get_bfd_profiles", "pa_bfd_p", "pa_bfd_profiles.csv", "No BFD profiles."),
    ]

    tabs = [
        {
            "label": "Interfaces",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_intf_sub",
                    "tabs": [
                        {
                            "label": "Ethernet / Aggregate",
                            "blocks": [
                                _table_block(
                                    parser.get_ethernet_interfaces(),
                                    "pa_eth_ifaces",
                                    empty_text="No ethernet/aggregate interfaces.",
                                    row_class_fn=_eth_row_class,
                                    legend=[
                                        {"label": "Physical / Layer3 (default)", "variant": "default"},
                                        {"label": "Aggregate Parent (blue)", "variant": "info"},
                                        {"label": "Sub-Interface (muted)", "variant": "muted"},
                                        {"label": "Virtual Wire (purple)", "variant": "purple"},
                                        {"label": "HA Interface (amber)", "variant": "warn"},
                                    ],
                                    export_filename="pa_ethernet_interfaces.csv",
                                )
                            ],
                        },
                        {"label": "VLAN", "blocks": [_table_block(parser.get_vlan_interfaces(), "pa_vlan_ifaces", empty_text="No VLAN interfaces.", export_filename="pa_vlan_interfaces.csv")]},
                        {"label": "Loopback", "blocks": [_table_block(parser.get_loopback_interfaces(), "pa_lo_ifaces", empty_text="No loopback interfaces.", export_filename="pa_loopback_interfaces.csv")]},
                        {"label": "Tunnel", "blocks": [_table_block(parser.get_tunnel_interfaces(), "pa_tun_ifaces", empty_text="No tunnel interfaces.", export_filename="pa_tunnel_interfaces.csv")]},
                        {"label": "SD-WAN", "blocks": [_table_block(parser.get_sdwan_interfaces(), "pa_sdwan_ifaces", empty_text="No SD-WAN interfaces.", export_filename="pa_sdwan_interfaces.csv")]},
                    ],
                }
            ],
        },
        {"label": "Zones", "blocks": [_table_block(parser.get_zones(), "pa_zones", empty_text="No zones configured.")]},
        {"label": "VLANs", "blocks": [_table_block(parser.get_vlans(), "pa_vlans", empty_text="No VLAN objects.")]},
        {"label": "Virtual Wires", "blocks": [_table_block(parser.get_virtual_wires(), "pa_vwires", empty_text="No virtual wires.", export_filename="pa_virtual_wires.csv")]},
        {"label": "Virtual Router", "blocks": vr_blocks},
        {
            "label": "IPSec & GRE Tunnels",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_tun_sub",
                    "tabs": [
                        {
                            "label": "IPSec Inspector",
                            "blocks": build_vpn_inspector_blocks(
                                inspect_paloalto_vpns(parser, policies_parser),
                                "pa",
                            ),
                        },
                        {"label": "IPSec Tunnels", "blocks": [_table_block(parser.get_ipsec_tunnels(), "pa_ipsec", empty_text="No IPSec tunnels.", export_filename="pa_ipsec_tunnels.csv")]},
                        {"label": "GRE Tunnels", "blocks": [_table_block(parser.get_gre_tunnels(), "pa_gre", empty_text="No GRE tunnels.", export_filename="pa_gre_tunnels.csv")]},
                    ],
                }
            ],
        },
        {
            "label": "DHCP",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_dhcp_sub",
                    "tabs": [
                        {"label": "DHCP Servers", "blocks": [_table_block(parser.get_dhcp_servers(), "pa_dhcp_srv", empty_text="No DHCP servers.", export_filename="pa_dhcp_servers.csv")]},
                        {"label": "DHCP Relay", "blocks": [_table_block(parser.get_dhcp_relays(), "pa_dhcp_relay", empty_text="No DHCP relays.", export_filename="pa_dhcp_relays.csv")]},
                    ],
                }
            ],
        },
        {"label": "DNS Proxy", "blocks": [_table_block(parser.get_dns_proxies(), "pa_dns_proxy", empty_text="No DNS proxy.")]},
        {
            "label": "GlobalProtect",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_gp_sub",
                    "tabs": [
                        {"label": "Portals", "blocks": [_table_block(parser.get_gp_portals(), "pa_gp_portals", empty_text="No GP portals.")]},
                        {"label": "Gateways", "blocks": [_table_block(parser.get_gp_gateways(), "pa_gp_gw", empty_text="No GP gateways.", export_filename="pa_gp_gateways.csv")]},
                        {"label": "MDM", "blocks": [_table_block(parser.get_gp_mdm(), "pa_gp_mdm", empty_text="No MDM configured.")]},
                        {"label": "Clientless Apps", "blocks": [_table_block(parser.get_gp_clientless_apps(), "pa_gp_apps", empty_text="No clientless apps.", export_filename="pa_gp_clientless_apps.csv")]},
                        {"label": "Clientless Groups", "blocks": [_table_block(parser.get_gp_clientless_groups(), "pa_gp_grps", empty_text="No clientless groups.", export_filename="pa_gp_clientless_groups.csv")]},
                    ],
                }
            ],
        },
        {
            "label": "QoS",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_qos_sub",
                    "tabs": [
                        {"label": "QoS Interfaces", "blocks": [_table_block(parser.get_qos_interfaces(), "pa_qos_intf", empty_text="No QoS interfaces.", export_filename="pa_qos_interfaces.csv")]},
                        {"label": "QoS Profiles", "blocks": qos_prof_blocks},
                    ],
                }
            ],
        },
        {
            "label": "Network Profiles",
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_np_sub",
                    "tabs": [
                        {
                            "label": label,
                            "blocks": [_table_block(getattr(parser, meth)(), key, empty_text=empty, export_filename=fname)],
                        }
                        for label, meth, key, fname, empty in np_defs
                    ],
                }
            ],
        },
        {"label": "SD-WAN Profiles", "blocks": [_table_block(parser.get_sdwan_interface_profiles(), "pa_sdwan_profs", empty_text="No SD-WAN interface profiles.", export_filename="pa_sdwan_interface_profiles.csv")]},
    ]

    return {"section": "Network", "blocks": [{"type": "tabs", "id": "pa_network_tabs", "tabs": tabs}]}


# ── 5. Device ────────────────────────────────────────────────────────────────
def _toggle_row(label: str, val: Any) -> dict[str, str]:
    on = str(val).lower() in ("yes", "enable", "true", "1")
    return {"label": label, "value": "Enabled" if on else "Disabled", "tone": "allow" if on else "deny"}


def _build_device_ha(parser: Any) -> list[dict[str, Any]]:
    gen = parser.get_ha_general()
    if str(gen.get("enabled", "no")).lower() not in ("yes", "true", "1", "enable"):
        return [{"type": "alert", "variant": "info", "text": "High Availability is disabled on this device."}]

    mode = str(gen.get("mode", "active-passive")).upper()
    priority = gen.get("priority", "-")
    if priority in ("-", "", None):
        priority = "100 (PAN-OS default)"

    blocks: list[dict[str, Any]] = [
        {"type": "alert", "variant": "success", "text": f"HA Mode: {mode} | Group ID: {gen.get('group_id', '-')}"},
        {
            "type": "expander",
            "title": "General / Election Settings",
            "open": True,
            "blocks": [
                {
                    "type": "kv_grid",
                    "items": [
                        {"label": "Device Priority", "value": str(priority)},
                        {"label": "Preemptive", "value": str(gen.get("preemptive", "no")).upper()},
                        {"label": "Config Sync", "value": str(gen.get("config_sync", "no")).upper()},
                        {"label": "Peer HA1 IP", "value": str(gen.get("peer_ha1_ip", "-"))},
                    ],
                }
            ],
        },
    ]

    ap = {}
    try:
        ap = parser.get_ha_active_passive()
    except Exception:
        pass
    pls = str(ap.get("Passive Link State", "shutdown")) if ap else "shutdown"
    mfhd = str(ap.get("Monitor Fail Hold Down (min)", "1")) if ap else "1"
    blocks.append(
        {
            "type": "expander",
            "title": "Active / Passive Settings",
            "open": True,
            "blocks": [
                {
                    "type": "kv_grid",
                    "items": [
                        {"label": "Passive Link State", "value": pls.upper(), "sub": "default: Shutdown"},
                        {"label": "Monitor Fail Hold Down (min)", "value": mfhd, "sub": "default: 1"},
                    ],
                }
            ],
        }
    )

    try:
        ifaces = parser.get_ha_interfaces()
    except Exception:
        ifaces = {}
    if ifaces:
        iface_blocks = []
        for name, info in ifaces.items():
            iface_blocks.append({"type": "section_header", "title": name.upper()})
            iface_blocks.append(
                {
                    "type": "kv_grid",
                    "items": [
                        {"label": "Port", "value": info.get("port", "-")},
                        {"label": "IP Address", "value": info.get("ip_address", "-")},
                        {"label": "Encryption", "value": str(info.get("encryption", "no")).upper()},
                    ],
                }
            )
        blocks.append({"type": "expander", "title": "HA Interfaces", "blocks": iface_blocks})

    try:
        lpm = parser.get_ha_link_path_monitoring()
    except Exception:
        lpm = {}
    lpm_blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": "Monitoring Status",
            "rows": [
                _toggle_row("Link Monitoring", lpm.get("link_enabled", "yes")),
                {"label": "Link Fail Condition", "value": str(lpm.get("link_fail_cond", "any")).upper()},
                _toggle_row("Path Monitoring", lpm.get("path_enabled", "yes")),
                {"label": "Path Fail Condition", "value": str(lpm.get("path_fail_cond", "any")).upper()},
            ],
        },
        _table_block(lpm.get("link_groups", []), "pa_ha_link_groups", title="Link Monitoring Groups", empty_text="No link monitoring groups configured."),
        _table_block(lpm.get("path_groups", []), "pa_ha_path_groups", title="Path Monitoring Groups", empty_text="No path monitoring groups configured."),
    ]
    blocks.append({"type": "expander", "title": "Link & Path Monitoring", "open": True, "blocks": lpm_blocks})
    return blocks


def build_device(parser: Any) -> dict[str, Any]:
    # Setup tab
    setup_blocks: list[dict[str, Any]] = [
        {"type": "section_header", "title": "General Settings"},
        _dict_table_block(parser.get_general_settings(), "pa_gen_settings", "pa_general_settings.csv"),
        {"type": "section_header", "title": "Management Interface"},
        _dict_table_block(parser.get_mgmt_interface(), "pa_mgmt_iface", "pa_mgmt_interface.csv"),
    ]
    svc = parser.get_mgmt_services()
    if svc:
        setup_blocks.append(
            {
                "type": "card",
                "title": "Management Services",
                "rows": [
                    _toggle_row("Telnet", "no" if svc.get("disable_telnet", "no") == "yes" else "yes"),
                    _toggle_row("HTTP", "no" if svc.get("disable_http", "no") == "yes" else "yes"),
                    _toggle_row("HTTPS", "no" if svc.get("disable_https", "no") == "yes" else "yes"),
                    _toggle_row("SSH", "no" if svc.get("disable_ssh", "no") == "yes" else "yes"),
                ],
            }
        )
    setup_blocks.extend(
        [
            {"type": "section_header", "title": "Services (DNS / NTP)"},
            _dict_table_block(parser.get_services_config(), "pa_svc_cfg", "pa_services_config.csv"),
            {"type": "section_header", "title": "Service Routes"},
            _table_block(parser.get_service_routes(), "pa_svc_routes", empty_text="No service routes configured.", export_filename="pa_service_routes.csv"),
            {"type": "section_header", "title": "Panorama"},
            _dict_table_block(parser.get_panorama_settings(), "pa_panorama", "pa_panorama_settings.csv"),
            {"type": "section_header", "title": "Logging Settings"},
            _dict_table_block(parser.get_logging_settings(), "pa_logging", "pa_logging_settings.csv"),
            {"type": "section_header", "title": "Authentication Settings"},
            _dict_table_block(parser.get_auth_settings(), "pa_auth_settings", "pa_auth_settings.csv"),
            {"type": "section_header", "title": "Password Complexity"},
            _dict_table_block(parser.get_password_complexity(), "pa_pwd_complex", "pa_password_complexity.csv"),
        ]
    )

    # Log Settings tab
    log_blocks: list[dict[str, Any]] = [
        {"type": "section_header", "title": "Syslog (Direct)"},
        _table_block(parser.get_syslog_direct(), "pa_syslog_direct", empty_text="No direct syslog config found."),
        {"type": "section_header", "title": "Scheduled Log Export"},
        _table_block(parser.get_scheduled_log_export(), "pa_sched_log", empty_text="No scheduled log exports found.", export_filename="pa_scheduled_log_export.csv"),
    ]
    log_tabs = parser.get_log_settings_tables() or {}
    for tname, trows in log_tabs.items():
        safe_key = tname.lower().replace(" ", "_").replace("/", "_")
        log_blocks.append({"type": "section_header", "title": tname})
        if isinstance(trows, list):
            log_blocks.append(_table_block(trows, f"pa_log_{safe_key}", empty_text="No entries."))
        elif isinstance(trows, dict):
            log_blocks.append(_dict_table_block(trows, f"pa_log_{safe_key}", f"pa_log_{safe_key}.csv"))
    alarm = parser.get_alarm_settings()
    if alarm:
        log_blocks.append({"type": "section_header", "title": "Alarm Settings"})
        log_blocks.append(_dict_table_block(alarm, "pa_alarms", "pa_alarm_settings.csv"))

    # Session tab
    sess_blocks: list[dict[str, Any]] = [
        {"type": "section_header", "title": "Session Settings"},
        _dict_table_block(parser.get_session_settings(), "pa_sess_settings", "pa_session_settings.csv"),
        {"type": "section_header", "title": "Session Timeouts"},
        _dict_table_block(parser.get_session_timeouts(), "pa_sess_timeouts", "pa_session_timeouts.csv"),
        {"type": "section_header", "title": "TCP Settings"},
        _dict_table_block(parser.get_tcp_settings(), "pa_tcp_settings", "pa_tcp_settings.csv"),
        {"type": "section_header", "title": "VPN Session Settings"},
        _dict_table_block(parser.get_vpn_session_settings(), "pa_vpn_sess", "pa_vpn_session_settings.csv"),
    ]
    dlp = parser.get_dlp_settings() or {}
    for sec, data in dlp.items():
        if isinstance(data, dict) and data:
            sess_blocks.append({"type": "section_header", "title": f"DLP — {sec.replace('_', ' ').title()}"})
            sess_blocks.append(_dict_table_block(data, f"pa_dlp_{sec}", f"pa_dlp_{sec}.csv"))

    # User-ID tab
    uid = parser.get_user_id_info()
    if not uid:
        uid_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No User-ID configuration found."}]
    else:
        uid_blocks = [
            {"type": "section_header", "title": "User-ID Settings"},
            _dict_table_block(uid.get("settings", {}), "pa_uid_settings", "pa_userid_settings.csv"),
            {"type": "section_header", "title": "User-ID Agents"},
            _table_block(uid.get("agents", []), "pa_uid_agents", empty_text="No User-ID agents configured.", export_filename="pa_userid_agents.csv"),
            {"type": "section_header", "title": "Include / Exclude Networks"},
            _table_block(uid.get("networks", []), "pa_uid_networks", empty_text="No networks configured.", export_filename="pa_userid_networks.csv"),
            {"type": "section_header", "title": "Syslog Senders"},
            _table_block(uid.get("syslog_senders", []), "pa_uid_syslog", empty_text="No syslog senders configured.", export_filename="pa_userid_syslog_senders.csv"),
        ]

    tabs = [
        {"label": "Setup", "blocks": setup_blocks},
        {"label": "High Availability", "blocks": _build_device_ha(parser)},
        {
            "label": "Administrators",
            "blocks": [
                {"type": "section_header", "title": "Administrators"},
                _table_block(parser.get_admins(), "pa_admins", empty_text="No administrator accounts found."),
                {"type": "section_header", "title": "Password Profiles"},
                _table_block(parser.get_password_profiles(), "pa_pwd_profiles", empty_text="No password profiles found.", export_filename="pa_password_profiles.csv"),
                {"type": "section_header", "title": "Admin Roles"},
                _table_block(parser.get_admin_roles(), "pa_admin_roles", empty_text="No admin roles found."),
                {"type": "section_header", "title": "Local Users"},
                _table_block(parser.get_local_users(), "pa_local_users", empty_text="No local users found."),
                {"type": "section_header", "title": "Local User Groups"},
                _table_block(parser.get_local_user_groups(), "pa_local_groups", empty_text="No local user groups found.", export_filename="pa_local_user_groups.csv"),
            ],
        },
        {
            "label": "Auth Profiles",
            "blocks": [
                {"type": "section_header", "title": "Authentication Profiles"},
                _table_block(parser.get_auth_profiles(), "pa_auth_profs", empty_text="No authentication profiles found.", export_filename="pa_auth_profiles.csv"),
                {"type": "section_header", "title": "Authentication Sequences"},
                _table_block(parser.get_auth_sequences(), "pa_auth_seqs", empty_text="No authentication sequences found.", export_filename="pa_auth_sequences.csv"),
                {"type": "section_header", "title": "RADIUS Profiles"},
                _table_block(parser.get_radius_profiles(), "pa_radius", empty_text="No RADIUS profiles found.", export_filename="pa_radius_profiles.csv"),
                {"type": "section_header", "title": "LDAP Profiles"},
                _table_block(parser.get_ldap_profiles(), "pa_ldap", empty_text="No LDAP profiles found.", export_filename="pa_ldap_profiles.csv"),
                {"type": "section_header", "title": "TACACS+ Profiles"},
                _table_block(parser.get_tacacs_profiles(), "pa_tacacs", empty_text="No TACACS+ profiles found.", export_filename="pa_tacacs_profiles.csv"),
                {"type": "section_header", "title": "Kerberos Profiles"},
                _table_block(parser.get_kerberos_profiles(), "pa_kerberos", empty_text="No Kerberos profiles found.", export_filename="pa_kerberos_profiles.csv"),
                {"type": "section_header", "title": "SAML IdP Profiles"},
                _table_block(parser.get_saml_idp_profiles(), "pa_saml", empty_text="No SAML IdP profiles found.", export_filename="pa_saml_profiles.csv"),
                {"type": "section_header", "title": "MFA Profiles"},
                _table_block(parser.get_mfa_profiles(), "pa_mfa", empty_text="No MFA profiles found.", export_filename="pa_mfa_profiles.csv"),
            ],
        },
        {
            "label": "Certificates",
            "blocks": [
                {"type": "section_header", "title": "Certificates"},
                _table_block(parser.get_certificates(), "pa_certs", empty_text="No certificates found.", export_filename="pa_certificates.csv"),
                {"type": "section_header", "title": "SSL/TLS Service Profiles"},
                _table_block(parser.get_ssl_tls_profiles(), "pa_ssl_tls", empty_text="No SSL/TLS profiles found.", export_filename="pa_ssl_tls_profiles.csv"),
                {"type": "section_header", "title": "Certificate Profiles"},
                _table_block(parser.get_certificate_profiles(), "pa_cert_profs", empty_text="No certificate profiles found.", export_filename="pa_cert_profiles.csv"),
                {"type": "section_header", "title": "OCSP Responders"},
                _table_block(parser.get_ocsp_responders(), "pa_ocsp", empty_text="No OCSP responders found.", export_filename="pa_ocsp_responders.csv"),
                {"type": "section_header", "title": "SCEP Profiles"},
                _table_block(parser.get_scep_profiles(), "pa_scep", empty_text="No SCEP profiles found.", export_filename="pa_scep_profiles.csv"),
                {"type": "section_header", "title": "SSL Decrypt Exclusions"},
                _table_block(parser.get_ssl_decrypt_exclusions(), "pa_ssl_excl", empty_text="No SSL decrypt exclusions found.", export_filename="pa_ssl_decrypt_exclusions.csv"),
            ],
        },
        {
            "label": "Server Profiles",
            "blocks": [
                {"type": "section_header", "title": "Syslog Profiles"},
                _table_block(parser.get_syslog_profiles(), "pa_syslog", empty_text="No syslog profiles found.", export_filename="pa_syslog_profiles.csv"),
                {"type": "section_header", "title": "Email Profiles"},
                _table_block(parser.get_email_profiles(), "pa_email", empty_text="No email profiles found.", export_filename="pa_email_profiles.csv"),
                {"type": "section_header", "title": "SNMP Profiles"},
                _table_block(parser.get_snmp_profiles(), "pa_snmp", empty_text="No SNMP profiles found.", export_filename="pa_snmp_profiles.csv"),
                {"type": "section_header", "title": "HTTP Profiles"},
                _table_block(parser.get_http_profiles(), "pa_http", empty_text="No HTTP profiles found.", export_filename="pa_http_profiles.csv"),
                {"type": "section_header", "title": "Netflow Profiles"},
                _table_block(parser.get_netflow_profiles(), "pa_netflow", empty_text="No Netflow profiles found.", export_filename="pa_netflow_profiles.csv"),
                {"type": "section_header", "title": "SCP Profiles"},
                _table_block(parser.get_scp_profiles(), "pa_scp", empty_text="No SCP profiles found.", export_filename="pa_scp_profiles.csv"),
                {"type": "section_header", "title": "SSH Service Profiles"},
                _table_block(parser.get_ssh_service_profiles(), "pa_ssh_profs", empty_text="No SSH service profiles found.", export_filename="pa_ssh_service_profiles.csv"),
            ],
        },
        {"label": "Log Settings", "blocks": log_blocks},
        {"label": "Session", "blocks": sess_blocks},
        {"label": "User-ID", "blocks": uid_blocks},
    ]

    return {"section": "Device", "blocks": [{"type": "tabs", "id": "pa_device_tabs", "tabs": tabs}]}


def build_paloalto_section(section: str, parsers: dict[str, Any]) -> dict[str, Any]:
    builders = {
        "Dashboard": lambda: build_dashboard(
            parsers["Dashboard"],
            network_parser=parsers.get("Network"),
            device_parser=parsers.get("Device"),
            policies_parser=parsers.get("Policies"),
            objects_parser=parsers.get("Objects"),
        ),
        "Policies": lambda: build_policies(parsers["Policies"]),
        "Objects": lambda: build_objects(parsers["Objects"]),
        "Network": lambda: build_network(parsers["Network"], policies_parser=parsers.get("Policies")),
        "Device": lambda: build_device(parsers["Device"]),
    }
    if section not in builders:
        raise KeyError(f"Unknown Palo Alto section: {section}")
    return builders[section]()
