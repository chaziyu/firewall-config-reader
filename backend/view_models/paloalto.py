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
from backend.cert_inspector_service import (
    build_cert_inspector_blocks,
    build_cert_overview_blocks,
    inspect_paloalto_certificates,
)
from backend.exposure_check import (
    build_exposure_overview_blocks,
    find_paloalto_public_mgmt_exposure,
)
from backend.hygiene_service import analyze_paloalto_hygiene, build_hygiene_blocks
from backend.lifecycle_service import (
    build_paloalto_lifecycle_blocks,
    evaluate_paloalto_lifecycle,
)
from backend.posture_service import evaluate_paloalto_posture
from backend.view_models.common import (
    ADMIN_LEGEND,
    PA_POLICY_LEGEND,
    kv_dict_blocks,
    policy_caption,
    table_block as _table_block,
    toggle_row as _common_toggle_row,
)
from backend.vpn_inspector_service import build_vpn_inspector_blocks, inspect_paloalto_vpns


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


def _policy_block(rows: list[dict[str, Any]] | None, key: str, label: str) -> dict[str, Any]:
    if not rows:
        return {"type": "alert", "variant": "info", "text": f"No {label} configured."}
    dis = sum(1 for r in rows if r.get("_disabled"))
    pan = sum(1 for r in rows if r.get("_panorama"))
    return _table_block(
        rows,
        table_id=key,
        caption=policy_caption(len(rows), dis, pan),
        export_filename=f"{key}.csv",
        row_class_fn=_policy_row_class,
        legend=PA_POLICY_LEGEND,
    )


# ── 1. Dashboard & Security/Health ───────────────────────────────────────────
def _eval_paloalto_health(
    parser: Any,
    network_parser: Any = None,
    device_parser: Any = None,
    policies_parser: Any = None,
    objects_parser: Any = None,
    *,
    allow_probe: bool = False,
) -> dict[str, Any]:
    info = parser.get_system_info()
    sw_version = str(info.get("software_version", "—"))
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
    exposure_badge, exposure_card = build_exposure_overview_blocks(
        exposure_findings,
        allow_probe=allow_probe,
        probe_endpoint="/api/pa/exposure-probe",
    )
    audit_result = run_paloalto_audit(
        {
            "Policies": policies_parser,
            "Objects": objects_parser,
            "Network": network_parser,
            "Device": device_parser,
        }
    )
    audit_badge, audit_expander = build_audit_overview_blocks(audit_result)
    cert_list = inspect_paloalto_certificates(device_parser)
    cert_badge, cert_card = build_cert_overview_blocks(cert_list)
    return {
        "info": info,
        "lifecycle_badge": lifecycle_badge,
        "lifecycle_card": lifecycle_card,
        "exposure_badge": exposure_badge,
        "exposure_card": exposure_card,
        "audit_badge": audit_badge,
        "audit_expander": audit_expander,
        "cert_badge": cert_badge,
        "cert_card": cert_card,
    }


def build_dashboard(
    parser: Any,
    network_parser: Any = None,
    device_parser: Any = None,
    policies_parser: Any = None,
    objects_parser: Any = None,
    *,
    allow_probe: bool = False,
) -> dict[str, Any]:
    health = _eval_paloalto_health(
        parser,
        network_parser=network_parser,
        device_parser=device_parser,
        policies_parser=policies_parser,
        objects_parser=objects_parser,
        allow_probe=allow_probe,
    )
    info = health["info"]
    ha = parser.get_ha_info()

    hostname = str(info.get("hostname", "Unknown"))
    sw_version = str(info.get("software_version", "—"))
    timezone = str(info.get("timezone", "—"))
    adv_routing = str(info.get("adv_routing", "Off"))
    dup_ip = str(info.get("dup_ip", "Disable"))

    posture = evaluate_paloalto_posture(
        network_parser,
        policies_parser=policies_parser,
        dashboard_parser=parser,
        device_parser=device_parser,
    )

    ha_badge = (
        {
            "text": f"HA Enabled · {'Active-Passive' if ha.get('mode', 'active-passive') == 'active-passive' else 'Active-Active'}",
            "variant": "allow",
        }
        if ha.get("enabled")
        else {"text": "Standalone", "variant": "muted"}
    )

    hero_badges = [
        ha_badge,
        {
            "text": f"Advanced Routing: {adv_routing}",
            "variant": "allow" if adv_routing == "On" else "muted",
        },
        {
            "text": f"Duplicate IP: {dup_ip}",
            "variant": "info" if dup_ip == "Enable" else "muted",
        },
        health["lifecycle_badge"],
        health["exposure_badge"],
        health["audit_badge"],
    ]
    if health["cert_badge"] is not None:
        hero_badges.append(health["cert_badge"])

    blocks: list[dict[str, Any]] = [
        {
            "type": "hero",
            "eyebrow": "PAN-OS Appliance",
            "title": hostname,
            "subtitle": f"PAN-OS {sw_version} · {timezone}",
            "badges": hero_badges,
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
                {"label": "Internet Connectivity", "value": posture["internet"], "sub": posture["internet_sub"]},
                {"label": "Local Hard Disk", "value": posture["disk"], "sub": posture["disk_sub"]},
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

    vr_names = ["all"]
    if network_parser is not None and hasattr(network_parser, "get_virtual_routers"):
        for vr in network_parser.get_virtual_routers() or []:
            vname = str(vr.get("Name", "")).strip()
            if vname and vname not in vr_names:
                vr_names.append(vname)
    blocks.append({"type": "where_used_lookup", "vendor": "pa"})
    blocks.append({"type": "packet_trace", "vendor": "pa", "virtual_routers": vr_names})
    blocks.append({"type": "config_diff", "vendor": "pa"})

    return {"section": "Dashboard", "blocks": blocks}


def build_security_health(
    parser: Any,
    network_parser: Any = None,
    device_parser: Any = None,
    policies_parser: Any = None,
    objects_parser: Any = None,
    *,
    allow_probe: bool = False,
) -> dict[str, Any]:
    """Build the Security & Health overview page for Palo Alto."""
    health = _eval_paloalto_health(
        parser,
        network_parser=network_parser,
        device_parser=device_parser,
        policies_parser=policies_parser,
        objects_parser=objects_parser,
        allow_probe=allow_probe,
    )
    info = health["info"]
    hostname = str(info.get("hostname", "Unknown"))
    sw_version = str(info.get("software_version", "—"))
    timezone = str(info.get("timezone", "—"))

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
            "title": hostname,
            "subtitle": f"PAN-OS {sw_version} · {timezone}",
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


# ── 2. Policies ──────────────────────────────────────────────────────────────
def build_policies(parser: Any, objects_parser: Any = None) -> dict[str, Any]:
    zones = ["any"] + (parser.get_zones_list() if hasattr(parser, "get_zones_list") else [])
    intfs = ["any"] + (parser.get_interfaces_list() if hasattr(parser, "get_interfaces_list") else [])

    def _pol_tab(title: str, ptype: str | None, rows: list, key: str, label: str) -> dict[str, Any]:
        blks: list[dict[str, Any]] = []
        if ptype:
            blks.append(
                {
                    "type": "policy_simulator",
                    "vendor": "pa",
                    "policy_type": ptype,
                    "zones": zones,
                    "interfaces": intfs,
                }
            )
        blks.append(_policy_block(rows, key, label))
        return {"label": title, "count": len(rows or []), "blocks": blks}

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
        {
            "label": "Cleanup & Hygiene",
            "blocks": build_hygiene_blocks(
                analyze_paloalto_hygiene({"Policies": parser, "Objects": objects_parser}),
                "pa",
            ),
        },
    ]

    return {"section": "Policies & NAT", "blocks": [{"type": "tabs", "id": "pa_policies_tabs", "tabs": tabs}]}


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


def _build_security_profiles_tabs(parser: Any) -> list[dict[str, Any]]:
    pg_rows = parser.get_security_profile_groups()
    if not pg_rows:
        pg_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No security profile groups configured."}]
    else:
        pg_blocks = []
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
            pg_blocks.append(
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

    dec_rows = parser.get_decryption_profiles()
    if not dec_rows:
        dec_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No decryption profiles configured."}]
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

    av_rows = parser.get_av_profiles()
    spy_rows = parser.get_spyware_profiles()
    vuln_rows = parser.get_vulnerability_profiles()
    fb_rows = parser.get_file_blocking_profiles()
    wf_rows = parser.get_wildfire_profiles()
    df_rows = parser.get_data_filtering_profiles()
    dos_rows = parser.get_dos_protection_profiles()

    return [
        {"label": "Profile Groups", "count": len(pg_rows), "blocks": pg_blocks},
        {"label": "Antivirus", "count": len(av_rows), "blocks": [_table_block(av_rows, "pa_av_profs", empty_text="No custom antivirus profiles.")]},
        {"label": "Anti-Spyware", "count": len(spy_rows), "blocks": [_table_block(spy_rows, "pa_spyware_profs", empty_text="No custom anti-spyware profiles.", row_class_fn=_sev_row_class, legend=_sev_legend)]},
        {"label": "Vulnerability", "count": len(vuln_rows), "blocks": [_table_block(vuln_rows, "pa_vuln_profs", empty_text="No custom vulnerability profiles.", row_class_fn=_sev_row_class, legend=_sev_legend)]},
        {"label": "URL Filtering", "count": len(url_profiles), "blocks": [url_block]},
        {"label": "File Blocking", "count": len(fb_rows), "blocks": [_table_block(fb_rows, "pa_fileblock_profs", empty_text="No custom file blocking profiles.")]},
        {"label": "WildFire", "count": len(wf_rows), "blocks": [_table_block(wf_rows, "pa_wildfire_profs", empty_text="No custom WildFire profiles.")]},
        {"label": "Data Filtering", "count": len(df_rows), "blocks": [_table_block(df_rows, "pa_datafilt_profs", empty_text="No custom data filtering profiles.")]},
        {"label": "DoS Protection", "count": len(dos_rows), "blocks": [_table_block(dos_rows, "pa_dos_profs", empty_text="No custom DoS protection profiles.")]},
        {"label": "Decryption Profiles", "count": len(dec_rows), "blocks": dec_blocks},
    ]


def build_security_profiles(parser: Any) -> dict[str, Any]:
    return {
        "section": "Security Profiles",
        "blocks": [{"type": "tabs", "id": "pa_sec_prof_tabs", "tabs": _build_security_profiles_tabs(parser)}],
    }


def build_objects(parser: Any) -> dict[str, Any]:
    addrs = parser.get_addresses()
    addr_grps = parser.get_address_groups()
    app_grps = parser.get_application_groups()
    svcs = parser.get_services()
    svc_grps = parser.get_service_groups()
    tags = parser.get_tags()
    regions = parser.get_regions()
    edls = parser.get_external_dynamic_lists()
    dpats = parser.get_data_patterns()
    cspy = parser.get_custom_spyware()
    cvuln = parser.get_custom_vulnerability()
    curl = parser.get_custom_url_categories()
    log_fwd = parser.get_log_forwarding_profiles()
    sdwan_pq = parser.get_sdwan_path_quality()
    sdwan_td = parser.get_sdwan_traffic_dist()
    sdwan_sq = parser.get_sdwan_saas_quality()
    sdwan_ec = parser.get_sdwan_error_correction()
    schedules = parser.get_schedules()

    tabs = [
        {
            "label": "Addresses",
            "count": len(addrs) + len(addr_grps) + len(app_grps),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_addr_sub",
                    "tabs": [
                        {"label": "Addresses", "count": len(addrs), "blocks": [_table_block(addrs, "pa_addresses", empty_text="No addresses configured.", filter_col="Type")]},
                        {"label": "Address Groups", "count": len(addr_grps), "blocks": [_table_block(addr_grps, "pa_address_groups", empty_text="No address groups configured.")]},
                        {"label": "Application Groups", "count": len(app_grps), "blocks": [_table_block(app_grps, "pa_application_groups", empty_text="No application groups configured.")]},
                    ],
                }
            ],
        },
        {
            "label": "Services",
            "count": len(svcs) + len(svc_grps),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_svc_sub",
                    "tabs": [
                        {"label": "Services", "count": len(svcs), "blocks": [_table_block(svcs, "pa_services", empty_text="No services configured.")]},
                        {"label": "Service Groups", "count": len(svc_grps), "blocks": [_table_block(svc_grps, "pa_service_groups", empty_text="No service groups configured.")]},
                    ],
                }
            ],
        },
        {"label": "Tags", "count": len(tags), "blocks": [_table_block(tags, "pa_tags", empty_text="No tags configured.")]},
        {"label": "Regions", "count": len(regions), "blocks": [_table_block(regions, "pa_regions", empty_text="No regions configured.")]},
        {"label": "External Dynamic Lists", "count": len(edls), "blocks": [_table_block(edls, "pa_edl", empty_text="No custom external dynamic lists configured.", export_filename="pa_external_dynamic_lists.csv", filter_col="Type")]},
        {
            "label": "Custom Objects",
            "count": len(dpats) + len(cspy) + len(cvuln) + len(curl),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_custom_obj_sub",
                    "tabs": [
                        {"label": "Data Patterns", "count": len(dpats), "blocks": [_table_block(dpats, "pa_data_patterns", empty_text="No custom data patterns configured.")]},
                        {"label": "Spyware", "count": len(cspy), "blocks": [_table_block(cspy, "pa_custom_spyware", empty_text="No custom spyware objects configured.")]},
                        {"label": "Vulnerability", "count": len(cvuln), "blocks": [_table_block(cvuln, "pa_custom_vulnerability", empty_text="No custom vulnerability objects configured.")]},
                        {"label": "URL Categories", "count": len(curl), "blocks": [_table_block(curl, "pa_custom_url_categories", empty_text="No custom URL categories configured.")]},
                    ],
                }
            ],
        },
        {"label": "Log Forwarding", "count": len(log_fwd), "blocks": [_table_block(log_fwd, "pa_log_forwarding", empty_text="No log forwarding profiles configured.")]},
        {
            "label": "SD-WAN Link Mgmt",
            "count": len(sdwan_pq) + len(sdwan_td) + len(sdwan_sq) + len(sdwan_ec),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_sdwan_obj_sub",
                    "tabs": [
                        {"label": "Path Quality", "count": len(sdwan_pq), "blocks": [_table_block(sdwan_pq, "pa_sdwan_path_quality", empty_text="No path quality profiles configured.")]},
                        {
                            "label": "Traffic Distribution",
                            "count": len(sdwan_td),
                            "blocks": [
                                _table_block(
                                    sdwan_td,
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
                        {"label": "SaaS Quality", "count": len(sdwan_sq), "blocks": [_table_block(sdwan_sq, "pa_sdwan_saas", empty_text="No SaaS quality profiles configured.")]},
                        {"label": "Error Correction", "count": len(sdwan_ec), "blocks": [_table_block(sdwan_ec, "pa_sdwan_error", empty_text="No error correction profiles configured.")]},
                    ],
                }
            ],
        },
        {
            "label": "Schedules",
            "count": len(schedules),
            "blocks": [
                _table_block(
                    schedules,
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
        return "row-purple"
    if t == "Virtual Wire":
        return "row-muted"
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


def build_network(parser: Any, policies_parser: Any = None, *, include_legacy_vpn: bool = False) -> dict[str, Any]:
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

    eth_ifaces = parser.get_ethernet_interfaces()
    vlan_ifaces = parser.get_vlan_interfaces()
    lo_ifaces = parser.get_loopback_interfaces()
    tun_ifaces = parser.get_tunnel_interfaces()
    sdwan_ifaces = parser.get_sdwan_interfaces()
    total_ifaces = len(eth_ifaces) + len(vlan_ifaces) + len(lo_ifaces) + len(tun_ifaces) + len(sdwan_ifaces)

    zones = parser.get_zones()
    vlans = parser.get_vlans()
    vwires = parser.get_virtual_wires()
    dhcp_srv = parser.get_dhcp_servers()
    dhcp_rel = parser.get_dhcp_relays()
    dns_proxies = parser.get_dns_proxies()
    qos_intfs = parser.get_qos_interfaces()
    sdwan_profs = parser.get_sdwan_interface_profiles()

    tabs = [
        {
            "label": "Interfaces",
            "count": total_ifaces,
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_intf_sub",
                    "tabs": [
                        {
                            "label": "Ethernet / Aggregate",
                            "count": len(eth_ifaces),
                            "blocks": [
                                _table_block(
                                    eth_ifaces,
                                    "pa_eth_ifaces",
                                    empty_text="No ethernet/aggregate interfaces.",
                                    row_class_fn=_eth_row_class,
                                    legend=[
                                        {"label": "Physical / Layer3 (default)", "variant": "default"},
                                        {"label": "Aggregate Parent (blue)", "variant": "info"},
                                        {"label": "Sub-Interface (purple)", "variant": "purple"},
                                        {"label": "Virtual Wire (muted)", "variant": "muted"},
                                        {"label": "HA Interface (amber)", "variant": "warn"},
                                    ],
                                    export_filename="pa_ethernet_interfaces.csv",
                                )
                            ],
                        },
                        {"label": "VLAN", "count": len(vlan_ifaces), "blocks": [_table_block(vlan_ifaces, "pa_vlan_ifaces", empty_text="No VLAN interfaces.", export_filename="pa_vlan_interfaces.csv")]},
                        {"label": "Loopback", "count": len(lo_ifaces), "blocks": [_table_block(lo_ifaces, "pa_lo_ifaces", empty_text="No loopback interfaces.", export_filename="pa_loopback_interfaces.csv")]},
                        {"label": "Tunnel", "count": len(tun_ifaces), "blocks": [_table_block(tun_ifaces, "pa_tun_ifaces", empty_text="No tunnel interfaces.", export_filename="pa_tunnel_interfaces.csv")]},
                        {"label": "SD-WAN", "count": len(sdwan_ifaces), "blocks": [_table_block(sdwan_ifaces, "pa_sdwan_ifaces", empty_text="No SD-WAN interfaces.", export_filename="pa_sdwan_interfaces.csv")]},
                    ],
                }
            ],
        },
        {"label": "Zones", "count": len(zones), "blocks": [_table_block(zones, "pa_zones", empty_text="No zones configured.")]},
        {"label": "VLANs", "count": len(vlans), "blocks": [_table_block(vlans, "pa_vlans", empty_text="No VLAN objects.")]},
        {"label": "Virtual Wires", "count": len(vwires), "blocks": [_table_block(vwires, "pa_vwires", empty_text="No virtual wires.", export_filename="pa_virtual_wires.csv")]},
        {"label": "Virtual Router", "count": len(vrs), "blocks": vr_blocks},
        {
            "label": "DHCP",
            "count": len(dhcp_srv) + len(dhcp_rel),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_dhcp_sub",
                    "tabs": [
                        {"label": "DHCP Servers", "count": len(dhcp_srv), "blocks": [_table_block(dhcp_srv, "pa_dhcp_srv", empty_text="No DHCP servers.", export_filename="pa_dhcp_servers.csv")]},
                        {"label": "DHCP Relay", "count": len(dhcp_rel), "blocks": [_table_block(dhcp_rel, "pa_dhcp_relay", empty_text="No DHCP relays.", export_filename="pa_dhcp_relays.csv")]},
                    ],
                }
            ],
        },
        {"label": "DNS Proxy", "count": len(dns_proxies), "blocks": [_table_block(dns_proxies, "pa_dns_proxy", empty_text="No DNS proxy.")]},
        {
            "label": "QoS",
            "count": len(qos_intfs) + len(qos_profiles),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_qos_sub",
                    "tabs": [
                        {"label": "QoS Interfaces", "count": len(qos_intfs), "blocks": [_table_block(qos_intfs, "pa_qos_intf", empty_text="No QoS interfaces.", export_filename="pa_qos_interfaces.csv")]},
                        {"label": "QoS Profiles", "count": len(qos_profiles), "blocks": qos_prof_blocks},
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
        {"label": "SD-WAN Profiles", "count": len(sdwan_profs), "blocks": [_table_block(sdwan_profs, "pa_sdwan_profs", empty_text="No SD-WAN interface profiles.", export_filename="pa_sdwan_interface_profiles.csv")]},
    ]

    if include_legacy_vpn:
        tabs.insert(
            5,
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
        )

    return {"section": "Interfaces & Network", "blocks": [{"type": "tabs", "id": "pa_network_tabs", "tabs": tabs}]}


def build_vpn(parser: Any, policies_parser: Any = None) -> dict[str, Any]:
    ipsec_tunnels = parser.get_ipsec_tunnels()
    gre_tunnels = parser.get_gre_tunnels()
    ike_gws = parser.get_ike_gateways()
    ike_cryptos = parser.get_ike_crypto_profiles()
    ipsec_cryptos = parser.get_ipsec_crypto_profiles()
    gp_cryptos = parser.get_gp_ipsec_crypto()

    gw_map = {str(g.get("Name", "")): g for g in ike_gws}
    ike_c_map = {str(c.get("Name", "")): c for c in ike_cryptos}
    ipsec_c_map = {str(c.get("Name", "")): c for c in ipsec_cryptos}

    if not ipsec_tunnels:
        ipsec_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No IPSec tunnels configured."}]
    else:
        def _pa_tun_detail(tun: dict[str, Any]) -> list[dict[str, Any]]:
            gw_name = str(tun.get("IKE GW", ""))
            gw = gw_map.get(gw_name, {})
            ike_prof_name = str(gw.get("Crypto Profile", "-"))
            ike_prof = ike_c_map.get(ike_prof_name, {})
            ipsec_prof_name = str(tun.get("Crypto", "-"))
            ipsec_prof = ipsec_c_map.get(ipsec_prof_name, {})

            blks: list[dict[str, Any]] = [
                {
                    "type": "kv_grid",
                    "items": [
                        {"label": "Tunnel Interface", "value": tun.get("Tunnel Intf", "-")},
                        {"label": "Virtual Router", "value": tun.get("VR", "-")},
                        {"label": "Zone", "value": tun.get("Zone", "-")},
                        {"label": "IKE Gateway", "value": gw_name or "-"},
                        {"label": "IKE Local IP", "value": tun.get("IKE Local IP", "-")},
                        {"label": "IKE Peer IP", "value": tun.get("IKE Peer IP", "-")},
                        {"label": "IKE Version", "value": gw.get("Version", "-")},
                        {"label": "Auth Method", "value": gw.get("Auth Method", "-")},
                    ],
                },
                {
                    "type": "expander",
                    "title": f"Phase 1 — IKE Crypto Profile ({ike_prof_name})",
                    "open": True,
                    "blocks": [
                        {
                            "type": "kv_grid",
                            "items": [
                                {"label": "Encryption", "value": ike_prof.get("Encryption", "-")},
                                {"label": "Authentication", "value": ike_prof.get("Authentication", "-")},
                                {"label": "DH Group", "value": ike_prof.get("DH Group", "-")},
                                {"label": "Key Lifetime", "value": ike_prof.get("Key Lifetime", "-")},
                                {"label": "NAT Traversal", "value": gw.get("NAT Traversal", "-")},
                            ],
                        }
                    ],
                },
                {
                    "type": "expander",
                    "title": f"Phase 2 — IPSec Crypto Profile ({ipsec_prof_name})",
                    "open": True,
                    "blocks": [
                        {
                            "type": "kv_grid",
                            "items": [
                                {"label": "Protocol", "value": ipsec_prof.get("Type", "-")},
                                {"label": "Encryption", "value": ipsec_prof.get("Encryption", "-")},
                                {"label": "Authentication", "value": ipsec_prof.get("Authentication", "-")},
                                {"label": "DH Group", "value": ipsec_prof.get("DH Group", "-")},
                                {"label": "Lifetime", "value": ipsec_prof.get("Lifetime", "-")},
                            ],
                        }
                    ],
                },
            ]
            return blks

        ipsec_blocks = [
            _table_block(ipsec_tunnels, "pa_ipsec", title="IPSec Tunnels", empty_text="No IPSec tunnels.", export_filename="pa_ipsec_tunnels.csv"),
            {
                "type": "profile_selector",
                "id": "pa_ipsec_detail_sel",
                "label": "Inspect Tunnel Details",
                "options": [{"name": str(t.get("Name", f"Tunnel {i+1}")), "blocks": _pa_tun_detail(t)} for i, t in enumerate(ipsec_tunnels)],
            },
        ]

    gp_portals = parser.get_gp_portals()
    gp_gws = parser.get_gp_gateways()
    gp_mdm = parser.get_gp_mdm()
    gp_apps = parser.get_gp_clientless_apps()
    gp_grps = parser.get_gp_clientless_groups()

    tabs = [
        {
            "label": "IPSec Inspector",
            "count": len(ipsec_tunnels),
            "blocks": build_vpn_inspector_blocks(inspect_paloalto_vpns(parser, policies_parser), "pa"),
        },
        {"label": "IPSec Tunnels", "count": len(ipsec_tunnels), "blocks": ipsec_blocks},
        {"label": "GRE Tunnels", "count": len(gre_tunnels), "blocks": [_table_block(gre_tunnels, "pa_gre", empty_text="No GRE tunnels.", export_filename="pa_gre_tunnels.csv")]},
        {
            "label": "GlobalProtect",
            "count": len(gp_portals) + len(gp_gws),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_gp_sub",
                    "tabs": [
                        {"label": "Portals", "count": len(gp_portals), "blocks": [_table_block(gp_portals, "pa_gp_portals", empty_text="No GP portals.")]},
                        {"label": "Gateways", "count": len(gp_gws), "blocks": [_table_block(gp_gws, "pa_gp_gw", empty_text="No GP gateways.", export_filename="pa_gp_gateways.csv")]},
                        {"label": "MDM", "count": len(gp_mdm), "blocks": [_table_block(gp_mdm, "pa_gp_mdm", empty_text="No MDM configured.")]},
                        {"label": "Clientless Apps", "count": len(gp_apps), "blocks": [_table_block(gp_apps, "pa_gp_apps", empty_text="No clientless apps.", export_filename="pa_gp_clientless_apps.csv")]},
                        {"label": "Clientless Groups", "count": len(gp_grps), "blocks": [_table_block(gp_grps, "pa_gp_grps", empty_text="No clientless groups.", export_filename="pa_gp_clientless_groups.csv")]},
                    ],
                }
            ],
        },
        {
            "label": "IKE & IPSec Crypto",
            "count": len(ike_gws) + len(ike_cryptos) + len(ipsec_cryptos),
            "blocks": [
                {
                    "type": "tabs",
                    "id": "pa_ike_sub",
                    "tabs": [
                        {"label": "IKE Gateways", "count": len(ike_gws), "blocks": [_table_block(ike_gws, "pa_ike_gw", empty_text="No IKE gateways.", export_filename="pa_ike_gateways.csv")]},
                        {"label": "IKE Crypto", "count": len(ike_cryptos), "blocks": [_table_block(ike_cryptos, "pa_ike_c", empty_text="No IKE crypto profiles.", export_filename="pa_ike_crypto.csv")]},
                        {"label": "IPSec Crypto", "count": len(ipsec_cryptos), "blocks": [_table_block(ipsec_cryptos, "pa_ipsec_c", empty_text="No IPSec crypto profiles.", export_filename="pa_ipsec_crypto.csv")]},
                        {"label": "GP-IPSec Crypto", "count": len(gp_cryptos), "blocks": [_table_block(gp_cryptos, "pa_gp_ipsec_c", empty_text="No GP IPSec crypto profiles.", export_filename="pa_gp_ipsec_crypto.csv")]},
                    ],
                }
            ],
        },
    ]
    return {"section": "VPN", "blocks": [{"type": "tabs", "id": "pa_vpn_tabs", "tabs": tabs}]}


def build_users_auth(device_parser: Any, objects_parser: Any = None) -> dict[str, Any]:
    auth_profs = device_parser.get_auth_profiles()
    auth_seqs = device_parser.get_auth_sequences()
    local_users = device_parser.get_local_users()
    local_groups = device_parser.get_local_user_groups()

    uid = device_parser.get_user_id_info()
    if not uid:
        uid_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No User-ID configuration found."}]
    else:
        uid_blocks = [
            *kv_dict_blocks(uid.get("settings", {}), title="User-ID Settings", empty_text="No User-ID settings configured."),
            {"type": "section_header", "title": "User-ID Agents"},
            _table_block(uid.get("agents", []), "pa_uid_agents", empty_text="No User-ID agents configured.", export_filename="pa_userid_agents.csv"),
            {"type": "section_header", "title": "Include / Exclude Networks"},
            _table_block(uid.get("networks", []), "pa_uid_networks", empty_text="No networks configured.", export_filename="pa_userid_networks.csv"),
            {"type": "section_header", "title": "Syslog Senders"},
            _table_block(uid.get("syslog_senders", []), "pa_uid_syslog", empty_text="No syslog senders configured.", export_filename="pa_userid_syslog_senders.csv"),
        ]

    dug_rows = objects_parser.get_dynamic_user_groups() if objects_parser is not None else []
    hip_objs = objects_parser.get_hip_objects() if objects_parser is not None else []
    hip_profs = objects_parser.get_hip_profiles() if objects_parser is not None else []

    tabs = [
        {
            "label": "Auth Profiles",
            "count": len(auth_profs) + len(auth_seqs),
            "blocks": [
                {"type": "section_header", "title": "Authentication Profiles"},
                _table_block(auth_profs, "pa_auth_profs", empty_text="No authentication profiles found.", export_filename="pa_auth_profiles.csv"),
                {"type": "section_header", "title": "Authentication Sequences"},
                _table_block(auth_seqs, "pa_auth_seqs", empty_text="No authentication sequences found.", export_filename="pa_auth_sequences.csv"),
                {"type": "section_header", "title": "RADIUS Profiles"},
                _table_block(device_parser.get_radius_profiles(), "pa_radius", empty_text="No RADIUS profiles found.", export_filename="pa_radius_profiles.csv"),
                {"type": "section_header", "title": "LDAP Profiles"},
                _table_block(device_parser.get_ldap_profiles(), "pa_ldap", empty_text="No LDAP profiles found.", export_filename="pa_ldap_profiles.csv"),
                {"type": "section_header", "title": "TACACS+ Profiles"},
                _table_block(device_parser.get_tacacs_profiles(), "pa_tacacs", empty_text="No TACACS+ profiles found.", export_filename="pa_tacacs_profiles.csv"),
                {"type": "section_header", "title": "Kerberos Profiles"},
                _table_block(device_parser.get_kerberos_profiles(), "pa_kerberos", empty_text="No Kerberos profiles found.", export_filename="pa_kerberos_profiles.csv"),
                {"type": "section_header", "title": "SAML IdP Profiles"},
                _table_block(device_parser.get_saml_idp_profiles(), "pa_saml", empty_text="No SAML IdP profiles found.", export_filename="pa_saml_profiles.csv"),
                {"type": "section_header", "title": "MFA Profiles"},
                _table_block(device_parser.get_mfa_profiles(), "pa_mfa", empty_text="No MFA profiles found.", export_filename="pa_mfa_profiles.csv"),
            ],
        },
        {
            "label": "Local Users & Groups",
            "count": len(local_users) + len(local_groups),
            "blocks": [
                {"type": "section_header", "title": "Local Users"},
                _table_block(local_users, "pa_local_users", empty_text="No local users found."),
                {"type": "section_header", "title": "Local User Groups"},
                _table_block(local_groups, "pa_local_groups", empty_text="No local user groups found.", export_filename="pa_local_user_groups.csv"),
            ],
        },
        {"label": "User-ID", "blocks": uid_blocks},
        {"label": "Dynamic User Groups", "count": len(dug_rows), "blocks": [_table_block(dug_rows, "pa_dynamic_groups", empty_text="No dynamic user groups configured.")]},
        {
            "label": "GlobalProtect HIP",
            "count": len(hip_objs) + len(hip_profs),
            "blocks": [
                {"type": "section_header", "title": "HIP Objects"},
                _table_block(hip_objs, "pa_hip_objects", empty_text="No HIP objects configured."),
                {"type": "section_header", "title": "HIP Profiles"},
                _table_block(hip_profs, "pa_hip_profiles", empty_text="No HIP profiles configured."),
            ],
        },
    ]
    return {"section": "Users & Auth", "blocks": [{"type": "tabs", "id": "pa_users_auth_tabs", "tabs": tabs}]}


# ── 5. Device ────────────────────────────────────────────────────────────────
def _toggle_row(label: str, val: Any) -> dict[str, str]:
    return _common_toggle_row(label, val, on_label="Enabled", off_label="Disabled")


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
    # Setup tab using compact kv_grid + toggle cards instead of verbose 2-col tables
    setup_blocks: list[dict[str, Any]] = [
        *kv_dict_blocks(
            parser.get_general_settings(),
            title="General Settings",
            toggle_keys={"Multi Virtual System", "Advanced Routing", "Cert Expiry Check", "Tunnel Acceleration"},
        ),
        *kv_dict_blocks(parser.get_mgmt_interface(), title="Management Interface"),
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
            *kv_dict_blocks(parser.get_services_config(), title="Services (DNS / NTP)"),
            {"type": "section_header", "title": "Service Routes"},
            _table_block(parser.get_service_routes(), "pa_svc_routes", empty_text="No service routes configured.", export_filename="pa_service_routes.csv"),
            *kv_dict_blocks(parser.get_panorama_settings(), title="Panorama"),
            *kv_dict_blocks(parser.get_logging_settings(), title="Logging Settings"),
            *kv_dict_blocks(parser.get_auth_settings(), title="Authentication Settings"),
            *kv_dict_blocks(parser.get_password_complexity(), title="Password Complexity", toggle_keys={"Enabled"}),
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
        log_blocks.extend(kv_dict_blocks(alarm, title="Alarm Settings"))

    # Session tab
    sess_blocks: list[dict[str, Any]] = [
        *kv_dict_blocks(parser.get_session_settings(), title="Session Settings"),
        *kv_dict_blocks(parser.get_session_timeouts(), title="Session Timeouts"),
        *kv_dict_blocks(parser.get_tcp_settings(), title="TCP Settings"),
        *kv_dict_blocks(parser.get_vpn_session_settings(), title="VPN Session Settings"),
    ]
    dlp = parser.get_dlp_settings() or {}
    for sec, data in dlp.items():
        if isinstance(data, dict) and data:
            sess_blocks.extend(kv_dict_blocks(data, title=f"DLP — {sec.replace('_', ' ').title()}"))

    admins = parser.get_admins()
    if admins:
        admins = sorted(
            admins,
            key=lambda x: (0 if str(x.get("Role", "")).lower() == "superuser" else 1, str(x.get("Name", ""))),
        )
    admin_roles = parser.get_admin_roles()
    if not admin_roles:
        admin_role_blocks: list[dict[str, Any]] = [{"type": "alert", "variant": "info", "text": "No custom admin roles found."}]
    else:
        admin_role_blocks = [
            {
                "type": "expander",
                "title": str(r.get("Name", "Role")),
                "blocks": [
                    {
                        "type": "kv_grid",
                        "items": [
                            {"label": k, "value": str(v) if v not in (None, "") else "—"}
                            for k, v in r.items()
                            if k != "Name"
                        ],
                    }
                ],
            }
            for r in admin_roles
        ]

    certs = inspect_paloalto_certificates(parser)

    tabs = [
        {"label": "Setup", "blocks": setup_blocks},
        {"label": "High Availability", "blocks": _build_device_ha(parser)},
        {
            "label": "Administrators",
            "count": len(admins or []),
            "blocks": [
                {"type": "section_header", "title": "Administrators"},
                _table_block(
                    admins,
                    "pa_admins",
                    empty_text="No administrator accounts found.",
                    row_class_fn=lambda r: "row-warn" if str(r.get("Role", "")).lower() == "superuser" else "",
                    legend=ADMIN_LEGEND,
                ),
                {"type": "section_header", "title": "Admin Roles"},
                *admin_role_blocks,
                {"type": "section_header", "title": "Password Profiles"},
                _table_block(parser.get_password_profiles(), "pa_pwd_profiles", empty_text="No password profiles found.", export_filename="pa_password_profiles.csv"),
            ],
        },
        {
            "label": "Certificates",
            "count": len(certs),
            "blocks": [
                {"type": "section_header", "title": "Certificate Expiry Inspector"},
                *build_cert_inspector_blocks(certs, "pa"),
                {"type": "section_header", "title": "Certificates (PAN-OS Metadata)"},
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
    ]

    return {"section": "System & Logs", "blocks": [{"type": "tabs", "id": "pa_device_tabs", "tabs": tabs}]}


def build_paloalto_section(section: str, parsers: dict[str, Any], *, allow_probe: bool = False) -> dict[str, Any]:
    builders = {
        "Overview": lambda: build_dashboard(
            parsers["Dashboard"],
            network_parser=parsers.get("Network"),
            device_parser=parsers.get("Device"),
            policies_parser=parsers.get("Policies"),
            objects_parser=parsers.get("Objects"),
            allow_probe=allow_probe,
        ),
        "Security & Health": lambda: build_security_health(
            parsers["Dashboard"],
            network_parser=parsers.get("Network"),
            device_parser=parsers.get("Device"),
            policies_parser=parsers.get("Policies"),
            objects_parser=parsers.get("Objects"),
            allow_probe=allow_probe,
        ),
        "Policies & NAT": lambda: build_policies(parsers["Policies"], objects_parser=parsers.get("Objects")),
        "Objects": lambda: build_objects(parsers["Objects"]),
        "Interfaces & Network": lambda: build_network(parsers["Network"], policies_parser=parsers.get("Policies")),
        "Security Profiles": lambda: build_security_profiles(parsers["Objects"]),
        "VPN": lambda: build_vpn(parsers["Network"], policies_parser=parsers.get("Policies")),
        "Users & Auth": lambda: build_users_auth(parsers["Device"], objects_parser=parsers.get("Objects")),
        "System & Logs": lambda: build_device(parsers["Device"]),
        # Backward-compatible legacy section aliases
        "Dashboard": lambda: build_dashboard(
            parsers["Dashboard"],
            network_parser=parsers.get("Network"),
            device_parser=parsers.get("Device"),
            policies_parser=parsers.get("Policies"),
            objects_parser=parsers.get("Objects"),
            allow_probe=allow_probe,
        ),
        "Policies": lambda: build_policies(parsers["Policies"], objects_parser=parsers.get("Objects")),
        "Network": lambda: build_network(parsers["Network"], policies_parser=parsers.get("Policies"), include_legacy_vpn=True),
        "Device": lambda: build_device(parsers["Device"]),
    }
    if section not in builders:
        raise KeyError(f"Unknown Palo Alto section: {section}")
    res = builders[section]()
    res["section"] = section
    return res
