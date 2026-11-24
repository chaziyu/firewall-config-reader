"""
backend/config_diff_service.py
Firewall-aware structural diff between the active configuration snapshot and a
second uploaded snapshot across Policies, NAT/VIPs, Static Routes, VPNs, and Interfaces.
"""

from __future__ import annotations

from typing import Any, Callable


def _clean_fg_iface(name: str) -> str:
    return str(name or "").replace("\u00a0", "").replace("\u2517 ", "").strip()


def _clean_pa_iface(name: str) -> str:
    return str(name or "").replace("\u2514 ", "").strip()


def _diff_records(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
    key_fn: Callable[[dict[str, Any]], str],
    compare_fields: list[str],
    summary_fields: list[str],
) -> list[dict[str, Any]]:
    before_map: dict[str, dict[str, Any]] = {}
    for r in before_rows:
        k = key_fn(r)
        if k:
            before_map[k] = r

    after_map: dict[str, dict[str, Any]] = {}
    for r in after_rows:
        k = key_fn(r)
        if k:
            after_map[k] = r

    all_keys = list(dict.fromkeys(list(before_map.keys()) + list(after_map.keys())))
    diffs: list[dict[str, Any]] = []

    for k in all_keys:
        b = before_map.get(k)
        a = after_map.get(k)
        if b is None and a is not None:
            summary = " · ".join(f"{f}: {a.get(f, '-')}" for f in summary_fields if a.get(f, "-") not in ("", "-", None))
            diffs.append(
                {
                    "Change": "Added",
                    "Item": k,
                    "Details": summary or "New entry added",
                    "_change_type": "added",
                }
            )
        elif a is None and b is not None:
            summary = " · ".join(f"{f}: {b.get(f, '-')}" for f in summary_fields if b.get(f, "-") not in ("", "-", None))
            diffs.append(
                {
                    "Change": "Removed",
                    "Item": k,
                    "Details": summary or "Entry removed",
                    "_change_type": "removed",
                }
            )
        elif b is not None and a is not None:
            changed: list[str] = []
            for f in compare_fields:
                bv = str(b.get(f, "-"))
                av = str(a.get(f, "-"))
                if bv != av:
                    changed.append(f"{f}: {bv} → {av}")
            if changed:
                diffs.append(
                    {
                        "Change": "Modified",
                        "Item": k,
                        "Details": "; ".join(changed),
                        "_change_type": "modified",
                    }
                )
    return diffs


def diff_fortigate_configs(before_fg: Any, after_fg: Any) -> dict[str, list[dict[str, Any]]]:
    pol_diffs = _diff_records(
        before_fg.parse_policies() or [],
        after_fg.parse_policies() or [],
        key_fn=lambda r: f"#{r.get('ID', '')} ({r.get('Name', '-')})",
        compare_fields=["Name", "Src Interface", "Dst Interface", "Source", "Destination", "Service", "Action", "NAT", "Status"],
        summary_fields=["Src Interface", "Dst Interface", "Source", "Destination", "Service", "Action"],
    )

    def _fg_nat_rows(fg: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for v in fg.parse_vip() or []:
            out.append({**v, "_key": f"VIP: {v.get('Name', '-')}"})
        for p in fg.parse_ip_pools() or []:
            out.append({**p, "_key": f"IP Pool: {p.get('Name', '-')}"})
        return out

    nat_diffs = _diff_records(
        _fg_nat_rows(before_fg),
        _fg_nat_rows(after_fg),
        key_fn=lambda r: str(r.get("_key", "")),
        compare_fields=["Interface", "Mapped From", "Mapped To", "External IP Range", "Type"],
        summary_fields=["Interface", "Mapped From", "Mapped To", "External IP Range"],
    )

    route_diffs = _diff_records(
        before_fg.parse_static_routes() or [],
        after_fg.parse_static_routes() or [],
        key_fn=lambda r: f"Seq {r.get('Seq', '-')} ({r.get('Destination', '-')})",
        compare_fields=["Destination", "Gateway", "Interface", "Distance", "Priority", "Status"],
        summary_fields=["Destination", "Gateway", "Interface", "Distance"],
    )

    vpn_diffs = _diff_records(
        before_fg.parse_ipsec_phase1() or [],
        after_fg.parse_ipsec_phase1() or [],
        key_fn=lambda r: str(r.get("name", "-")),
        compare_fields=["interface", "remote_gw", "ike_version", "proposal", "dhgrp", "status"],
        summary_fields=["interface", "remote_gw", "ike_version", "status"],
    )

    def _fg_iface_rows(fg: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in fg.parse_interfaces() or []:
            if str(r.get("Type", "")).lower() == "zone":
                out.append({**r, "_key": f"Zone: {r.get('Zone', '-')}"})
            else:
                out.append({**r, "_key": _clean_fg_iface(str(r.get("Name", "")))})
        return out

    iface_diffs = _diff_records(
        _fg_iface_rows(before_fg),
        _fg_iface_rows(after_fg),
        key_fn=lambda r: str(r.get("_key", "")),
        compare_fields=["Type", "IP/Netmask", "Zone", "Admin Access", "Status", "Members"],
        summary_fields=["Type", "IP/Netmask", "Zone", "Status"],
    )

    return {
        "Firewall Policies": pol_diffs,
        "NAT / VIPs & IP Pools": nat_diffs,
        "Static Routes": route_diffs,
        "IPSec VPN Tunnels": vpn_diffs,
        "Interfaces & Zones": iface_diffs,
    }


def diff_paloalto_configs(before_parsers: dict[str, Any], after_parsers: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    b_pol = before_parsers["Policies"]
    a_pol = after_parsers["Policies"]
    b_net = before_parsers["Network"]
    a_net = after_parsers["Network"]

    sec_diffs = _diff_records(
        b_pol.get_security_rules() or [],
        a_pol.get_security_rules() or [],
        key_fn=lambda r: str(r.get("Name", "-")),
        compare_fields=["Source Zone", "Source Addr", "Dest Zone", "Dest Addr", "Application", "Service", "Action", "_disabled"],
        summary_fields=["Source Zone", "Dest Zone", "Source Addr", "Dest Addr", "Action"],
    )

    nat_diffs = _diff_records(
        b_pol.get_nat_rules() or [],
        a_pol.get_nat_rules() or [],
        key_fn=lambda r: str(r.get("Name", "-")),
        compare_fields=["Source Zone", "Dest Zone", "Source Addr", "Dest Addr", "Service", "Src Translation", "Dst Translation", "_disabled"],
        summary_fields=["Source Zone", "Dest Zone", "Src Translation", "Dst Translation"],
    )

    def _pa_routes(net_p: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for vr in net_p.get_virtual_routers() or []:
            vr_el = vr.get("_vr_el")
            if vr_el is None:
                continue
            detail = net_p.get_vr_detail(vr_el)
            vr_name = detail.get("name", vr.get("Name", "default"))
            for rt in detail.get("static_v4", []) or []:
                out.append({**rt, "_key": f"{vr_name}: {rt.get('Name', '-')}"})
        return out

    route_diffs = _diff_records(
        _pa_routes(b_net),
        _pa_routes(a_net),
        key_fn=lambda r: str(r.get("_key", "")),
        compare_fields=["Destination", "Interface", "NH Type", "NH Value", "Metric"],
        summary_fields=["Destination", "Interface", "NH Value"],
    )

    vpn_diffs = _diff_records(
        b_net.get_ipsec_tunnels() or [],
        a_net.get_ipsec_tunnels() or [],
        key_fn=lambda r: str(r.get("Name", "-")),
        compare_fields=["IKE GW", "IKE Interface", "IKE Peer IP", "Tunnel Intf", "Zone", "Crypto"],
        summary_fields=["IKE GW", "IKE Peer IP", "Tunnel Intf", "Zone"],
    )

    def _pa_ifaces(net_p: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rows in (
            net_p.get_ethernet_interfaces() or [],
            net_p.get_vlan_interfaces() or [],
            net_p.get_loopback_interfaces() or [],
            net_p.get_tunnel_interfaces() or [],
        ):
            for r in rows:
                out.append({**r, "_key": _clean_pa_iface(str(r.get("Interface", "")))})
        return out

    iface_diffs = _diff_records(
        _pa_ifaces(b_net),
        _pa_ifaces(a_net),
        key_fn=lambda r: str(r.get("_key", "")),
        compare_fields=["Type", "IP Address", "Zone", "Virtual Router", "Mgmt Profile", "_disabled"],
        summary_fields=["IP Address", "Zone", "Virtual Router"],
    )

    return {
        "Security Policies": sec_diffs,
        "NAT Policies": nat_diffs,
        "Static Routes": route_diffs,
        "IPSec Tunnels": vpn_diffs,
        "Interfaces": iface_diffs,
    }


def build_config_diff_blocks(
    diff_res: dict[str, list[dict[str, Any]]],
    before_name: str,
    after_name: str,
) -> dict[str, Any]:
    added = modified = removed = 0
    for rows in diff_res.values():
        for r in rows:
            ct = r.get("_change_type")
            if ct == "added":
                added += 1
            elif ct == "modified":
                modified += 1
            elif ct == "removed":
                removed += 1

    total = added + modified + removed
    if total == 0:
        return {
            "has_diff": False,
            "summary": {"added": 0, "modified": 0, "removed": 0, "total": 0},
            "blocks": [
                {
                    "type": "alert",
                    "variant": "success",
                    "text": f"No differences found between '{before_name}' and '{after_name}' across Policies, NAT, Routes, VPNs, and Interfaces.",
                }
            ],
        }

    blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": f"Config Diff: {before_name} → {after_name}",
            "subtitle": f"Detected {total} structural change(s) across firewall domains.",
            "badge": {"text": f"{total} Change(s)", "variant": "info"},
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Added", "value": str(added)},
                {"label": "Modified", "value": str(modified)},
                {"label": "Removed", "value": str(removed)},
                {"label": "Total Changes", "value": str(total)},
            ],
        },
    ]

    for idx, (domain, rows) in enumerate(diff_res.items()):
        if not rows:
            continue
        clean_rows = [
            {"Change": r["Change"], "Item": r["Item"], "Details": r["Details"]}
            for r in rows
        ]
        row_classes = [
            "row-success" if r["_change_type"] == "added" else ("row-warn" if r["_change_type"] == "modified" else "row-danger")
            for r in rows
        ]
        blocks.append(
            {
                "type": "expander",
                "title": f"{domain} ({len(rows)})",
                "open": True,
                "blocks": [
                    {
                        "type": "table",
                        "id": f"cfg_diff_{idx}",
                        "columns": ["Change", "Item", "Details"],
                        "rows": clean_rows,
                        "row_classes": row_classes,
                        "legend": [
                            {"label": "Added (green)", "variant": "success"},
                            {"label": "Modified (amber)", "variant": "warn"},
                            {"label": "Removed (red)", "variant": "danger"},
                        ],
                        "export_filename": f"config_diff_{idx}.csv",
                    }
                ],
            }
        )

    return {
        "has_diff": True,
        "summary": {"added": added, "modified": modified, "removed": removed, "total": total},
        "blocks": blocks,
    }
