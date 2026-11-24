"""
backend/audit_service.py
Quick security & hygiene audit checks for FortiGate and Palo Alto configurations.
"""

from __future__ import annotations

import re
from typing import Any

_WEAK_CRYPTO_RE = re.compile(r"\b(des|3des|md5|sha1)\b", re.IGNORECASE)
_FG_WEAK_DH = {"1", "2", "5"}
_PA_WEAK_DH = {"group1", "group2", "group5"}


def _split_csv_lower(val: Any) -> set[str]:
    return {t.strip().lower() for t in str(val or "").split(",") if t.strip()}


def _has_weak_crypto(text: Any) -> bool:
    return bool(_WEAK_CRYPTO_RE.search(str(text or "")))


def _has_weak_dh(dh_str: Any, weak_tokens: set[str]) -> bool:
    tokens = {t.strip().lower() for t in re.split(r"[\s,;/]+", str(dh_str or "")) if t.strip()}
    return bool(tokens & weak_tokens)


def _preview_names(names: list[str], limit: int = 8) -> str:
    if not names:
        return "None"
    shown = names[:limit]
    tail = f" (+{len(names) - limit} more)" if len(names) > limit else ""
    return ", ".join(shown) + tail


def _collect_unused_fg_addresses(parser: Any) -> list[str]:
    addrs = parser.parse_addresses() if hasattr(parser, "parse_addresses") else {}
    defined: list[str] = []
    for bucket in ("subnet", "iprange", "ipmask", "fqdn", "other"):
        for obj in addrs.get(bucket, []) or []:
            name = str(obj.get("Name", "")).strip()
            if name and name.lower() not in ("all", "any"):
                defined.append(name)
    if not defined:
        return []

    used_tokens: set[str] = set()
    for pol in parser.parse_policies() or []:
        for field in ("Source", "Destination"):
            for tok in str(pol.get(field, "")).split(","):
                if tok.strip():
                    used_tokens.add(tok.strip())
    for pol in parser.parse_proxy_policy() or []:
        for field in ("Source", "Destination"):
            for tok in str(pol.get(field, "")).split(","):
                if tok.strip():
                    used_tokens.add(tok.strip())
    for grp in addrs.get("groups", []) or []:
        for tok in str(grp.get("Members", "")).split(","):
            if tok.strip():
                used_tokens.add(tok.strip())
    for vip in parser.parse_vip() or []:
        if vip.get("Name"):
            used_tokens.add(str(vip["Name"]).strip())

    return [n for n in defined if n not in used_tokens]


def _collect_unused_pa_addresses(
    policies_parser: Any,
    objects_parser: Any,
) -> list[str]:
    if objects_parser is None:
        return []
    defined = [
        str(a.get("Name", "")).strip()
        for a in (objects_parser.get_addresses() or [])
        if str(a.get("Name", "")).strip()
    ]
    if not defined:
        return []

    used_tokens: set[str] = set()
    for grp in objects_parser.get_address_groups() or []:
        for tok in str(grp.get("Members", "")).split(","):
            if tok.strip():
                used_tokens.add(tok.strip())

    if policies_parser is not None:
        for getter in (
            "get_security_rules",
            "get_nat_rules",
            "get_pbf_rules",
            "get_decryption_rules",
            "get_qos_rules",
            "get_dos_rules",
            "get_auth_rules",
        ):
            fn = getattr(policies_parser, getter, None)
            if fn is None:
                continue
            for r in fn() or []:
                for field in ("Source Addr", "Dest Addr", "Src Translation", "Dst Translation"):
                    val = str(r.get(field, "") or "")
                    for tok in re.split(r"[\s,|]+", val):
                        cleaned = tok.strip()
                        if cleaned:
                            used_tokens.add(cleaned)

    return [n for n in defined if n not in used_tokens]


def run_fortigate_audit(parser: Any) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    policies = parser.parse_policies() or []

    any_any: list[str] = []
    no_profile: list[str] = []
    unlogged: list[str] = []
    disabled_pols: list[str] = []

    for pol in policies:
        label = f"#{pol.get('ID', '?')} {pol.get('Name', '-')}"
        status = str(pol.get("Status", "Enable")).strip().lower()
        if status == "disable":
            disabled_pols.append(label)
            continue

        if str(pol.get("Action", "")).strip().upper() != "ACCEPT":
            continue

        srcs = _split_csv_lower(pol.get("Source"))
        dsts = _split_csv_lower(pol.get("Destination"))
        svcs = _split_csv_lower(pol.get("Service"))
        if (srcs & {"all", "any"}) and (dsts & {"all", "any"}) and (svcs & {"all", "any"}):
            any_any.append(label)

        if not pol.get("_has_profile"):
            no_profile.append(label)

        log_val = str(pol.get("Log", "-")).strip().lower()
        if log_val in ("disable", "-", "none", ""):
            unlogged.append(label)

    # Weak VPN crypto
    weak_vpn_high: list[str] = []
    weak_vpn_med: list[str] = []
    for p1 in (parser.parse_ipsec_phase1() if hasattr(parser, "parse_ipsec_phase1") else []) or []:
        if str(p1.get("status", "Enable")).strip().lower() == "disable":
            continue
        tname = p1.get("name", "-")
        if _has_weak_crypto(p1.get("proposal")):
            weak_vpn_high.append(f"P1 {tname} ({p1.get('proposal')})")
        if str(p1.get("ike_version", "1")).strip() == "1":
            weak_vpn_med.append(f"P1 {tname} (IKEv1)")
        if _has_weak_dh(p1.get("dhgrp"), _FG_WEAK_DH):
            weak_vpn_med.append(f"P1 {tname} (DH {p1.get('dhgrp')})")

    for p2 in (parser.parse_ipsec_phase2() if hasattr(parser, "parse_ipsec_phase2") else []) or []:
        tname = p2.get("name", "-")
        if _has_weak_crypto(p2.get("proposal")):
            weak_vpn_high.append(f"P2 {tname} ({p2.get('proposal')})")
        if str(p2.get("pfs", "enable")).strip().lower() == "enable" and _has_weak_dh(
            p2.get("dhgrp"), _FG_WEAK_DH
        ):
            weak_vpn_med.append(f"P2 {tname} (DH {p2.get('dhgrp')})")

    unused_addrs = _collect_unused_fg_addresses(parser)

    if any_any:
        findings.append(
            {
                "Severity": "High",
                "Category": "Overly Permissive ANY-ANY Allow Rules",
                "Count": len(any_any),
                "Details": _preview_names(any_any),
            }
        )
    if weak_vpn_high:
        findings.append(
            {
                "Severity": "High",
                "Category": "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)",
                "Count": len(weak_vpn_high),
                "Details": _preview_names(weak_vpn_high),
            }
        )
    if no_profile:
        findings.append(
            {
                "Severity": "Medium",
                "Category": "Allow Policies Missing Security Profiles",
                "Count": len(no_profile),
                "Details": _preview_names(no_profile),
            }
        )
    if weak_vpn_med:
        findings.append(
            {
                "Severity": "Medium",
                "Category": "Legacy VPN IKEv1 or Weak DH Group (1/2/5)",
                "Count": len(weak_vpn_med),
                "Details": _preview_names(weak_vpn_med),
            }
        )
    if unlogged:
        findings.append(
            {
                "Severity": "Info",
                "Category": "Unlogged Allow Policies",
                "Count": len(unlogged),
                "Details": _preview_names(unlogged),
            }
        )
    if disabled_pols:
        findings.append(
            {
                "Severity": "Info",
                "Category": "Disabled Firewall Policies",
                "Count": len(disabled_pols),
                "Details": _preview_names(disabled_pols),
            }
        )
    if unused_addrs:
        findings.append(
            {
                "Severity": "Info",
                "Category": "Unused Address Objects (Best-Effort)",
                "Count": len(unused_addrs),
                "Details": _preview_names(unused_addrs),
            }
        )

    return _summarize_findings(findings)


def run_paloalto_audit(parsers: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    pol = parsers.get("Policies")
    obj = parsers.get("Objects")
    net = parsers.get("Network")

    any_any: list[str] = []
    no_profile: list[str] = []
    disabled_rules: list[str] = []

    if pol is not None:
        for rule in pol.get_security_rules() or []:
            rname = str(rule.get("Name", "-"))
            if rule.get("_disabled"):
                disabled_rules.append(rname)
                continue
            if str(rule.get("Action", "")).strip().lower() != "allow":
                continue

            srcs = _split_csv_lower(rule.get("Source Addr"))
            dsts = _split_csv_lower(rule.get("Dest Addr"))
            apps = _split_csv_lower(rule.get("Application"))
            svcs = _split_csv_lower(rule.get("Service"))
            if (
                "any" in srcs
                and "any" in dsts
                and "any" in apps
                and bool(svcs & {"any", "application-default"})
            ):
                any_any.append(rname)

            if str(rule.get("Profile Type", "None")).strip() == "None":
                no_profile.append(rname)

    weak_vpn_high: list[str] = []
    weak_vpn_med: list[str] = []
    if net is not None:
        for gw in (net.get_ike_gateways() if hasattr(net, "get_ike_gateways") else []) or []:
            ver = str(gw.get("Version", "")).strip().lower()
            if ver == "ikev1":
                weak_vpn_med.append(f"GW {gw.get('Name', '-')} (IKEv1)")

        for prof in (net.get_ike_crypto_profiles() if hasattr(net, "get_ike_crypto_profiles") else []) or []:
            pname = prof.get("Name", "-")
            if _has_weak_crypto(prof.get("Encryption")) or _has_weak_crypto(prof.get("Authentication")):
                weak_vpn_high.append(f"IKE {pname} ({prof.get('Encryption')} / {prof.get('Authentication')})")
            if _has_weak_dh(prof.get("DH Group"), _PA_WEAK_DH):
                weak_vpn_med.append(f"IKE {pname} ({prof.get('DH Group')})")

        for prof in (net.get_ipsec_crypto_profiles() if hasattr(net, "get_ipsec_crypto_profiles") else []) or []:
            pname = prof.get("Name", "-")
            if _has_weak_crypto(prof.get("Encryption")) or _has_weak_crypto(prof.get("Authentication")):
                weak_vpn_high.append(f"IPSec {pname} ({prof.get('Encryption')} / {prof.get('Authentication')})")
            if _has_weak_dh(prof.get("DH Group"), _PA_WEAK_DH):
                weak_vpn_med.append(f"IPSec {pname} ({prof.get('DH Group')})")

    unused_addrs = _collect_unused_pa_addresses(pol, obj)

    if any_any:
        findings.append(
            {
                "Severity": "High",
                "Category": "Overly Permissive ANY-ANY Allow Rules",
                "Count": len(any_any),
                "Details": _preview_names(any_any),
            }
        )
    if weak_vpn_high:
        findings.append(
            {
                "Severity": "High",
                "Category": "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)",
                "Count": len(weak_vpn_high),
                "Details": _preview_names(weak_vpn_high),
            }
        )
    if no_profile:
        findings.append(
            {
                "Severity": "Medium",
                "Category": "Allow Rules Missing Security Profiles",
                "Count": len(no_profile),
                "Details": _preview_names(no_profile),
            }
        )
    if weak_vpn_med:
        findings.append(
            {
                "Severity": "Medium",
                "Category": "Legacy VPN IKEv1 or Weak DH Group (1/2/5)",
                "Count": len(weak_vpn_med),
                "Details": _preview_names(weak_vpn_med),
            }
        )
    if disabled_rules:
        findings.append(
            {
                "Severity": "Info",
                "Category": "Disabled Security Rules",
                "Count": len(disabled_rules),
                "Details": _preview_names(disabled_rules),
            }
        )
    if unused_addrs:
        findings.append(
            {
                "Severity": "Info",
                "Category": "Unused Address Objects (Best-Effort)",
                "Count": len(unused_addrs),
                "Details": _preview_names(unused_addrs),
            }
        )

    return _summarize_findings(findings)


def _summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    high_count = sum(1 for f in findings if f["Severity"] == "High")
    med_count = sum(1 for f in findings if f["Severity"] == "Medium")
    info_count = sum(1 for f in findings if f["Severity"] == "Info")
    return {
        "findings": findings,
        "high_count": high_count,
        "med_count": med_count,
        "info_count": info_count,
    }


def build_audit_overview_blocks(audit: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    high_count = int(audit.get("high_count", 0))
    med_count = int(audit.get("med_count", 0))
    info_count = int(audit.get("info_count", 0))
    findings = audit.get("findings", []) or []

    actionable = high_count + med_count
    if high_count > 0:
        badge = {"text": f"Audit: {actionable} Findings", "variant": "deny"}
    elif med_count > 0:
        badge = {"text": f"Audit: {actionable} Findings", "variant": "warn"}
    else:
        badge = {"text": "Audit: Clean", "variant": "allow"}

    summary_grid = {
        "type": "kv_grid",
        "items": [
            {"label": "High Risk", "value": str(high_count)},
            {"label": "Medium Risk", "value": str(med_count)},
            {"label": "Hygiene / Info", "value": str(info_count)},
        ],
    }

    if not findings:
        inner_blocks: list[dict[str, Any]] = [
            summary_grid,
            {
                "type": "alert",
                "variant": "success",
                "text": "No risky ANY-ANY rules, unprotected allow policies, weak VPN crypto, or unused address objects detected.",
            },
        ]
    else:
        row_classes = [
            "row-danger"
            if f["Severity"] == "High"
            else ("row-warn" if f["Severity"] == "Medium" else "row-info")
            for f in findings
        ]
        inner_blocks = [
            summary_grid,
            {
                "type": "table",
                "id": "fw_quick_audit",
                "columns": ["Severity", "Category", "Count", "Details"],
                "rows": [
                    {
                        "Severity": str(f["Severity"]),
                        "Category": str(f["Category"]),
                        "Count": str(f["Count"]),
                        "Details": str(f["Details"]),
                    }
                    for f in findings
                ],
                "row_classes": row_classes,
                "export_filename": "quick_security_audit.csv",
                "legend": [
                    {"label": "High Severity (red)", "variant": "danger"},
                    {"label": "Medium Severity (amber)", "variant": "warn"},
                    {"label": "Info / Hygiene (blue)", "variant": "info"},
                ],
            },
        ]

    expander = {
        "type": "expander",
        "title": f"🩺 Quick Security & Hygiene Audit ({high_count} High · {med_count} Med · {info_count} Info)",
        "open": high_count > 0,
        "blocks": inner_blocks,
    }
    return badge, expander
