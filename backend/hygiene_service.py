"""
backend/hygiene_service.py
Unused / Orphaned Object & Rule Cleanup Analyzer for FortiGate and Palo Alto.
Finds unreferenced Address Objects, Groups, Services, VIPs, and IP Pools, plus
rule hygiene issues (disabled rules, broad any/all rules, expired schedules, no logging).
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


def _split_csv(val: str) -> list[str]:
    out: list[str] = []
    for part in str(val or "").split(","):
        tok = part.strip()
        if tok.startswith("!"):
            tok = tok[1:].strip()
        if tok and tok != "-":
            out.append(tok)
    return out


def _parse_fg_onetime_end(sched_str: str) -> datetime | None:
    # Format: "HH:MM YYYY/MM/DD to HH:MM YYYY/MM/DD"
    if " to " not in str(sched_str or ""):
        return None
    end_part = str(sched_str).split(" to ", 1)[1].strip()
    for fmt in ("%H:%M %Y/%m/%d", "%Y/%m/%d %H:%M", "%Y/%m/%d"):
        try:
            return datetime.strptime(end_part, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_pa_onetime_end(times_str: str) -> datetime | None:
    # Format: "2025/01/01@00:00-2025/01/02@23:59"
    parts = [p.strip() for p in str(times_str or "").split(",") if p.strip()]
    ends: list[datetime] = []
    for part in parts:
        end_tok = part.split("-", 1)[1].strip() if "-" in part else part
        for fmt in ("%Y/%m/%d@%H:%M", "%Y/%m/%d"):
            try:
                ends.append(datetime.strptime(end_tok, fmt).replace(tzinfo=timezone.utc))
                break
            except ValueError:
                continue
    return max(ends) if ends else None


def analyze_fortigate_hygiene(fg: Any, now: datetime | None = None) -> dict[str, Any]:
    now_dt = now or datetime.now(timezone.utc)
    addresses = fg.parse_addresses() or {}
    services_data = fg.parse_services() or {}
    vips = fg.parse_vip() or []
    ip_pools = fg.parse_ip_pools() or []
    policies = fg.parse_policies() or []
    proxy_pols = fg.parse_proxy_policy() or []
    schedules = fg.parse_schedules() or []
    p2_list = fg.parse_ipsec_phase2() or []
    ssl_portals = fg.parse_ssl_portals() or []
    ssl_settings = fg.parse_ssl_settings() or {}

    referenced: set[str] = set()
    used_schedules: set[str] = set()

    for pol in policies:
        for field in ("Source", "Destination", "Service", "Schedule"):
            for tok in _split_csv(str(pol.get(field, ""))):
                referenced.add(tok)
                if field == "Schedule":
                    used_schedules.add(tok)

    for pp in proxy_pols:
        for field in ("Source", "Destination", "Service", "Schedule"):
            for tok in _split_csv(str(pp.get(field, ""))):
                referenced.add(tok)

    for grp in addresses.get("groups", []) or []:
        for tok in _split_csv(str(grp.get("Members", ""))):
            referenced.add(tok)

    for sgrp in services_data.get("groups", []) or []:
        for tok in _split_csv(str(sgrp.get("Members", ""))):
            referenced.add(tok)

    for p2 in p2_list:
        if p2.get("src_addr_type") == "name" and p2.get("src_name") not in (None, "-"):
            referenced.add(str(p2["src_name"]))
        if p2.get("dst_addr_type") == "name" and p2.get("dst_name") not in (None, "-"):
            referenced.add(str(p2["dst_name"]))

    for portal in ssl_portals:
        for tok in _split_csv(str(portal.get("ip_pools", ""))):
            referenced.add(tok)
    if ssl_settings.get("ip_range") not in (None, "-"):
        for tok in _split_csv(str(ssl_settings["ip_range"])):
            referenced.add(tok)

    # Check raw policy poolname & portal split-tunneling references
    extract = getattr(fg, "_extract_block", None)
    if extract is not None:
        pol_raw = extract("firewall policy") or ""
        for m in re.findall(r'set poolname (.*)', pol_raw):
            for tok in re.findall(r'"([^"]+)"', m):
                referenced.add(tok)
        portal_raw = extract("vpn ssl web portal") or ""
        for m in re.findall(r'set split-tunneling-routing-address (.*)', portal_raw):
            for tok in re.findall(r'"([^"]+)"', m):
                referenced.add(tok)
        local_in_raw = extract("firewall local-in-policy") or ""
        for m in re.findall(r'set (?:srcaddr|dstaddr|service) (.*)', local_in_raw):
            for tok in re.findall(r'"([^"]+)"', m):
                referenced.add(tok)

    unused_objects: list[dict[str, str]] = []
    cleanup_cmds: dict[str, list[str]] = {
        "firewall address": [],
        "firewall addrgrp": [],
        "firewall service custom": [],
        "firewall vip": [],
        "firewall ippool": [],
    }

    builtin_addrs = {
        "all",
        "none",
        "any",
        "SSLVPN_TUNNEL_ADDR1",
        "EMS_ALL_UNKNOWN_CLIENTS",
        "EMS_ALL_UNMANAGEABLE_CLIENTS",
        "FABRIC_DEVICE",
        "FIREWALL_AUTH_PORTAL_ADDRESS",
        "FCTEMS_ALL_FORTICLOUD_SERVERS",
        "*.live.com",
    }
    builtin_services = {
        "ALL", "ANY", "FTP", "FTP_GET", "FTP_PUT", "DNS", "HTTP", "HTTPS",
        "IMAP", "IMAPS", "LDAP", "DCE-RPC", "POP3", "POP3S", "SAMBA", "SMTP",
        "SMTPS", "KERBEROS", "LDAP_UDP", "SMB", "ALL_TCP", "ALL_UDP", "ALL_ICMP",
        "ALL_ICMP6", "GRE", "AH", "ESP", "AOL", "BGP", "DHCP", "FINGER",
        "GOPHER", "H323", "IKE", "Internet-Locator-Service", "IRC", "L2TP",
        "NetMeeting", "NFS", "NNTP", "NTP", "OSPF", "PC-Anywhere", "PING",
        "TIMESTAMP", "INFO_REQUEST", "INFO_ADDRESS", "ONC-RPC", "PPTP", "QUAKE",
        "RAUDIO", "REXEC", "RIP", "RLOGIN", "RSH", "SCCP", "SIP",
        "SIP-MSNmessenger", "SNMP", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP",
        "MGCP", "UUCP", "VDOLIVE", "WAIS", "WINFRAME", "X-WINDOWS", "PING6",
        "MS-SQL", "MYSQL", "RDP", "VNC", "DHCP6", "SQUID", "SOCKS", "WINS",
        "RADIUS", "RADIUS-OLD", "CVSPSERVER", "AFS3", "TRACEROUTE", "RTSP",
        "MMS", "NONE", "webproxy",
    }
    for bucket in ("subnet", "iprange", "ipmask", "fqdn", "other"):
        for obj in addresses.get(bucket, []) or []:
            name = str(obj.get("Name", "")).strip()
            if not name or name in builtin_addrs or name in referenced:
                continue
            val = str(obj.get("Details", obj.get("FQDN", "-")))
            unused_objects.append({"Category": f"Address ({obj.get('Type', bucket)})", "Name": name, "Value": val})
            cleanup_cmds["firewall address"].append(name)

    for grp in addresses.get("groups", []) or []:
        name = str(grp.get("Name", "")).strip()
        if not name or name in referenced:
            continue
        unused_objects.append({"Category": "Address Group", "Name": name, "Value": str(grp.get("Members", "-"))})
        cleanup_cmds["firewall addrgrp"].append(name)

    for svc in services_data.get("services", []) or []:
        name = str(svc.get("Name", "")).strip()
        if not name or name in builtin_services or name.upper() in ("ALL", "ANY") or name in referenced:
            continue
        unused_objects.append({"Category": "Custom Service", "Name": name, "Value": str(svc.get("Details", "-"))})
        cleanup_cmds["firewall service custom"].append(name)

    for vip in vips:
        name = str(vip.get("Name", "")).strip()
        if not name or name in referenced:
            continue
        unused_objects.append(
            {
                "Category": "Virtual IP (VIP)",
                "Name": name,
                "Value": f"{vip.get('Mapped From', '-')} → {vip.get('Mapped To', '-')}",
            }
        )
        cleanup_cmds["firewall vip"].append(name)

    for pool in ip_pools:
        name = str(pool.get("Name", "")).strip()
        if not name or name in referenced:
            continue
        unused_objects.append({"Category": "IP Pool", "Name": name, "Value": str(pool.get("External IP Range", "-"))})
        cleanup_cmds["firewall ippool"].append(name)

    hygiene_issues: list[dict[str, Any]] = []
    disabled_count = broad_count = extra_count = 0

    for pol in policies:
        pid = str(pol.get("ID", "-"))
        pname = str(pol.get("Name", "-"))
        status = str(pol.get("Status", "Enable")).lower()
        action = str(pol.get("Action", "-")).upper()
        if status == "disable":
            disabled_count += 1
            hygiene_issues.append(
                {
                    "Finding": "Disabled Policy",
                    "Target": f"Policy #{pid} ({pname})",
                    "Details": f"{pol.get('Src Interface', '-')} → {pol.get('Dst Interface', '-')}",
                    "Severity": "Warning",
                    "_sev": "warn",
                }
            )
            continue

        if action == "ACCEPT":
            src = str(pol.get("Source", "")).strip().lower()
            dst = str(pol.get("Destination", "")).strip().lower()
            svc = str(pol.get("Service", "")).strip().lower()
            if src in ("all", "any") and dst in ("all", "any") and svc in ("all", "any"):
                broad_count += 1
                hygiene_issues.append(
                    {
                        "Finding": "Overly Broad Allow Policy",
                        "Target": f"Policy #{pid} ({pname})",
                        "Details": f"{pol.get('Src Interface', '-')} → {pol.get('Dst Interface', '-')} permits all/ALL",
                        "Severity": "Critical",
                        "_sev": "danger",
                    }
                )
            log_val = str(pol.get("Log", "-")).strip().lower()
            if log_val in ("disable", "-"):
                extra_count += 1
                hygiene_issues.append(
                    {
                        "Finding": "Logging Disabled on Allow Policy",
                        "Target": f"Policy #{pid} ({pname})",
                        "Details": "Enable logtraffic (all/utm) for visibility and incident triage.",
                        "Severity": "Warning",
                        "_sev": "warn",
                    }
                )

    for sched in schedules:
        if str(sched.get("Type", "")).lower() == "one-time":
            end_dt = _parse_fg_onetime_end(str(sched.get("Schedule", "")))
            if end_dt is not None and end_dt < now_dt:
                sname = str(sched.get("Name", "-"))
                extra_count += 1
                in_pol = " (referenced by policy)" if sname in used_schedules else " (unreferenced)"
                hygiene_issues.append(
                    {
                        "Finding": "Expired One-Time Schedule",
                        "Target": sname,
                        "Details": f"Ended {end_dt.strftime('%Y-%m-%d %H:%M')} UTC{in_pol}",
                        "Severity": "Warning",
                        "_sev": "warn",
                    }
                )

    cli_lines: list[str] = []
    for block_name, names in cleanup_cmds.items():
        if not names:
            continue
        cli_lines.append(f"config {block_name}")
        for n in names:
            cli_lines.append(f'    delete "{n}"')
        cli_lines.append("end")
        cli_lines.append("")

    return {
        "unused_objects": unused_objects,
        "hygiene_issues": hygiene_issues,
        "counts": {
            "unused": len(unused_objects),
            "disabled": disabled_count,
            "broad": broad_count,
            "extra": extra_count,
        },
        "cleanup_cli": "\n".join(cli_lines).strip(),
    }


def analyze_paloalto_hygiene(parsers: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now_dt = now or datetime.now(timezone.utc)
    pol_p = parsers.get("Policies")
    obj_p = parsers.get("Objects")

    referenced: set[str] = set()
    used_schedules: set[str] = set()

    rule_getters = (
        ("get_security_rules", ["Source Addr", "Dest Addr", "Service"]),
        ("get_nat_rules", ["Source Addr", "Dest Addr", "Service", "Src Translation", "Dst Translation"]),
        ("get_pbf_rules", ["Source", "Destination", "Service"]),
        ("get_decryption_rules", ["Source", "Destination", "Service"]),
        ("get_qos_rules", ["Source", "Destination", "Service"]),
        ("get_auth_rules", ["Source", "Destination", "Service"]),
        ("get_dos_rules", ["Source", "Destination", "Service"]),
        ("get_app_override_rules", ["Source", "Destination"]),
    )

    sec_rules: list[dict[str, Any]] = []
    if pol_p is not None:
        sec_rules = pol_p.get_security_rules() or []
        for getter, fields in rule_getters:
            fn = getattr(pol_p, getter, None)
            if fn is None:
                continue
            for r in fn() or []:
                for f in fields:
                    for tok in _split_csv(str(r.get(f, ""))):
                        referenced.add(tok)

        # Also inspect schedule XML tags directly on security rules
        rb = getattr(pol_p, "rb", None)
        if rb is not None:
            for entry in rb.findall("security/rules/entry"):
                sched = entry.findtext("schedule")
                if sched:
                    used_schedules.add(sched.strip())
                    referenced.add(sched.strip())

    unused_objects: list[dict[str, str]] = []
    if obj_p is not None:
        addr_groups = obj_p.get_address_groups() or []
        svc_groups = obj_p.get_service_groups() or []
        for grp in addr_groups:
            for tok in _split_csv(str(grp.get("Members", ""))):
                referenced.add(tok)
        for sgrp in svc_groups:
            for tok in _split_csv(str(sgrp.get("Members", ""))):
                referenced.add(tok)

        for obj in obj_p.get_addresses() or []:
            name = str(obj.get("Name", "")).strip()
            if not name or name in referenced:
                continue
            unused_objects.append({"Category": f"Address ({obj.get('Type', '-')})", "Name": name, "Value": str(obj.get("Value", "-"))})

        for grp in addr_groups:
            name = str(grp.get("Name", "")).strip()
            if not name or name in referenced:
                continue
            unused_objects.append({"Category": f"Address Group ({grp.get('Type', '-')})", "Name": name, "Value": str(grp.get("Members", "-"))})

        for svc in obj_p.get_services() or []:
            name = str(svc.get("Name", "")).strip()
            if not name or name.startswith("[Predefined]") or name.lower() in ("any", "application-default") or name in referenced:
                continue
            # Custom services only (skip predefined entries)
            if str(svc.get("Location", "")).lower() == "predefined":
                continue
            unused_objects.append({"Category": "Custom Service", "Name": name, "Value": str(svc.get("Destination Port", svc.get("Port", "-")))})

        for sgrp in svc_groups:
            name = str(sgrp.get("Name", "")).strip()
            if not name or name in referenced:
                continue
            unused_objects.append({"Category": "Service Group", "Name": name, "Value": str(sgrp.get("Members", "-"))})

    hygiene_issues: list[dict[str, Any]] = []
    disabled_count = broad_count = extra_count = 0

    for rule in sec_rules:
        rname = str(rule.get("Name", "-"))
        if rule.get("_disabled"):
            disabled_count += 1
            hygiene_issues.append(
                {
                    "Finding": "Disabled Security Rule",
                    "Target": rname,
                    "Details": f"{rule.get('Source Zone', '-')} → {rule.get('Dest Zone', '-')}",
                    "Severity": "Warning",
                    "_sev": "warn",
                }
            )
            continue

        if str(rule.get("Action", "")).lower() == "allow":
            src = str(rule.get("Source Addr", "")).strip().lower()
            dst = str(rule.get("Dest Addr", "")).strip().lower()
            app = str(rule.get("Application", "")).strip().lower()
            svc = str(rule.get("Service", "")).strip().lower()
            if src == "any" and dst == "any" and app == "any" and svc == "any":
                broad_count += 1
                hygiene_issues.append(
                    {
                        "Finding": "Overly Broad Allow Rule",
                        "Target": rname,
                        "Details": f"{rule.get('Source Zone', '-')} → {rule.get('Dest Zone', '-')} allows any/any/any/any",
                        "Severity": "Critical",
                        "_sev": "danger",
                    }
                )

    if obj_p is not None and hasattr(obj_p, "get_schedules"):
        for sched in obj_p.get_schedules() or []:
            if str(sched.get("Recurrence", "")).lower() == "one-time":
                end_dt = _parse_pa_onetime_end(str(sched.get("Times", "")))
                if end_dt is not None and end_dt < now_dt:
                    sname = str(sched.get("Name", "-"))
                    extra_count += 1
                    in_pol = " (referenced by rule)" if sname in used_schedules else " (unreferenced)"
                    hygiene_issues.append(
                        {
                            "Finding": "Expired One-Time Schedule",
                            "Target": sname,
                            "Details": f"Ended {end_dt.strftime('%Y-%m-%d %H:%M')} UTC{in_pol}",
                            "Severity": "Warning",
                            "_sev": "warn",
                        }
                    )

    return {
        "unused_objects": unused_objects,
        "hygiene_issues": hygiene_issues,
        "counts": {
            "unused": len(unused_objects),
            "disabled": disabled_count,
            "broad": broad_count,
            "extra": extra_count,
        },
        "cleanup_cli": "",
    }


def build_hygiene_blocks(analysis: dict[str, Any], vendor: str) -> list[dict[str, Any]]:
    unused = analysis.get("unused_objects") or []
    issues = analysis.get("hygiene_issues") or []
    counts = analysis.get("counts") or {}
    total = len(unused) + len(issues)

    badge = (
        {"text": f"{total} Cleanup Item(s)", "variant": "warn"}
        if total > 0
        else {"text": "Clean Rulebase", "variant": "allow"}
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": "Unused Objects & Rule Hygiene Analyzer",
            "subtitle": "Identifies unreferenced address/service/NAT objects and rulebase cleanup candidates.",
            "badge": badge,
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Unused Objects", "value": str(counts.get("unused", 0))},
                {"label": "Disabled Rules", "value": str(counts.get("disabled", 0))},
                {"label": "Broad Any/All Rules", "value": str(counts.get("broad", 0))},
                {"label": "Expired Schedules / Logging", "value": str(counts.get("extra", 0))},
            ],
        },
    ]

    if total == 0:
        blocks.append({"type": "alert", "variant": "success", "text": "No unused objects or rule hygiene issues detected."})
        return blocks

    if unused:
        blocks.append(
            {
                "type": "expander",
                "title": f"Unused / Unreferenced Objects ({len(unused)})",
                "open": True,
                "blocks": [
                    {
                        "type": "table",
                        "id": f"{vendor}_hygiene_unused",
                        "columns": list(unused[0].keys()),
                        "rows": unused,
                        "export_filename": f"{vendor}_unused_objects.csv",
                    }
                ],
            }
        )

    if issues:
        clean_issues = [
            {"Finding": r["Finding"], "Target": r["Target"], "Details": r["Details"], "Severity": r["Severity"]}
            for r in issues
        ]
        row_classes = ["row-danger" if r.get("_sev") == "danger" else "row-warn" for r in issues]
        blocks.append(
            {
                "type": "expander",
                "title": f"Rule & Schedule Hygiene Findings ({len(issues)})",
                "open": True,
                "blocks": [
                    {
                        "type": "table",
                        "id": f"{vendor}_hygiene_rules",
                        "columns": ["Finding", "Target", "Details", "Severity"],
                        "rows": clean_issues,
                        "row_classes": row_classes,
                        "legend": [
                            {"label": "Critical — Overly Broad Any/All Rule (red)", "variant": "danger"},
                            {"label": "Warning — Disabled / Logging / Expired Schedule (amber)", "variant": "warn"},
                        ],
                        "export_filename": f"{vendor}_hygiene_findings.csv",
                    }
                ],
            }
        )

    cleanup_cli = analysis.get("cleanup_cli", "")
    if cleanup_cli:
        blocks.append(
            {
                "type": "expander",
                "title": "Draft Unused Object Cleanup CLI (Review Before Applying)",
                "open": False,
                "blocks": [
                    {
                        "type": "code_block",
                        "title": "Draft FortiOS Cleanup CLI",
                        "subtitle": "Verify objects are not referenced via dynamic scripts or outside this VDOM before deleting.",
                        "code": cleanup_cli,
                    }
                ],
            }
        )

    return blocks
