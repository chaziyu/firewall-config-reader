"""
backend/ssl_to_ipsec_service.py
FortiGate SSL-VPN -> Dial-up IPSec (IKEv2) Migration Assistant.
Audits existing SSL-VPN settings, portals, certificates, user groups, and
ssl.root policies to produce readiness checks, GUI/Wizard quick-reference
parameters, draft Phase 1 / Phase 2 / Policy CLI, and cutover checklists.
"""

from __future__ import annotations

import re
from typing import Any


def _split_csv(val: str) -> list[str]:
    return [p.strip() for p in str(val or "").split(",") if p.strip() and p.strip() != "-"]


def _extract_local_certs(fg: Any) -> set[str]:
    block = fg._extract_block("vpn certificate local")
    if not block:
        return set()
    return set(re.findall(r'^\s*edit "([^"]+)"', block, re.MULTILINE))


def _extract_saml_servers(fg: Any) -> set[str]:
    block = fg._extract_block("user saml")
    if not block:
        return set()
    return set(re.findall(r'^\s*edit "([^"]+)"', block, re.MULTILINE))


def _extract_portal_split_addrs(fg: Any) -> dict[str, list[str]]:
    block = fg._extract_block("vpn ssl web portal")
    if not block:
        return {}
    out: dict[str, list[str]] = {}
    entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
    for name, body in entries:
        m = re.search(r"set split-tunneling-routing-address (.*)", body)
        if m:
            out[name] = re.findall(r'"([^"]+)"', m.group(1))
    return out


def _extract_ssl_policy_details(fg: Any) -> dict[str, dict[str, Any]]:
    block = fg._extract_block("firewall policy")
    if not block:
        return {}
    details: dict[str, dict[str, Any]] = {}
    entries = re.findall(r"^\s*edit (\d+)(.*?)^\s*next", block, re.DOTALL | re.MULTILINE)
    profile_keys = (
        "utm-status",
        "profile-protocol-options",
        "ssl-ssh-profile",
        "av-profile",
        "webfilter-profile",
        "dnsfilter-profile",
        "ips-sensor",
        "application-list",
        "file-filter-profile",
        "emailfilter-profile",
        "waf-profile",
        "profile-group",
    )
    for pid, body in entries:
        srcintf_m = re.search(r"set srcintf (.*)", body)
        srcintfs = re.findall(r'"([^"]+)"', srcintf_m.group(1)) if srcintf_m else []
        if not any(s.lower().startswith("ssl.") for s in srcintfs):
            continue

        grp_m = re.search(r"set groups (.*)", body)
        usr_m = re.search(r"set users (.*)", body)
        groups = re.findall(r'"([^"]+)"', grp_m.group(1)) if grp_m else []
        users = re.findall(r'"([^"]+)"', usr_m.group(1)) if usr_m else []

        prof_lines: list[str] = []
        for pk in profile_keys:
            pm = re.search(rf"^\s*set {pk} (.+)$", body, re.MULTILINE)
            if pm:
                prof_lines.append(f"set {pk} {pm.group(1).strip()}")

        details[pid] = {
            "groups": groups,
            "users": users,
            "profile_lines": prof_lines,
        }
    return details


def _quote_list(items: list[str]) -> str:
    return " ".join(f'"{x}"' for x in items if x and x != "-")


def analyze_fortigate_ssl_to_ipsec(fg: Any) -> dict[str, Any]:
    settings = fg.parse_ssl_settings() or {}
    portals = fg.parse_ssl_portals() or []
    policies = fg.parse_policies() or []

    ssl_policies = [
        p
        for p in policies
        if any(s.lower().startswith("ssl.") for s in _split_csv(str(p.get("Src Interface", ""))))
    ]

    if not settings and not portals and not ssl_policies:
        return {"has_ssl_vpn": False}

    local_certs = _extract_local_certs(fg)
    saml_servers = _extract_saml_servers(fg)
    portal_split_addrs = _extract_portal_split_addrs(fg)
    policy_details = _extract_ssl_policy_details(fg)

    user_groups = fg.parse_user_groups() or []
    ldap_servers = fg.parse_ldap() or []
    radius_servers = fg.parse_radius() or []

    group_members_map: dict[str, list[str]] = {}
    for ug in user_groups:
        gname = str(ug.get("Group Name", "")).strip()
        if gname:
            group_members_map[gname] = _split_csv(str(ug.get("Members", "")))

    servercert = str(settings.get("servercert", "Fortinet_Factory") or "Fortinet_Factory")
    is_factory_cert = servercert.lower() in ("fortinet_factory", "fortinet_factory2", "-", "")
    cert_exists_locally = servercert in local_certs
    require_client_cert = str(settings.get("require_cert", "disable")).lower() == "enable"

    # Collect referenced groups from auth rules and ssl policies
    referenced_groups: list[str] = []
    for ar in settings.get("auth_rules", []) or []:
        ug_val = str(ar.get("Users/Groups", "")).strip()
        if ug_val and ug_val != "All Other Users/Groups":
            for tok in _split_csv(ug_val):
                if tok not in referenced_groups:
                    referenced_groups.append(tok)
    for pd in policy_details.values():
        for g in pd.get("groups", []):
            if g not in referenced_groups:
                referenced_groups.append(g)

    detected_saml: list[str] = []
    for g in referenced_groups:
        for mem in group_members_map.get(g, []):
            if mem in saml_servers and mem not in detected_saml:
                detected_saml.append(mem)
    if not detected_saml and saml_servers:
        detected_saml = sorted(saml_servers)

    if detected_saml:
        auth_mode = "saml"
    elif require_client_cert:
        auth_mode = "cert"
    else:
        auth_mode = "eap"

    listen_intfs = [
        i for i in (settings.get("listen_interfaces") or []) if i and i != "(default)"
    ]
    wan_intf = listen_intfs[0] if listen_intfs else "wan1"

    ip_pools: list[str] = []
    if settings.get("ip_range") and settings.get("ip_range") != "-":
        ip_pools.append(str(settings["ip_range"]))
    for p in portals:
        for pool in _split_csv(str(p.get("ip_pools", ""))):
            if pool not in ip_pools:
                ip_pools.append(pool)
    primary_pool = ip_pools[0] if ip_pools else "SSLVPN_TUNNEL_ADDR1"

    split_addrs: list[str] = []
    for addrs in portal_split_addrs.values():
        for a in addrs:
            if a not in split_addrs:
                split_addrs.append(a)

    dns1 = str(settings.get("dns_server1", "-") or "-")
    dns2 = str(settings.get("dns_server2", "-") or "-")

    # Readiness findings
    warnings: list[str] = []
    infos: list[str] = []

    if str(settings.get("enabled", "enable")).lower() == "disable":
        infos.append("SSL-VPN status is currently disabled in settings; verify if legacy portals/policies are just leftover config.")

    if is_factory_cert:
        warnings.append(
            f"SSL-VPN uses '{servercert}' (self-signed). For IPSec IKEv2 EAP/SAML/Signature, install a CA-signed server certificate matching your VPN FQDN."
        )
    elif not cert_exists_locally and local_certs:
        warnings.append(
            f"Configured servercert '{servercert}' was not found in 'config vpn certificate local'; verify it exists before referencing it in IPSec."
        )

    web_portals = [
        p["name"]
        for p in portals
        if str(p.get("web_mode", "")).lower() == "enable" or bool(p.get("bookmarks"))
    ]
    if web_portals:
        warnings.append(
            f"Web-Mode / Bookmarks enabled on portal(s): {', '.join(web_portals)}. Dial-up IPSec has no clientless web portal — plan ZTNA / reverse proxy or full tunnel client access."
        )

    host_check_portals = [
        f"{p['name']} ({p.get('host_check')})"
        for p in portals
        if str(p.get("host_check", "none")).lower() not in ("none", "-", "disable")
    ]
    if host_check_portals:
        warnings.append(
            f"Host-Check is configured on {', '.join(host_check_portals)}. SSL-VPN host-check does not transfer directly to IPSec — migrate posture checks to FortiClient EMS / ZTNA tags."
        )

    if not ssl_policies:
        warnings.append("No firewall policies found with an ssl.* source interface; verify VDOM or policy bindings before cutover.")

    if require_client_cert:
        infos.append("Client certificate verification (reqclientcert) is enabled — draft includes 'config user peer' + 'authmethod signature'.")
    if len(portals) > 1:
        infos.append(
            f"Multiple SSL portals detected ({len(portals)}). Either consolidate onto one Dial-up IPSec tunnel with policy-level group matching, or create separate Dial-up tunnels with distinct Peer IDs."
        )
    if auth_mode == "saml":
        infos.append(
            f"SAML server(s) detected ({', '.join(detected_saml)}): requires FortiOS 7.2.4+ / 7.4+ and 'set ike-saml-server' bound on underlay interface '{wan_intf}'."
        )
    elif ldap_servers or radius_servers:
        infos.append(
            f"Detected external auth ({len(ldap_servers)} LDAP, {len(radius_servers)} RADIUS): mapped to IKEv2 + EAP in Phase 1."
        )
    infos.append(
        "IPSec uses UDP 500 & UDP 4500 (NAT-T) by default; ensure upstream ISP/firewalls permit them, or enable IPSec over TCP 443 ('set transport tcp' in FortiOS 7.4.2+) for restrictive networks."
    )

    tunnel_name = "RA-IPSec-IKEv2"
    p2_name = "RA-IPSec-P2"
    primary_group = referenced_groups[0] if referenced_groups else "SSL_VPN_USERS"
    cert_to_use = "<UPLOAD_CA_SIGNED_CERT>" if is_factory_cert else servercert

    # GUI / Wizard quick-reference table
    auth_label = {
        "saml": f"IKEv2 + SAML ({', '.join(detected_saml)})",
        "cert": "IKEv2 + Signature (Client & Server Certificates)",
        "eap": "IKEv2 + EAP (PSK + User Group / LDAP / RADIUS)",
    }[auth_mode]

    gui_rows = [
        {"Parameter": "Tunnel Name", "Recommended Value": tunnel_name, "Notes": "Custom Remote Access (Dial-up)"},
        {"Parameter": "Incoming Interface", "Recommended Value": wan_intf, "Notes": f"All SSL listen intfs: {', '.join(listen_intfs) or 'default'}"},
        {"Parameter": "IKE Version", "Recommended Value": "IKEv2", "Notes": "Required for modern EAP / SAML"},
        {"Parameter": "Authentication", "Recommended Value": auth_label, "Notes": f"Groups: {', '.join(referenced_groups) or 'None detected'}"},
        {"Parameter": "Server Certificate", "Recommended Value": cert_to_use, "Notes": "Must match VPN FQDN (SAN) & be trusted by client OS"},
        {"Parameter": "Phase 1 Proposal", "Recommended Value": "AES256GCM-PRFSHA256 / AES256-SHA256", "Notes": "DH Group 19, 20, 14"},
        {"Parameter": "Phase 2 Proposal", "Recommended Value": "AES256GCM / AES256-SHA256", "Notes": "Enable PFS (DH Group 19, 20, 14)"},
        {"Parameter": "Mode Config IP Pool", "Recommended Value": primary_pool, "Notes": f"All pools: {', '.join(ip_pools) or primary_pool}"},
        {"Parameter": "DNS Server(s)", "Recommended Value": ", ".join(d for d in (dns1, dns2) if d != "-") or "Use System DNS", "Notes": "Pushed via Mode Config"},
        {"Parameter": "Split Tunneling", "Recommended Value": ", ".join(split_addrs) if split_addrs else "Disabled (Full Tunnel) or Policy-based", "Notes": "Set via ipv4-split-include on Phase 1"},
    ]

    # Build Draft CLI
    cli_lines: list[str] = [
        "# ======================================================================",
        "# DRAFT FortiGate Dial-up IPSec (IKEv2) Migration CLI",
        "# Generated offline from backup config — REVIEW & REPLACE <PLACEHOLDERS>",
        "# ======================================================================",
        "",
    ]

    if auth_mode == "saml":
        saml_name = detected_saml[0]
        cli_lines.extend(
            [
                "# 1. Bind SAML server on the WAN underlay interface (FortiOS 7.2.4+ / 7.4+)",
                "config system interface",
                f'    edit "{wan_intf}"',
                f'        set ike-saml-server "{saml_name}"',
                "    next",
                "end",
                "",
            ]
        )

    if require_client_cert:
        cli_lines.extend(
            [
                "# 1b. PKI Peer definition for client certificate validation",
                "config user peer",
                '    edit "IPSEC_CLIENT_PKI"',
                '        set ca "<REPLACE_WITH_CA_CERT_NAME>"',
                "    next",
                "end",
                "",
            ]
        )

    cli_lines.extend(
        [
            "# 2. Phase 1 Dial-up IPSec Interface (IKEv2 + Mode Config)",
            "config vpn ipsec phase1-interface",
            f'    edit "{tunnel_name}"',
            "        set type dynamic",
            f'        set interface "{wan_intf}"',
            "        set ike-version 2",
            "        set peertype any",
            "        set net-device disable",
            "        set mode-cfg enable",
            "        set proposal aes256gcm-prfsha256 aes256-sha256",
            "        set dhgrp 19 20 14",
            "        set dpd on-idle",
            "        set dpd-retrycount 3",
            "        set dpd-retryinterval 10",
            "        set assign-ip-from name",
            f'        set ipv4-name "{primary_pool}"',
        ]
    )

    if dns1 != "-":
        cli_lines.append("        set dns-mode manual")
        cli_lines.append(f"        set ipv4-dns-server1 {dns1}")
        if dns2 != "-":
            cli_lines.append(f"        set ipv4-dns-server2 {dns2}")
    else:
        cli_lines.append("        set dns-mode auto")

    if split_addrs:
        cli_lines.append(f'        set ipv4-split-include {_quote_list(split_addrs)}')

    if auth_mode == "cert":
        cli_lines.extend(
            [
                "        set authmethod signature",
                f'        set certificate "{cert_to_use}"',
                '        set peer "IPSEC_CLIENT_PKI"',
            ]
        )
    elif auth_mode == "saml":
        cli_lines.extend(
            [
                "        set eap enable",
                "        set eap-identity send-request",
                f'        set authusrgrp "{primary_group}"',
                "        set psksecret <REPLACE_WITH_STRONG_PSK>",
                f'        # Optional cert auth if replacing PSK: set authmethod signature / set certificate "{cert_to_use}"',
            ]
        )
    else:
        cli_lines.extend(
            [
                "        set eap enable",
                "        set eap-identity send-request",
                f'        set authusrgrp "{primary_group}"',
                "        set psksecret <REPLACE_WITH_STRONG_PSK>",
            ]
        )

    cli_lines.extend(["    next", "end", ""])

    cli_lines.extend(
        [
            "# 3. Phase 2 Selector",
            "config vpn ipsec phase2-interface",
            f'    edit "{p2_name}"',
            f'        set phase1name "{tunnel_name}"',
            "        set proposal aes256gcm aes256-sha256",
            "        set pfs enable",
            "        set dhgrp 19 20 14",
            "        set src-subnet 0.0.0.0 0.0.0.0",
            "        set dst-subnet 0.0.0.0 0.0.0.0",
            "        set keepalive enable",
            "    next",
            "end",
            "",
        ]
    )

    if ssl_policies:
        cli_lines.extend(
            [
                "# 4. Cloned Firewall Policies (ssl.root -> Dial-up IPSec Tunnel)",
                "# Uses 'edit 0' so existing SSL-VPN policies remain untouched during parallel cutover.",
                "config firewall policy",
            ]
        )
        for pol in ssl_policies:
            pid = str(pol.get("ID", ""))
            pname = str(pol.get("Name", f"Pol-{pid}") or f"Pol-{pid}")
            new_name = f"IPSec-{pname}" if pname != "-" else f"IPSec-From-Policy-{pid}"
            dstintfs = _split_csv(str(pol.get("Dst Interface", "")))
            srcaddrs = _split_csv(str(pol.get("Source", "all")))
            dstaddrs = _split_csv(str(pol.get("Destination", "all")))
            services = _split_csv(str(pol.get("Service", "ALL")))
            action = str(pol.get("Action", "ACCEPT")).lower()
            if action not in ("accept", "deny"):
                action = "accept"
            nat_val = "enable" if str(pol.get("NAT", "")).lower() == "enable" else "disable"
            pdet = policy_details.get(pid, {})

            cli_lines.append("    edit 0")
            cli_lines.append(f'        set name "{new_name}"')
            cli_lines.append(f'        set srcintf "{tunnel_name}"')
            if dstintfs:
                cli_lines.append(f"        set dstintf {_quote_list(dstintfs)}")
            cli_lines.append(f"        set action {action}")
            cli_lines.append(f"        set srcaddr {_quote_list(srcaddrs) or '\"all\"'}")
            cli_lines.append(f"        set dstaddr {_quote_list(dstaddrs) or '\"all\"'}")
            cli_lines.append(f"        set service {_quote_list(services) or '\"ALL\"'}")
            cli_lines.append(f'        set schedule "{pol.get("Schedule", "always")}"')
            cli_lines.append(f"        set nat {nat_val}")
            if pdet.get("groups"):
                cli_lines.append(f"        set groups {_quote_list(pdet['groups'])}")
            if pdet.get("users"):
                cli_lines.append(f"        set users {_quote_list(pdet['users'])}")
            for pline in pdet.get("profile_lines", []):
                cli_lines.append(f"        {pline}")
            cli_lines.append("    next")
        cli_lines.append("end")

    forticlient_rows = [
        {"Setting": "VPN Type", "Value": "IPsec VPN (IKEv2)"},
        {"Setting": "Remote Gateway", "Value": f"VPN FQDN on {wan_intf} (matches cert SAN)"},
        {"Setting": "Authentication Method", "Value": auth_label},
        {"Setting": "IKEv2 Proposals", "Value": "Phase 1: AES256-GCM / SHA256 (DH 19/20/14) · Phase 2: AES256-GCM / PFS"},
        {"Setting": "Transport Fallback", "Value": "UDP 500/4500 (or TCP 443 if FortiOS 7.4.2+ transport tcp enabled)"},
    ]

    cutover_rows = [
        {"Step": "1", "Phase": "Pre-Check", "Action": "Install CA-signed server cert matching VPN FQDN (do not reuse Fortinet_Factory)."},
        {"Step": "2", "Phase": "Build Parallel", "Action": f"Apply Phase 1 ({tunnel_name}), Phase 2 ({p2_name}), and cloned policies alongside SSL-VPN."},
        {"Step": "3", "Phase": "Pilot Test", "Action": "Test with 1-2 pilot FortiClient users: verify Mode Config IP, DNS, split routes, and policy logs."},
        {"Step": "4", "Phase": "Rollout", "Action": "Deploy updated FortiClient IPsec profile via EMS / MDM to all remote users."},
        {"Step": "5", "Phase": "Decommission", "Action": "Confirm 0 active SSL-VPN sessions, set vpn ssl settings status disable, and remove ssl.root policies."},
    ]

    return {
        "has_ssl_vpn": True,
        "model": fg.get_model(),
        "firmware": fg.get_firmware_version(),
        "servercert": servercert,
        "is_factory_cert": is_factory_cert,
        "require_client_cert": require_client_cert,
        "auth_mode": auth_mode,
        "auth_label": auth_label,
        "wan_intf": wan_intf,
        "primary_pool": primary_pool,
        "portals_count": len(portals),
        "ssl_policies": ssl_policies,
        "referenced_groups": referenced_groups,
        "warnings": warnings,
        "infos": infos,
        "gui_rows": gui_rows,
        "cli_draft": "\n".join(cli_lines),
        "forticlient_rows": forticlient_rows,
        "cutover_rows": cutover_rows,
    }


def build_ssl_to_ipsec_blocks(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    if not analysis.get("has_ssl_vpn"):
        return [
            {
                "type": "alert",
                "variant": "info",
                "text": "No active SSL-VPN configuration detected in this FortiGate backup — no SSL-to-IPSec migration is required.",
            }
        ]

    warnings = analysis.get("warnings") or []
    infos = analysis.get("infos") or []
    ssl_policies = analysis.get("ssl_policies") or []

    badge = (
        {"text": f"{len(warnings)} Review Item(s)", "variant": "warn"}
        if warnings
        else {"text": "Ready to Draft", "variant": "allow"}
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "card",
            "title": "SSL-VPN → Dial-up IPSec (IKEv2) Migration Assistant",
            "subtitle": f"{analysis.get('model', 'FortiGate')} · Firmware {analysis.get('firmware', 'Unknown')} · Offline Draft from Backup Config",
            "badge": badge,
        },
        {
            "type": "kv_grid",
            "items": [
                {"label": "Detected Auth Mode", "value": analysis.get("auth_label", "-")},
                {"label": "Server Certificate", "value": analysis.get("servercert", "-")},
                {"label": "Underlay Interface", "value": analysis.get("wan_intf", "-")},
                {"label": "Tunnel IP Pool", "value": analysis.get("primary_pool", "-")},
                {"label": "SSL Portals", "value": str(analysis.get("portals_count", 0))},
                {"label": "ssl.* Policies to Clone", "value": str(len(ssl_policies))},
            ],
        },
    ]

    for w in warnings:
        blocks.append({"type": "alert", "variant": "warn", "text": w})
    for inf in infos:
        blocks.append({"type": "alert", "variant": "info", "text": inf})

    blocks.append({"type": "section_header", "title": "1. Existing SSL-VPN Policies to Migrate"})
    if ssl_policies:
        cols = [k for k in ssl_policies[0].keys() if not str(k).startswith("_")]
        pol_classes: list[str] = []
        for p in ssl_policies:
            if str(p.get("Status", "Enable")).lower() == "disable":
                pol_classes.append("row-danger")
            elif str(p.get("Action", "")).upper() == "ACCEPT":
                pol_classes.append("row-success")
            else:
                pol_classes.append("row-danger")
        blocks.append(
            {
                "type": "table",
                "id": "fg_ssl_mig_policies",
                "columns": cols,
                "rows": [{c: str(p.get(c, "")) for c in cols} for p in ssl_policies],
                "row_classes": pol_classes,
                "legend": [
                    {"label": "Enabled Allow Policy (green)", "variant": "success"},
                    {"label": "Deny or Disabled Policy (red)", "variant": "danger"},
                ],
                "export_filename": "fg_ssl_policies_to_migrate.csv",
            }
        )
    else:
        blocks.append(
            {
                "type": "alert",
                "variant": "warn",
                "text": "No firewall policies referencing ssl.* interfaces were found.",
            }
        )

    gui_rows = analysis.get("gui_rows") or []
    blocks.append(
        {
            "type": "expander",
            "title": "2. FortiGate GUI / Wizard Quick-Reference Parameters",
            "open": False,
            "blocks": [
                {
                    "type": "table",
                    "id": "fg_ssl_mig_gui",
                    "columns": list(gui_rows[0].keys()),
                    "rows": gui_rows,
                    "export_filename": "fg_ssl_to_ipsec_gui_params.csv",
                }
            ],
        }
    )

    blocks.append({"type": "section_header", "title": "3. Draft Dial-up IPSec Migration CLI (Phase 1, Phase 2 & Policies)"})
    blocks.append(
        {
            "type": "code_block",
            "title": "Draft FortiOS CLI — Review Before Applying",
            "subtitle": "Reuses your existing IP pool, DNS, split-tunnel addresses, user groups, and UTM profiles.",
            "code": analysis.get("cli_draft", ""),
        }
    )

    fc_rows = analysis.get("forticlient_rows") or []
    cut_rows = analysis.get("cutover_rows") or []
    blocks.append(
        {
            "type": "expander",
            "title": "4. FortiClient Profile & Zero-Downtime Cutover Checklist",
            "open": False,
            "blocks": [
                {
                    "type": "table",
                    "id": "fg_ssl_mig_fc",
                    "title": "FortiClient Endpoint Parameters",
                    "columns": list(fc_rows[0].keys()),
                    "rows": fc_rows,
                },
                {
                    "type": "table",
                    "id": "fg_ssl_mig_cutover",
                    "title": "Parallel Cutover Sequence",
                    "columns": list(cut_rows[0].keys()),
                    "rows": cut_rows,
                },
            ],
        }
    )

    return blocks
