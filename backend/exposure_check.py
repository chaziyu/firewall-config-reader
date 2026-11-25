"""
backend/exposure_check.py
Detects active firewall interfaces configured with a public IP address that also
enable HTTP, HTTPS, or SSH administrative management access, grades severity
from config restrictions (trusthost / local-in-policy / permitted-ip), and
supports optional local-only on-demand TCP reachability verification.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
import socket
import ssl
from typing import Any

_MGMT_PROTOCOLS = ("HTTP", "HTTPS", "SSH")
_PA_PORT_MAP = {"HTTP": 80, "HTTPS": 443, "SSH": 22}
_HIGH_RISK_VIP_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
}
_CRITICAL_VIP_PORTS = {22, 23, 445, 1433, 3306, 3389, 5432, 5900}
_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")
_TREE_PREFIX_RE = re.compile(r"^[\s\u00a0]*(?:\u2517|\u2514)?[\s\u00a0]*")


def _clean_interface_name(name: str) -> str:
    return _TREE_PREFIX_RE.sub("", str(name or "")).strip()


def _bare_ip(ip_str: str) -> str:
    s = str(ip_str or "").split("/", 1)[0].strip()
    if s.count(":") == 1:
        s = s.split(":", 1)[0].strip()
    return s


def is_public_ip(ip_str: str | None) -> bool:
    """Return True if ip_str (optionally with /mask or /prefix) is a routable public IP."""
    if not ip_str:
        return False
    raw = str(ip_str).strip()
    if not raw or raw.lower() in ("-", "none", "dhcp", "pppoe", "unknown"):
        return False
    addr_part = _bare_ip(raw)
    if not addr_part:
        return False
    try:
        ip = ipaddress.ip_address(addr_part)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NET:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return bool(ip.is_global)


def _extract_public_ips(ip_field: str | None) -> list[str]:
    if not ip_field:
        return []
    out: list[str] = []
    for part in str(ip_field).split(","):
        candidate = part.strip()
        if is_public_ip(candidate):
            out.append(candidate)
    return out


def _fg_local_in_restricted_ifaces(parser: Any) -> set[str]:
    """Return interface names (or 'any') covered by an active firewall local-in-policy restriction."""
    extract = getattr(parser, "_extract_block", None)
    if extract is None:
        return set()
    try:
        block = extract("firewall local-in-policy")
    except Exception:
        return set()
    if not block:
        return set()

    restricted: set[str] = set()
    entries = re.findall(r"^\s*edit \d+(.*?)^\s*next", block, re.DOTALL | re.MULTILINE)
    for body in entries:
        status_m = re.search(r"^\s*set status (\S+)", body, re.MULTILINE)
        if status_m and status_m.group(1).strip().lower() == "disable":
            continue
        intf_m = re.search(r'^\s*set intf "([^"]+)"', body, re.MULTILINE)
        if not intf_m:
            continue
        intf_name = intf_m.group(1).strip()
        action_m = re.search(r"^\s*set action (\S+)", body, re.MULTILINE)
        action = action_m.group(1).strip().lower() if action_m else "accept"
        srcaddr_m = re.search(r"^\s*set srcaddr (.*)", body, re.MULTILINE)
        srcaddrs = re.findall(r'"([^"]+)"', srcaddr_m.group(1)) if srcaddr_m else []
        if action == "deny" or any(s.lower() != "all" for s in srcaddrs):
            restricted.add(intf_name)
    return restricted


def _fg_admins_all_trusthost_restricted(parser: Any) -> tuple[bool, bool]:
    """Return (has_admins, all_admins_have_non_wildcard_trusthost)."""
    extract = getattr(parser, "_extract_block", None)
    if extract is None:
        return False, False
    try:
        block = extract("system admin")
    except Exception:
        return False, False
    if not block:
        return False, False

    entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
    if not entries:
        return False, False

    for _, body in entries:
        trusthosts = re.findall(r"^\s*set trusthost\d+\s+([\d\.]+)\s+([\d\.]+)", body, re.MULTILINE)
        valid = [
            (ip, mask)
            for ip, mask in trusthosts
            if not (ip == "0.0.0.0" and mask == "0.0.0.0")
        ]
        if not valid:
            return True, False
    return True, True


def _build_targets(public_ips: list[str], protocols: list[str], port_map: dict[str, int]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for raw_ip in public_ips:
        ip = _bare_ip(raw_ip)
        if not is_public_ip(ip):
            continue
        for proto in protocols:
            port = port_map.get(proto)
            if port:
                targets.append({"ip": ip, "port": int(port), "protocol": proto})
    return targets


def find_fortigate_public_mgmt_exposure(parser: Any) -> list[dict[str, Any]]:
    """Return active FortiGate interfaces with a public IP and HTTP/HTTPS/SSH access."""
    try:
        rows = parser.parse_interfaces() or []
    except Exception:
        return []

    settings: dict[str, Any] = {}
    if hasattr(parser, "parse_system_settings"):
        try:
            settings = parser.parse_system_settings() or {}
        except Exception:
            settings = {}

    port_map = {
        "HTTP": int(settings.get("http_port") or 80),
        "HTTPS": int(settings.get("https_port") or 443),
        "SSH": int(settings.get("ssh_port") or 22),
    }

    local_in_ifaces = _fg_local_in_restricted_ifaces(parser)
    has_admins, all_trusthost = _fg_admins_all_trusthost_restricted(parser)

    sdwan_members: set[str] = set()
    if hasattr(parser, "parse_sdwan"):
        try:
            sdwan = parser.parse_sdwan() or {}
            for m in sdwan.get("members", []) or []:
                m_intf = str(m.get("Interface", "")).strip()
                if m_intf and m_intf != "-":
                    sdwan_members.add(m_intf)
        except Exception:
            sdwan_members = set()

    vips = parser.parse_vip() if hasattr(parser, "parse_vip") else []
    intf_to_vip_public_ips: dict[str, list[str]] = {}
    for vip in vips:
        v_intf = str(vip.get("Interface", "") or "").strip()
        v_ext = _bare_ip(str(vip.get("Mapped From", "-") or ""))
        if v_intf and v_intf != "any" and is_public_ip(v_ext):
            bucket = intf_to_vip_public_ips.setdefault(v_intf, [])
            if v_ext not in bucket:
                bucket.append(v_ext)

    findings: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("Type", "")).strip().lower() == "zone":
            continue
        if str(row.get("Status", "Enable")).strip().lower() == "disable":
            continue

        raw_access = str(row.get("Admin Access", "") or "")
        tokens = {t.strip().upper() for t in re.split(r"[,\s]+", raw_access) if t.strip()}
        protocols = [p for p in _MGMT_PROTOCOLS if p in tokens]
        if not protocols:
            continue

        iface_name = _clean_interface_name(row.get("Name", ""))
        ip_field = str(row.get("IP/Netmask", "") or "").strip()
        public_ips = _extract_public_ips(ip_field)

        if public_ips:
            if iface_name in local_in_ifaces or "any" in local_in_ifaces:
                restricted = True
                note = "Restricted (local-in-policy)"
            elif has_admins and all_trusthost:
                restricted = True
                note = "Restricted (admin trusthost)"
            else:
                restricted = False
                note = "Unrestricted (no trusthost / local-in-policy)"

            severity = "critical" if ("HTTP" in protocols or not restricted) else "warn"

            findings.append(
                {
                    "category": "mgmt",
                    "interface": iface_name,
                    "ip": ", ".join(public_ips),
                    "protocols": protocols,
                    "display_protocols": [f"{p} ({port_map[p]})" for p in protocols],
                    "note": note,
                    "restricted": restricted,
                    "severity": severity,
                    "targets": _build_targets(public_ips, protocols, port_map),
                }
            )
            continue

        # Flag WAN / SD-WAN interfaces behind NAT with a private IP and management access enabled
        role_low = str(row.get("Role", "")).strip().lower()
        is_wan_like = role_low == "wan" or iface_name.lower().startswith("wan") or iface_name in sdwan_members
        if is_wan_like and ip_field not in ("", "-", "none"):
            inferred_ips = intf_to_vip_public_ips.get(iface_name, [])
            if inferred_ips:
                note = f"WAN Behind NAT (inferred public IP via VIP: {', '.join(inferred_ips)}) — verify upstream DMZ/forwarding"
                targets = _build_targets(inferred_ips, protocols, port_map)
            else:
                note = "WAN Behind NAT (private IP) — check upstream router DMZ / port-forwarding"
                targets = []
            findings.append(
                {
                    "category": "nat_mgmt",
                    "interface": iface_name,
                    "ip": ip_field,
                    "protocols": protocols,
                    "display_protocols": [f"{p} ({port_map[p]})" for p in protocols],
                    "note": note,
                    "restricted": False,
                    "severity": "warn",
                    "targets": targets,
                }
            )

    # Also detect public VIPs (DNAT) exposing high-risk administrative/service ports
    policies = parser.parse_policies() if hasattr(parser, "parse_policies") else []
    if vips and policies:
        for vip in vips:
            vip_name = str(vip.get("Name", "")).strip()
            vip_intf = str(vip.get("Interface", "any")).strip()
            mapped_from = str(vip.get("Mapped From", "-") or "").strip()
            mapped_to = str(vip.get("Mapped To", "-") or "").strip()
            ext_ip = _bare_ip(mapped_from)
            if not vip_name or not is_public_ip(ext_ip):
                continue

            port_str = ""
            if ":" in mapped_from:
                port_str = mapped_from.split(":", 1)[1].strip()
            elif ":" in mapped_to:
                port_str = mapped_to.split(":", 1)[1].strip()
            try:
                vip_port = int(port_str)
            except ValueError:
                continue
            if vip_port not in _HIGH_RISK_VIP_PORTS:
                continue

            matching_pols = []
            for pol in policies:
                if str(pol.get("Status", "Enable")).strip().lower() == "disable":
                    continue
                if str(pol.get("Action", "")).strip().upper() != "ACCEPT":
                    continue
                dst_tokens = {d.strip() for d in str(pol.get("Destination", "")).split(",") if d.strip()}
                if vip_name in dst_tokens:
                    matching_pols.append(pol)
            if not matching_pols:
                continue

            proto_label = _HIGH_RISK_VIP_PORTS[vip_port]
            any_src_all = any(
                s.strip().lower() in ("all", "any")
                for p in matching_pols
                for s in str(p.get("Source", "")).split(",")
                if s.strip()
            )
            severity = "critical" if (vip_port in _CRITICAL_VIP_PORTS and any_src_all) else "warn"
            pol_ids = ", ".join(f"#{p.get('ID', '?')}" for p in matching_pols)
            findings.append(
                {
                    "category": "vip",
                    "interface": f"VIP: {vip_name} ({vip_intf})",
                    "ip": ext_ip,
                    "protocols": [proto_label],
                    "display_protocols": [f"{proto_label} ({vip_port}) → {mapped_to}"],
                    "note": f"Public DNAT to internal server via Policy {pol_ids} · Source: {'all (Unrestricted)' if any_src_all else 'Restricted'}",
                    "restricted": not any_src_all,
                    "severity": severity,
                    "targets": [{"ip": ext_ip, "port": vip_port, "protocol": proto_label}],
                }
            )

    return findings


def _pa_mgt_exposure(
    network_parser: Any,
    device_parser: Any | None = None,
    dashboard_parser: Any | None = None,
) -> list[dict[str, Any]]:
    sys_info: dict[str, Any] = {}
    info_source = dashboard_parser or device_parser or network_parser
    if info_source is not None and hasattr(info_source, "get_system_info"):
        try:
            sys_info = info_source.get_system_info() or {}
        except Exception:
            sys_info = {}

    mgt_ips: list[str] = []
    for key in ("ip_address", "ipv6_address"):
        val = sys_info.get(key)
        if is_public_ip(val):
            mgt_ips.append(str(val).strip())

    if not mgt_ips:
        return []

    mgmt_svc: dict[str, str] = {}
    if device_parser is not None and hasattr(device_parser, "get_mgmt_services"):
        try:
            mgmt_svc = device_parser.get_mgmt_services() or {}
        except Exception:
            mgmt_svc = {}
    else:
        dev = getattr(info_source, "dev", None)
        sys_el = dev.find("deviceconfig/system") if dev is not None else None
        svc_el = sys_el.find("service") if sys_el is not None else None
        if svc_el is not None:
            mgmt_svc = {
                "disable_http": svc_el.findtext("disable-http") or "no",
                "disable_https": svc_el.findtext("disable-https") or "no",
                "disable_ssh": svc_el.findtext("disable-ssh") or "no",
            }

    # In PAN-OS, MGT HTTP/HTTPS/SSH default to enabled unless disable-* is "yes".
    enabled_protos: list[str] = []
    for proto, flag_key in (("HTTP", "disable_http"), ("HTTPS", "disable_https"), ("SSH", "disable_ssh")):
        if str(mgmt_svc.get(flag_key, "no")).strip().lower() not in ("yes", "true", "1"):
            enabled_protos.append(proto)

    if not enabled_protos:
        return []

    dev = getattr(info_source, "dev", None)
    sys_el = dev.find("deviceconfig/system") if dev is not None else None
    permitted: list[str] = []
    if sys_el is not None:
        permitted = [e.get("name", "").strip() for e in sys_el.findall("permitted-ip/entry") if e.get("name")]

    non_wild = [p for p in permitted if p not in ("0.0.0.0/0", "::/0", "any")]
    restricted = bool(non_wild)
    note = f"Permitted IPs: {', '.join(permitted)}" if permitted else "Permitted IPs: any (Unrestricted)"
    severity = "critical" if ("HTTP" in enabled_protos or not restricted) else "warn"

    return [
        {
            "category": "mgmt",
            "interface": "Management (MGT)",
            "ip": ", ".join(mgt_ips),
            "protocols": enabled_protos,
            "note": note,
            "restricted": restricted,
            "severity": severity,
            "targets": _build_targets(mgt_ips, enabled_protos, _PA_PORT_MAP),
        }
    ]


def _pa_permitted_is_restricted(permitted: str) -> bool:
    tokens = [p.strip().lower() for p in str(permitted or "").split(",") if p.strip()]
    if not tokens:
        return False
    return not any(t in ("any", "-", "none", "0.0.0.0/0", "::/0") for t in tokens)


def find_paloalto_public_mgmt_exposure(
    network_parser: Any,
    device_parser: Any | None = None,
    dashboard_parser: Any | None = None,
) -> list[dict[str, Any]]:
    """Return active Palo Alto MGT and dataplane interfaces with a public IP and HTTP/HTTPS/SSH."""
    findings = _pa_mgt_exposure(
        network_parser,
        device_parser=device_parser,
        dashboard_parser=dashboard_parser,
    )
    if network_parser is None:
        return findings

    try:
        profiles_list = network_parser.get_intf_mgmt_profiles() or []
    except Exception:
        profiles_list = []

    profile_map: dict[str, tuple[list[str], str]] = {}
    for prof in profiles_list:
        pname = str(prof.get("Name", "")).strip()
        if not pname:
            continue
        protos = [p for p in _MGMT_PROTOCOLS if prof.get(p) == "✓"]
        permitted = str(prof.get("Permitted IPs", "any") or "any").strip()
        if protos:
            profile_map[pname] = (protos, permitted)

    if not profile_map:
        return findings

    iface_getters = (
        "get_ethernet_interfaces",
        "get_vlan_interfaces",
        "get_loopback_interfaces",
        "get_tunnel_interfaces",
    )
    seen_ifaces: set[str] = set()
    for getter in iface_getters:
        fn = getattr(network_parser, getter, None)
        if fn is None:
            continue
        try:
            rows = fn() or []
        except Exception:
            continue
        for row in rows:
            if row.get("_disabled"):
                continue
            if str(row.get("Status", "")).strip().lower() == "disable":
                continue

            prof_name = str(row.get("Mgmt Profile", "-") or "-").strip()
            if prof_name not in profile_map:
                continue

            public_ips = _extract_public_ips(row.get("IP Address"))
            if not public_ips:
                continue

            iface_name = _clean_interface_name(row.get("Interface", ""))
            seen_ifaces.add(iface_name)
            protos, permitted = profile_map[prof_name]
            restricted = _pa_permitted_is_restricted(permitted)
            severity = "critical" if ("HTTP" in protos or not restricted) else "warn"
            findings.append(
                {
                    "category": "mgmt",
                    "interface": iface_name,
                    "ip": ", ".join(public_ips),
                    "protocols": protos,
                    "note": f"Profile: {prof_name} · Permitted IPs: {permitted}",
                    "restricted": restricted,
                    "severity": severity,
                    "targets": _build_targets(public_ips, protos, _PA_PORT_MAP),
                }
            )

    # Also check ethernet L3 sub-interfaces (<ethernet><entry><layer3><units><entry>),
    # which PaloNetworkParser.get_ethernet_interfaces() does not list.
    dev = getattr(network_parser, "dev", None)
    eth_el = dev.find("network/interface/ethernet") if dev is not None else None
    if eth_el is not None:
        for eth_entry in eth_el.findall("entry"):
            if (eth_entry.findtext("link-state") or "").strip().lower() == "down":
                continue
            l3 = eth_entry.find("layer3")
            if l3 is None:
                continue
            for unit in l3.findall("units/entry"):
                uname = _clean_interface_name(unit.get("name", ""))
                if not uname or uname in seen_ifaces:
                    continue
                prof_name = (unit.findtext("interface-management-profile") or "").strip()
                if prof_name not in profile_map:
                    continue
                ips = [x.get("name", "") for x in unit.findall("ip/entry") if x.get("name")]
                public_ips = [ip for ip in ips if is_public_ip(ip)]
                if not public_ips:
                    continue
                protos, permitted = profile_map[prof_name]
                restricted = _pa_permitted_is_restricted(permitted)
                severity = "critical" if ("HTTP" in protos or not restricted) else "warn"
                findings.append(
                    {
                        "category": "mgmt",
                        "interface": uname,
                        "ip": ", ".join(public_ips),
                        "protocols": protos,
                        "note": f"Profile: {prof_name} · Permitted IPs: {permitted}",
                        "restricted": restricted,
                        "severity": severity,
                        "targets": _build_targets(public_ips, protos, _PA_PORT_MAP),
                    }
                )

    return findings


def build_exposure_overview_blocks(
    findings: list[dict[str, Any]],
    *,
    allow_probe: bool = False,
    probe_endpoint: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return (hero_badge, optional_detail_card) following the Option B UI design."""
    if not findings:
        return ({"text": "No Public Mgmt Exposure", "variant": "allow"}, None)

    crit_count = sum(1 for f in findings if f.get("severity") == "critical")
    has_mgmt = any(f.get("category", "mgmt") in ("mgmt", "nat_mgmt") for f in findings)
    has_vip = any(f.get("category") == "vip" for f in findings)
    severity = "deny" if crit_count > 0 else "warn"

    if has_mgmt:
        badge_text = f"Public Mgmt Exposed ({len(findings)})"
        card_title = "Public Interface Management Exposure"
        if has_vip:
            card_subtitle = (
                "Active firewall management interfaces and public VIP (DNAT) port-forwards. "
                "VIP entries forward to internal servers (not the firewall GUI). "
                "Critical = unrestricted mgmt, plaintext HTTP mgmt, or unrestricted RDP/SSH/SMB/DB VIP; "
                "Warning = restricted, WAN behind NAT, or HTTP/FTP VIP."
            )
        else:
            card_subtitle = (
                "Active interfaces with a public IP and HTTP, HTTPS, or SSH admin access enabled. "
                "Critical = unrestricted or plaintext HTTP; "
                "Warning = restricted via trusthost / local-in-policy / permitted-ip or WAN behind NAT."
            )
        card_badge_text = (
            f"{crit_count} Critical · {len(findings)} Exposed"
            if crit_count > 0
            else f"{len(findings)} Exposed (Restricted)"
        )
    else:
        badge_text = f"Public VIP Exposed ({len(findings)})"
        card_title = "Public VIP / Port-Forward (DNAT) Exposure"
        card_subtitle = (
            "Public VIP (DNAT) rules forwarding WAN traffic to internal servers — "
            "these do not expose the firewall login GUI. "
            "Critical = unrestricted RDP/SSH/Telnet/SMB/DB/VNC; "
            "Warning = plaintext HTTP/FTP web service or restricted source."
        )
        card_badge_text = (
            f"{crit_count} Critical · {len(findings)} VIP(s)"
            if crit_count > 0
            else f"{len(findings)} Warning · {len(findings)} VIP(s)"
        )

    badge = {
        "text": badge_text,
        "variant": severity,
        "id": "fw_exposure_badge",
    }
    card: dict[str, Any] = {
        "type": "card",
        "title": card_title,
        "subtitle": card_subtitle,
        "badge": {"text": card_badge_text, "variant": severity},
        "rows": [
            {
                "label": f"{f['interface']} ({f['ip']})" + (f" · {f['note']}" if f.get("note") else ""),
                "value": ", ".join(f.get("display_protocols") or f["protocols"]),
                "tone": "deny" if f.get("severity") == "critical" else "warn",
            }
            for f in findings
        ],
    }
    if allow_probe and probe_endpoint:
        card["probe_url"] = probe_endpoint
        card["probe_badge_id"] = "fw_exposure_badge"
    return badge, card


def _read_ssh_banner(conn: Any, timeout: float) -> str | None:
    if not hasattr(conn, "recv"):
        return None
    try:
        if hasattr(conn, "settimeout"):
            conn.settimeout(min(2.0, timeout))
        raw = conn.recv(256)
        if not raw:
            return None
        first_line = raw.decode("utf-8", errors="ignore").splitlines()[0]
        cleaned = "".join(ch for ch in first_line if 32 <= ord(ch) <= 126).strip()
        if cleaned.startswith("SSH-"):
            return cleaned[:64]
    except Exception:
        return None
    return None


def _read_tls_version(conn: Any, ip: str, timeout: float) -> str | None:
    if not isinstance(conn, socket.socket):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn.settimeout(min(5.0, timeout))
        with ctx.wrap_socket(conn, server_hostname=ip) as tls_sock:
            return tls_sock.version()
    except Exception:
        return None


def _read_http_hint(conn: Any, ip: str, timeout: float) -> str | None:
    if not (hasattr(conn, "sendall") and hasattr(conn, "recv")):
        return None
    try:
        if hasattr(conn, "settimeout"):
            conn.settimeout(min(2.0, timeout))
        req = (
            f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
            "User-Agent: FirewallConfigReader/1.0\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        conn.sendall(req)
        chunks: list[bytes] = []
        total = 0
        while total < 4096:
            chunk = conn.recv(2048)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"</title>" in b"".join(chunks).lower():
                break
        raw = b"".join(chunks)
        if not raw:
            return None
        text = raw.decode("utf-8", errors="ignore")
        head, _, body = text.partition("\r\n\r\n")
        if not body and "\n\n" in text:
            head, _, body = text.partition("\n\n")
        lines = head.splitlines()
        if not lines or not lines[0].upper().startswith("HTTP/"):
            return None
        status_parts = lines[0].split(None, 2)
        status_code = status_parts[1] if len(status_parts) >= 2 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        server = "".join(ch for ch in headers.get("server", "") if 32 <= ord(ch) <= 126).strip()[:40]
        location = "".join(ch for ch in headers.get("location", "") if 32 <= ord(ch) <= 126).strip()[:60]
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = ""
        if title_m:
            raw_title = re.sub(r"\s+", " ", title_m.group(1)).strip()
            title = "".join(ch for ch in raw_title if 32 <= ord(ch) <= 126).strip()[:48]

        parts: list[str] = []
        if status_code:
            parts.append(f"HTTP {status_code}")
        if location and status_code.startswith("3"):
            parts.append(f"→ {location}")
        if server:
            parts.append(f"Server: {server}")
        if title:
            parts.append(f'Title: "{title}"')
        return " · ".join(parts) if parts else None
    except Exception:
        return None


def _probe_one(task: tuple[str, str, int, str, str, bool, str], timeout: float) -> dict[str, Any]:
    iface, ip, port, proto, cfg_sev, restricted, category = task
    try:
        conn = socket.create_connection((ip, port), timeout=timeout)
        status = "open"
        detail = "TCP Open (Verified Reachable)"
        try:
            if proto == "SSH":
                banner = _read_ssh_banner(conn, timeout)
                if banner:
                    detail = f"TCP Open — SSH Banner: {banner}"
            elif proto == "HTTPS":
                tls_ver = _read_tls_version(conn, ip, timeout)
                if tls_ver:
                    detail = f"TCP Open — {tls_ver} Handshake OK"
            elif proto in ("HTTP", "HTTP-Alt"):
                http_hint = _read_http_hint(conn, ip, timeout)
                if http_hint:
                    detail = f"TCP Open — {http_hint}"
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except ConnectionRefusedError:
        status = "refused"
        detail = "Connection Refused (from this host)"
    except (TimeoutError, socket.timeout, OSError):
        status = "filtered"
        detail = "Filtered / Timed Out (from this host)"

    if cfg_sev == "critical":
        sev_label = "Critical"
    elif restricted:
        sev_label = "Warning (Restricted)"
    else:
        sev_label = "Warning"

    return {
        "category": category,
        "interface": iface,
        "ip": ip,
        "port": port,
        "protocol": proto,
        "config_severity": sev_label,
        "status": status,
        "detail": detail,
    }


def probe_exposure_targets(findings: list[dict[str, Any]], timeout: float = 5.0) -> list[dict[str, Any]]:
    """Perform TCP connect probes strictly against targets derived from exposure findings."""
    tasks: list[tuple[str, str, int, str, str, bool, str]] = []
    seen: set[tuple[str, str, int]] = set()
    for f in findings:
        iface = str(f.get("interface", "-"))
        cfg_sev = str(f.get("severity", "warn"))
        restricted = bool(f.get("restricted", False))
        category = str(f.get("category", "mgmt"))
        for t in f.get("targets") or []:
            ip = _bare_ip(str(t.get("ip", "")))
            port = int(t.get("port", 0) or 0)
            proto = str(t.get("protocol", ""))
            if not is_public_ip(ip) or port <= 0:
                continue
            key = (iface, ip, port)
            if key in seen:
                continue
            seen.add(key)
            tasks.append((iface, ip, port, proto, cfg_sev, restricted, category))

    if not tasks:
        return []

    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        return list(pool.map(lambda t: _probe_one(t, timeout), tasks))


def build_exposure_probe_blocks(probe_results: list[dict[str, Any]]) -> dict[str, Any]:
    if not probe_results:
        return {
            "open_count": 0,
            "total": 0,
            "blocks": [{"type": "alert", "variant": "info", "text": "No public management or VIP IP/port targets to test."}],
        }

    open_results = [r for r in probe_results if r["status"] == "open"]
    open_count = len(open_results)
    total = len(probe_results)
    has_mgmt = any(r.get("category", "mgmt") in ("mgmt", "nat_mgmt") for r in probe_results)
    open_mgmt = any(r.get("category", "mgmt") in ("mgmt", "nat_mgmt") for r in open_results)
    open_crit_vip = any(r.get("category") == "vip" and r.get("config_severity") == "Critical" for r in open_results)

    probe_badge_text: str | None = None
    probe_badge_variant: str | None = None

    if open_count > 0:
        if open_mgmt:
            alert_variant = "error"
            alert_text = (
                f"CONFIRMED CRITICAL: {open_count} of {total} public management port(s) accepted a TCP connection from this host!"
            )
            probe_badge_text = f"Public Mgmt Reachable ({open_count})"
            probe_badge_variant = "deny"
        elif open_crit_vip:
            alert_variant = "error"
            alert_text = (
                f"CONFIRMED CRITICAL: {open_count} of {total} public VIP port-forward(s) (internal server) "
                "accepted a TCP connection from this host!"
            )
            probe_badge_text = f"Public VIP Reachable ({open_count})"
            probe_badge_variant = "deny"
        else:
            alert_variant = "warn"
            alert_text = (
                f"REACHABLE (WARNING): {open_count} of {total} public VIP port-forward(s) "
                "(internal server, not firewall GUI) accepted a TCP connection from this host."
            )
            probe_badge_text = f"Public VIP Reachable ({open_count})"
            probe_badge_variant = "warn"
        alert = {"type": "alert", "variant": alert_variant, "text": alert_text}
    else:
        target_label = "management/VIP" if has_mgmt else "VIP"
        alert = {
            "type": "alert",
            "variant": "info",
            "text": (
                f"0 of {total} tested {target_label} port(s) accepted a TCP connection from this host. "
                "Note: ports may still be reachable from other networks or blocked by your local firewall — keep config restrictions in place."
            ),
        }

    rows = [
        {
            "Interface": r["interface"],
            "Public IP": r["ip"],
            "Protocol / Port": f"{r['protocol']} ({r['port']})",
            "Config Severity": r["config_severity"],
            "Live Reachability": r["detail"],
        }
        for r in probe_results
    ]
    row_classes = [
        "row-danger" if r["status"] == "open" else ("row-muted" if r["status"] == "refused" else "row-warn")
        for r in probe_results
    ]

    res: dict[str, Any] = {
        "open_count": open_count,
        "total": total,
        "blocks": [
            alert,
            {
                "type": "table",
                "id": "fw_exposure_probe_results",
                "columns": list(rows[0].keys()),
                "rows": rows,
                "row_classes": row_classes,
                "legend": [
                    {"label": "TCP Open — Confirmed Reachable (red)", "variant": "danger"},
                    {"label": "Filtered / Timed Out from This Host (amber)", "variant": "warn"},
                    {"label": "Connection Refused from This Host (muted)", "variant": "muted"},
                ],
                "export_filename": "public_mgmt_reachability_probe.csv",
            },
        ],
    }
    if probe_badge_text and probe_badge_variant:
        res["probe_badge_text"] = probe_badge_text
        res["probe_badge_variant"] = probe_badge_variant
    return res
