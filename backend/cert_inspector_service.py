"""
backend/cert_inspector_service.py
Certificate Expiry Inspector for FortiGate (.conf) and Palo Alto (.xml).
Parses embedded PEM X.509 certificates and PAN-OS certificate metadata to
surface CN, SAN/FQDN, Issuer, validity dates, days remaining, and expiry alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _attr_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else "-"


def _cert_dates(cert: x509.Certificate) -> tuple[datetime, datetime]:
    nb = getattr(cert, "not_valid_before_utc", None)
    na = getattr(cert, "not_valid_after_utc", None)
    if nb is None:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if na is None:
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nb, na


def _parse_pem_cert(pem_text: str, now: datetime) -> dict[str, Any] | None:
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8", errors="ignore"))
    except Exception:
        return None

    nb, na = _cert_dates(cert)
    days_left = (na - now).days
    if days_left < 0:
        status = "Expired"
    elif days_left < 30:
        status = "Expiring Soon"
    else:
        status = "Valid"

    cn = _attr_value(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _attr_value(cert.issuer, NameOID.COMMON_NAME)
    if issuer_cn == "-":
        issuer_cn = _attr_value(cert.issuer, NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for dns in san_ext.get_values_for_type(x509.DNSName):
            sans.append(str(dns))
        for ip in san_ext.get_values_for_type(x509.IPAddress):
            sans.append(str(ip))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    return {
        "common_name": cn,
        "san": ", ".join(sans[:6]) + ("..." if len(sans) > 6 else "") if sans else "-",
        "issuer": issuer_cn,
        "not_before": nb.strftime("%Y-%m-%d"),
        "expires": na.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "status": status,
    }


def inspect_fortigate_certificates(fg: Any, now: datetime | None = None) -> list[dict[str, Any]]:
    now_dt = now or datetime.now(timezone.utc)
    extract = getattr(fg, "_extract_block", None)
    if extract is None:
        return []

    rows: list[dict[str, Any]] = []
    stores = (
        ("vpn certificate local", "Local"),
        ("vpn certificate ca", "CA"),
        ("vpn certificate remote", "Remote"),
    )
    for keyword, store_label in stores:
        block = extract(keyword)
        if not block:
            continue
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            pem_m = _PEM_CERT_RE.search(body)
            if pem_m:
                parsed = _parse_pem_cert(pem_m.group(0), now_dt)
                if parsed is not None:
                    rows.append(
                        {
                            "Name": name,
                            "Store": store_label,
                            "Common Name": parsed["common_name"],
                            "SAN / FQDN": parsed["san"],
                            "Issuer": parsed["issuer"],
                            "Not Before": parsed["not_before"],
                            "Expires": parsed["expires"],
                            "Days Left": str(parsed["days_left"]),
                            "Status": parsed["status"],
                        }
                    )
                    continue
            rows.append(
                {
                    "Name": name,
                    "Store": store_label,
                    "Common Name": "-",
                    "SAN / FQDN": "-",
                    "Issuer": "-",
                    "Not Before": "-",
                    "Expires": "-",
                    "Days Left": "-",
                    "Status": "No PEM",
                }
            )
    return rows


def _parse_panos_time(val: str) -> datetime | None:
    s = str(val or "").strip()
    if not s or s == "-":
        return None
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def inspect_paloalto_certificates(device_parser: Any, now: datetime | None = None) -> list[dict[str, Any]]:
    if device_parser is None:
        return []
    now_dt = now or datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []

    containers: list[tuple[Any, str]] = []
    shared = device_parser._shared() if hasattr(device_parser, "_shared") else None
    if shared is not None:
        containers.append((shared.find("certificate"), "Shared"))
    vsys = getattr(device_parser, "vsys", None)
    if vsys is not None:
        containers.append((vsys.find("certificate"), "vsys1"))

    for cert_el, store_label in containers:
        if cert_el is None:
            continue
        for entry in cert_el.findall("entry"):
            name = entry.get("name", "-")
            pub_pem = entry.findtext("public-key", "") or ""
            pem_m = _PEM_CERT_RE.search(pub_pem)
            if pem_m:
                parsed = _parse_pem_cert(pem_m.group(0), now_dt)
                if parsed is not None:
                    rows.append(
                        {
                            "Name": name,
                            "Store": store_label,
                            "Common Name": parsed["common_name"],
                            "SAN / FQDN": parsed["san"],
                            "Issuer": parsed["issuer"],
                            "Not Before": parsed["not_before"],
                            "Expires": parsed["expires"],
                            "Days Left": str(parsed["days_left"]),
                            "Status": parsed["status"],
                        }
                    )
                    continue

            nb_raw = entry.findtext("not-valid-before", "-")
            exp_raw = entry.findtext("not-valid-after", "-")
            exp_dt = _parse_panos_time(exp_raw)
            nb_dt = _parse_panos_time(nb_raw)
            if exp_dt is not None:
                days_left = (exp_dt - now_dt).days
                status = "Expired" if days_left < 0 else ("Expiring Soon" if days_left < 30 else "Valid")
                days_str = str(days_left)
                exp_str = exp_dt.strftime("%Y-%m-%d")
            else:
                status = "No PEM"
                days_str = "-"
                exp_str = exp_raw

            rows.append(
                {
                    "Name": name,
                    "Store": store_label,
                    "Common Name": entry.findtext("common-name", "-"),
                    "SAN / FQDN": "-",
                    "Issuer": entry.findtext("issuer", "-"),
                    "Not Before": nb_dt.strftime("%Y-%m-%d") if nb_dt is not None else nb_raw,
                    "Expires": exp_str,
                    "Days Left": days_str,
                    "Status": status,
                }
            )
    return rows


def build_cert_overview_blocks(certs: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    expired = [c for c in certs if c.get("Status") == "Expired"]
    expiring = [c for c in certs if c.get("Status") == "Expiring Soon"]
    flagged = expired + expiring
    if not flagged:
        return None, None

    if expired:
        badge = {"text": f"Expired Certs ({len(expired)})", "variant": "deny"}
        card_variant = "deny"
        card_badge = f"{len(expired)} Expired" + (f" · {len(expiring)} Expiring" if expiring else "")
    else:
        badge = {"text": f"Certs Expiring Soon ({len(expiring)})", "variant": "warn"}
        card_variant = "warn"
        card_badge = f"{len(expiring)} Expiring < 30d"

    card = {
        "type": "card",
        "title": "Certificate Expiry Alerts",
        "subtitle": "Certificates that are expired or expiring within 30 days (may impact VPN, HTTPS mgmt, or SSL inspection).",
        "badge": {"text": card_badge, "variant": card_variant},
        "rows": [
            {
                "label": f"{c['Name']} ({c['Store']}) · CN: {c['Common Name']}",
                "value": f"{c['Status']} ({c['Expires']}, {c['Days Left']}d)",
                "tone": "deny" if c["Status"] == "Expired" else "warn",
            }
            for c in flagged
        ],
    }
    return badge, card


def _cert_row_class(r: dict[str, Any]) -> str:
    st = str(r.get("Status", ""))
    if st == "Expired":
        return "row-danger"
    if st == "Expiring Soon":
        return "row-warn"
    if st == "Valid":
        return "row-success"
    return ""


def build_cert_inspector_blocks(certs: list[dict[str, Any]], vendor: str) -> list[dict[str, Any]]:
    if not certs:
        return [{"type": "alert", "variant": "info", "text": "No certificates found in this configuration."}]

    expired_n = sum(1 for c in certs if c.get("Status") == "Expired")
    expiring_n = sum(1 for c in certs if c.get("Status") == "Expiring Soon")
    valid_n = sum(1 for c in certs if c.get("Status") == "Valid")

    return [
        {
            "type": "kv_grid",
            "items": [
                {"label": "Total Certificates", "value": str(len(certs))},
                {"label": "Expired", "value": str(expired_n)},
                {"label": "Expiring < 30 Days", "value": str(expiring_n)},
                {"label": "Valid", "value": str(valid_n)},
            ],
        },
        {
            "type": "table",
            "id": f"{vendor}_cert_expiry_tbl",
            "title": "Certificate Expiry Inspector",
            "columns": list(certs[0].keys()),
            "rows": certs,
            "row_classes": [_cert_row_class(c) for c in certs],
            "legend": [
                {"label": "Valid >= 30 Days (green)", "variant": "success"},
                {"label": "Expiring < 30 Days (amber)", "variant": "warn"},
                {"label": "Expired (red)", "variant": "danger"},
                {"label": "Reference Only / No PEM (default)", "variant": "default"},
            ],
            "export_filename": f"{vendor}_certificate_expiry.csv",
        },
    ]
