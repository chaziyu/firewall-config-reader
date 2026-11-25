"""
backend/upload_service.py
File validation & security sanitization for uploaded firewall configs and TSF archives.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_CONFIG_MB = 50
MAX_TSF_MB = 500
ALLOWED_CONFIG_EXTS = {".xml", ".conf", ".txt"}
ALLOWED_TSF_EXTS = {".zip"}

FORBIDDEN_SIGS = [
    b"<script",  # XSS in XML
    b"<?php",    # PHP injection
    b"#!/",      # Shell scripts
    b"\x4d\x5a", # PE executable (MZ)
    b"\x7fELF",  # ELF executable
]

_FG_CONFIG_RE = re.compile(rb"^\s*config\s+[a-zA-Z0-9_-]+", re.MULTILINE)
_FG_END_RE = re.compile(rb"^\s*end\s*$", re.MULTILINE)
_XML_DTD_RE = re.compile(rb"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_PA_ROOT_CHILDREN = {"devices", "shared", "mgt-config", "panorama", "readonly"}


class UploadValidationError(ValueError):
    """Raised when an uploaded file fails extension, size, or security checks."""


def validate_filename(filename: str) -> tuple[str, bool]:
    """Validate extension and return (ext, is_tsf)."""
    ext = Path(filename or "").suffix.lower()
    is_tsf = ext in ALLOWED_TSF_EXTS
    if ext not in ALLOWED_CONFIG_EXTS and not is_tsf:
        allowed = ", ".join(sorted(ALLOWED_CONFIG_EXTS | ALLOWED_TSF_EXTS))
        raise UploadValidationError(f"Unsupported file type '{ext or '(none)'}'. Use: {allowed}")
    return ext, is_tsf


def validate_content(content: bytes, is_tsf: bool) -> None:
    """Validate size limits and basic binary/script signatures."""
    if not content:
        raise UploadValidationError("Uploaded file is empty.")

    limit_mb = MAX_TSF_MB if is_tsf else MAX_CONFIG_MB
    if len(content) > limit_mb * 1024 * 1024:
        kind = "TSF archive" if is_tsf else "File"
        raise UploadValidationError(f"{kind} exceeds the {limit_mb} MB limit.")

    if not is_tsf:
        head = content[:4096].lower()
        for sig in FORBIDDEN_SIGS:
            if sig in head:
                raise UploadValidationError("File content failed the security check.")


def validate_structure(content: bytes, ext: str) -> None:
    """Validate lightweight file structure for ZIP, XML, and FortiGate CLI configs."""
    if ext == ".zip":
        if content[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
            raise UploadValidationError("File is not a valid ZIP archive.")
        return

    # Reject binary files disguised as plain-text configs
    if b"\x00" in content[:8192]:
        raise UploadValidationError(
            "File appears to be binary, not a plain-text firewall config."
        )

    stripped = content.lstrip(b"\xef\xbb\xbf \t\r\n")

    if ext == ".xml":
        if not stripped.startswith(b"<"):
            raise UploadValidationError("File does not appear to be valid XML.")
        if _XML_DTD_RE.search(content):
            raise UploadValidationError("XML DOCTYPE/ENTITY declarations are not allowed.")
        return

    # FortiGate (.conf / .txt)
    if stripped.startswith((b"<?xml", b"<config")):
        raise UploadValidationError(
            "This looks like an XML config. Please upload it with a .xml extension."
        )
    if not (_FG_CONFIG_RE.search(content) and _FG_END_RE.search(content)):
        raise UploadValidationError(
            "File does not look like a FortiGate CLI config (expected 'config ... end' blocks)."
        )


def validate_palo_alto_root(root: ET.Element) -> None:
    """Verify the parsed XML root matches a Palo Alto PAN-OS configuration structure."""
    if root.tag != "config":
        raise UploadValidationError(
            "XML root element must be <config> (not a Palo Alto PAN-OS config)."
        )
    if not any(child.tag in _PA_ROOT_CHILDREN for child in root):
        raise UploadValidationError(
            "XML <config> does not contain expected Palo Alto sections (e.g. <devices>, <shared>, <mgt-config>)."
        )


# Pre-compiled secret redaction patterns (applied immediately on upload before storing in RAM)
_PA_XML_SECRET_RE = re.compile(
    rb"<(phash|private-key|psk|secret|bind-password|key|password|auth-password|priv-password)>(\s*.*?\s*)</\1>",
    re.IGNORECASE | re.DOTALL,
)
_FG_LINE_SECRET_RE = re.compile(
    rb"(^\s*set\s+(?:password|passwd|psksecret|secret|key|auth-password-l1|auth-password-l2|private-key)\s+)"
    rb'(?:ENC\s+\S+|"-----BEGIN[^"]*-----"|"[^"\r\n]*"|\S+)',
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)


def sanitize_config_bytes(content: bytes, vendor: str) -> bytes:
    """Redact sensitive cryptographic keys, password hashes, and PSKs before keeping in RAM."""
    if vendor == "Palo Alto":
        return _PA_XML_SECRET_RE.sub(rb"<\1>[REDACTED]</\1>", content)
    return _FG_LINE_SECRET_RE.sub(rb'\1"[REDACTED]"', content)

