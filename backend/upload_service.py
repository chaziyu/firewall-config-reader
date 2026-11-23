"""
backend/upload_service.py
File validation & security sanitization for uploaded firewall configs and TSF archives.
"""

from __future__ import annotations

import re
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
        head = content[:512].lower()
        for sig in FORBIDDEN_SIGS:
            if sig in head:
                raise UploadValidationError("File content failed the security check.")


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

