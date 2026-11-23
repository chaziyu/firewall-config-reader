"""
backend/auth.py
Optional password gate controlled by the FW_PASSWORD environment variable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from backend.session_store import SessionData


def password_required() -> bool:
    return bool(os.environ.get("FW_PASSWORD", ""))


def is_authenticated(sess: SessionData | None) -> bool:
    if not password_required():
        return True
    return bool(sess and sess.authenticated)


def verify_password(candidate: str) -> bool:
    expected = os.environ.get("FW_PASSWORD", "")
    if not expected:
        return True
    h_cand = hashlib.sha256(candidate.encode("utf-8")).digest()
    h_exp = hashlib.sha256(expected.encode("utf-8")).digest()
    if hmac.compare_digest(h_cand, h_exp):
        return True
    time.sleep(0.8)  # Brute-force delay
    return False
