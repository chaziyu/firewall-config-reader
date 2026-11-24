"""
backend/session_store.py
In-memory cookie-backed session store, SHA-256 parser cache, and TSF extraction job tracker.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request, Response

SESSION_COOKIE = "fw_session_id"
SESSION_TTL_SECONDS = int(os.environ.get("FW_SESSION_TTL_SECONDS", str(30 * 60)))  # 30 minutes
MAX_SESSIONS = 24
PARSER_CACHE_MAX = 16


def is_https_request(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "")
    return request.url.scheme == "https" or proto.split(",")[0].strip().lower() == "https"


def is_loopback_request(request: Request) -> bool:
    """Return True only when the request originates directly from local loopback (no proxy headers)."""
    if request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"):
        return False
    client_host = (request.client.host if request.client else "") or ""
    return client_host in ("127.0.0.1", "::1", "localhost")


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """Obfuscate/deobfuscate compressed bytes in RAM using a repeating key stream."""
    if not data or not key:
        return data
    klen = len(key)
    # Repeat key to match data length and XOR via int.from_bytes for C-speed execution
    full_key = (key * ((len(data) // klen) + 1))[: len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(full_key, "little")).to_bytes(len(data), "little")


@dataclass
class SessionData:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    authenticated: bool = False

    # Config session state (encrypted + zlib-compressed in RAM; never stored as plain text)
    vendor: str | None = None  # "Palo Alto" | "FortiGate" | "TSF"
    filename: str | None = None
    content_hash: str | None = None
    _sealed_content: bytes | None = field(default=None, repr=False)
    _mem_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    # TSF session state
    tsf_session_id: str | None = None
    tsf_filename: str | None = None

    # Chatbot state
    chat_history: list[dict[str, str]] = field(default_factory=list)
    config_summary: str | None = None
    vendor_mismatch: str | None = None
    gemini_api_key: str | None = None

    @property
    def raw_content(self) -> bytes | None:
        """Unseal (decrypt + decompress) the config bytes on demand."""
        if self._sealed_content is None:
            return None
        compressed = _xor_bytes(self._sealed_content, self._mem_key)
        return zlib.decompress(compressed)

    @raw_content.setter
    def raw_content(self, data: bytes | None) -> None:
        """Compress with zlib and XOR-seal with a fresh random 32-byte key so plain text never sits in RAM."""
        if data is None:
            self._sealed_content = None
            self._mem_key = secrets.token_bytes(32)
            return
        self._mem_key = secrets.token_bytes(32)
        compressed = zlib.compress(data, level=6)
        self._sealed_content = _xor_bytes(compressed, self._mem_key)

    def reset_config(self) -> None:
        old_hash = self.content_hash
        self.vendor = None
        self.filename = None
        self.content_hash = None
        self.raw_content = None
        self.chat_history = []
        self.config_summary = None
        self.vendor_mismatch = None
        if old_hash:
            store.evict_parser_cache_if_unreferenced(old_hash, exclude_sid=self.session_id)

    def clear_all(self) -> None:
        self.reset_config()
        self.reset_tsf()
        self.gemini_api_key = None

    def reset_tsf(self) -> None:
        if self.tsf_session_id:
            try:
                from tsf.extractor import cleanup_session
                from tsf.indexer import drop_index

                cleanup_session(self.tsf_session_id)
                drop_index(self.tsf_session_id)
            except Exception:
                pass
        self.tsf_session_id = None
        self.tsf_filename = None
        if self.vendor == "TSF":
            self.vendor = None
            self.filename = None


@dataclass
class TsfJob:
    job_id: str
    session_id: str
    filename: str
    status: str = "running"  # running | done | error
    progress: float = 0.0
    message: str = "Starting extraction..."
    error: str | None = None
    total_files: int = 0
    skipped: list[str] = field(default_factory=list)
    tsf_session_id: str | None = None
    created_at: float = field(default_factory=time.time)


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionData] = {}
        self._parser_cache: dict[str, tuple[float, Any]] = {}
        self._tsf_jobs: dict[str, TsfJob] = {}

    def get_or_create(self, request: Request, response: Response | None = None) -> SessionData:
        sid = request.cookies.get(SESSION_COOKIE)
        with self._lock:
            self._evict_expired_locked()
            if sid and sid in self._sessions:
                sess = self._sessions[sid]
                sess.last_accessed = time.time()
                return sess

            if len(self._sessions) >= MAX_SESSIONS:
                oldest_sid = min(self._sessions, key=lambda k: self._sessions[k].last_accessed)
                evicted = self._sessions.pop(oldest_sid, None)
                if evicted is not None:
                    evicted.clear_all()

            new_sid = secrets.token_urlsafe(24)
            sess = SessionData(session_id=new_sid)
            self._sessions[new_sid] = sess

        if response is not None:
            response.set_cookie(
                key=SESSION_COOKIE,
                value=new_sid,
                httponly=True,
                samesite="lax",
                secure=is_https_request(request),
                path="/",
            )
        return sess

    def get_existing(self, request: Request) -> SessionData | None:
        sid = request.cookies.get(SESSION_COOKIE)
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess.last_accessed = time.time()
            return sess

    def get_by_id(self, sid: str) -> SessionData | None:
        with self._lock:
            return self._sessions.get(sid)

    def _evict_expired_locked(self) -> None:
        now = time.time()
        expired = [
            sid
            for sid, s in self._sessions.items()
            if now - s.last_accessed > SESSION_TTL_SECONDS
        ]
        for sid in expired:
            sess = self._sessions.pop(sid, None)
            if sess:
                sess.clear_all()

        old_jobs = [
            jid
            for jid, j in self._tsf_jobs.items()
            if now - j.created_at > 3600
        ]
        for jid in old_jobs:
            self._tsf_jobs.pop(jid, None)

    # ── Parser cache (replaces @st.cache_resource) ────────────────────────
    def get_palo_alto_parsers(self, content_hash: str, content: bytes) -> dict[str, Any]:
        cache_key = f"pa:{content_hash}"
        with self._lock:
            cached = self._parser_cache.get(cache_key)
            if cached is not None:
                self._parser_cache[cache_key] = (time.time(), cached[1])
                return cached[1]

        from parsers.paloalto import (
            PaloDashboardParser,
            PaloDeviceParser,
            PaloNetworkParser,
            PaloObjectsParser,
            PaloPoliciesParser,
        )

        root = ET.fromstring(content.lstrip(b"\xef\xbb\xbf"))
        parsers = {
            "Dashboard": PaloDashboardParser(root),
            "Policies": PaloPoliciesParser(root),
            "Objects": PaloObjectsParser(root),
            "Network": PaloNetworkParser(root),
            "Device": PaloDeviceParser(root),
        }
        self._put_cache(cache_key, parsers)
        return parsers

    def get_fortigate_parser(self, content_hash: str, content: bytes) -> Any:
        cache_key = f"fg:{content_hash}"
        with self._lock:
            cached = self._parser_cache.get(cache_key)
            if cached is not None:
                self._parser_cache[cache_key] = (time.time(), cached[1])
                return cached[1]

        from parsers.fortigate import FortiGateParser

        text = content.decode("utf-8", errors="replace")
        parser = FortiGateParser(text)
        self._put_cache(cache_key, parser)
        return parser

    def _put_cache(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._parser_cache) >= PARSER_CACHE_MAX:
                oldest_key = min(self._parser_cache, key=lambda k: self._parser_cache[k][0])
                self._parser_cache.pop(oldest_key, None)
            self._parser_cache[key] = (time.time(), value)

    def evict_parser_cache_if_unreferenced(self, content_hash: str, exclude_sid: str | None = None) -> None:
        """Evict cached parser objects for content_hash if no other active session uses it."""
        if not content_hash:
            return
        with self._lock:
            still_used = any(
                s.content_hash == content_hash and s.session_id != exclude_sid
                for s in self._sessions.values()
            )
            if not still_used:
                self._parser_cache.pop(f"pa:{content_hash}", None)
                self._parser_cache.pop(f"fg:{content_hash}", None)

    # ── TSF jobs ──────────────────────────────────────────────────────────
    def create_tsf_job(self, session_id: str, filename: str) -> TsfJob:
        job_id = secrets.token_urlsafe(12)
        job = TsfJob(job_id=job_id, session_id=session_id, filename=filename)
        with self._lock:
            self._tsf_jobs[job_id] = job
        return job

    def get_tsf_job(self, job_id: str) -> TsfJob | None:
        with self._lock:
            return self._tsf_jobs.get(job_id)

    def cleanup_all(self) -> None:
        with self._lock:
            for sess in self._sessions.values():
                sess.reset_tsf()
            self._sessions.clear()
            self._parser_cache.clear()
            self._tsf_jobs.clear()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


store = SessionStore()
