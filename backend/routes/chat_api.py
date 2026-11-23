"""
backend/routes/chat_api.py
Endpoints for the floating AI config assistant (/api/chat).
API keys entered in the UI are stored strictly per-session in RAM (never written to disk).
Server environment keys (GEMINI_API_KEY / .env) are only available to direct local loopback sessions.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from backend.auth import is_authenticated
from backend.chat_service import (
    ask_gemini,
    build_config_summary,
    detect_vendor_from_content,
    get_api_key_status,
)
from backend.session_store import is_loopback_request, store

router = APIRouter(prefix="/api/chat")


class ChatQuestion(BaseModel):
    question: str


class ApiKeyPayload(BaseModel):
    api_key: str


def _mismatch_message(sess) -> str | None:
    if sess.vendor_mismatch and sess.vendor_mismatch != sess.vendor:
        return f"Note: File extension indicated {sess.vendor}, but content looks like {sess.vendor_mismatch}."
    return None


@router.get("")
def chat_state(request: Request):
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    allow_env = is_loopback_request(request)
    if sess is None:
        return {
            "history": [],
            "vendor_mismatch": None,
            "key_status": get_api_key_status(None, allow_env_fallback=allow_env),
        }
    return {
        "history": sess.chat_history,
        "vendor_mismatch": _mismatch_message(sess),
        "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
    }


@router.post("/key")
def chat_set_key(body: ApiKeyPayload, request: Request):
    """Store user-supplied Gemini API key strictly in this session's RAM."""
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None:
        raise HTTPException(status_code=404, detail="No active session.")

    allow_env = is_loopback_request(request)
    cleaned = body.api_key.strip()
    sess.gemini_api_key = cleaned or None

    return {
        "ok": True,
        "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
    }


@router.post("")
def chat_ask(body: ChatQuestion, request: Request):
    """Run in FastAPI's threadpool (sync def) so Gemini network I/O never blocks the event loop."""
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or not sess.raw_content or sess.vendor not in ("Palo Alto", "FortiGate"):
        raise HTTPException(status_code=404, detail="No active firewall configuration loaded.")

    q = body.question.strip()
    if not q:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    raw_bytes = sess.raw_content
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    if sess.config_summary is None:
        sess.config_summary = build_config_summary(
            raw_text,
            sess.vendor,
            content_hash=sess.content_hash,
            raw_bytes=raw_bytes,
        )
        detected = detect_vendor_from_content(raw_text)
        if detected and detected != sess.vendor:
            sess.vendor_mismatch = detected

    allow_env = is_loopback_request(request)
    ok, reply = ask_gemini(
        question=q,
        config_summary=sess.config_summary,
        vendor=sess.vendor,
        filename=sess.filename or "config",
        chat_history=sess.chat_history,
        vendor_mismatch=sess.vendor_mismatch,
        api_key_override=sess.gemini_api_key,
        allow_env_fallback=allow_env,
    )

    if ok:
        sess.chat_history.append({"role": "user", "content": q})
        sess.chat_history.append({"role": "assistant", "content": reply})

    return {
        "ok": ok,
        "reply": reply,
        "history": sess.chat_history,
        "vendor_mismatch": _mismatch_message(sess),
        "key_status": get_api_key_status(sess.gemini_api_key, allow_env_fallback=allow_env),
    }


@router.delete("")
async def chat_clear(request: Request):
    sess = store.get_existing(request)
    if sess is not None:
        sess.chat_history = []
    return {"ok": True}
