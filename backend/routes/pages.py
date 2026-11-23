"""
backend/routes/pages.py
HTML page routes: /health, /login, /, /workspace, /tsf.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from backend.auth import is_authenticated, password_required, verify_password
from backend.session_store import SESSION_COOKIE, is_https_request, store

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(ROOT_DIR / "templates"))

PA_PAGES = [
    ("Dashboard", "📊"),
    ("Policies", "🛡"),
    ("Objects", "📦"),
    ("Network", "🌐"),
    ("Device", "⚙"),
]

FG_PAGES = [
    ("Summary", "📊"),
    ("Interfaces", "🔌"),
    ("Network", "🌐"),
    ("Policy & Objects", "🛡"),
    ("Security", "🔒"),
    ("VPN", "🔑"),
    ("User & Auth", "👥"),
    ("WiFi & Switch", "📶"),
    ("System", "⚙"),
    ("Log & Report", "📋"),
]

router = APIRouter()


def _attach_cookie(resp, sid: str, request: Request):
    if request.cookies.get(SESSION_COOKIE) != sid:
        resp.set_cookie(
            key=SESSION_COOKIE,
            value=sid,
            httponly=True,
            samesite="lax",
            secure=is_https_request(request),
            path="/",
        )
    return resp


@router.get("/health")
async def health():
    return JSONResponse({"status": "ok"})


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not password_required():
        return RedirectResponse("/", status_code=303)
    sess = store.get_or_create(request)
    if sess.authenticated:
        return RedirectResponse("/", status_code=303)
    resp = templates.TemplateResponse(request, "login.html", {"error": None})
    return _attach_cookie(resp, sess.session_id, request)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, password: str = Form(...)):
    sess = store.get_or_create(request)
    if verify_password(password):
        sess.authenticated = True
        resp = RedirectResponse("/", status_code=303)
        return _attach_cookie(resp, sess.session_id, request)
    resp = templates.TemplateResponse(
        request, "login.html", {"error": "Incorrect password."}, status_code=401
    )
    return _attach_cookie(resp, sess.session_id, request)


@router.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    sess = store.get_or_create(request)
    if not is_authenticated(sess):
        resp = RedirectResponse("/login", status_code=303)
        return _attach_cookie(resp, sess.session_id, request)

    if sess.tsf_session_id:
        return _attach_cookie(RedirectResponse("/tsf", status_code=303), sess.session_id, request)
    if sess.raw_content and sess.vendor in ("Palo Alto", "FortiGate"):
        return _attach_cookie(RedirectResponse("/workspace", status_code=303), sess.session_id, request)

    assets_dir = ROOT_DIR / "assets"
    resp = templates.TemplateResponse(
        request,
        "landing.html",
        {
            "has_pa_logo": (assets_dir / "paloalto_logo.png").exists(),
            "has_fg_logo": (assets_dir / "fortigate_logo.png").exists(),
        },
    )
    return _attach_cookie(resp, sess.session_id, request)


@router.get("/workspace", response_class=HTMLResponse)
async def workspace(request: Request):
    sess = store.get_or_create(request)
    if not is_authenticated(sess):
        return _attach_cookie(RedirectResponse("/login", status_code=303), sess.session_id, request)
    if not sess.raw_content or sess.vendor not in ("Palo Alto", "FortiGate"):
        return _attach_cookie(RedirectResponse("/", status_code=303), sess.session_id, request)

    pages = PA_PAGES if sess.vendor == "Palo Alto" else FG_PAGES
    resp = templates.TemplateResponse(
        request,
        "workspace.html",
        {
            "vendor": sess.vendor,
            "filename": sess.filename or "config",
            "pages": pages,
        },
    )
    return _attach_cookie(resp, sess.session_id, request)


@router.get("/tsf", response_class=HTMLResponse)
async def tsf_page(request: Request):
    sess = store.get_or_create(request)
    if not is_authenticated(sess):
        return _attach_cookie(RedirectResponse("/login", status_code=303), sess.session_id, request)
    if not sess.tsf_session_id:
        return _attach_cookie(RedirectResponse("/", status_code=303), sess.session_id, request)

    resp = templates.TemplateResponse(
        request,
        "tsf.html",
        {
            "filename": sess.tsf_filename or "package.zip",
        },
    )
    return _attach_cookie(resp, sess.session_id, request)
