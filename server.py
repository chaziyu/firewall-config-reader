"""
server.py — FastAPI entrypoint for Firewall Config Reader.
Replaces the legacy Streamlit app.py shell with FastAPI + Jinja2 HTML + Vanilla JS/CSS.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.routes import chat_api, config_api, pages, tsf_api, update_api, upload
from backend.session_store import is_https_request, is_loopback_request, store

ROOT_DIR = Path(__file__).resolve().parent


def _allowed_hosts() -> set[str]:
    hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
    extra = os.environ.get("FW_ALLOWED_HOSTS", "")
    for item in extra.split(","):
        cleaned = item.strip().lower()
        if cleaned:
            hosts.add(cleaned)
    return hosts


def _extract_hostname(host_header: str) -> str:
    raw = host_header.strip()
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return ""
        return raw[1:end].lower()
    if raw.count(":") > 1:
        return raw.lower()
    return raw.split(":", 1)[0].lower()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    store.cleanup_all()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Firewall Config Reader",
        version="2.4.4",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        host = _extract_hostname(request.headers.get("host", ""))
        loopback = is_loopback_request(request)
        allowed = _allowed_hosts()

        if loopback:
            if host and host not in allowed:
                return JSONResponse({"detail": "Invalid Host header."}, status_code=403)
        elif os.environ.get("FW_ALLOWED_HOSTS", "").strip():
            if host not in allowed:
                return JSONResponse({"detail": "Invalid Host header."}, status_code=403)

        if loopback and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin:
                origin_host = (urlparse(origin).hostname or "").lower()
                if origin_host not in allowed:
                    return JSONResponse({"detail": "Cross-origin request blocked."}, status_code=403)

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if is_https_request(request):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if not request.url.path.startswith(("/static/", "/assets/")):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    static_dir = ROOT_DIR / "static"
    assets_dir = ROOT_DIR / "assets"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    app.include_router(pages.router)
    app.include_router(upload.router)
    app.include_router(config_api.router)
    app.include_router(tsf_api.router)
    app.include_router(chat_api.router)
    app.include_router(update_api.router)

    return app


app = create_app()

if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.environ.get("FW_PORT", "8501"))
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=False)
