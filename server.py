"""
server.py — FastAPI entrypoint for Firewall Config Reader.
Replaces the legacy Streamlit app.py shell with FastAPI + Jinja2 HTML + Vanilla JS/CSS.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.routes import chat_api, config_api, pages, tsf_api, update_api, upload
from backend.session_store import store

ROOT_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    store.cleanup_all()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Firewall Config Reader",
        version="2.3.1",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

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
