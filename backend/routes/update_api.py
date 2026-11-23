"""
backend/routes/update_api.py
Endpoints for checking GitHub Releases for a newer version and triggering a verified upgrade.
- Cloud / Render mode (proxied requests): returns mode="cloud", hiding the update UI completely.
- Local Source mode (Start Local.bat / python server.py): checks GitHub Releases and offers `git pull --ff-only`.
- Packaged Desktop .exe mode (PyInstaller): downloads Inno Setup .exe, verifies SHA-256, and silently upgrades.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from backend.auth import is_authenticated
from backend.session_store import is_loopback_request, store
from backend.update_service import check_for_updates, download_and_trigger_install

router = APIRouter(prefix="/api/update")


@router.get("/check")
def api_update_check(request: Request):
    """Run in threadpool (sync def) so GitHub API check never blocks FastAPI's event loop."""
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")

    return check_for_updates(is_loopback=is_loopback_request(request))


@router.post("/install")
def api_update_install(request: Request):
    """Trigger either silent Inno Setup upgrade (desktop .exe) or git pull (local source checkout)."""
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not is_loopback_request(request):
        raise HTTPException(status_code=403, detail="Self-update is only allowed from local sessions.")

    try:
        return download_and_trigger_install()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
