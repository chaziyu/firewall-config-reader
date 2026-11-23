"""
backend/routes/tsf_api.py
JSON & download endpoints for the TSF Explorer.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse

from backend.auth import is_authenticated
from backend.session_store import store
from tsf.file_preview import human_size, page_containing_line, preview_file
from tsf.indexer import IndexState, get_index, list_dir, search_content, search_filenames

router = APIRouter(prefix="/api/tsf")


def _require_tsf_index(request: Request) -> IndexState:
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    if sess is None or not sess.tsf_session_id:
        raise HTTPException(status_code=404, detail="No active TSF session.")
    idx = get_index(sess.tsf_session_id)
    if idx is None:
        raise HTTPException(status_code=404, detail="TSF index expired or not found.")
    return idx


@router.get("/status")
async def tsf_status(request: Request):
    idx = _require_tsf_index(request)
    return {
        "total_files": len(idx.file_index),
        "content_ready": idx.content_ready,
        "content_progress": idx.content_progress,
        "content_error": idx.content_error,
    }


@router.get("/tree")
async def tsf_tree(request: Request, path: str = Query(default="")):
    idx = _require_tsf_index(request)
    dirs, files = list_dir(idx, path)
    return {
        "path": path,
        "dirs": dirs,
        "files": [
            {
                "rel_path": f.rel_path,
                "name": f.name,
                "size_bytes": f.size_bytes,
                "size_human": human_size(f.size_bytes),
                "is_text": f.is_text,
            }
            for f in files
        ],
    }


@router.get("/file")
async def tsf_file(
    request: Request,
    path: str = Query(...),
    page: int = Query(default=0, ge=0),
    jump_line: int = Query(default=0, ge=0),
):
    idx = _require_tsf_index(request)
    entry = idx.file_index.get(path)
    if entry is None:
        raise HTTPException(status_code=404, detail="File not found in TSF archive.")

    res = preview_file(entry.abs_path)
    if not res.success:
        return {
            "success": False,
            "rel_path": entry.rel_path,
            "is_binary": res.is_binary,
            "error": res.error,
            "size_human": human_size(entry.size_bytes),
        }

    target_page = page_containing_line(res, jump_line) if jump_line > 0 else page
    target_page = max(0, min(target_page, max(0, res.total_pages - 1)))
    lines = res.pages[target_page] if res.pages else []

    return {
        "success": True,
        "rel_path": entry.rel_path,
        "size_human": human_size(res.file_size_bytes),
        "truncated": res.truncated,
        "total_lines": res.total_lines,
        "total_pages": res.total_pages,
        "page": target_page,
        "lines": [[ln, txt] for ln, txt in lines],
    }


@router.get("/search")
async def tsf_search(
    request: Request,
    mode: str = Query(default="filename"),
    q: str = Query(default=""),
):
    idx = _require_tsf_index(request)
    query = q.strip()
    if not query:
        return {"mode": mode, "results": []}

    if mode == "content":
        matches = search_content(idx, query, max_results=300)
        return {
            "mode": "content",
            "results": [
                {
                    "rel_path": m.rel_path,
                    "line_number": m.line_number,
                    "line_text": m.line_text,
                }
                for m in matches
            ],
        }

    files = search_filenames(idx, query)[:300]
    return {
        "mode": "filename",
        "results": [
            {
                "rel_path": f.rel_path,
                "name": f.name,
                "size_human": human_size(f.size_bytes),
            }
            for f in files
        ],
    }


@router.get("/download")
async def tsf_download(request: Request, path: str = Query(...)):
    idx = _require_tsf_index(request)
    entry = idx.file_index.get(path)
    if entry is None or not entry.abs_path.exists():
        raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(path=str(entry.abs_path), filename=entry.name)
