"""
backend/routes/upload.py
File upload endpoint (/api/upload), TSF extraction progress polling, and session reset.
"""

from __future__ import annotations

import threading

from fastapi import APIRouter, File, HTTPException, Request, Response, UploadFile

from backend.auth import is_authenticated
from backend.session_store import SESSION_COOKIE, TsfJob, sha256_bytes, store
from backend.upload_service import (
    UploadValidationError,
    sanitize_config_bytes,
    validate_content,
    validate_filename,
    validate_structure,
)
from tsf.extractor import cleanup_old_sessions, validate_and_extract
from tsf.indexer import build_file_index, start_content_indexing

router = APIRouter(prefix="/api")


def _run_tsf_extraction(job: TsfJob, zip_bytes: bytes) -> None:
    try:
        cleanup_old_sessions(max_age_hours=6)

        def _on_progress(frac: float, msg: str) -> None:
            job.progress = max(0.0, min(0.9, frac * 0.9))
            job.message = msg

        result = validate_and_extract(zip_bytes, progress_cb=_on_progress)
        if not result.success:
            job.status = "error"
            job.error = result.error or "Extraction failed."
            return

        job.progress = 0.94
        job.message = "Indexing directory structure..."
        build_file_index(result.session_id, result.session_path)
        start_content_indexing(result.session_id)

        sess = store.get_by_id(job.session_id)
        if sess is not None:
            sess.reset_config()
            sess.reset_tsf()
            sess.tsf_session_id = result.session_id
            sess.tsf_filename = job.filename
            sess.vendor = "TSF"
            sess.filename = job.filename

        job.tsf_session_id = result.session_id
        job.total_files = result.total_files
        job.skipped = result.skipped[:200]
        job.progress = 1.0
        job.message = f"Extracted {result.total_files:,} files."
        job.status = "done"
    except Exception as exc:
        job.status = "error"
        job.error = str(exc)


@router.post("/upload")
async def upload_file(request: Request, response: Response, file: UploadFile = File(...)):
    sess = store.get_or_create(request, response)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")

    filename = file.filename or "upload"
    try:
        ext, is_tsf = validate_filename(filename)
        content = await file.read()
        validate_content(content, is_tsf)
        validate_structure(content, ext)
    except UploadValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if is_tsf:
        job = store.create_tsf_job(sess.session_id, filename)
        t = threading.Thread(target=_run_tsf_extraction, args=(job, content), daemon=True)
        t.start()
        return {"type": "tsf", "job_id": job.job_id, "filename": filename}

    # Palo Alto XML or FortiGate CLI config
    vendor = "Palo Alto" if ext == ".xml" else "FortiGate"
    # Immediately scrub password hashes, PSKs, and private keys before hashing, caching, or storing in RAM
    content = sanitize_config_bytes(content, vendor)
    content_hash = sha256_bytes(content)

    try:
        if vendor == "Palo Alto":
            store.get_palo_alto_parsers(content_hash, content)
        else:
            store.get_fortigate_parser(content_hash, content)
    except UploadValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse {vendor} config: {exc}") from exc

    sess.reset_tsf()
    sess.reset_config()
    sess.raw_content = content
    sess.content_hash = content_hash
    sess.filename = filename
    sess.vendor = vendor

    return {"type": "config", "vendor": vendor, "filename": filename, "redirect": "/workspace"}


@router.get("/tsf/progress/{job_id}")
async def tsf_progress(job_id: str, request: Request):
    sess = store.get_existing(request)
    if not is_authenticated(sess):
        raise HTTPException(status_code=401, detail="Authentication required.")
    job = store.get_tsf_job(job_id)
    if job is None or (sess is not None and job.session_id != sess.session_id):
        raise HTTPException(status_code=404, detail="Extraction job not found.")
    return {
        "status": job.status,
        "progress": job.progress,
        "message": job.message,
        "error": job.error,
        "total_files": job.total_files,
        "skipped_count": len(job.skipped),
    }


@router.post("/session/reset")
async def reset_session(request: Request):
    sess = store.get_existing(request)
    if sess is not None:
        sess.reset_config()
        sess.reset_tsf()
    return {"ok": True}
