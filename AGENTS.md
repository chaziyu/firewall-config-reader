# AGENTS.md — AI Coding Agent Guide

This document provides architectural context, conventions, and guardrails for AI coding agents working on **Firewall Config Reader**.

---

## 1. System Overview & Tech Stack

* **Backend**: Python 3.11+, **FastAPI**, **Uvicorn**, **Jinja2** templates (`server.py`, `backend/`).
* **Frontend**: Server-rendered HTML shells (`templates/*.html`) + declarative JSON block rendering in Vanilla JavaScript (`static/js/*.js`) + CSS custom-property theming (`static/css/*.css`). **No Streamlit, React, or bundler step is used.**
* **AI Assistant**: Google GenAI SDK (`google-genai`) calling `gemini-flash-lite-latest` (`backend/chat_service.py`).
* **Desktop Packaging**: `scripts/desktop_launcher.py` spawns Uvicorn on a local loopback port and wraps it in a native `pywebview` window, packaged via PyInstaller (`Build Desktop App.bat`) and Inno Setup (`scripts/installer/FirewallConfigReader.iss`).

---

## 2. Repository Map

* `server.py`: FastAPI app factory (`create_app()`) and lifespan cleanup (`store.cleanup_all()`).
* `backend/session_store.py`:
  * Thread-safe in-memory `SessionStore` (`store`) managing `SessionData` keyed by the `fw_session_id` `HttpOnly` cookie.
  * Caches parsed vendor objects by SHA-256 hash (`get_palo_alto_parsers`, `get_fortigate_parser`) and evicts unreferenced cache entries on `reset_config()` / `clear_all()`.
  * Enforces `MAX_SESSIONS = 24` (LRU eviction) and `SESSION_TTL_SECONDS = 7200`.
* `backend/routes/`:
  * `pages.py`: HTML routes (`/`, `/login`, `/workspace`, `/tsf`, `/health`).
  * `upload.py`: `POST /api/upload`, `GET /api/tsf/progress/{job_id}`, `POST /api/session/reset`.
  * `config_api.py`: `GET /api/pa/{section}`, `POST /api/pa/policy-test`, `GET /api/fg/{section}`, `POST /api/fg/policy-lookup`.
  * `tsf_api.py`: `GET /api/tsf/tree`, `GET /api/tsf/search`, `GET /api/tsf/file`, `GET /api/tsf/download`.
  * `chat_api.py`: `GET /api/chat`, `POST /api/chat`, `DELETE /api/chat`, `POST /api/chat/key`.
* `backend/view_models/`:
  * `fortigate.py`: Builds declarative UI block trees for all 10 FortiGate sections.
  * `paloalto.py`: Builds declarative UI block trees for all 5 Palo Alto sections.
* `parsers/`:
  * `base.py`: `BaseFirewallParser` abstract class.
  * `fortigate/`: FortiOS CLI parsers (`core.py` defines `FortiGateParser`, inheriting mixins from `security.py`, `vpn.py`, `user.py`, `wifi.py`, `system.py`, plus `bgp.py` and `logs.py`).
  * `paloalto/`: PAN-OS XML parsers (`base.py` defines `PaloAltoParser` and XML helpers; section subclasses live in `dashboard.py`, `policies.py`, `objects.py`, `network.py`, `device.py`).
* `tsf/`: Hardened archive extraction (`extractor.py`), background indexing (`indexer.py`), and paginated file preview (`file_preview.py`).

---

## 3. Declarative UI Block Protocol (`view_models` → `workspace.js` / `table.js`)

Backend view models (`backend/view_models/fortigate.py` and `paloalto.py`) must return JSON-serializable block dictionaries rendered by `static/js/workspace.js` and `static/js/table.js`:

* **`hero`**: `{ "type": "hero", "eyebrow": str, "title": str, "subtitle": str, "badges": [{"text": str, "variant": str}] }`
* **`section_header`**: `{ "type": "section_header", "title": str }`
* **`kv_grid`**: `{ "type": "kv_grid", "items": [{"label": str, "value": str, "sub": str}] }`
* **`badge_grid`**: `{ "type": "badge_grid", "items": [{"label": str, "value": str, "variant": str}] }`
* **`card`**: `{ "type": "card", "title": str, "subtitle": str, "badge": {...}, "rows": [{"label": str, "value": str, "tone": str}] }`
* **`alert`**: `{ "type": "alert", "variant": "info"|"success"|"warn"|"error", "text": str }`
* **`legend`**: `{ "type": "legend", "items": [{"label": str, "variant": "muted"|"info"|"purple"|"danger"|"warn"|"success"|"default"}] }`
* **`table`**: Built via `_table_block(...)`. Supports `columns`, `rows`, `row_classes`, `caption`, `export_filename`, `filter_col`, and `legend`.
  * **Mandatory UX Rule**: Whenever a table uses `row_class_fn` to color-code rows (`row-danger`, `row-warn`, `row-success`, `row-info`, `row-purple`, `row-muted`, `row-zone`, `row-sub`), you **must** supply a matching `legend` list on `_table_block(...)` (or a preceding `legend` block) so users can understand what each color represents.
* **`tabs`**: `{ "type": "tabs", "id": str, "tabs": [{"label": str, "blocks": [...]}] }` (lazy-rendered on tab click).
* **`expander`**: `{ "type": "expander", "title": str, "open": bool, "blocks": [...] }`.
* **`profile_selector`**: Dropdown switcher that renders child blocks for the selected profile.

---

## 4. Critical Engineering & Security Rules

1. **XML `ElementTree` Truthiness (Python 3.12+)**:
   * **NEVER** write `if elem:` or `elem.find(...) if elem else None` on `xml.etree.ElementTree.Element` objects. Empty XML elements evaluate to `False` in boolean context and trigger `DeprecationWarning`.
   * **ALWAYS** use explicit identity checks: `if elem is not None:`.
2. **Zero Disk Persistence for Configs & User API Keys**:
   * Never write uploaded `.xml` or `.conf` files to disk. Keep them in `SessionData.raw_content` (RAM) and evict parser caches when `reset_config()` is called.
   * Never persist user-supplied Gemini API keys to disk. Keep them strictly in `sess.gemini_api_key` (per-session RAM).
   * Server environment `GEMINI_API_KEY` / `.env` fallback must only be enabled when `is_loopback_request(request)` is `True` (no `X-Forwarded-For` / `X-Real-IP` proxy headers).
3. **FastAPI Event Loop Non-Blocking I/O**:
   * Routes performing synchronous blocking network or CPU-heavy calls (such as `chat_ask` calling `client.models.generate_content`) must be defined with synchronous `def` (so FastAPI runs them in a worker threadpool) rather than `async def`.
4. **XSS Safety in Frontend JS**:
   * Always use `textContent` when inserting untrusted config values into DOM elements in `workspace.js` and `table.js`.
   * In `chat.js`, always pass text through `escapeHtml()` before applying inline Markdown transformations in `renderMarkdownSafe()`.

---

## 5. Verification & Testing Workflow

After making changes, always run both the test suite and the startup import check:

```powershell
.venv\Scripts\python.exe -m pytest -v ; .venv\Scripts\python.exe -c "import fastapi, uvicorn, jinja2, multipart, parsers.fortigate, parsers.paloalto, tsf.extractor, server; print('Startup import check OK')"
```

* All tests in `tests/test_app.py` must pass with zero `ElementTree` deprecation warnings.
* Note: If you add or rename top-level packages, ensure `Start Local.bat` and `Build Desktop App.bat` (`PYINSTALLER_ARGS`) remain in sync.
