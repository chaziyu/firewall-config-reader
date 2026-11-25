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

* `server.py`: FastAPI app factory (`create_app()`), security middleware (`Host`/`Origin` validation, `no-store` cache headers, security headers), and lifespan cleanup (`store.cleanup_all()`).
* `backend/session_store.py`:
  * Thread-safe in-memory `SessionStore` (`store`) managing `SessionData` keyed by the `fw_session_id` `HttpOnly` cookie.
  * Seals sanitized config bytes in RAM (`zlib` + ephemeral per-session 256-bit XOR key), caches parsed vendor objects by SHA-256 hash (`get_palo_alto_parsers`, `get_fortigate_parser`), and evicts unreferenced cache entries on `reset_config()` / `clear_all()`.
  * Enforces `MAX_SESSIONS = 24` (4 in desktop mode), `PARSER_CACHE_MAX = 16` (2 in desktop mode), and `SESSION_TTL_SECONDS = 1800` (30 min default, configurable via `FW_SESSION_TTL_SECONDS`).
* `backend/routes/`:
  * `pages.py`: HTML routes (`/`, `/login`, `/workspace`, `/tsf`, `/health`) and unified sidebar page lists (10 Palo Alto sections, 11 FortiGate sections).
  * `upload.py`: `POST /api/upload`, `GET /api/tsf/progress/{job_id}`, `POST /api/session/reset`.
  * `config_api.py`: Section view endpoints (`GET /api/pa/{section}`, `GET /api/fg/{section}`), lifecycle (`GET /api/{pa|fg}/lifecycle`), interactive simulators & analyzers (`policy-test`, `policy-lookup`, `route-lookup`, `where-used`, `exposure-probe`, `config-diff`, `packet-trace`), and exports (`GET /api/export/report`, `GET /api/export/excel`).
  * `tsf_api.py`: `GET /api/tsf/tree`, `GET /api/tsf/search`, `GET /api/tsf/file`, `GET /api/tsf/download`.
  * `chat_api.py`: `GET /api/chat`, `POST /api/chat`, `DELETE /api/chat`, `POST /api/chat/key`.
  * `update_api.py`: Desktop app auto-update check and installer download/verification endpoints.
* `backend/*_service.py` & `backend/excel_export.py` & `backend/exposure_check.py`: Domain services for audit, certificate inspection, config diff, Excel export, exposure checks, hygiene, lifecycle, packet trace, PM checklist (`pm_checklist_service.py`), policy/route lookup, posture, HTML audit report, SSL-to-IPSec migration, auto-update, upload sanitization, VPN inspector, and where-used search.
* `backend/view_models/`:
  * `common.py`: Shared table/block helpers (`_table_block`, etc.).
  * `fortigate.py`: Declarative UI block builders for all 11 FortiGate sections.
  * `paloalto.py`: Declarative UI block builders for all 10 Palo Alto sections.
* `parsers/`:
  * `base.py`: `BaseFirewallParser` abstract class.
  * `fortigate/`: FortiOS CLI parsers (`core.py` defines `FortiGateParser`, inheriting mixins from `security.py`, `vpn.py`, `user.py`, `wifi.py`, `system.py`, plus `bgp.py` and `logs.py`).
  * `paloalto/`: PAN-OS XML parsers (`base.py` defines `PaloAltoParser` and XML helpers; section subclasses live in `dashboard.py`, `policies.py`, `objects.py`, `network.py`, `device.py`).
* `tsf/`: Hardened archive extraction (`extractor.py`), background indexing (`indexer.py`), search (`search.py`), and paginated file preview (`file_preview.py`).
* `data/`: Bundled offline lifecycle JSON catalogs (`fortigate_lifecycle.json`, `paloalto_lifecycle.json`) and CLI reference docs.

---

## 3. Declarative UI Block Protocol (`view_models` → `workspace.js` / `table.js`)

Backend view models (`backend/view_models/fortigate.py` and `paloalto.py`) must return JSON-serializable block dictionaries rendered by `static/js/workspace.js` and `static/js/table.js`:

* **Display blocks**: `hero`, `section_header`, `kv_grid`, `badge_grid`, `card`, `alert`, `legend`, `code_block`.
* **Container blocks**: `tabs` (lazy-rendered on tab click), `expander`, `profile_selector`.
* **Data table**: `table` built via `_table_block(...)` (`columns`, `rows`, `row_classes`, `caption`, `export_filename`, `filter_col`, `legend`).
  * **Mandatory UX Rule**: Whenever a table uses `row_class_fn` to color-code rows (`row-danger`, `row-warn`, `row-success`, `row-info`, `row-purple`, `row-muted`, `row-zone`, `row-sub`), you **must** supply a matching `legend` list on `_table_block(...)` (or a preceding `legend` block) so users can understand what each color represents.
* **Interactive tool blocks**: `pa_policy_test`, `fg_policy_lookup`, `route_lookup`, `where_used_lookup`, `config_diff`, `packet_trace`.

---

## 4. Critical Engineering & Security Rules

1. **XML `ElementTree` Truthiness (Python 3.12+)**:
   * **NEVER** write `if elem:` or `elem.find(...) if elem else None` on `xml.etree.ElementTree.Element` objects. Empty XML elements evaluate to `False` in boolean context and trigger `DeprecationWarning`.
   * **ALWAYS** use explicit identity checks: `if elem is not None:`.
2. **Secret Redaction & Zero Disk Persistence**:
   * Uploaded `.xml` / `.conf` / `.txt` files must pass through `sanitize_config_bytes()` (`backend/upload_service.py`) before hashing, parsing, or storing in RAM.
   * Never write uploaded configs or user-supplied Gemini API keys to disk, logs, or error responses. Keep configs sealed in `SessionData.raw_content` and keys strictly in `sess.gemini_api_key` (per-session RAM).
3. **Loopback-Only Privileged Actions**:
   * Server environment `GEMINI_API_KEY` / `.env` fallback, live reachability probes (`/api/*/exposure-probe`), and desktop auto-update actions must only be enabled when `is_loopback_request(request)` is `True` (direct `127.0.0.1`/`::1`/`localhost` with no `X-Forwarded-For` / `X-Real-IP` headers).
4. **Security Middleware Invariants (`server.py`)**:
   * Preserve loopback `Host` and `Origin` validation (anti-DNS-rebinding & CSRF) and `Cache-Control: no-store` on all non-static responses.
5. **FastAPI Event Loop Non-Blocking I/O**:
   * Routes performing synchronous blocking network or CPU-heavy calls (such as `chat_ask`, `lifecycle` checks, `exposure-probe`, or Excel/report generation) must be defined with synchronous `def` (so FastAPI runs them in a worker threadpool) rather than `async def`.
6. **Offline / Air-Gapped Safety**:
   * Any outbound HTTP request (e.g., `lifecycle_service.py`, `update_service.py`) must use short timeouts, degrade gracefully on failure, and (for lifecycle checks) respect `DISABLE_ONLINE_CHECKS=1`.
7. **AI Chatbox Hardening (`chat_service.py` / `chat_api.py`)**:
   * Keep `config_summary` framed strictly as untrusted data (prompt-injection defense), sanitize filenames before prompt interpolation, enforce `sess.chat_lock` + `GEMINI_TIMEOUT_MS`, and map SDK/HTTP errors to safe user-facing messages without leaking raw internals.
8. **XSS Safety in Frontend JS**:
   * Always use `textContent` when inserting untrusted config values into DOM elements in `workspace.js` and `table.js`.
   * In `chat.js`, always pass text through `escapeHtml()` before applying inline Markdown transformations in `renderMarkdownSafe()`.

---

## 5. Release, Packaging & Verification Checklist

* **Version Bump Sync**: When bumping `APP_VERSION`, update **all 8 locations** together:
  1. `server.py` (`version="..."`)
  2. `Build Desktop App.bat` (`APP_VERSION=...`)
  3. `backend/update_service.py` (`APP_VERSION = ...`)
  4. `backend/lifecycle_service.py` (`_USER_AGENT = ...`)
  5. `scripts/installer/FirewallConfigReader.iss` (`#define AppVersion ...`)
  6. `templates/landing.html`, `templates/workspace.html`, `templates/tsf.html` (`.fw-sidebar-version`)
* **Packaging Sync**: If you add or rename top-level packages or bundled data folders (e.g., `data/`, `assets/`), keep `Start Local.bat` and `Build Desktop App.bat` (`PYINSTALLER_ARGS` `--add-data` / `--collect-submodules`) in sync.
* **Verification Command**: After making changes, always run both the test suite and the startup import check:

```powershell
.venv\Scripts\python.exe -m pytest -v ; .venv\Scripts\python.exe -c "import fastapi, uvicorn, jinja2, multipart, parsers.fortigate, parsers.paloalto, tsf.extractor, server; print('Startup import check OK')"
```

* All tests in `tests/` (`tests/test_*.py`) must pass with zero `ElementTree` deprecation warnings.
