# Firewall Config Reader

**Offline-first firewall configuration analyzer, policy simulator, Tech Support File (TSF) explorer, and AI config assistant for Palo Alto Networks (PAN-OS) and Fortinet FortiGate (FortiOS).**

Built with **FastAPI**, **Jinja2**, and **Vanilla JS/CSS** — with instant browser access, one-click local startup, and standalone Windows desktop packaging via **PyInstaller + pywebview + Inno Setup**.

🌐 **Live Web App:** **[Firewall Config Reader](https://firewall-config-reader-e7hs.onrender.com/)**  
💻 **Windows Desktop App:** **[Download Latest Installer (`.exe`) & Portable ZIP](https://github.com/chaziyu/firewall-config-reader/releases/latest)**

---

## Key Features

### 1. Palo Alto Networks (PAN-OS `.xml`)
* **Dashboard**: Appliance identity, management IPv4/IPv6 settings, software version, and High Availability (Active-Passive / Active-Active) cluster overview.
* **Policies & Traffic Match Simulator**:
  * Interactive **Policy Match Tester** supporting 5-tuple + Zone/Interface/User evaluation across **Security**, **NAT**, **PBF**, **Decryption**, **Authentication**, and **DoS** rulebases.
  * Full inspection of Security, NAT, QoS, PBF, Decryption, Tunnel Inspection, App Override, Authentication, DoS Protection, and SD-WAN rulebases with color-coded indicators (`Enabled`, `Disabled`, `Panorama-pushed`).
* **Objects**: Addresses, Address Groups, Application Groups, Services, Service Groups, Tags, Regions, Dynamic User Groups, Devices, GlobalProtect HIP Objects/Profiles, External Dynamic Lists (EDL), Custom Objects (Data Patterns, Spyware, Vulnerability, URL Categories), Security Profiles & Groups, Log Forwarding, Authentication, Decryption Profiles, SD-WAN Link Management, and Schedules.
* **Network**: Ethernet / Aggregate / Sub-Interfaces, VLANs, Loopbacks, Tunnels, SD-WAN, Zones, Virtual Wires, Virtual Routers (Static Routes, Admin Distances, ECMP, BGP), IPSec & GRE Tunnels, DHCP Servers/Relays, DNS Proxy, GlobalProtect Portals/Gateways/MDM/Clientless, QoS, and Network Profiles.
* **Device**: General Setup, Management Interface & Services, Service Routes, Panorama, High Availability (Election, Link/Path Monitoring), Administrators, Admin Roles, Auth Profiles (RADIUS, LDAP, TACACS+, Kerberos, SAML, MFA), Certificates, Server Profiles, Log Settings, Session Timeouts, and User-ID.

### 2. Fortinet FortiGate (FortiOS `.conf` / `.txt` / `.cfg`)
* **Summary**: Hostname, Serial Number, Firmware Version, WAN IP/Netmask, Primary/Secondary DNS, and HA cluster status.
* **Interfaces**: Hierarchical interface tree with visual row indicators for **Zones (muted)**, **Hardware / Aggregate Switches (blue)**, **Sub-interfaces / VLANs (purple)**, and **Disabled interfaces (red)**.
* **Network**: IPAM, FortiExtender, SD-WAN (Zones, Members, Rules, Performance SLA), Static Routes, Policy Routes, RIP, OSPF, BGP, Routing Objects (Prefix Lists, Route Maps, AS Path Lists), and Multicast (PIM).
* **Policy & Objects + Policy Lookup Simulator**:
  * Interactive top-to-bottom **Policy Lookup Simulator** evaluating Source/Destination Interface, Source/Destination IP/CIDR/Object, and Protocol/Service with implicit deny detection.
  * Firewall Policies, Proxy Policies, Auth Rules, Addresses (Subnet, IP Range, FQDN, Interface Subnet, Address Groups, Host Regex), Services, Schedules, Virtual IPs (VIP/DNAT), IP Pools, Protocol Options, Traffic Shaping, Virtual Servers, and Health Checks.
* **Security Profiles**: Antivirus, Web Filter, DNS Filter, Application Control, IPS, File Filter, Email Filter, VoIP, WAF, SSL Inspection, Web Rating Overrides, and Web Profile Overrides.
* **VPN**: IPSec Phase 1 & Phase 2 Selectors, IPSec Concentrators, SSL-VPN Portals, SSL-VPN Settings, and SSL-VPN Clients.
* **User & Auth**: Local Users, User Groups, Guest Management, LDAP Servers, RADIUS Servers, FSSO, FortiTokens, and Auth Portal Settings.
* **WiFi & Switch**: Managed FortiAPs, SSIDs, FortiAP Profiles, WIDS Profiles, Managed FortiSwitches, Port Policies, and NAC Policies.
* **System & Logs**: Administrators (`super_admin` highlighting), Admin Profiles, System Settings, High Availability, SNMP, Global/Local Log Settings, and Threat Weight scores.

### 3. Tech Support File (TSF) Explorer (`.zip` / `.tgz` / `.tar.gz`)
* **Hardened Archive Extraction**: Screens against path traversal (Zip Slip), symlink escapes, deep nesting (>20 levels), oversized files, password-protected archives, and executable binaries (`.exe`, `.dll`, `.elf`, shell/PHP scripts).
* **Instant Filename & Full-Text Search**: Lazy directory tree browser, instant filename filter, background full-text content indexing with line-level jump-to-match preview, and raw file download.

### 4. Floating AI Config Assistant (`gemini-flash-lite-latest`)
* Context-aware firewall assistant grounded strictly on the active configuration summary (up to 250,000 characters / 500 rules per table).
* Built-in **🔑 API Key Drawer** in the chat header: keys entered in the UI are stored **strictly in per-session RAM** (never written to disk or shared across sessions).
* Supports Compact, Expanded, and centered Overlay modes with XSS-safe Markdown rendering.

---

## Project Architecture

```text
firewall-config-reader/
├── server.py                     # FastAPI application factory & Uvicorn entrypoint
├── Start Local.bat               # One-click Windows local server + browser launcher
├── Build Desktop App.bat         # PyInstaller + Inno Setup Windows desktop builder
├── requirements.txt              # Runtime Python dependencies
├── backend/
│   ├── __init__.py
│   ├── auth.py                   # Optional password authentication (FW_PASSWORD)
│   ├── chat_service.py           # Gemini AI config summary builder & prompt engine
│   ├── policy_lookup_service.py  # FortiGate top-down 5-tuple policy match engine
│   ├── session_store.py          # In-memory LRU session store & SHA-256 parser cache
│   ├── upload_service.py         # Upload filename, size, XXE, and magic-byte validation
│   ├── routes/
│   │   ├── chat_api.py           # GET/POST/DELETE /api/chat & POST /api/chat/key
│   │   ├── config_api.py         # GET /api/pa/{section}, /api/fg/{section}, policy matchers
│   │   ├── pages.py              # HTML routes: /, /login, /workspace, /tsf, /health
│   │   ├── tsf_api.py            # TSF tree, search, file preview, and download APIs
│   │   └── upload.py             # POST /api/upload, TSF progress polling, session reset
│   └── view_models/
│       ├── fortigate.py          # Declarative UI block builders for 10 FortiGate sections
│       └── paloalto.py           # Declarative UI block builders for 5 Palo Alto sections
├── parsers/
│   ├── __init__.py               # Top-level parser exports
│   ├── base.py                   # Abstract BaseFirewallParser
│   ├── fortigate/                # FortiGate (FortiOS) CLI parser subpackage
│   │   ├── __init__.py
│   │   ├── core.py               # FortiGateParser main class
│   │   ├── bgp.py
│   │   ├── logs.py
│   │   ├── security.py
│   │   ├── system.py
│   │   ├── user.py
│   │   ├── vpn.py
│   │   └── wifi.py
│   └── paloalto/                 # Palo Alto (PAN-OS) XML parser subpackage
│       ├── __init__.py
│       ├── base.py               # PaloAltoParser base class & XML helpers
│       ├── dashboard.py
│       ├── device.py
│       ├── network.py
│       ├── objects.py
│       └── policies.py
├── tsf/
│   ├── extractor.py              # Hardened TSF ZIP/TGZ validator & extractor
│   ├── file_preview.py           # Paginated text preview & binary detection
│   ├── indexer.py                # Directory tree & background full-text search indexer
│   └── search.py                 # Search helpers
├── templates/
│   ├── base.html                 # Shared shell, theme script, and CSS imports
│   ├── landing.html              # Upload dropzone & vendor cards
│   ├── login.html                # Password authentication gate
│   ├── tsf.html                  # TSF split-pane explorer
│   └── workspace.html            # Main firewall config workspace & floating AI chatbox
├── static/
│   ├── css/
│   │   ├── theme.css             # Dark & Light mode color tokens and row highlight palette
│   │   ├── app.css               # Layout, cards, tabs, tables, legend pills, badges
│   │   ├── chat.css              # Floating AI chatbox & API key drawer styles
│   │   └── tsf.css               # TSF split-pane tree and code viewer styles
│   └── js/
│       ├── theme.js              # Dark/Light theme toggle & sidebar collapse
│       ├── upload.js             # Drag-and-drop upload & TSF extraction progress bar
│       ├── workspace.js          # Declarative JSON block renderer & policy simulators
│       ├── table.js              # Searchable, sortable, filterable table + CSV exporter
│       ├── chat.js               # Floating AI assistant + XSS-safe Markdown renderer
│       └── tsf.js                # TSF tree browser, search, and line-jump viewer
├── scripts/
│   ├── desktop_launcher.py       # Native desktop window launcher (pywebview + Uvicorn)
│   ├── assets/                   # Application icon (app.ico) and splash screen
│   └── installer/
│       └── FirewallConfigReader.iss  # Inno Setup 6 Windows installer script
└── tests/
    └── test_app.py               # End-to-end FastAPI test suite
```

---

## Quick Start

### Option 1: Instant Online Web App (No Installation Required)
Open **[Firewall Config Reader](https://firewall-config-reader-e7hs.onrender.com/)** directly in your browser.
* Uploaded `.xml` and `.conf` files are sanitized (`[REDACTED]` credentials) and held strictly in ephemeral compressed RAM for your session only.
* To use the AI Config Assistant online, click the **🔑 key icon** in the chatbox to enter your own Gemini API key for your session.
* *(Tip: For large 100–500 MB TSF `.zip` archives or 100% air-gapped offline auditing, use the Windows Desktop App or Local Run below).*

### Option 2: Windows Desktop Installer (`.exe`)
Download and run **`FirewallConfigReader-Setup-<version>.exe`** from **[GitHub Releases](https://github.com/chaziyu/firewall-config-reader/releases/latest)**.
* Runs 100% locally in a native desktop window with zero Python setup required.
* Includes a built-in **Auto-Update Checker** in the sidebar footer to download, verify (SHA-256), and install new releases in one click.

### Option 3: One-Click Local Run from Source (Windows)
Double-click **`Start Local.bat`** (or run it from a terminal):
```bat
"Start Local.bat"
```
This script automatically creates `.venv` (if missing), installs `requirements.txt`, starts Uvicorn on `http://127.0.0.1:8501/`, and opens your default browser once `/health` reports ready.

### Option 4: Manual Python / Cross-Platform Run
Requires **Python 3.11+**:
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
python server.py
```
Open **`http://127.0.0.1:8501/`** in your browser.

### Option 5: Build Standalone Windows Desktop App & Installer Locally
Double-click **`Build Desktop App.bat`**:
* Produces a standalone `--onedir` desktop bundle at `dist\FirewallConfigReader\FirewallConfigReader.exe`.
* If **Inno Setup 6** (`ISCC.exe`) is installed (`winget install JRSoftware.InnoSetup`), it also compiles a redistributable Windows installer at `dist\FirewallConfigReader-Setup-<version>.exe`.

---

## Configuration & Environment Variables

All environment variables are optional:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `FW_PORT` | `8501` | Local TCP port for Uvicorn (`server.py` / `Start Local.bat`). |
| `FW_PASSWORD` | *(unset)* | When set, enables the `/login` password gate across all pages and APIs (recommended for shared or cloud deployments). |
| `GEMINI_API_KEY` | *(unset)* | Default Gemini API key for **direct local loopback (`127.0.0.1`) sessions only**. Remote/proxied visitors must enter their own session key in the chatbox UI. |
| `GEMINI_MODEL` | `gemini-flash-lite-latest` | Gemini model ID used by the AI Config Assistant. |
| `TSF_SESSIONS_DIR` | `%TEMP%/tsf_sessions` | Temporary directory used for extracted TSF archives. |

---

## Security & Data Privacy Design

1. **Three-Layer In-Memory Config Protection (Zero Disk Persistence)**:
   * **Layer 1 — Immediate Secret Redaction on Upload**: Before uploaded config bytes are hashed, parsed, or stored in RAM, `sanitize_config_bytes()` (`backend/upload_service.py`) automatically scrubs sensitive cryptographic fields to `[REDACTED]`:
     * **FortiGate**: `set password`, `set passwd`, `set psksecret`, `set secret`, `set key`, `set auth-password-l1/l2`, and `set private-key`.
     * **Palo Alto**: `<phash>`, `<private-key>`, `<psk>`, `<secret>`, `<bind-password>`, `<key>`, `<password>`, `<auth-password>`, and `<priv-password>`.
     * This ensures password hashes, VPN pre-shared keys, and private keys never sit in memory and can never be leaked to the Gemini AI assistant.
   * **Layer 2 — Compressed & Ephemeral Key-Sealed RAM Storage**:
     * Uploaded configs are **never written to disk** and are **never kept as raw plain-text bytes** in `SessionData`.
     * `sess.raw_content` (`backend/session_store.py`) transparently compresses the sanitized config with `zlib` (~90% smaller memory footprint) and XOR-seals the compressed payload using an ephemeral per-session 256-bit random key (`sess._mem_key = secrets.token_bytes(32)`), unsealing only on demand.
     * Clicking **`↑ Load new config`** (or session expiration) immediately wipes `_sealed_content`, rotates `_mem_key` to a new random key, clears chat history, and evicts unreferenced parser cache entries (`evict_parser_cache_if_unreferenced`).
   * **Layer 3 — Deduplicated XML Element Trees**:
     * `PaloAltoParser` (`parsers/paloalto/base.py`) operates directly on the shared `ElementTree` root without serializing duplicate plain-text XML strings across section parsers.
2. **Per-Session RAM-Only API Keys**:
   * Gemini API keys entered via the chatbox 🔑 button are stored only in `sess.gemini_api_key` in RAM for that session ID. They are never saved to disk, never returned in plaintext to the browser (only masked as `AIza...xxxx`), and never shared across sessions.
   * When deployed behind a reverse proxy (e.g., Render, Cloudflare, Nginx where `X-Forwarded-For` is present), server-wide `.env` / `GEMINI_API_KEY` fallback is automatically disabled so every visitor must supply their own session key.
3. **Bounded Memory & Session Eviction**:
   * Active sessions are capped at `MAX_SESSIONS = 24` with a 2-hour idle TTL (`SESSION_TTL_SECONDS`) and automatic LRU eviction to prevent memory exhaustion (OOM) on cloud containers.
4. **Upload & Archive Hardening**:
   * Blocks script payloads, executable binaries, and path-traversal ZIP entries before parsing or extraction.
5. **Cryptographic Session Cookies**:
   * Sessions use 192-bit `secrets.token_urlsafe(24)` tokens stored in `HttpOnly`, `SameSite=Lax` cookies (with `Secure` auto-enabled over HTTPS).

---

## Running Tests

```bash
.venv\Scripts\python.exe -m pytest -v
```
