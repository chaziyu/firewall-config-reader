# Firewall Config Reader

**Offline-first firewall configuration analyzer, traffic simulator, security auditor, Tech Support File (TSF) explorer, and AI config assistant for Palo Alto Networks (PAN-OS) and Fortinet FortiGate (FortiOS).**

Designed for network and security engineers to audit, troubleshoot, compare, and document firewall configs quickly — without needing console access to the live appliance.

🌐 **Live Web App:** **[Open Firewall Config Reader](https://firewall-config-reader-e7hs.onrender.com/)**  
💻 **Windows Desktop App:** **[Download Latest Installer (`.exe`) & Portable ZIP](https://github.com/chaziyu/firewall-config-reader/releases/latest)**

---

## Supported Files

| Platform / Input | File Format | Max Size | What It Opens |
| :--- | :--- | :--- | :--- |
| **Palo Alto Networks (PAN-OS 10.x+)** | `.xml` | 50 MB | Full Config Workspace + Simulators & Audits |
| **Fortinet FortiGate (FortiOS 6.x / 7.x)** | `.conf`, `.txt` | 50 MB | Full Config Workspace + Simulators & Audits |
| **Palo Alto Tech Support File (TSF)** | `.zip` | 500 MB | Split-Pane TSF Tree & Full-Text Log Explorer |

---

## Core Capabilities

### 🔍 Troubleshoot & Simulate Traffic
* **End-to-End Packet Flow Simulator (`Trace Packet`)**: Trace a packet step-by-step through RPF, DNAT/VIP, Longest-Prefix-Match routing, Security Policy evaluation, and SNAT/IP Pool translation.
* **Policy Match / Policy Lookup Simulator**: Test 5-tuple traffic (zones/interfaces, source/destination IP or object, port/protocol, user) with top-down first-match evaluation, shadowed-rule awareness, and implicit deny detection.
* **Longest-Prefix-Match (LPM) Route Lookup**: Quickly verify which static route or Virtual Router entry wins for any destination IP.
* **Global Quick Search (`Ctrl+K`) & "Where-Used" Lookup**: Search any IP, CIDR subnet, address object, VIP, or interface from anywhere in the workspace to see every policy, NAT rule, route, VPN, and interface referencing it.

### 🩺 Audit Security, Health & Lifecycle
* **Preventive Maintenance (PM) Lookup**: Automatically evaluates backup-config verifiable PM checks for FortiGate and Palo Alto — firmware/EoS/FFR, timezone (GMT+8) & NTP, log managers (FortiAnalyzer/FortiCloud/Syslog), interfaces, routing, VPN, HA, management access, and dynamic 90-day PAN-OS log filter — in a color-coded, filterable table exportable to CSV and Excel.
* **Hardware & Firmware Lifecycle Checker**: Automatically checks FortiGate hardware EoS, last supported firmware, and FortiOS / PAN-OS branch EoL/EoS dates and latest available patches (works online with a bundled offline fallback for air-gapped environments).
* **Public Management & VIP Exposure Check**: Flags publicly exposed management interfaces, VIPs, and WAN-behind-NAT risks with severity grading. When running locally, includes an optional **live TCP/TLS/SSH reachability probe**.
* **Quick Security Audit**: Automatically flags overly broad `any → any` / `all → ALL` allow rules, rules missing security profiles or logging, weak VPN crypto/DH groups, unused addresses, and disabled rules.
* **Certificate Expiry Inspector**: Parses embedded X.509 PEM certificates (CN, SAN, issuer, validity dates) and highlights expired or expiring-soon certificates.
* **Cleanup & Hygiene Analyzer**: Finds unused address/service/VIP/IP Pool objects (with draft cleanup CLI for FortiGate), disabled policies, overly broad rules, and expired one-time schedules.
* **Appliance Posture Indicators**: Displays Internet connectivity posture and local hard disk status (e.g., SSD vs. diskless FortiGate) right on the Overview.

### 🔄 Compare, Migrate & Export
* **Firewall-Aware Config Diff**: Upload a second snapshot to compare structural changes across policies, NAT, objects, routes, interfaces, and VPNs — not just raw line diffs.
* **Site-to-Site IPSec VPN Inspector**: Stitches together Phase 1/IKE, Phase 2/IPSec, tunnel interfaces, zones, static routes, and firewall policies into one health view — flagging missing routes/policies, accidental NAT, IKEv1, and weak crypto.
* **FortiGate SSL-VPN → Dial-up IPSec Migration Assistant**: Offline readiness audit (certificates, SAML, Web Mode), GUI/Wizard quick-reference parameters, copyable draft IKEv2 CLI (Phase 1, Phase 2, and cloned `ssl.root` policies), and a FortiClient cutover checklist.
* **One-Click Full Config Excel Export (`.xlsx`)**: Export every parsed section into a clean, multi-sheet Excel workbook (`⬇ Export to Excel` in the top bar). Individual tables also support live search, sorting, column filtering, and **CSV export**.
* **Standalone Audit Report (HTML / Print-to-PDF)**: Generate a shareable security and health summary report in one click (`📄 Audit Report`).

### 📦 Tech Support File (TSF) Explorer
* **Safe, Fast Archive Inspection**: Extracts `.zip` TSF bundles (up to 500 MB) into a split-pane directory tree with built-in security screening against path traversal, symlink escapes, and executable binaries.
* **Filename & Full-Text Search**: Filter files instantly by name (e.g. `mp-log`, `running-config`, `dp-monitor`) or search file contents across the entire archive with line-level jump-to-match preview and raw file download.

### ✨ Floating AI Config Assistant
* Ask natural-language questions about policies, NAT, routing, VPNs, or hardening — grounded strictly on your loaded config (read-only, defensive-only, and prompt-injection hardened).
* Click the **🔑 key icon** in the chat header to paste your own Gemini API key (stored in your session's RAM only).
* Supports Compact, Expanded, and Overlay window sizes, plus Dark and Light themes across the entire app.

---

## Quick Start

### Option 1: Instant Web App (No Installation)
1. Open **[Firewall Config Reader](https://firewall-config-reader-e7hs.onrender.com/)** in your browser.
2. Drag and drop your `.xml`, `.conf`, `.txt`, or `.zip` file.
3. *(Optional)* To use the AI Config Assistant online, click the **✨** button → **🔑** icon and paste your Gemini API key for the current session.

> **Tip:** For large 100–500 MB TSF archives, local live reachability probes, or 100% air-gapped offline audits, use the Windows Desktop App or Local Run below.

### Option 2: Windows Desktop App (Recommended for Daily Use)
1. Download **`FirewallConfigReader-Setup-<version>.exe`** (or the Portable ZIP) from **[GitHub Releases](https://github.com/chaziyu/firewall-config-reader/releases/latest)**.
2. Run the installer and launch **Firewall Config Reader** — runs 100% locally in a native window with zero Python setup.
3. Includes a built-in **Auto-Update Checker** in the sidebar footer to download, SHA-256 verify, and install new releases in one click.

### Option 3: Run Locally from Source
**Windows (One-Click):**
Double-click **`Start Local.bat`** — it automatically creates `.venv`, installs dependencies, starts the local server on `http://127.0.0.1:8501/`, and opens your browser.

**macOS / Linux / Manual Python (Requires Python 3.11+):**
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python server.py
```
Then open **`http://127.0.0.1:8501/`** in your browser.

---

## How to Use It (Engineer Workflow)

### 1. Load a Config
Drag and drop a backup file onto the landing page (or click **Browse files**). The vendor is detected automatically, credentials are redacted on upload, and you are taken straight into the workspace. Click **`↑ Load new config`** in the sidebar footer at any time to wipe the current session and load another file.

### 2. Navigate the Workspace
Both Palo Alto and FortiGate share a unified sidebar layout so you don't have to re-learn the UI between vendors:

| Sidebar Tab | What You'll Find Here |
| :--- | :--- |
| **📊 Overview** | Hostname, model/version, management & WAN IPs, HA cluster status, Internet/Disk posture, plus **Where-Used Search**, **Trace Packet**, and **Config Diff**. |
| **🩺 Security & Health** | **Hardware/Firmware Lifecycle (EoL/EoS)**, **Public Management & VIP Exposure** (with local reachability probe), **Certificate Expiry Alerts**, and **Quick Security Audit** findings. |
| **📋 PM Lookup** | Automated backup-config Preventive Maintenance checks (firmware/EoS/FFR, GMT+8 & NTP, log managers, interfaces, routing, VPN, HA, GUI/SSH access, and 90-day PAN-OS log filter) with status filtering and CSV/Excel export. |
| **🛡 Policies & NAT** | **Policy Match / Lookup Simulator**, **Cleanup & Hygiene Analyzer**, and all rulebases (Security, NAT, Proxy, PBF, Decryption, QoS, DoS, Auth, SD-WAN) with color-coded status legends. |
| **📦 Objects** | Addresses, address groups, services, service groups, VIPs/IP Pools, schedules, EDLs, tags, regions, and custom objects. |
| **🌐 Interfaces & Network** | Hierarchical interface tables (zones, switches, VLANs, sub-interfaces, disabled highlights), SD-WAN, Virtual Routers, Static/Policy/BGP/OSPF/RIP routes, and **LPM Route Lookup**. |
| **🔒 Security Profiles** | Antivirus, Web/URL Filter, DNS Filter, IPS/Vulnerability, App Control, File/Data Filtering, SSL Inspection / Decryption profiles, and Profile Groups. |
| **🔑 VPN** | **Site-to-Site IPSec Inspector**, **SSL-to-IPSec Migration Assistant** *(FortiGate)*, IKE/Phase 1 & Phase 2 tunnels, SSL-VPN portals/settings, and GlobalProtect *(Palo Alto)*. |
| **👥 Users & Auth** | Local users & groups, LDAP/RADIUS/SAML/TACACS+/Kerberos/MFA profiles, FSSO, FortiTokens, and User-ID. |
| **📶 WiFi & Switch** *(FortiGate)* | Managed FortiAPs, SSIDs, FortiAP & WIDS profiles, managed FortiSwitches, port policies, and NAC policies. |
| **⚙ System & Logs** | Administrators, admin roles/profiles, HA details, Panorama/SNMP, **Certificate Expiry Inspector**, session timeouts, and log forwarding/settings. |

### 3. Top-Bar Shortcuts
* **`🔎 Search (Ctrl+K)`**: Open Global Quick Search from any tab to find where an IP, subnet, object, VIP, or interface is used.
* **`📄 Audit Report`**: Download/open a printable HTML security & health audit report (use your browser's Print → Save as PDF).
* **`⬇ Export to Excel`**: Export the entire parsed configuration into a single `.xlsx` workbook (saves directly to your `Downloads` folder in the Desktop App).
* **`☀ Light / 🌙 Dark`**: Switch themes anytime.
* **`✨` (bottom-right)**: Open the AI Config Assistant to ask questions about the loaded config.

### 4. Inspecting a TSF Archive (`.zip`)
1. Drop a Palo Alto TSF `.zip` archive onto the landing page and wait for extraction/indexing to finish.
2. Browse the directory tree on the left, or switch between **Filename** and **Content** search modes in the top bar.
3. Click any search match to jump straight to that line in the file viewer, or download the raw file.

---

## Security & Privacy

Built to handle sensitive customer and production firewall backups safely:

* **Automatic Secret Redaction on Upload**: Passwords, password hashes, VPN pre-shared keys (PSKs), private keys, and shared secrets are scrubbed to `[REDACTED]` immediately upon upload — before parsing, caching, or AI summarization.
* **Zero Disk Persistence for Configs**: Uploaded `.xml` and `.conf` files are never written to disk. They are compressed and sealed in ephemeral per-session RAM, and immediately wiped when you click **`↑ Load new config`** or when your session expires (30-minute idle timeout by default).
* **Session-Only AI Keys**: Gemini API keys entered in the chatbox are kept strictly in your session's RAM, never saved to disk, never returned in plaintext, and never shared with other users.
* **Safe for Shared / Cloud Hosting**: Server-side `GEMINI_API_KEY` fallback only works for direct local (`localhost`) sessions — remote visitors always supply their own session key. Optional `FW_PASSWORD` enables a login gate.
* **Hardened Uploads & Air-Gapped Mode**: Rejects executables, scripts, XXE XML declarations, and Zip Slip / symlink-escape archives. Set `DISABLE_ONLINE_CHECKS=1` to disable external lifecycle lookups in strictly offline environments.

---

## Self-Hosting, Settings & Building from Source

### Optional Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `FW_PORT` | `8501` | Local TCP port for the web server. |
| `FW_PASSWORD` | *(unset)* | Enables a `/login` password gate across all pages and APIs (recommended for shared deployments). |
| `GEMINI_API_KEY` | *(unset)* | Default Gemini API key for direct local (`127.0.0.1`) sessions only. Remote visitors must enter their own key in the UI. |
| `GEMINI_MODEL` | `gemini-flash-lite-latest` | Gemini model ID used by the AI Config Assistant. |
| `GEMINI_TIMEOUT_MS` | `60000` | Request timeout (in milliseconds) for Gemini API calls. |
| `DISABLE_ONLINE_CHECKS` | `0` | Set to `1` / `true` to disable online EoL/EoS & firmware RSS lookups (uses bundled offline catalog only). |
| `TSF_SESSIONS_DIR` | `%TEMP%/tsf_sessions` | Temporary directory used for extracted TSF archives. |

### Build the Windows Desktop App Locally
Double-click **`Build Desktop App.bat`**:
* Builds a standalone desktop bundle at `dist\FirewallConfigReader\FirewallConfigReader.exe`.
* If **Inno Setup 6** (`ISCC.exe`) is installed (`winget install JRSoftware.InnoSetup`), it also builds the Windows installer at `dist\FirewallConfigReader-Setup-<version>.exe`.

### Run the Test Suite
```powershell
.venv\Scripts\python.exe -m pytest -v
```
