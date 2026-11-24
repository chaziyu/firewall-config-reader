"""End-to-end API tests for the FastAPI + HTML Firewall Config Reader."""

from __future__ import annotations

import io
import time
import zipfile

from fastapi.testclient import TestClient

from server import create_app

SAMPLE_PA_XML = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-FW-01</hostname>
          <ip-address>192.168.1.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <timezone>UTC</timezone>
        </system>
      </deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="10.0.0.1/24"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"/>
          </zone>
          <address>
            <entry name="LAN_NET"><ip-netmask>10.0.0.0/24</ip-netmask></entry>
          </address>
          <rulebase>
            <security>
              <rules>
                <entry name="Allow-Web">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>web-browsing</member></application>
                  <service><member>application-default</member></service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""

SAMPLE_FG_CONF = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-EDGE-01"
    set timezone 55
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
end
config firewall address
    edit "LAN_SUBNET"
        set subnet 10.10.1.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "Allow-Outbound"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN_SUBNET"
        set dstaddr "all"
        set service "HTTPS"
        set nat enable
    next
end
"""


def _make_tsf_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("logs/mp-log/authd.log", "2026-01-01 INFO authd started\n2026-01-01 ERROR login failed for admin\n")
        zf.writestr("opt/pancfg/running-config.xml", "<config><hostname>PA-TSF</hostname></config>\n")
    return buf.getvalue()


def test_health_and_landing():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

    r = client.get("/")
    assert r.status_code == 200
    assert "Inspect firewall configurations" in r.text


def test_upload_validation():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400

    r = client.post("/api/upload", files={"file": ("bad.xml", b"<script>alert(1)</script>", "text/xml")})
    assert r.status_code == 400


def test_palo_alto_full_flow():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("running.xml", SAMPLE_PA_XML, "application/xml")})
    assert r.status_code == 200
    assert r.json()["vendor"] == "Palo Alto"

    ws = client.get("/workspace")
    assert ws.status_code == 200
    assert "PA" in ws.text or "Palo Alto" in ws.text

    for sec in ("Dashboard", "Policies", "Objects", "Network", "Device"):
        res = client.get(f"/api/pa/{sec}")
        assert res.status_code == 200, f"PA section {sec} failed: {res.text}"
        data = res.json()
        assert data["section"] == sec
        assert isinstance(data["blocks"], list)

    match = client.post(
        "/api/pa/policy-test",
        json={
            "policy_type": "security",
            "src_zone": "trust",
            "dst_zone": "untrust",
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "dst_port": "443",
            "protocol": "tcp",
        },
    )
    assert match.status_code == 200
    assert "matched" in match.json()


def test_fortigate_full_flow_and_lookup():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("fgt.conf", SAMPLE_FG_CONF, "text/plain")})
    assert r.status_code == 200
    assert r.json()["vendor"] == "FortiGate"

    for sec in (
        "Summary",
        "Interfaces",
        "Network",
        "Policy & Objects",
        "Security",
        "VPN",
        "User & Auth",
        "WiFi & Switch",
        "System",
        "Log & Report",
    ):
        res = client.get(f"/api/fg/{sec}")
        assert res.status_code == 200, f"FG section {sec} failed: {res.text}"
        assert res.json()["section"] == sec

    # Match policy #1
    hit = client.post(
        "/api/fg/policy-lookup",
        json={
            "src_iface": "internal",
            "dst_iface": "wan1",
            "src_addr": "10.10.1.50",
            "dst_addr": "8.8.8.8",
            "protocol": "HTTPS",
        },
    )
    assert hit.status_code == 200
    assert hit.json()["matched"] is True

    # Implicit deny
    miss = client.post(
        "/api/fg/policy-lookup",
        json={
            "src_iface": "wan1",
            "dst_iface": "internal",
            "src_addr": "1.1.1.1",
            "dst_addr": "10.10.1.50",
            "protocol": "SSH",
        },
    )
    assert miss.status_code == 200
    assert miss.json()["matched"] is False


def test_tsf_full_flow():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("techsupport.zip", _make_tsf_zip(), "application/zip")})
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    # Poll until extraction finishes
    for _ in range(40):
        st = client.get(f"/api/tsf/progress/{job_id}").json()
        if st["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert st["status"] == "done"
    assert st["total_files"] == 2

    page = client.get("/tsf")
    assert page.status_code == 200

    tree = client.get("/api/tsf/tree?path=").json()
    assert "logs" in tree["dirs"]

    fn = client.get("/api/tsf/search?mode=filename&q=authd").json()
    assert len(fn["results"]) == 1

    fview = client.get("/api/tsf/file?path=logs/mp-log/authd.log&page=0&jump_line=2").json()
    assert fview["success"] is True
    assert fview["total_lines"] == 2

    # Clean up session
    assert client.post("/api/session/reset").status_code == 200


def test_optional_password_auth(monkeypatch):
    monkeypatch.setenv("FW_PASSWORD", "supersecret")
    client = TestClient(create_app(), client=("127.0.0.1", 50000))

    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"

    bad = client.post("/login", data={"password": "wrong"}, follow_redirects=False)
    assert bad.status_code == 401

    ok = client.post("/login", data={"password": "supersecret"}, follow_redirects=False)
    assert ok.status_code == 303
    assert ok.headers["location"] == "/"

    home = client.get("/")
    assert home.status_code == 200


def test_chat_api_key_history_and_error_handling(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    client = TestClient(create_app(), client=("127.0.0.1", 50000))

    r = client.post("/api/upload", files={"file": ("fgt.conf", SAMPLE_FG_CONF, "text/plain")})
    assert r.status_code == 200

    # Initial chat state
    st = client.get("/api/chat")
    assert st.status_code == 200
    assert st.json()["history"] == []

    # Without API key, error reply should NOT be saved into history
    no_key = client.post("/api/chat", json={"question": "What policies exist?"})
    assert no_key.status_code == 200
    assert no_key.json()["ok"] is False
    assert no_key.json()["history"] == []

    # Save API key via chatbox endpoint (session-only)
    set_k = client.post("/api/chat/key", json={"api_key": "AIzaSyTestKey12345", "persist": False})
    assert set_k.status_code == 200
    assert set_k.json()["key_status"]["configured"] is True
    assert set_k.json()["key_status"]["source"] == "session"

    # Mock ask_gemini to simulate a successful reply
    import backend.routes.chat_api as chat_api_mod

    monkeypatch.setattr(
        chat_api_mod,
        "ask_gemini",
        lambda **kwargs: (True, "Policy **Allow-Outbound** permits `LAN_SUBNET` to `all`."),
    )
    ok_res = client.post("/api/chat", json={"question": "What policies exist?"})
    assert ok_res.status_code == 200
    data = ok_res.json()
    assert data["ok"] is True
    assert len(data["history"]) == 2

    # Refresh state via GET /api/chat preserves history
    st2 = client.get("/api/chat")
    assert st2.status_code == 200
    assert len(st2.json()["history"]) == 2


def test_fortigate_interface_row_indicators():
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
    edit "lan_sw"
        set type hard-switch
        set ip 192.168.1.1 255.255.255.0
    next
    edit "vlan10"
        set interface "lan_sw"
        set vlanid 10
        set ip 192.168.10.1 255.255.255.0
    next
    edit "port_down"
        set status disable
    next
    edit "vpn_tun"
        set type tunnel
        set interface "wan1"
    next
end
config system zone
    edit "TRUST_ZONE"
        set interface "vpn_tun"
    next
end
"""
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("ifaces.conf", fg_conf, "text/plain")})
    assert r.status_code == 200

    res = client.get("/api/fg/Interfaces")
    assert res.status_code == 200
    blocks = res.json()["blocks"]
    tbl = next(b for b in blocks if b["type"] == "table")

    class_by_name = {
        row["Name"].replace("\u00a0", "").replace("\u2517", "").replace("\U0001f4e6", "").strip(): cls
        for row, cls in zip(tbl["rows"], tbl["row_classes"])
    }
    assert class_by_name["TRUST_ZONE"] == "row-zone"
    assert class_by_name["vpn_tun"] == ""
    assert class_by_name["lan_sw"] == "row-info"
    assert class_by_name["vlan10"] == "row-sub"
    assert class_by_name["port_down"] == "row-danger"


def test_session_api_key_isolation_and_public_proxy_guard(monkeypatch):
    # Even if GEMINI_API_KEY is present in server env, a remote/proxied visitor
    # (with X-Forwarded-For on Render) cannot use the server env key automatically.
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaServerEnvSecretKey9999")
    app = create_app()
    user_a = TestClient(app)
    user_b = TestClient(app)

    user_a.post("/api/upload", files={"file": ("fgt.conf", SAMPLE_FG_CONF, "text/plain")})
    user_b.post("/api/upload", files={"file": ("fgt.conf", SAMPLE_FG_CONF, "text/plain")})

    # Remote visitor A (via Render proxy header) sees configured=False
    st_a = user_a.get("/api/chat", headers={"X-Forwarded-For": "203.0.113.5"})
    assert st_a.status_code == 200
    assert st_a.json()["key_status"]["configured"] is False

    # Visitor A enters their own key in the chatbox
    user_a.post(
        "/api/chat/key",
        json={"api_key": "AIzaUserAPrivateKey1111"},
        headers={"X-Forwarded-For": "203.0.113.5"},
    )
    st_a_after = user_a.get("/api/chat", headers={"X-Forwarded-For": "203.0.113.5"})
    assert st_a_after.json()["key_status"]["configured"] is True
    assert st_a_after.json()["key_status"]["source"] == "session"

    # Visitor B in another session STILL has no key and cannot use Visitor A's key
    st_b = user_b.get("/api/chat", headers={"X-Forwarded-For": "198.51.100.42"})
    assert st_b.status_code == 200
    assert st_b.json()["key_status"]["configured"] is False


def test_config_secrets_redacted_and_sealed_in_ram():
    from backend.session_store import store

    fg_with_secrets = (
        SAMPLE_FG_CONF
        + b"""
config system admin
    edit "admin"
        set password ENC SH2abcdef1234567890TOPSECRET
    next
end
config vpn ipsec phase1-interface
    edit "hq-vpn"
        set psksecret ENC 998877665544332211SUPERSECRETPSK
    next
end
"""
    )
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    r = client.post("/api/upload", files={"file": ("secret_fgt.conf", fg_with_secrets, "text/plain")})
    assert r.status_code == 200

    sid = client.cookies.get("fw_session_id")
    assert sid is not None
    sess = store.get_by_id(sid)
    assert sess is not None

    # 1. Stored _sealed_content in RAM is compressed + XOR-encrypted (not readable plain text)
    assert sess._sealed_content is not None
    assert b"config system global" not in sess._sealed_content
    assert b"FGT-EDGE-01" not in sess._sealed_content

    # 2. Even when unsealed via sess.raw_content, password hashes and PSKs are redacted
    unsealed = sess.raw_content
    assert unsealed is not None
    assert b"SH2abcdef1234567890TOPSECRET" not in unsealed
    assert b"998877665544332211SUPERSECRETPSK" not in unsealed
    assert b"[REDACTED]" in unsealed


def test_auto_update_check_and_sha256_verification(monkeypatch):
    from backend.update_service import _verify_sha256, is_newer_version
    import backend.routes.update_api as update_api_mod

    assert is_newer_version("2.3.0", "2.2.0") is True
    assert is_newer_version("v2.2.1", "2.2.0") is True
    assert is_newer_version("2.2.0", "2.2.0") is False
    assert is_newer_version("2.1.9", "2.2.0") is False

    fake_exe = b"MZ" + b"\x00" * 2048
    import hashlib

    h = hashlib.sha256(fake_exe).hexdigest()
    sums_txt = f"{h}  FirewallConfigReader-Setup-2.3.0.exe\n"
    assert _verify_sha256(fake_exe, "FirewallConfigReader-Setup-2.3.0.exe", sums_txt) is True
    assert _verify_sha256(fake_exe + b"x", "FirewallConfigReader-Setup-2.3.0.exe", sums_txt) is False

    monkeypatch.setattr(
        update_api_mod,
        "check_for_updates",
        lambda is_loopback=True: (
            {
                "mode": "cloud",
                "checked": True,
                "current_version": "2.2.0",
                "latest_version": "2.2.0",
                "update_available": False,
                "can_auto_install": False,
            }
            if not is_loopback
            else {
                "mode": "source",
                "checked": True,
                "current_version": "2.2.0",
                "latest_version": "2.3.0",
                "update_available": True,
                "can_auto_install": True,
                "install_method": "git_pull",
                "release_url": "https://github.com/chaziyu/firewall-config-reader/releases/tag/v2.3.0",
            }
        ),
    )

    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    # Proxied / public server visitors have auto-update disabled (mode="cloud")
    pub_res = client.get("/api/update/check", headers={"X-Forwarded-For": "203.0.113.10"})
    assert pub_res.status_code == 200
    assert pub_res.json()["mode"] == "cloud"
    assert pub_res.json()["update_available"] is False

    pub_install = client.post("/api/update/install", headers={"X-Forwarded-For": "203.0.113.10"})
    assert pub_install.status_code == 403


def test_excel_export_for_paloalto_and_fortigate():
    import io
    from openpyxl import load_workbook

    # 1. Palo Alto
    pa_client = TestClient(create_app())
    assert pa_client.post("/api/upload", files={"file": ("pa_sample.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200

    ws_html = pa_client.get("/workspace").text
    assert 'id="fw-export-excel-btn"' in ws_html
    assert ws_html.index('id="fw-export-excel-btn"') < ws_html.index("data-theme-toggle")

    pa_res = pa_client.get("/api/export/excel")
    assert pa_res.status_code == 200
    assert "pa_sample_export.xlsx" in pa_res.headers.get("content-disposition", "")
    wb_pa = load_workbook(io.BytesIO(pa_res.content))
    assert wb_pa.sheetnames == ["Dashboard", "Policies", "Objects", "Network", "Device"]
    assert any(
        cell.fill and cell.fill.fill_type == "solid"
        for row in wb_pa["Policies"].iter_rows()
        for cell in row
    )
    assert (wb_pa["Policies"].column_dimensions["A"].width or 0) >= 12

    # 2. FortiGate
    fg_client = TestClient(create_app())
    assert fg_client.post("/api/upload", files={"file": ("fg_sample.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200

    fg_res = fg_client.get("/api/export/excel")
    assert fg_res.status_code == 200
    assert "fg_sample_export.xlsx" in fg_res.headers.get("content-disposition", "")
    wb_fg = load_workbook(io.BytesIO(fg_res.content))
    assert len(wb_fg.sheetnames) == 10
    assert wb_fg.sheetnames[0] == "Summary"
    assert any(
        cell.fill and cell.fill.fill_type == "solid"
        for row in wb_fg["Policy & Objects"].iter_rows()
        for cell in row
    )


def test_desktop_exe_excel_export_direct_save_with_dedup(monkeypatch, tmp_path):
    import backend.excel_export as excel_mod
    import backend.update_service as upd_mod

    monkeypatch.setattr(upd_mod, "is_frozen_desktop_exe", lambda: True)
    monkeypatch.setattr(excel_mod, "get_downloads_dir", lambda: tmp_path)

    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert client.post("/api/upload", files={"file": ("myfw.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200

    r1 = client.get("/api/export/excel")
    assert r1.status_code == 200
    assert r1.json()["saved"] is True
    assert r1.json()["filename"] == "myfw_export.xlsx"
    assert (tmp_path / "myfw_export.xlsx").exists()

    r2 = client.get("/api/export/excel")
    assert r2.status_code == 200
    assert r2.json()["filename"] == "myfw_export-1.xlsx"
    assert (tmp_path / "myfw_export-1.xlsx").exists()

    r3 = client.get("/api/export/excel")
    assert r3.status_code == 200
    assert r3.json()["filename"] == "myfw_export-2.xlsx"
    assert (tmp_path / "myfw_export-2.xlsx").exists()


def test_public_ip_classifier():
    from backend.exposure_check import is_public_ip

    assert is_public_ip("8.8.8.8/255.255.255.0") is True
    assert is_public_ip("1.1.1.1/24") is True
    assert is_public_ip("2606:4700:4700::1111/64") is True

    assert is_public_ip("10.0.0.1/24") is False
    assert is_public_ip("172.16.5.1/255.255.255.0") is False
    assert is_public_ip("192.168.1.1/24") is False
    assert is_public_ip("100.64.0.1/10") is False
    assert is_public_ip("127.0.0.1/8") is False
    assert is_public_ip("169.254.1.1/16") is False
    assert is_public_ip("dhcp") is False
    assert is_public_ip("-") is False


def test_fortigate_overview_public_mgmt_exposure():
    # Baseline sample has no allowaccess HTTP/HTTPS/SSH -> clean badge, no card
    clean_client = TestClient(create_app())
    assert clean_client.post("/api/upload", files={"file": ("clean.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200
    clean_summary = clean_client.get("/api/fg/Summary").json()
    clean_hero = next(b for b in clean_summary["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "No Public Mgmt Exposure" and b["variant"] == "allow" for b in clean_hero["badges"])
    assert not any(b["type"] == "card" and b.get("title") == "Public Interface Management Exposure" for b in clean_summary["blocks"])

    # Exposed active wan1 (HTTPS, SSH), ignored disabled wan2 (HTTP), ignored private internal (HTTP, HTTPS, SSH)
    fg_exposed = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-EXPOSED"
end
config system interface
    edit "wan1"
        set ip 8.8.8.8 255.255.255.0
        set allowaccess ping https ssh
        set status enable
    next
    edit "wan2"
        set ip 1.1.1.1 255.255.255.0
        set allowaccess http https ssh
        set status disable
    next
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping http https ssh
        set status enable
    next
end
"""
    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("exposed.conf", fg_exposed, "text/plain")}).status_code == 200
    summary = client.get("/api/fg/Summary").json()
    hero = next(b for b in summary["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "Public Mgmt Exposed (1)" and b["variant"] == "warn" for b in hero["badges"])

    card = next(b for b in summary["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    sys_overview_idx = next(i for i, b in enumerate(summary["blocks"]) if b["type"] == "section_header" and b.get("title") == "System Overview")
    kv_idx = next(i for i, b in enumerate(summary["blocks"]) if b["type"] == "kv_grid")
    exposure_idx = next(i for i, b in enumerate(summary["blocks"]) if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert sys_overview_idx < kv_idx < exposure_idx
    assert card["badge"] == {"text": "1 Exposed", "variant": "warn"}
    assert len(card["rows"]) == 1
    assert "wan1" in card["rows"][0]["label"]
    assert "8.8.8.8/255.255.255.0" in card["rows"][0]["label"]
    assert card["rows"][0]["value"] == "HTTPS (443), SSH (22)"
    assert card["rows"][0]["tone"] == "warn"

    kv = next(b for b in summary["blocks"] if b["type"] == "kv_grid")
    kv_map = {item["label"]: item for item in kv["items"]}
    assert kv_map["Management IP"]["value"] == "Not configured"
    assert kv_map["Admin Ports"]["value"] == "HTTPS 443 · SSH 22"
    assert kv_map["Admin Ports"]["sub"] == "HTTP 80"

    # Active interface with HTTP -> red (deny) severity
    fg_http = fg_exposed.replace(b"set allowaccess ping https ssh", b"set allowaccess ping http https")
    http_client = TestClient(create_app())
    assert http_client.post("/api/upload", files={"file": ("http.conf", fg_http, "text/plain")}).status_code == 200
    http_summary = http_client.get("/api/fg/Summary").json()
    http_card = next(b for b in http_summary["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert http_card["badge"]["variant"] == "deny"
    assert http_card["rows"][0]["value"] == "HTTP (80), HTTPS (443)"
    assert http_card["rows"][0]["tone"] == "deny"


def test_fortigate_overview_management_ip_and_custom_ports():
    fg_custom = b"""#config-version=FG100F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-CORP-01"
    set admin-port 8080
    set admin-sport 8443
    set admin-ssh-port 2222
end
config system interface
    edit "mgmt"
        set ip 192.168.100.10 255.255.255.0
        set dedicated-to management
        set status enable
    next
    edit "wan1"
        set ip 8.8.8.8 255.255.255.0
        set allowaccess https ssh
        set status enable
    next
end
"""
    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("custom.conf", fg_custom, "text/plain")}).status_code == 200
    summary = client.get("/api/fg/Summary").json()

    kv = next(b for b in summary["blocks"] if b["type"] == "kv_grid")
    kv_map = {item["label"]: item for item in kv["items"]}
    assert kv_map["Management IP"]["value"] == "192.168.100.10/255.255.255.0"
    assert kv_map["Management IP"]["sub"] == "Dedicated (mgmt)"
    assert kv_map["Admin Ports"]["value"] == "HTTPS 8443 · SSH 2222"
    assert kv_map["Admin Ports"]["sub"] == "HTTP 8080"

    card = next(b for b in summary["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert card["rows"][0]["value"] == "HTTPS (8443), SSH (2222)"

    # HA management reservation takes priority over generic interface lookup
    fg_ha_mgmt = b"""#config-version=FG200F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-HA-01"
end
config system ha
    set mode a-p
    set group-name "FW-CL"
    set ha-mgmt-status enable
    config ha-mgmt-interfaces
        edit 1
            set interface "mgmt1"
            set gateway 172.16.0.1
        next
    end
end
config system interface
    edit "mgmt1"
        set ip 172.16.0.10 255.255.255.0
        set status enable
    next
    edit "port1"
        set ip 10.20.30.40 255.255.255.0
        set dedicated-to management
        set status enable
    next
end
"""
    ha_client = TestClient(create_app())
    assert ha_client.post("/api/upload", files={"file": ("ha_mgmt.conf", fg_ha_mgmt, "text/plain")}).status_code == 200
    ha_summary = ha_client.get("/api/fg/Summary").json()
    ha_kv = next(b for b in ha_summary["blocks"] if b["type"] == "kv_grid")
    ha_map = {item["label"]: item for item in ha_kv["items"]}
    assert ha_map["Management IP"]["value"] == "172.16.0.10/255.255.255.0"
    assert ha_map["Management IP"]["sub"] == "HA Mgmt (mgmt1)"


def test_paloalto_overview_public_mgmt_exposure():
    # Baseline sample has private MGT and no mgmt profile -> clean badge, no card
    clean_client = TestClient(create_app())
    assert clean_client.post("/api/upload", files={"file": ("clean.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200
    clean_dash = clean_client.get("/api/pa/Dashboard").json()
    clean_hero = next(b for b in clean_dash["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "No Public Mgmt Exposure" and b["variant"] == "allow" for b in clean_hero["badges"])
    assert not any(b["type"] == "card" and b.get("title") == "Public Interface Management Exposure" for b in clean_dash["blocks"])

    # Public MGT (HTTP disabled, HTTPS+SSH enabled by default) + active L3 ethernet1/1 + disabled ethernet1/2 + private ethernet1/3
    pa_exposed = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-EXPOSED</hostname>
          <ip-address>1.1.1.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <service>
            <disable-http>yes</disable-http>
          </service>
          <permitted-ip>
            <entry name="198.51.100.0/24"/>
          </permitted-ip>
        </system>
      </deviceconfig>
      <network>
        <profiles>
          <interface-management-profile>
            <entry name="WAN-MGMT-SSH">
              <https>yes</https>
              <ssh>yes</ssh>
              <ping>yes</ping>
            </entry>
            <entry name="WAN-MGMT-HTTP">
              <http>yes</http>
            </entry>
          </interface-management-profile>
        </profiles>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip><entry name="8.8.8.8/24"/></ip>
                <interface-management-profile>WAN-MGMT-SSH</interface-management-profile>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <link-state>down</link-state>
              <layer3>
                <ip><entry name="9.9.9.9/24"/></ip>
                <interface-management-profile>WAN-MGMT-HTTP</interface-management-profile>
              </layer3>
            </entry>
            <entry name="ethernet1/3">
              <layer3>
                <ip><entry name="10.0.0.1/24"/></ip>
                <interface-management-profile>WAN-MGMT-HTTP</interface-management-profile>
              </layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""
    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("pa_exp.xml", pa_exposed, "text/xml")}).status_code == 200
    dash = client.get("/api/pa/Dashboard").json()
    hero = next(b for b in dash["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "Public Mgmt Exposed (2)" and b["variant"] == "warn" for b in hero["badges"])

    card = next(b for b in dash["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert card["badge"] == {"text": "2 Exposed", "variant": "warn"}
    labels = [r["label"] for r in card["rows"]]
    assert any("Management (MGT)" in lbl and "1.1.1.1" in lbl and "198.51.100.0/24" in lbl for lbl in labels)
    assert any("ethernet1/1" in lbl and "8.8.8.8/24" in lbl and "WAN-MGMT-SSH" in lbl for lbl in labels)
    assert not any("ethernet1/2" in lbl or "ethernet1/3" in lbl for lbl in labels)
    mgt_row = next(r for r in card["rows"] if "Management (MGT)" in r["label"])
    assert mgt_row["value"] == "HTTPS, SSH"


def test_fortigate_policy_lookup_groups_vip_services_and_shadow():
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-LOOKUP-TEST"
end
config system interface
    edit "internal"
        set ip 10.10.0.1 255.255.0.0
        set status up
    next
    edit "wan1"
        set ip 203.0.113.1 255.255.255.0
        set status up
    next
end
config firewall address
    edit "APP_SUBNET"
        set subnet 10.10.20.0 255.255.255.0
    next
    edit "UNUSED_OBJ"
        set subnet 192.168.99.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "INNER_GRP"
        set member "APP_SUBNET"
    next
    edit "OUTER_GRP"
        set member "INNER_GRP"
    next
end
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.50
        set mappedip "10.10.20.10"
        set extintf "wan1"
    next
end
config firewall service custom
    edit "CUSTOM_APP_8443"
        set tcp-portrange 8443
    next
end
config firewall service group
    edit "WEB_CUSTOM_GRP"
        set member "HTTPS" "CUSTOM_APP_8443"
    next
end
config firewall policy
    edit 10
        set name "Allow-VIP-Custom"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "WEB_VIP"
        set service "WEB_CUSTOM_GRP"
    next
    edit 20
        set name "Allow-Group-Outbound"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "OUTER_GRP"
        set dstaddr "all"
        set service "WEB_CUSTOM_GRP"
        set av-profile "default"
        set logtraffic all
    next
    edit 30
        set name "Shadowed-Broad-Outbound"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
end
"""
    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("fg_adv.conf", fg_conf, "text/plain")}).status_code == 200

    # 1. VIP destination + custom port via service group
    vip_hit = client.post(
        "/api/fg/policy-lookup",
        json={
            "src_iface": "wan1",
            "dst_iface": "internal",
            "src_addr": "198.51.100.5",
            "dst_addr": "203.0.113.50",
            "protocol": "tcp/8443",
        },
    )
    assert vip_hit.status_code == 200
    vip_data = vip_hit.json()
    assert vip_data["matched"] is True
    assert vip_data["blocks"][0]["title"] == "First Matching Policy: #10 — Allow-VIP-Custom"

    # 2. Nested address group + service group (tcp/443 -> HTTPS) + shadowed rule detection
    grp_hit = client.post(
        "/api/fg/policy-lookup",
        json={
            "src_iface": "internal",
            "dst_iface": "wan1",
            "src_addr": "10.10.20.42",
            "dst_addr": "8.8.8.8",
            "protocol": "tcp/443",
        },
    )
    assert grp_hit.status_code == 200
    grp_data = grp_hit.json()
    assert grp_data["matched"] is True
    assert grp_data["blocks"][0]["title"] == "First Matching Policy: #20 — Allow-Group-Outbound"
    assert any(b["type"] == "alert" and b["variant"] == "warn" and "1 subsequent shadowed" in b["text"] for b in grp_data["blocks"])
    shadow_exp = next(b for b in grp_data["blocks"] if b["type"] == "expander")
    assert shadow_exp["blocks"][0]["rows"][0]["ID"] == "30"


def test_route_lookup_fortigate_and_paloalto():
    fg_routes = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-RTR"
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set status up
    next
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
        set status up
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 203.0.113.1
        set device "wan1"
        set distance 10
    next
    edit 2
        set dst 10.20.0.0 255.255.0.0
        set gateway 10.0.0.254
        set device "lan"
        set distance 10
    next
    edit 3
        set dst 10.20.30.0 255.255.255.0
        set gateway 10.0.0.253
        set device "lan"
        set distance 10
    next
end
"""
    fg_client = TestClient(create_app())
    assert fg_client.post("/api/upload", files={"file": ("fg_rtr.conf", fg_routes, "text/plain")}).status_code == 200

    # Invalid IP
    bad = fg_client.post("/api/fg/route-lookup", json={"dest_ip": "not-an-ip"})
    assert bad.status_code == 200
    assert bad.json()["matched"] is False

    # Static LPM: /24 beats /16 and /0
    lpm = fg_client.post("/api/fg/route-lookup", json={"dest_ip": "10.20.30.55"})
    assert lpm.status_code == 200
    lpm_data = lpm.json()
    assert lpm_data["matched"] is True
    assert "10.20.30.0/24" in lpm_data["blocks"][0]["title"]
    assert len(lpm_data["blocks"][2]["rows"]) == 3

    # Connected /24 beats /0
    conn = fg_client.post("/api/fg/route-lookup", json={"dest_ip": "10.0.0.99"})
    assert conn.status_code == 200
    assert "Connected" in conn.json()["blocks"][0]["badge"]["text"]

    # Palo Alto VR Route Lookup
    pa_routes = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-RTR</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="192.168.10.1/24"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member></interface>
            <routing-table>
              <ip>
                <static-route>
                  <entry name="Default">
                    <destination>0.0.0.0/0</destination>
                    <interface>ethernet1/1</interface>
                    <nexthop><ip-address>192.168.10.254</ip-address></nexthop>
                    <metric>10</metric>
                  </entry>
                  <entry name="Corp-Specific">
                    <destination>172.16.5.0/24</destination>
                    <interface>ethernet1/1</interface>
                    <nexthop><ip-address>192.168.10.2</ip-address></nexthop>
                    <metric>10</metric>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""
    pa_client = TestClient(create_app())
    assert pa_client.post("/api/upload", files={"file": ("pa_rtr.xml", pa_routes, "text/xml")}).status_code == 200
    pa_lpm = pa_client.post("/api/pa/route-lookup", json={"dest_ip": "172.16.5.12", "virtual_router": "default"})
    assert pa_lpm.status_code == 200
    pa_data = pa_lpm.json()
    assert pa_data["matched"] is True
    assert "172.16.5.0/24" in pa_data["blocks"][0]["title"]

    pa_conn = pa_client.post("/api/pa/route-lookup", json={"dest_ip": "192.168.10.44", "virtual_router": "all"})
    assert pa_conn.status_code == 200
    assert pa_conn.json()["blocks"][0]["badge"]["text"] == "Connected"


def test_quick_audit_and_pa_policy_legend():
    # FortiGate with ANY-ANY unprofiled rule + weak 3des/sha1 VPN + strong aes256/sha256 VPN
    fg_audit_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-AUDIT"
end
config firewall address
    edit "ORPHAN_NET"
        set subnet 10.99.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "Allow-All-Risky"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
end
config vpn ipsec phase1-interface
    edit "VPN-WEAK"
        set interface "wan1"
        set ike-version 1
        set proposal 3des-sha1
        set dhgrp 2
    next
    edit "VPN-STRONG"
        set interface "wan1"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14
    next
end
"""
    fg_client = TestClient(create_app())
    assert fg_client.post("/api/upload", files={"file": ("fg_audit.conf", fg_audit_conf, "text/plain")}).status_code == 200
    fg_sum = fg_client.get("/api/fg/Summary").json()
    fg_hero = next(b for b in fg_sum["blocks"] if b["type"] == "hero")
    assert any(b["text"].startswith("Audit:") and b["variant"] == "deny" for b in fg_hero["badges"])
    fg_audit_exp = next(b for b in fg_sum["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    fg_rows = fg_audit_exp["blocks"][1]["rows"]
    cats = {r["Category"]: r for r in fg_rows}
    assert "Overly Permissive ANY-ANY Allow Rules" in cats
    assert "Allow Policies Missing Security Profiles" in cats
    assert "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)" in cats
    # Ensure strong aes256-sha256 was NOT flagged as weak
    assert "VPN-STRONG" not in cats["Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)"]["Details"]
    assert "VPN-WEAK" in cats["Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)"]["Details"]
    assert "Unused Address Objects (Best-Effort)" in cats

    # Palo Alto Dashboard audit + Policy table legend check
    pa_client = TestClient(create_app())
    assert pa_client.post("/api/upload", files={"file": ("pa_audit.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200
    pa_dash = pa_client.get("/api/pa/Dashboard").json()
    pa_hero = next(b for b in pa_dash["blocks"] if b["type"] == "hero")
    assert any(b["text"].startswith("Audit:") for b in pa_hero["badges"])
    assert any(b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"] for b in pa_dash["blocks"])

    pa_pols = pa_client.get("/api/pa/Policies").json()
    sec_tab = pa_pols["blocks"][0]["tabs"][0]
    sec_table = next(b for b in sec_tab["blocks"] if b["type"] == "table")
    assert isinstance(sec_table.get("legend"), list) and len(sec_table["legend"]) == 3


def test_fortigate_model_and_lifecycle_evaluation(monkeypatch):
    from datetime import date
    from backend import lifecycle_service as ls
    from parsers.fortigate import FortiGateParser

    # 1. Model & branch extraction across header formats + serial fallback
    p1 = FortiGateParser("#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0\n")
    assert p1.get_model() == "FGT60F"
    assert p1.get_firmware_branch() == "7.2"

    p2 = FortiGateParser("#config-version=FG60E-POE-7.2.8-FW-build1639-240328:opmode=0:vdom=0\n")
    assert p2.get_model() == "FG60E-POE"
    assert p2.get_firmware_branch() == "7.2"

    p3 = FortiGateParser("#config-version=FGVM64-7.4.4-FW-build2662-240514:opmode=0:vdom=0\n")
    assert p3.get_model() == "FGVM64"
    assert p3.get_firmware_branch() == "7.4"

    p_serial = FortiGateParser('config system global\n    set sn "FG100FTK21001234"\nend\n')
    assert p_serial.get_model() == "FG100F"
    assert p_serial.get_firmware_branch() == "Unknown"

    # 2. Normalization
    assert ls.normalize_fortigate_model("FGT60F") == "FG-60F"
    assert ls.normalize_fortigate_model("FG60E-POE") == "FG-60E-POE"
    assert ls.normalize_fortigate_model("FortiGate-100E") == "FG-100E"
    assert ls.normalize_fortigate_model("FGVM64") == "FG-VM"
    assert ls.normalize_fortigate_model("Unknown") == ""

    # 3. Offline deterministic evaluations
    ls.clear_lifecycle_cache()
    ref_day = date(2026, 11, 24)

    res_ok = ls.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", allow_online=False, today=ref_day)
    assert res_ok["badge_variant"] == "allow"
    assert res_ok["badge_text"] == "Lifecycle OK · Up to Date"
    assert res_ok["patch_status"] == "up_to_date"

    res_patch = ls.evaluate_fortigate_lifecycle("FGT60F", "7.4.5", allow_online=False, today=ref_day)
    assert res_patch["badge_variant"] == "warn"
    assert res_patch["badge_text"] == "Patch Available (7.4.13)"
    assert res_patch["latest_in_branch"] == "7.4.13"

    res_branch_eos = ls.evaluate_fortigate_lifecycle("FGT60F", "7.0.19", allow_online=False, today=ref_day)
    assert res_branch_eos["badge_variant"] == "deny"
    assert res_branch_eos["badge_text"] == "Branch EOS"

    res_hw_eos = ls.evaluate_fortigate_lifecycle("FG-60D", "6.0.18", allow_online=False, today=ref_day)
    assert res_hw_eos["badge_variant"] == "deny"
    assert res_hw_eos["badge_text"] == "Hardware EOS"
    assert res_hw_eos["last_supported_firmware"] == "6.0.x"

    res_vm = ls.evaluate_fortigate_lifecycle("FGVM64", "7.6.8", allow_online=False, today=ref_day)
    assert res_vm["is_vm"] is True
    assert res_vm["badge_variant"] == "allow"

    # 4. Mocked live merge (endoflife.date + Fortinet RSS filtering out FIPS-CC)
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "0")
    monkeypatch.setattr(
        ls,
        "_fetch_endoflife_branches",
        lambda: {
            "7.4": {
                "release_date": "2023-05-11",
                "eoes": "2027-05-11",
                "eos": "2028-11-11",
                "latest": None,
            }
        },
    )
    rss_xml = """<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0"><channel>
      <item><title>FortiOS 7.4.4-FIPS-CC b9481-FIPS-CC-74-15</title></item>
      <item><title>FortiOS 7.4.15</title></item>
      <item><title>FortiOS 7.4.14</title></item>
    </channel></rss>"""

    class _FakeResp:
        def __init__(self, body: bytes):
            self._body = body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return self._body

    monkeypatch.setattr(ls.urllib.request, "urlopen", lambda req, timeout=3.0: _FakeResp(rss_xml.encode("utf-8")))
    rss_parsed = ls._fetch_fortinet_rss_latest()
    assert rss_parsed == {"7.4": "7.4.15"}

    monkeypatch.setattr(ls, "_fetch_fortinet_rss_latest", lambda: {"7.4": "7.4.15"})
    res_live = ls.evaluate_fortigate_lifecycle("FGT60F", "7.4.13", allow_online=True, today=ref_day)
    assert res_live["latest_in_branch"] == "7.4.15"
    assert res_live["badge_variant"] == "warn"
    assert res_live["badge_text"] == "Patch Available (7.4.15)"
    assert "Live (endoflife.date + Fortinet RSS)" in res_live["source_label"]

    # 5. Summary API is non-blocking (cache-only) and /api/fg/lifecycle populates live cache
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "0")
    fetch_calls = {"eol": 0, "rss": 0}

    def _counting_eol():
        fetch_calls["eol"] += 1
        return {
            "7.2": {
                "release_date": "2022-03-31",
                "eoes": "2025-03-31",
                "eos": "2026-09-30",
                "latest": None,
            }
        }

    def _counting_rss():
        fetch_calls["rss"] += 1
        return {"7.2": "7.2.15"}

    monkeypatch.setattr(ls, "_fetch_endoflife_branches", _counting_eol)
    monkeypatch.setattr(ls, "_fetch_fortinet_rss_latest", _counting_rss)

    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("fg.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200
    summary = client.get("/api/fg/Summary").json()
    assert fetch_calls == {"eol": 0, "rss": 0}
    hero = next(b for b in summary["blocks"] if b["type"] == "hero")
    assert "FortiGate-60F" in hero["subtitle"]
    assert any(b["text"] == "Branch EOS" and b["variant"] == "deny" and b.get("id") == "fg_lifecycle_badge" for b in hero["badges"])
    lc_card = next(b for b in summary["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
    assert all("tone" not in r for r in lc_card["rows"])
    assert lc_card.get("async_refresh_url") == "/api/fg/lifecycle"
    assert lc_card.get("async_badge_id") == "fg_lifecycle_badge"
    assert "Fetching live data" in lc_card["subtitle"]
    row_map = {r["label"]: r for r in lc_card["rows"]}
    assert row_map["Hardware Model"]["value"] == "FortiGate-60F"
    assert "7.2.5" in row_map["Current Firmware"]["value"]
    assert "7.2.14" in row_map["Latest Firmware in Branch"]["value"]

    # Background lifecycle fetch populates live cache and updates card/badge
    lc_resp = client.get("/api/fg/lifecycle")
    assert lc_resp.status_code == 200
    assert fetch_calls == {"eol": 1, "rss": 1}
    lc_payload = lc_resp.json()
    assert lc_payload["badge"]["id"] == "fg_lifecycle_badge"
    assert "async_refresh_url" not in lc_payload["card"]
    assert "Live (endoflife.date + Fortinet RSS)" in lc_payload["card"]["subtitle"]
    live_rows = {r["label"]: r for r in lc_payload["card"]["rows"]}
    assert "7.2.15" in live_rows["Latest Firmware in Branch"]["value"]

    # Subsequent Summary uses warm cache immediately with no async_refresh_url
    summary_warm = client.get("/api/fg/Summary").json()
    assert fetch_calls == {"eol": 1, "rss": 1}
    lc_card_warm = next(b for b in summary_warm["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
    assert "async_refresh_url" not in lc_card_warm
    warm_rows = {r["label"]: r for r in lc_card_warm["rows"]}
    assert "7.2.15" in warm_rows["Latest Firmware in Branch"]["value"]

    # 6. Summary API with DISABLE_ONLINE_CHECKS=1 never triggers async refresh
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "1")
    summary_off = client.get("/api/fg/Summary").json()
    lc_card_off = next(b for b in summary_off["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
    assert "async_refresh_url" not in lc_card_off
    assert "Offline snapshot" in lc_card_off["subtitle"]


def test_paloalto_panos_lifecycle_evaluation(monkeypatch):
    from datetime import date
    from backend import lifecycle_service as ls

    # 1. Hotfix-aware PAN-OS version tuple ordering
    assert ls._parse_panos_version_tuple("10.2.7") == (10, 2, 7, 0)
    assert ls._parse_panos_version_tuple("10.2.7-h3") == (10, 2, 7, 3)
    assert ls._parse_panos_version_tuple("10.2.18-h15") == (10, 2, 18, 15)
    assert ls._parse_panos_version_tuple("10.2.7") < ls._parse_panos_version_tuple("10.2.7-h3") < ls._parse_panos_version_tuple("10.2.18-h15")

    # 2. Offline evaluations
    ls.clear_lifecycle_cache()
    ref_day = date(2026, 11, 24)

    pa_ok = ls.evaluate_paloalto_lifecycle("12.1.10-h6", allow_online=False, today=ref_day)
    assert pa_ok["badge_variant"] == "allow"
    assert pa_ok["badge_text"] == "PAN-OS Up to Date"

    pa_soon = ls.evaluate_paloalto_lifecycle("11.1.16-h6", allow_online=False, today=ref_day)
    assert pa_soon["badge_variant"] == "warn"
    assert pa_soon["badge_text"] == "Branch EOL Soon"

    pa_patch = ls.evaluate_paloalto_lifecycle("11.1.4-h7", allow_online=False, today=ref_day)
    assert pa_patch["badge_variant"] == "warn"
    assert pa_patch["badge_text"] == "Patch Available (11.1.16-h6)"
    assert pa_patch["latest_in_branch"] == "11.1.16-h6"

    pa_eol = ls.evaluate_paloalto_lifecycle("10.2.18-h15", allow_online=False, today=ref_day)
    assert pa_eol["badge_variant"] == "deny"
    assert pa_eol["badge_text"] == "Branch EOL"

    # 3. Non-blocking /api/pa/Dashboard + /api/pa/lifecycle background refresh
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "0")
    calls = {"panos": 0}

    def _counting_panos():
        calls["panos"] += 1
        return {
            "11.1": {
                "release_date": "2023-11-03",
                "eos": "2027-05-03",
                "latest": "11.1.17-h1",
                "latest_date": "2026-11-24",
            }
        }

    monkeypatch.setattr(ls, "_fetch_panos_endoflife_branches", _counting_panos)
    pa_xml = SAMPLE_PA_XML.replace(
        b'<config version="10.2.0">',
        b'<config version="11.1.0" detail-version="11.1.4-h7">',
    )
    client = TestClient(create_app())
    assert client.post("/api/upload", files={"file": ("pa.xml", pa_xml, "text/xml")}).status_code == 200

    dash = client.get("/api/pa/Dashboard").json()
    assert calls["panos"] == 0
    hero = next(b for b in dash["blocks"] if b["type"] == "hero")
    assert any(b.get("id") == "pa_lifecycle_badge" and b["variant"] == "warn" for b in hero["badges"])
    pa_card = next(b for b in dash["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    mgmt_idx = next(i for i, b in enumerate(dash["blocks"]) if b["type"] == "section_header" and b.get("title") == "Management & Network Identity")
    ha_idx = next(i for i, b in enumerate(dash["blocks"]) if b["type"] == "section_header" and b.get("title") == "High Availability")
    lc_idx = next(i for i, b in enumerate(dash["blocks"]) if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    assert mgmt_idx < ha_idx < lc_idx
    assert all("tone" not in r for r in pa_card["rows"])
    assert pa_card.get("async_refresh_url") == "/api/pa/lifecycle"
    assert pa_card.get("async_badge_id") == "pa_lifecycle_badge"
    assert "Fetching live data" in pa_card["subtitle"]

    # Background fetch updates card & warms cache
    lc_resp = client.get("/api/pa/lifecycle")
    assert lc_resp.status_code == 200
    assert calls["panos"] == 1
    lc_payload = lc_resp.json()
    assert lc_payload["badge"]["text"] == "Patch Available (11.1.17-h1)"
    assert "async_refresh_url" not in lc_payload["card"]
    assert "Live (endoflife.date)" in lc_payload["card"]["subtitle"]
    rows_live = {r["label"]: r["value"] for r in lc_payload["card"]["rows"]}
    assert rows_live["Current PAN-OS"] == "11.1.4-h7 (Branch 11.1)"
    assert "11.1.17-h1" in rows_live["Latest Patch in Branch"]
    assert rows_live["Latest Release Date"] == "2026-11-24"
    assert rows_live["Branch End of Life (EOL)"].startswith("2027-05-03")

    # Subsequent Dashboard uses warm cache directly
    dash_warm = client.get("/api/pa/Dashboard").json()
    assert calls["panos"] == 1
    pa_card_warm = next(b for b in dash_warm["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    assert "async_refresh_url" not in pa_card_warm
    assert "11.1.17-h1" in {r["label"]: r["value"] for r in pa_card_warm["rows"]}["Latest Patch in Branch"]

    # 4. Schema-only XML (no detail-version) adds helpful note in Current PAN-OS row
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "1")
    client2 = TestClient(create_app())
    assert client2.post("/api/upload", files={"file": ("pa_schema.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200
    dash_schema = client2.get("/api/pa/Dashboard").json()
    pa_card_schema = next(b for b in dash_schema["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    schema_rows = {r["label"]: r["value"] for r in pa_card_schema["rows"]}
    assert "XML schema version" in schema_rows["Current PAN-OS"]
    assert "async_refresh_url" not in pa_card_schema


def test_security_headers_and_no_store():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert client.post("/api/upload", files={"file": ("running.xml", SAMPLE_PA_XML, "application/xml")}).status_code == 200

    for path in ("/health", "/", "/api/pa/Dashboard"):
        resp = client.get(path, follow_redirects=False)
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert "no-store" in resp.headers.get("cache-control", "")
        assert resp.headers.get("pragma") == "no-cache"

    https_resp = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert https_resp.status_code == 200
    assert "max-age=31536000" in https_resp.headers.get("strict-transport-security", "")

    static_resp = client.get("/static/css/theme.css")
    assert static_resp.status_code == 200
    assert static_resp.headers.get("x-content-type-options") == "nosniff"
    assert "no-store" not in static_resp.headers.get("cache-control", "")


def test_loopback_host_and_origin_protection():
    client = TestClient(create_app(), client=("127.0.0.1", 50000))

    assert client.get("/health", headers={"Host": "evil.example.com"}).status_code == 403
    for allowed_host in ("127.0.0.1:8501", "localhost:8501", "[::1]:8501"):
        assert client.get("/health", headers={"Host": allowed_host}).status_code == 200

    assert client.post("/api/session/reset", headers={"Origin": "https://evil.example.com"}).status_code == 403
    assert client.post("/api/session/reset", headers={"Origin": "http://127.0.0.1:8501"}).status_code == 200

    proxied = client.get(
        "/health",
        headers={"X-Forwarded-For": "203.0.113.5", "Host": "fw.corp.internal"},
    )
    assert proxied.status_code == 200


def test_session_ttl_default():
    import backend.session_store as ss

    assert ss.SESSION_TTL_SECONDS == 1800


def test_where_used_search_fortigate_and_paloalto():
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-WU"
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
end
config firewall address
    edit "LAN_SUBNET"
        set subnet 10.10.1.0 255.255.255.0
    next
    edit "APP_SRV"
        set subnet 10.10.1.50 255.255.255.255
    next
end
config firewall addrgrp
    edit "CORP_SERVERS"
        set member "APP_SRV"
    next
    edit "ALL_INTERNAL"
        set member "CORP_SERVERS" "LAN_SUBNET"
    next
end
config firewall vip
    edit "VIP_WEB"
        set extip 203.0.113.50
        set extintf "wan1"
        set mappedip "10.10.1.50"
    next
end
config firewall policy
    edit 10
        set name "Allow-Corp"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "ALL_INTERNAL"
        set dstaddr "all"
        set service "HTTPS"
    next
    edit 11
        set name "Allow-VIP"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "VIP_WEB"
        set service "HTTPS"
    next
end
config router static
    edit 1
        set dst 10.10.1.0 255.255.255.0
        set gateway 10.10.1.254
        set device "internal"
    next
end
"""
    fg_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert fg_client.post("/api/upload", files={"file": ("fg_wu.conf", fg_conf, "text/plain")}).status_code == 200

    # Summary exposes where_used_lookup block
    fg_sum = fg_client.get("/api/fg/Summary").json()
    assert any(b.get("type") == "where_used_lookup" and b.get("vendor") == "fg" for b in fg_sum["blocks"])

    # Empty / unmatched query
    empty_res = fg_client.post("/api/fg/where-used", json={"query": ""}).json()
    assert empty_res["found"] is False
    miss_res = fg_client.post("/api/fg/where-used", json={"query": "198.51.100.99"}).json()
    assert miss_res["found"] is False

    # IP 10.10.1.50 resolves through LAN_SUBNET + APP_SRV -> nested groups -> VIP_WEB -> both policies + route + interface
    hit_res = fg_client.post("/api/fg/where-used", json={"query": "10.10.1.50"}).json()
    assert hit_res["found"] is True
    expanders = {b["title"].split(" (")[0]: b["blocks"][0] for b in hit_res["blocks"] if b["type"] == "expander"}
    assert "Addresses & Groups" in expanders
    addr_names = {r["Name"] for r in expanders["Addresses & Groups"]["rows"]}
    assert {"LAN_SUBNET", "APP_SRV", "CORP_SERVERS", "ALL_INTERNAL"} <= addr_names
    assert "NAT / VIP / IP Pools" in expanders
    assert any(r["Name"] == "VIP_WEB" for r in expanders["NAT / VIP / IP Pools"]["rows"])
    assert "Firewall / Security Policies" in expanders
    pol_ids = {r["ID"] for r in expanders["Firewall / Security Policies"]["rows"]}
    assert {"10", "11"} <= pol_ids
    assert "Static Routes" in expanders
    assert "VPN & Interfaces" in expanders

    # Palo Alto Where-Used
    pa_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-WU</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member></interface>
            <routing-table><ip><static-route>
              <entry name="To-LAN">
                <destination>10.0.0.0/24</destination>
                <interface>ethernet1/1</interface>
                <nexthop><ip-address>10.0.0.254</ip-address></nexthop>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"/>
          </zone>
          <address>
            <entry name="LAN_NET"><ip-netmask>10.0.0.0/24</ip-netmask></entry>
          </address>
          <address-group>
            <entry name="TRUST_GRP"><static><member>LAN_NET</member></static></entry>
          </address-group>
          <rulebase>
            <security><rules>
              <entry name="Allow-LAN">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>TRUST_GRP</member></source>
                <destination><member>any</member></destination>
                <application><member>any</member></application>
                <service><member>application-default</member></service>
                <action>allow</action>
              </entry>
            </rules></security>
            <nat><rules>
              <entry name="Outbound-NAT">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>TRUST_GRP</member></source>
                <destination><member>any</member></destination>
              </entry>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""
    # Fix typo in closing nat tag before uploading
    pa_xml = pa_xml.replace(b"</nat>\n          </rulebase>", b"</rules></nat>\n          </rulebase>")
    pa_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert pa_client.post("/api/upload", files={"file": ("pa_wu.xml", pa_xml, "application/xml")}).status_code == 200

    pa_dash = pa_client.get("/api/pa/Dashboard").json()
    assert any(b.get("type") == "where_used_lookup" and b.get("vendor") == "pa" for b in pa_dash["blocks"])

    pa_hit = pa_client.post("/api/pa/where-used", json={"query": "10.0.0.42"}).json()
    assert pa_hit["found"] is True
    pa_exp = {b["title"].split(" (")[0]: b["blocks"][0] for b in pa_hit["blocks"] if b["type"] == "expander"}
    assert {"LAN_NET", "TRUST_GRP"} <= {r["Name"] for r in pa_exp["Addresses & Groups"]["rows"]}
    assert any(r["Name"] == "Allow-LAN" for r in pa_exp["Firewall / Security Policies"]["rows"])
    assert any(r["Name"] == "Outbound-NAT" for r in pa_exp["NAT / VIP / IP Pools"]["rows"])
    assert any(r["Name"] == "To-LAN" for r in pa_exp["Static Routes"]["rows"])


def test_site_to_site_vpn_inspector_fortigate_and_paloalto():
    fg_vpn_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-VPN"
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
    edit "lan"
        set ip 10.1.0.1 255.255.255.0
        set status up
    next
    edit "to-hq"
        set type tunnel
        set interface "wan1"
    next
    edit "to-broken"
        set type tunnel
        set interface "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "to-hq"
        set interface "wan1"
        set ike-version 2
        set peertype any
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 198.51.100.10
    next
    edit "to-broken"
        set interface "wan1"
        set ike-version 1
        set proposal 3des-sha1
        set dhgrp 2
        set remote-gw 198.51.100.20
    next
end
config vpn ipsec phase2-interface
    edit "to-hq-p2"
        set phase1name "to-hq"
        set proposal aes256-sha256
        set dhgrp 14
        set src-subnet 10.1.0.0 255.255.255.0
        set dst-subnet 10.2.0.0 255.255.255.0
    next
end
config router static
    edit 1
        set dst 10.2.0.0 255.255.255.0
        set device "to-hq"
    next
end
config firewall policy
    edit 1
        set name "HQ-Out"
        set srcintf "lan"
        set dstintf "to-hq"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat disable
    next
    edit 2
        set name "Broken-NAT"
        set srcintf "lan"
        set dstintf "to-broken"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
end
"""
    fg_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert fg_client.post("/api/upload", files={"file": ("fg_vpn.conf", fg_vpn_conf, "text/plain")}).status_code == 200
    fg_vpn = fg_client.get("/api/fg/VPN").json()
    tabs = fg_vpn["blocks"][0]["tabs"]
    insp_tab = next(t for t in tabs if t["label"] == "Site-to-Site Inspector")
    overview_tbl = next(b for b in insp_tab["blocks"] if b["type"] == "table")
    assert overview_tbl["legend"]  # Mandatory UX rule
    by_tun = {r["Tunnel"]: (r, overview_tbl["row_classes"][i]) for i, r in enumerate(overview_tbl["rows"])}
    assert by_tun["to-hq"][0]["Status"] == "Healthy"
    assert by_tun["to-hq"][1] == "row-success"
    assert by_tun["to-broken"][1] == "row-danger"
    assert "No Phase 2" in by_tun["to-broken"][0]["Findings"]
    assert "No active static route" in by_tun["to-broken"][0]["Findings"]
    assert "NAT is enabled" in by_tun["to-broken"][0]["Findings"]
    assert "IKEv1" in by_tun["to-broken"][0]["Findings"]

    # Palo Alto IPSec Inspector
    pa_vpn_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-VPN</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.10/24"/></ip></layer3></entry>
          </ethernet>
          <tunnel><units>
            <entry name="tunnel.1"><ip><entry name="169.254.1.1/30"/></ip></entry>
          </units></tunnel>
        </interface>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="IKE-AES256">
                <encryption><member>aes-256-cbc</member></encryption>
                <hash><member>sha256</member></hash>
                <dh-group><member>group14</member></dh-group>
                <lifetime><hours>8</hours></lifetime>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="IPSEC-AES256">
                <esp><encryption><member>aes-256-gcm</member></encryption><authentication><member>sha256</member></authentication></esp>
                <dh-group>group14</dh-group>
                <lifetime><hours>1</hours></lifetime>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="GW-Branch">
              <protocol><version>ikev2</version><ikev2><ike-crypto-profile>IKE-AES256</ike-crypto-profile></ikev2></protocol>
              <local-address><interface>ethernet1/1</interface><ip>203.0.113.10</ip></local-address>
              <peer-address><ip>198.51.100.50</ip></peer-address>
              <authentication><pre-shared-key><key>secret</key></pre-shared-key></authentication>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="Tun-Branch">
              <tunnel-interface>tunnel.1</tunnel-interface>
              <auto-key>
                <ike-gateway><entry name="GW-Branch"/></ike-gateway>
                <ipsec-crypto-profile>IPSEC-AES256</ipsec-crypto-profile>
              </auto-key>
            </entry>
          </ipsec>
        </tunnel>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member><member>tunnel.1</member></interface>
            <routing-table><ip><static-route>
              <entry name="To-Branch">
                <destination>172.16.20.0/24</destination>
                <interface>tunnel.1</interface>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="vpn-zone"><network><layer3><member>tunnel.1</member></layer3></network></entry>
          </zone>
          <rulebase><security><rules>
            <entry name="Allow-VPN">
              <from><member>trust</member></from>
              <to><member>vpn-zone</member></to>
              <source><member>any</member></source>
              <destination><member>any</member></destination>
              <application><member>any</member></application>
              <service><member>application-default</member></service>
              <action>allow</action>
            </entry>
          </rules></security></rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""
    pa_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert pa_client.post("/api/upload", files={"file": ("pa_vpn.xml", pa_vpn_xml, "application/xml")}).status_code == 200
    pa_net = pa_client.get("/api/pa/Network").json()
    net_tabs = pa_net["blocks"][0]["tabs"]
    tun_tab = next(t for t in net_tabs if t["label"] == "IPSec & GRE Tunnels")
    sub_tabs = tun_tab["blocks"][0]["tabs"]
    pa_insp = next(t for t in sub_tabs if t["label"] == "IPSec Inspector")
    pa_ov = next(b for b in pa_insp["blocks"] if b["type"] == "table")
    assert pa_ov["legend"]
    assert pa_ov["rows"][0]["Tunnel"] == "Tun-Branch"
    assert pa_ov["rows"][0]["Status"] == "Healthy"
    assert pa_ov["rows"][0]["Routes"] == "1"
    assert pa_ov["rows"][0]["Allow Policies"] == "1"
    assert pa_ov["row_classes"][0] == "row-success"


def test_fortigate_ssl_to_ipsec_migration_assistant():
    # 1. Config without SSL-VPN -> informational message
    no_ssl_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert no_ssl_client.post("/api/upload", files={"file": ("fg_no_ssl.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200
    no_ssl_vpn = no_ssl_client.get("/api/fg/VPN").json()
    no_ssl_tabs = no_ssl_vpn["blocks"][0]["tabs"]
    mig_empty = next(t for t in no_ssl_tabs if t["label"] == "SSL-to-IPSec Migration")
    assert mig_empty["blocks"][0]["type"] == "alert"
    assert "No active SSL-VPN" in mig_empty["blocks"][0]["text"]

    # 2. Config with SSL-VPN (Factory cert, Web-Mode bookmarks, SAML group, split-tunnel, ssl.root policy)
    ssl_conf = b"""#config-version=FGT60F-7.2.8-FW-build1639-240315:opmode=0:vdom=0
config system global
    set hostname "FGT-SSLVPN"
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
    edit "lan"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
end
config firewall address
    edit "SSLVPN_POOL"
        set type iprange
        set start-ip 10.212.134.200
        set end-ip 10.212.134.210
    next
    edit "CORP_LAN"
        set subnet 10.10.1.0 255.255.255.0
    next
end
config user saml
    edit "azure-ad-saml"
        set entity-id "https://vpn.example.com/saml"
    next
end
config user group
    edit "SAML_VPN_USERS"
        set member "azure-ad-saml"
    next
end
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set web-mode enable
        set ip-pools "SSLVPN_POOL"
        set split-tunneling enable
        set split-tunneling-routing-address "CORP_LAN"
        config bookmarks
            edit "Intranet"
                set type http
                set url "http://intranet.corp"
            next
        end
    next
end
config vpn ssl settings
    set status enable
    set servercert "Fortinet_Factory"
    set tunnel-ip-pools "SSLVPN_POOL"
    set dns-server1 10.10.1.10
    set port 443
    set source-interface "wan1"
    set default-portal "full-access"
    config authentication-rule
        edit 1
            set groups "SAML_VPN_USERS"
            set portal "full-access"
        next
    end
end
config firewall policy
    edit 5
        set name "SSL-to-LAN"
        set srcintf "ssl.root"
        set dstintf "lan"
        set action accept
        set srcaddr "SSLVPN_POOL"
        set dstaddr "CORP_LAN"
        set service "ALL"
        set schedule "always"
        set groups "SAML_VPN_USERS"
        set nat disable
    next
end
"""
    ssl_client = TestClient(create_app(), client=("127.0.0.1", 50000))
    assert ssl_client.post("/api/upload", files={"file": ("fg_ssl.conf", ssl_conf, "text/plain")}).status_code == 200
    vpn_res = ssl_client.get("/api/fg/VPN").json()
    tabs = vpn_res["blocks"][0]["tabs"]

    # SSL-VPN Settings includes migration heads-up banner
    ssl_set_tab = next(t for t in tabs if t["label"] == "SSL-VPN Settings")
    assert any(b.get("type") == "alert" and "SSL-to-IPSec Migration" in b.get("text", "") for b in ssl_set_tab["blocks"])

    mig_tab = next(t for t in tabs if t["label"] == "SSL-to-IPSec Migration")
    blks = mig_tab["blocks"]
    alerts = [b["text"] for b in blks if b.get("type") == "alert"]
    assert any("Fortinet_Factory" in t for t in alerts)
    assert any("Web-Mode / Bookmarks" in t for t in alerts)

    pol_tbl = next(b for b in blks if b.get("type") == "table" and b.get("id") == "fg_ssl_mig_policies")
    assert pol_tbl["legend"]
    assert pol_tbl["rows"][0]["ID"] == "5"

    code_blk = next(b for b in blks if b.get("type") == "code_block")
    cli = code_blk["code"]
    assert 'set ike-saml-server "azure-ad-saml"' in cli
    assert "config vpn ipsec phase1-interface" in cli
    assert "set ike-version 2" in cli
    assert 'set ipv4-name "SSLVPN_POOL"' in cli
    assert 'set ipv4-split-include "CORP_LAN"' in cli
    assert "config vpn ipsec phase2-interface" in cli
    assert "config firewall policy" in cli
    assert 'set srcintf "RA-IPSec-IKEv2"' in cli











