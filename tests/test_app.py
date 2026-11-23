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
    client = TestClient(create_app())
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

    r = client.get("/")
    assert r.status_code == 200
    assert "Inspect firewall configurations offline" in r.text


def test_upload_validation():
    client = TestClient(create_app())
    r = client.post("/api/upload", files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400

    r = client.post("/api/upload", files={"file": ("bad.xml", b"<script>alert(1)</script>", "text/xml")})
    assert r.status_code == 400


def test_palo_alto_full_flow():
    client = TestClient(create_app())
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
    client = TestClient(create_app())
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
    client = TestClient(create_app())
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
    client = TestClient(create_app())

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
    client = TestClient(create_app())

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
    client = TestClient(create_app())
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
    client = TestClient(create_app())
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

    client = TestClient(create_app())
    # Proxied / public server visitors have auto-update disabled (mode="cloud")
    pub_res = client.get("/api/update/check", headers={"X-Forwarded-For": "203.0.113.10"})
    assert pub_res.status_code == 200
    assert pub_res.json()["mode"] == "cloud"
    assert pub_res.json()["update_available"] is False

    pub_install = client.post("/api/update/install", headers={"X-Forwarded-For": "203.0.113.10"})
    assert pub_install.status_code == 403





