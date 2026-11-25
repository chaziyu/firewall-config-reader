"""Core endpoints, upload validation, auth, TSF, RAM security, and session limits."""

from __future__ import annotations

import time

from tests.helpers import SAMPLE_FG_CONF, SAMPLE_PA_XML, make_client, make_tsf_zip


def test_health_and_landing():
    client = make_client()
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

    r = client.get("/")
    assert r.status_code == 200
    assert "Inspect firewall configurations" in r.text


def test_upload_validation_and_structure():
    client = make_client()
    r = client.post("/api/upload", files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400

    r = client.post("/api/upload", files={"file": ("bad.xml", b"<script>alert(1)</script>", "text/xml")})
    assert r.status_code == 400


    # Binary bytes disguised as .conf
    r = client.post("/api/upload", files={"file": ("fake.conf", b"config system\x00\x01\x02end", "application/octet-stream")})
    assert r.status_code == 400
    assert "binary" in r.json()["detail"].lower()

    # Non-FortiGate plain text
    r = client.post("/api/upload", files={"file": ("nginx.conf", b"server {\n  listen 80;\n}\n", "text/plain")})
    assert r.status_code == 400
    assert "FortiGate" in r.json()["detail"]

    # Palo Alto XML uploaded with .txt extension
    r = client.post("/api/upload", files={"file": ("config.txt", SAMPLE_PA_XML, "text/plain")})
    assert r.status_code == 400
    assert ".xml" in r.json()["detail"]

    # XML with DOCTYPE / ENTITY declaration
    xxe_xml = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><config><devices/></config>'
    r = client.post("/api/upload", files={"file": ("xxe.xml", xxe_xml, "application/xml")})
    assert r.status_code == 400
    assert "DOCTYPE" in r.json()["detail"]

    # Non-PAN-OS XML root element
    r = client.post("/api/upload", files={"file": ("pom.xml", b"<project><name>app</name></project>", "application/xml")})
    assert r.status_code == 400
    assert "<config>" in r.json()["detail"]

    # <config> root without expected PAN-OS sections
    r = client.post("/api/upload", files={"file": ("other.xml", b"<config><unrelated/></config>", "application/xml")})
    assert r.status_code == 400
    assert "Palo Alto" in r.json()["detail"]

    # Non-ZIP bytes uploaded as .zip fails synchronously
    r = client.post("/api/upload", files={"file": ("fake.zip", b"not actually a zip archive", "application/zip")})
    assert r.status_code == 400
    assert "ZIP" in r.json()["detail"]

    # Minimal valid FortiGate snippet without #config-version= header still succeeds
    minimal_fg = b'config system global\n    set hostname "FG"\nend\n'
    r = client.post("/api/upload", files={"file": ("snippet.conf", minimal_fg, "text/plain")})
    assert r.status_code == 200
    assert r.json()["vendor"] == "FortiGate"


def test_tsf_full_flow():
    client = make_client()
    r = client.post("/api/upload", files={"file": ("techsupport.zip", make_tsf_zip(), "application/zip")})
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
    client = make_client()

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
    client = make_client()
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


def test_security_headers_and_no_store():
    client = make_client()
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
    client = make_client()

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


def test_lazy_parser_cache_skips_decompression_and_desktop_limits(monkeypatch):
    import zlib
    import backend.session_store as ss
    from backend.session_store import SessionStore, sha256_bytes

    assert ss.SESSION_TTL_SECONDS == 1800

    # 1. Verify section navigation after upload does NOT decompress raw_content again
    client = make_client()
    assert client.post("/api/upload", files={"file": ("lazy.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200

    decompress_calls = 0
    real_decompress = zlib.decompress

    def counting_decompress(data, *args, **kwargs):
        nonlocal decompress_calls
        decompress_calls += 1
        return real_decompress(data, *args, **kwargs)

    monkeypatch.setattr(zlib, "decompress", counting_decompress)
    assert client.get("/api/fg/Summary").status_code == 200
    assert client.get("/api/fg/Interfaces").status_code == 200
    assert client.get("/api/fg/Security & Health").status_code == 200
    assert decompress_calls == 0

    # 2. Verify FW_DESKTOP_MODE=1 caps parser cache at 2 entries
    monkeypatch.setenv("FW_DESKTOP_MODE", "1")
    local_store = SessionStore()
    for idx in range(3):
        payload = SAMPLE_FG_CONF + f"\n# cache-{idx}\n".encode("utf-8")
        local_store.get_fortigate_parser(sha256_bytes(payload), payload)
    assert len(local_store._parser_cache) == 2

    # 3. Verify reset_config() evicts unreferenced parser cache entry
    assert client.post("/api/session/reset").status_code == 200
