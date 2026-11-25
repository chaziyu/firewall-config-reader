"""Public exposure checks, reachability probe, quick audit, cert expiry, hygiene, and posture."""

from __future__ import annotations

from fastapi.testclient import TestClient

from server import create_app
from tests.helpers import SAMPLE_FG_CONF, SAMPLE_PA_XML, make_client


def _make_test_pem_cert(cn: str, not_before, not_after, san_dns: str | None = None) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii").strip()


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
    clean_health = clean_client.get("/api/fg/Security & Health").json()
    assert not any(b["type"] == "card" and b.get("title") == "Public Interface Management Exposure" for b in clean_health["blocks"])

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
    assert any(b["text"] == "Public Mgmt Exposed (1)" and b["variant"] == "deny" for b in hero["badges"])

    sec_health = client.get("/api/fg/Security & Health").json()
    card = next(b for b in sec_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    lifecycle_idx = next(i for i, b in enumerate(sec_health["blocks"]) if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
    exposure_idx = next(i for i, b in enumerate(sec_health["blocks"]) if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert lifecycle_idx < exposure_idx
    assert card["badge"] == {"text": "1 Critical · 1 Exposed", "variant": "deny"}
    assert len(card["rows"]) == 1
    assert "wan1" in card["rows"][0]["label"]
    assert "8.8.8.8/255.255.255.0" in card["rows"][0]["label"]
    assert "Unrestricted" in card["rows"][0]["label"]
    assert card["rows"][0]["value"] == "HTTPS (443), SSH (22)"
    assert card["rows"][0]["tone"] == "deny"

    # Restricted HTTPS/SSH via admin trusthost -> warn severity
    fg_restricted = fg_exposed + b"""
config system admin
    edit "admin"
        set trusthost1 198.51.100.0 255.255.255.0
    next
end
"""
    res_client = TestClient(create_app())
    assert res_client.post("/api/upload", files={"file": ("restricted.conf", fg_restricted, "text/plain")}).status_code == 200
    res_health = res_client.get("/api/fg/Security & Health").json()
    res_card = next(b for b in res_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert res_card["badge"] == {"text": "1 Exposed (Restricted)", "variant": "warn"}
    assert res_card["rows"][0]["tone"] == "warn"
    assert "Restricted (admin trusthost)" in res_card["rows"][0]["label"]

    kv = next(b for b in summary["blocks"] if b["type"] == "kv_grid")
    kv_map = {item["label"]: item for item in kv["items"]}
    assert kv_map["Management IP"]["value"] == "Not configured"
    assert kv_map["Admin Ports"]["value"] == "HTTPS 443 · SSH 22"
    assert kv_map["Admin Ports"]["sub"] == "HTTP 80"

    # Active interface with HTTP -> red (deny) severity even when trusthost is set
    fg_http = fg_restricted.replace(b"set allowaccess ping https ssh", b"set allowaccess ping http https")
    http_client = TestClient(create_app())
    assert http_client.post("/api/upload", files={"file": ("http.conf", fg_http, "text/plain")}).status_code == 200
    http_health = http_client.get("/api/fg/Security & Health").json()
    http_card = next(b for b in http_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
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

    sec_health = client.get("/api/fg/Security & Health").json()
    card = next(b for b in sec_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
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
    clean_health = clean_client.get("/api/pa/Security & Health").json()
    assert not any(b["type"] == "card" and b.get("title") == "Public Interface Management Exposure" for b in clean_health["blocks"])

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
    assert any(b["text"] == "Public Mgmt Exposed (2)" and b["variant"] == "deny" for b in hero["badges"])

    pa_health = client.get("/api/pa/Security & Health").json()
    card = next(b for b in pa_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert card["badge"] == {"text": "1 Critical · 2 Exposed", "variant": "deny"}
    labels = [r["label"] for r in card["rows"]]
    assert any("Management (MGT)" in lbl and "1.1.1.1" in lbl and "198.51.100.0/24" in lbl for lbl in labels)
    assert any("ethernet1/1" in lbl and "8.8.8.8/24" in lbl and "WAN-MGMT-SSH" in lbl for lbl in labels)
    assert not any("ethernet1/2" in lbl or "ethernet1/3" in lbl for lbl in labels)
    mgt_row = next(r for r in card["rows"] if "Management (MGT)" in r["label"])
    eth_row = next(r for r in card["rows"] if "ethernet1/1" in r["label"])
    assert mgt_row["value"] == "HTTPS, SSH"
    assert mgt_row["tone"] == "warn"
    assert eth_row["tone"] == "deny"


def test_public_mgmt_reachability_probe_loopback_guard_and_results(monkeypatch):
    import socket

    fg_exposed = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-PROBE"
end
config system interface
    edit "wan1"
        set ip 8.8.8.8 255.255.255.0
        set allowaccess https ssh http
        set status enable
    next
end
"""
    client = make_client()
    assert client.post("/api/upload", files={"file": ("probe.conf", fg_exposed, "text/plain")}).status_code == 200

    # Proxied request: probe_url hidden and probe endpoint blocked with 403
    proxy_headers = {"X-Forwarded-For": "203.0.113.50"}
    proxied_sum = client.get("/api/fg/Security & Health", headers=proxy_headers).json()
    proxied_card = next(b for b in proxied_sum["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert "probe_url" not in proxied_card
    assert client.post("/api/fg/exposure-probe", headers=proxy_headers).status_code == 403
    assert client.post("/api/pa/exposure-probe", headers=proxy_headers).status_code == 403

    # Loopback request: probe_url is exposed on card
    local_sum = client.get("/api/fg/Security & Health").json()
    local_card = next(b for b in local_sum["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert local_card.get("probe_url") == "/api/fg/exposure-probe"

    # Mock socket.create_connection: 443 open, 22 refused, 80 filtered
    class DummySock:
        def close(self):
            pass

    def fake_connect(addr, timeout=2.0):
        ip, port = addr
        assert ip == "8.8.8.8"
        if port == 443:
            return DummySock()
        if port == 22:
            raise ConnectionRefusedError()
        raise TimeoutError()

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    probe_res = client.post("/api/fg/exposure-probe").json()
    assert probe_res["open_count"] == 1
    assert probe_res["total"] == 3
    assert "CONFIRMED CRITICAL" in probe_res["blocks"][0]["text"]
    tbl = probe_res["blocks"][1]
    assert tbl["legend"]
    by_proto = {r["Protocol / Port"]: (r["Live Reachability"], tbl["row_classes"][i]) for i, r in enumerate(tbl["rows"])}
    assert by_proto["HTTPS (443)"][1] == "row-danger"
    assert by_proto["SSH (22)"][1] == "row-muted"
    assert by_proto["HTTP (80)"][1] == "row-warn"

    # Mock open SSH returning passive SSH banner
    class DummySshSock:
        def settimeout(self, t):
            pass

        def recv(self, n):
            return b"SSH-2.0-FortiSSH\r\n"

        def close(self):
            pass

    def fake_ssh_open(addr, timeout=2.0):
        if addr[1] == 22:
            return DummySshSock()
        raise TimeoutError()

    monkeypatch.setattr(socket, "create_connection", fake_ssh_open)
    ssh_res = client.post("/api/fg/exposure-probe").json()
    assert ssh_res["open_count"] == 1
    ssh_tbl = ssh_res["blocks"][1]
    ssh_by_proto = {r["Protocol / Port"]: (r["Live Reachability"], ssh_tbl["row_classes"][i]) for i, r in enumerate(ssh_tbl["rows"])}
    assert "SSH-2.0-FortiSSH" in ssh_by_proto["SSH (22)"][0]
    assert ssh_by_proto["SSH (22)"][1] == "row-danger"


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
    fg_health = fg_client.get("/api/fg/Security & Health").json()
    fg_audit_exp = next(b for b in fg_health["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    fg_rows = fg_audit_exp["blocks"][1]["rows"]
    cats = {r["Category"]: r for r in fg_rows}
    assert "Overly Permissive ANY-ANY Allow Rules" in cats
    assert "Allow Policies Missing Security Profiles" in cats
    assert "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)" in cats
    # Ensure strong aes256-sha256 was NOT flagged as weak
    assert "VPN-STRONG" not in cats["Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)"]["Details"]
    assert "VPN-WEAK" in cats["Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)"]["Details"]
    assert "Unused Address Objects (Best-Effort)" in cats

    # Palo Alto Dashboard audit badge + Security & Health audit expander + Policy table legend check
    pa_client = TestClient(create_app())
    assert pa_client.post("/api/upload", files={"file": ("pa_audit.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200
    pa_dash = pa_client.get("/api/pa/Dashboard").json()
    pa_hero = next(b for b in pa_dash["blocks"] if b["type"] == "hero")
    assert any(b["text"].startswith("Audit:") for b in pa_hero["badges"])
    pa_health = pa_client.get("/api/pa/Security & Health").json()
    assert any(b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"] for b in pa_health["blocks"])

    pa_pols = pa_client.get("/api/pa/Policies").json()
    sec_tab = pa_pols["blocks"][0]["tabs"][0]
    sec_table = next(b for b in sec_tab["blocks"] if b["type"] == "table")
    assert isinstance(sec_table.get("legend"), list) and len(sec_table["legend"]) == 3


def test_certificate_expiry_inspector_fortigate_and_paloalto():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    expired_pem = _make_test_pem_cert(
        "vpn-expired.example.com",
        now - timedelta(days=400),
        now - timedelta(days=10),
        san_dns="vpn-expired.example.com",
    )
    valid_pem = _make_test_pem_cert(
        "vpn-valid.example.com",
        now - timedelta(days=10),
        now + timedelta(days=180),
        san_dns="vpn-valid.example.com",
    )

    fg_cert_conf = (
        "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0\n"
        'config system global\n    set hostname "FGT-CERT"\nend\n'
        "config vpn certificate local\n"
        '    edit "OLD_VPN_CERT"\n'
        f'        set certificate "{expired_pem}"\n'
        "    next\n"
        '    edit "NEW_VPN_CERT"\n'
        f'        set certificate "{valid_pem}"\n'
        "    next\n"
        "end\n"
    ).encode("utf-8")

    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("fg_certs.conf", fg_cert_conf, "text/plain")}).status_code == 200

    fg_sum = fg_client.get("/api/fg/Summary").json()
    fg_hero = next(b for b in fg_sum["blocks"] if b["type"] == "hero")
    assert any("Expired Certs (1)" in b["text"] and b["variant"] == "deny" for b in fg_hero["badges"])
    fg_health = fg_client.get("/api/fg/Security & Health").json()
    cert_card = next(b for b in fg_health["blocks"] if b["type"] == "card" and b.get("title") == "Certificate Expiry Alerts")
    assert cert_card["rows"][0]["tone"] == "deny"

    fg_sys = fg_client.get("/api/fg/System").json()
    cert_tab = next(t for t in fg_sys["blocks"][0]["tabs"] if t["label"] == "Certificates")
    cert_tbl = next(b for b in cert_tab["blocks"] if b["type"] == "table")
    assert cert_tbl["legend"]
    by_name = {r["Name"]: (r, cert_tbl["row_classes"][i]) for i, r in enumerate(cert_tbl["rows"])}
    assert by_name["OLD_VPN_CERT"][0]["Status"] == "Expired"
    assert by_name["OLD_VPN_CERT"][0]["SAN / FQDN"] == "vpn-expired.example.com"
    assert by_name["OLD_VPN_CERT"][1] == "row-danger"
    assert by_name["NEW_VPN_CERT"][0]["Status"] == "Valid"
    assert by_name["NEW_VPN_CERT"][1] == "row-success"

    # Palo Alto Certificate Expiry Inspector
    pa_cert_xml = f"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-CERT</hostname></system></deviceconfig>
      <vsys><entry name="vsys1"/></vsys>
    </entry>
  </devices>
  <shared>
    <certificate>
      <entry name="PA_EXPIRED"><public-key>{expired_pem}</public-key></entry>
      <entry name="PA_VALID"><public-key>{valid_pem}</public-key></entry>
    </certificate>
  </shared>
</config>
""".encode("utf-8")

    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_certs.xml", pa_cert_xml, "application/xml")}).status_code == 200
    pa_dash = pa_client.get("/api/pa/Dashboard").json()
    pa_hero = next(b for b in pa_dash["blocks"] if b["type"] == "hero")
    assert any("Expired Certs (1)" in b["text"] and b["variant"] == "deny" for b in pa_hero["badges"])

    pa_dev = pa_client.get("/api/pa/Device").json()
    pa_cert_tab = next(t for t in pa_dev["blocks"][0]["tabs"] if t["label"] == "Certificates")
    pa_tbl = next(b for b in pa_cert_tab["blocks"] if b["type"] == "table" and b.get("id") == "pa_cert_expiry_tbl")
    assert pa_tbl["legend"]
    pa_by_name = {r["Name"]: (r, pa_tbl["row_classes"][i]) for i, r in enumerate(pa_tbl["rows"])}
    assert pa_by_name["PA_EXPIRED"][0]["Status"] == "Expired"
    assert pa_by_name["PA_EXPIRED"][1] == "row-danger"
    assert pa_by_name["PA_VALID"][0]["Status"] == "Valid"
    assert pa_by_name["PA_VALID"][1] == "row-success"


def test_hygiene_cleanup_analyzer_fortigate_and_paloalto():
    fg_hygiene = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-HYG"
end
config firewall address
    edit "USED_NET"
        set subnet 10.1.0.0 255.255.255.0
    next
    edit "ORPHAN_NET"
        set subnet 10.99.0.0 255.255.255.0
    next
end
config firewall vip
    edit "ORPHAN_VIP"
        set extip 203.0.113.99
        set extintf "wan1"
        set mappedip "10.99.0.10"
    next
end
config firewall policy
    edit 1
        set name "Broad-Allow"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
    edit 2
        set name "Disabled-Used"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "USED_NET"
        set dstaddr "all"
        set service "HTTPS"
        set status disable
    next
end
"""
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("fg_hyg.conf", fg_hygiene, "text/plain")}).status_code == 200
    po = fg_client.get("/api/fg/Policy & Objects").json()
    hyg_tab = next(t for t in po["blocks"][0]["tabs"] if t["label"] == "Cleanup & Hygiene")
    exps = {b["title"].split(" (")[0]: b["blocks"][0] for b in hyg_tab["blocks"] if b["type"] == "expander"}
    unused_names = {r["Name"] for r in exps["Unused / Unreferenced Objects"]["rows"]}
    assert {"ORPHAN_NET", "ORPHAN_VIP"} <= unused_names
    assert "USED_NET" not in unused_names
    rule_tbl = exps["Rule & Schedule Hygiene Findings"]
    assert rule_tbl["legend"]
    findings_set = {r["Finding"] for r in rule_tbl["rows"]}
    assert "Overly Broad Allow Policy" in findings_set
    assert "Disabled Policy" in findings_set
    cli_blk = exps["Draft Unused Object Cleanup CLI"]
    assert 'delete "ORPHAN_NET"' in cli_blk["code"]
    assert 'delete "ORPHAN_VIP"' in cli_blk["code"]

    # Palo Alto Cleanup & Hygiene
    pa_hyg = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-HYG</hostname></system></deviceconfig>
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="USED_OBJ"><ip-netmask>10.0.0.0/24</ip-netmask></entry>
            <entry name="UNUSED_OBJ"><ip-netmask>10.55.0.0/24</ip-netmask></entry>
          </address>
          <rulebase><security><rules>
            <entry name="Allow-Any-Any">
              <from><member>trust</member></from>
              <to><member>untrust</member></to>
              <source><member>any</member></source>
              <destination><member>any</member></destination>
              <application><member>any</member></application>
              <service><member>any</member></service>
              <action>allow</action>
            </entry>
            <entry name="Disabled-Rule">
              <disabled>yes</disabled>
              <from><member>trust</member></from>
              <to><member>untrust</member></to>
              <source><member>USED_OBJ</member></source>
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
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_hyg.xml", pa_hyg, "application/xml")}).status_code == 200
    pa_pols = pa_client.get("/api/pa/Policies").json()
    pa_hyg_tab = next(t for t in pa_pols["blocks"][0]["tabs"] if t["label"] == "Cleanup & Hygiene")
    pa_exps = {b["title"].split(" (")[0]: b["blocks"][0] for b in pa_hyg_tab["blocks"] if b["type"] == "expander"}
    pa_unused = {r["Name"] for r in pa_exps["Unused / Unreferenced Objects"]["rows"]}
    assert "UNUSED_OBJ" in pa_unused
    assert "USED_OBJ" not in pa_unused
    assert pa_exps["Rule & Schedule Hygiene Findings"]["legend"]
    pa_findings = {r["Finding"] for r in pa_exps["Rule & Schedule Hygiene Findings"]["rows"]}
    assert "Overly Broad Allow Rule" in pa_findings
    assert "Disabled Security Rule" in pa_findings


def test_fortigate_public_vip_and_wan_behind_nat_exposure(monkeypatch):
    import socket

    fg_conf = b"""#config-version=FGT80F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config system global
    set hostname "FGT-VIP-NAT"
end
config system interface
    edit "wan2"
        set ip 192.168.1.2 255.255.255.0
        set allowaccess ping https ssh http
        set status enable
    next
    edit "Internal"
        set ip 192.168.5.1 255.255.254.0
        set allowaccess ping https ssh
        set status enable
    next
    edit "MY-SG-Email"
        set type tunnel
        set interface "wan2"
    next
end
config firewall vip
    edit "fe_fmes_rdp_WAN2"
        set extip 175.143.54.222
        set extintf "wan2"
        set portforward enable
        set mappedip "192.168.5.133"
        set extport 3389
        set mappedport 3389
    next
    edit "FeFmesWeb_WAN2"
        set extip 175.143.54.222
        set extintf "wan2"
        set portforward enable
        set mappedip "192.168.5.133"
        set extport 8080
        set mappedport 8080
    next
end
config firewall service custom
    edit "FTP"
        set tcp-portrange 21
    next
    edit "CUSTOM_UNUSED_APP"
        set tcp-portrange 9443
    next
end
config firewall policy
    edit 9
        set name "WAN2 to Internal"
        set srcintf "wan2"
        set dstintf "Internal"
        set action accept
        set srcaddr "all"
        set dstaddr "fe_fmes_rdp_WAN2"
        set service "ALL"
        set schedule "always"
    next
    edit 10
        set name "WAN2 to Web"
        set srcintf "wan2"
        set dstintf "Internal"
        set action accept
        set srcaddr "all"
        set dstaddr "FeFmesWeb_WAN2"
        set service "ALL"
        set schedule "always"
    next
end
config vpn ipsec phase1-interface
    edit "MY-SG-Email"
        set interface "wan2"
        set peertype any
        set proposal aes256-sha256
        set dhgrp 14
        set remote-gw 202.176.200.178
    next
end
"""
    client = make_client()
    assert client.post("/api/upload", files={"file": ("vip_nat.conf", fg_conf, "text/plain")}).status_code == 200

    sec_health = client.get("/api/fg/Security & Health").json()
    card = next(b for b in sec_health["blocks"] if b["type"] == "card" and b.get("title") == "Public Interface Management Exposure")
    assert card["badge"]["variant"] == "deny"
    labels = {r["label"]: r for r in card["rows"]}
    wan2_row = next(r for lbl, r in labels.items() if "wan2 (192.168.1.2/255.255.255.0)" in lbl)
    assert wan2_row["tone"] == "warn"
    assert "WAN Behind NAT" in wan2_row["label"]
    rdp_row = next(r for lbl, r in labels.items() if "VIP: fe_fmes_rdp_WAN2" in lbl and "175.143.54.222" in lbl)
    assert rdp_row["tone"] == "deny"
    assert "RDP (3389)" in rdp_row["value"]
    web_row = next(r for lbl, r in labels.items() if "VIP: FeFmesWeb_WAN2" in lbl)
    assert web_row["tone"] == "warn"

    # Probe tests inferred public VIP IP for wan2 (80, 443, 22) + VIP ports (3389, 8080), never private 192.168.1.2
    probed = []

    def fake_connect(addr, timeout=5.0):
        probed.append(addr)
        raise TimeoutError()

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    probe_res = client.post("/api/fg/exposure-probe").json()
    assert sorted(probed) == [
        ("175.143.54.222", 22),
        ("175.143.54.222", 80),
        ("175.143.54.222", 443),
        ("175.143.54.222", 3389),
        ("175.143.54.222", 8080),
    ]
    assert probe_res["total"] == 5
    probe_tbl = probe_res["blocks"][1]
    web_probe_row = next(r for r in probe_tbl["rows"] if "FeFmesWeb_WAN2" in r["Interface"])
    assert web_probe_row["Config Severity"] == "Warning"

    # Site-to-Site Inspector shows real static remote_gw instead of Dial-Up / Any
    vpn = client.get("/api/fg/VPN").json()
    insp_tab = next(t for t in vpn["blocks"][0]["tabs"] if t["label"] == "Site-to-Site Inspector")
    ov_tbl = next(b for b in insp_tab["blocks"] if b["type"] == "table")
    assert ov_tbl["rows"][0]["Remote Peer"] == "202.176.200.178"

    # Cleanup & Hygiene skips built-in FTP service but flags CUSTOM_UNUSED_APP
    po = client.get("/api/fg/Policy & Objects").json()
    hyg_tab = next(t for t in po["blocks"][0]["tabs"] if t["label"] == "Cleanup & Hygiene")
    unused_tbl = next(b["blocks"][0] for b in hyg_tab["blocks"] if b["type"] == "expander" and b["title"].startswith("Unused"))
    unused_names = {r["Name"] for r in unused_tbl["rows"]}
    assert "CUSTOM_UNUSED_APP" in unused_names
    assert "FTP" not in unused_names


def test_fortigate_http_vip_only_not_labeled_mgmt_and_probes_http_banner(monkeypatch):
    import socket

    fg_web_vips = b"""#config-version=FGT100F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-WEB-VIPS"
end
config system interface
    edit "wan1"
        set ip 202.133.107.81 255.255.255.240
        set allowaccess ping
        set status enable
    next
    edit "lan"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh
        set status enable
    next
end
config firewall vip
    edit "BPMSv2-HTTP"
        set extip 202.133.107.85
        set extintf "wan1"
        set portforward enable
        set mappedip "192.168.1.32"
        set extport 80
        set mappedport 80
    next
    edit "E-INVOICE-HTTP"
        set extip 202.133.107.83
        set extintf "wan1"
        set portforward enable
        set mappedip "192.168.1.51"
        set extport 80
        set mappedport 80
    next
end
config firewall policy
    edit 14
        set name "Allow BPMSv2"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set srcaddr "all"
        set dstaddr "BPMSv2-HTTP"
        set service "HTTP"
        set schedule "always"
    next
    edit 36
        set name "Allow E-INVOICE"
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set srcaddr "all"
        set dstaddr "E-INVOICE-HTTP"
        set service "HTTP"
        set schedule "always"
    next
end
"""
    client = make_client()
    assert client.post("/api/upload", files={"file": ("web_vips.conf", fg_web_vips, "text/plain")}).status_code == 200

    summary = client.get("/api/fg/Summary").json()
    hero = next(b for b in summary["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "Public VIP Exposed (2)" and b["variant"] == "warn" for b in hero["badges"])
    assert not any("Public Mgmt Exposed" in b["text"] for b in hero["badges"])

    sec_health = client.get("/api/fg/Security & Health").json()
    card = next(b for b in sec_health["blocks"] if b["type"] == "card" and b.get("title") == "Public VIP / Port-Forward (DNAT) Exposure")
    assert card["badge"] == {"text": "2 Warning · 2 VIP(s)", "variant": "warn"}
    assert all(r["tone"] == "warn" for r in card["rows"])
    assert all("internal server" in r["label"] for r in card["rows"])

    class DummyHttpSock:
        def __init__(self, payload: bytes):
            self._payload = payload
            self._sent = False

        def settimeout(self, t):
            pass

        def sendall(self, data):
            pass

        def recv(self, n):
            if self._sent:
                return b""
            self._sent = True
            return self._payload

        def close(self):
            pass

    def fake_connect(addr, timeout=5.0):
        ip, port = addr
        assert port == 80
        if ip == "202.133.107.85":
            return DummyHttpSock(
                b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n<html><head><title>Encorp Portal</title></head></html>"
            )
        return DummyHttpSock(
            b"HTTP/1.1 302 Found\r\nServer: Microsoft-IIS/10.0\r\nLocation: https://einvoice.encorp.com.my/\r\n\r\n"
        )

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    probe_res = client.post("/api/fg/exposure-probe").json()
    assert probe_res["open_count"] == 2
    assert probe_res["probe_badge_text"] == "Public VIP Reachable (2)"
    assert probe_res["probe_badge_variant"] == "warn"
    assert probe_res["blocks"][0]["variant"] == "warn"
    assert "not firewall GUI" in probe_res["blocks"][0]["text"]
    assert "CONFIRMED CRITICAL" not in probe_res["blocks"][0]["text"]

    probe_tbl = probe_res["blocks"][1]
    by_ip = {r["Public IP"]: r for r in probe_tbl["rows"]}
    assert by_ip["202.133.107.85"]["Config Severity"] == "Warning"
    assert "Microsoft-IIS/10.0" in by_ip["202.133.107.85"]["Live Reachability"]
    assert "Encorp Portal" in by_ip["202.133.107.85"]["Live Reachability"]
    assert "HTTP 302" in by_ip["202.133.107.83"]["Live Reachability"]
    assert "https://einvoice.encorp.com.my/" in by_ip["202.133.107.83"]["Live Reachability"]


def test_internet_connectivity_and_hard_disk_posture():
    # 1. FortiGate-80F behind upstream NAT (SD-WAN default + private WAN + outbound NAT + public DNS)
    fg_nat = b"""#config-version=FGT80F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config system global
    set hostname "FGT-NAT"
end
config system dns
    set primary 8.8.8.8
end
config system interface
    edit "wan1"
        set ip 192.168.0.2 255.255.255.0
        set status up
    next
end
config router static
    edit 1
        set sdwan-zone "virtual-wan-link"
    next
end
config firewall policy
    edit 1
        set name "Out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
end
"""
    c1 = make_client()
    assert c1.post("/api/upload", files={"file": ("nat.conf", fg_nat, "text/plain")}).status_code == 200
    s1 = c1.get("/api/fg/Summary").json()
    kv1 = {item["label"]: item for item in next(b for b in s1["blocks"] if b["type"] == "kv_grid")["items"]}
    assert kv1["Internet Connectivity"]["value"] == "Connected (Behind Upstream NAT)"
    assert kv1["Local Hard Disk"]["value"] == "No (Diskless Model)"
    assert "Memory-only" in kv1["Local Hard Disk"]["sub"]

    # 2. FortiGate-81F with direct public WAN IP + 0.0.0.0/0 + log disk setting
    fg_ssd = b"""#config-version=FGT81F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-SSD"
end
config system interface
    edit "wan1"
        set ip 1.1.1.10 255.255.255.0
        set status up
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.1
        set device "wan1"
    next
end
config log disk setting
    set status enable
end
"""
    c2 = make_client()
    assert c2.post("/api/upload", files={"file": ("ssd.conf", fg_ssd, "text/plain")}).status_code == 200
    s2 = c2.get("/api/fg/Summary").json()
    kv2 = {item["label"]: item for item in next(b for b in s2["blocks"] if b["type"] == "kv_grid")["items"]}
    assert kv2["Internet Connectivity"]["value"] == "Connected (Direct Public IP)"
    assert kv2["Local Hard Disk"]["value"] == "Yes (Onboard SSD)"
    assert kv2["Local Hard Disk"]["sub"] == "Disk logging enabled"

    # 3. Air-gapped FortiGate-60F
    fg_airgap = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-AIRGAP"
end
config system interface
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
end
"""
    c3 = make_client()
    assert c3.post("/api/upload", files={"file": ("air.conf", fg_airgap, "text/plain")}).status_code == 200
    s3 = c3.get("/api/fg/Summary").json()
    kv3 = {item["label"]: item for item in next(b for b in s3["blocks"] if b["type"] == "kv_grid")["items"]}
    assert kv3["Internet Connectivity"]["value"] == "Internal / Air-Gapped"
    assert kv3["Local Hard Disk"]["value"] == "No (Diskless Model)"

    # 4. Palo Alto with 0.0.0.0/0 + public interface IP
    pa_inet = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-INET</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="8.8.8.20/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member></interface>
            <routing-table><ip><static-route>
              <entry name="Default">
                <destination>0.0.0.0/0</destination>
                <interface>ethernet1/1</interface>
                <nexthop><ip-address>8.8.8.1</ip-address></nexthop>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys><entry name="vsys1"/></vsys>
    </entry>
  </devices>
</config>
"""
    c4 = make_client()
    assert c4.post("/api/upload", files={"file": ("pa_inet.xml", pa_inet, "application/xml")}).status_code == 200
    d4 = c4.get("/api/pa/Dashboard").json()
    kv4 = {item["label"]: item for item in next(b for b in d4["blocks"] if b["type"] == "kv_grid")["items"]}
    assert kv4["Internet Connectivity"]["value"] == "Connected (Direct Public IP)"
    assert kv4["Local Hard Disk"]["value"] == "Yes (PAN-OS Local Disk)"
