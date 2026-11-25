"""Site-to-Site IPSec VPN inspector and FortiGate SSL-to-IPSec migration tests."""

from __future__ import annotations

from tests.helpers import SAMPLE_FG_CONF, make_client


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
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("fg_vpn.conf", fg_vpn_conf, "text/plain")}).status_code == 200
    fg_vpn = fg_client.get("/api/fg/VPN").json()
    tabs = fg_vpn["blocks"][0]["tabs"]
    insp_tab = next(t for t in tabs if t["label"] == "Site-to-Site Inspector")
    overview_tbl = next(b for b in insp_tab["blocks"] if b["type"] == "table")
    assert overview_tbl["legend"]  # Mandatory UX rule
    by_tun = {r["Tunnel"]: (r, overview_tbl["row_classes"][i]) for i, r in enumerate(overview_tbl["rows"])}
    assert by_tun["to-hq"][0]["Status"] == "Healthy"
    assert by_tun["to-hq"][0]["Findings"] == "OK"
    assert by_tun["to-hq"][1] == "row-success"
    assert by_tun["to-broken"][1] == "row-danger"
    assert "No P2 selectors" in by_tun["to-broken"][0]["Findings"]
    assert "No static route" in by_tun["to-broken"][0]["Findings"]
    assert "NAT on policy #2" in by_tun["to-broken"][0]["Findings"]
    assert "IKEv1" in by_tun["to-broken"][0]["Findings"]
    assert "Weak P1 (3DES, SHA1, DH 2)" in by_tun["to-broken"][0]["Findings"]

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
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_vpn.xml", pa_vpn_xml, "application/xml")}).status_code == 200
    pa_vpn = pa_client.get("/api/pa/VPN").json()
    vpn_tabs = pa_vpn["blocks"][0]["tabs"]
    pa_insp = next(t for t in vpn_tabs if t["label"] == "IPSec Inspector")
    pa_ov = next(b for b in pa_insp["blocks"] if b["type"] == "table")
    assert pa_ov["legend"]
    assert pa_ov["rows"][0]["Tunnel"] == "Tun-Branch"
    assert pa_ov["rows"][0]["Status"] == "Healthy"
    assert pa_ov["rows"][0]["Findings"] == "OK"
    assert pa_ov["rows"][0]["Routes"] == "1"
    assert pa_ov["rows"][0]["Allow Policies"] == "1"
    assert pa_ov["row_classes"][0] == "row-success"

    # Legacy /api/pa/Network alias still preserves IPSec & GRE Tunnels
    pa_net = pa_client.get("/api/pa/Network").json()
    net_tabs = pa_net["blocks"][0]["tabs"]
    assert any(t["label"] == "IPSec & GRE Tunnels" for t in net_tabs)


def test_vpn_inspector_aggregates_phase2_and_caps_nat_summary():
    fg_multi_p2_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-MULTI-P2"
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
    edit "Oasis-P1"
        set type tunnel
        set interface "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "Oasis-P1"
        set interface "wan1"
        set ike-version 1
        set peertype any
        set proposal aes256-sha256
        set dhgrp 2
        set remote-gw 203.106.222.25
    next
end
config vpn ipsec phase2-interface
    edit "sel-1"
        set phase1name "Oasis-P1"
        set proposal aes256-sha256
        set dhgrp 2
    next
    edit "sel-2"
        set phase1name "Oasis-P1"
        set proposal aes256-sha256
        set dhgrp 2
    next
    edit "sel-3"
        set phase1name "Oasis-P1"
        set proposal aes256-sha256
        set dhgrp 5
    next
    edit "sel-4"
        set phase1name "Oasis-P1"
        set proposal aes256-sha256
        set dhgrp 5
    next
end
config router static
    edit 1
        set dst 10.2.0.0 255.255.255.0
        set device "Oasis-P1"
    next
end
config firewall policy
    edit 1
        set name "Allow-1"
        set srcintf "lan"
        set dstintf "Oasis-P1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
    edit 2
        set name "Allow-2"
        set srcintf "lan"
        set dstintf "Oasis-P1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
    edit 3
        set name "Allow-3"
        set srcintf "lan"
        set dstintf "Oasis-P1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
    edit 4
        set name "Allow-4"
        set srcintf "lan"
        set dstintf "Oasis-P1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
    next
end
"""
    client = make_client()
    assert client.post("/api/upload", files={"file": ("fg_multi_p2.conf", fg_multi_p2_conf, "text/plain")}).status_code == 200
    fg_vpn = client.get("/api/fg/VPN").json()
    insp_tab = next(t for t in fg_vpn["blocks"][0]["tabs"] if t["label"] == "Site-to-Site Inspector")
    overview_tbl = next(b for b in insp_tab["blocks"] if b["type"] == "table")
    row = overview_tbl["rows"][0]
    assert row["Status"] == "Warning (4)"
    assert row["Findings"] == "NAT on 4 policies (#1, #2, +2) | IKEv1 | Weak P1 (DH 2) | Weak P2 (4 selectors: DH 2, DH 5)"

    sel_block = next(b for b in insp_tab["blocks"] if b["type"] == "profile_selector")
    p2_tbl = next(b for b in sel_block["options"][0]["blocks"] if b["type"] == "table" and b.get("title") == "Phase 2 / IPSec Crypto Details")
    assert "_weak" not in p2_tbl["columns"]
    assert p2_tbl["row_classes"] == ["row-warn", "row-warn", "row-warn", "row-warn"]
    assert p2_tbl["legend"]


def test_fortigate_ssl_to_ipsec_migration_assistant():
    # 1. Config without SSL-VPN -> informational message
    no_ssl_client = make_client()
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
    ssl_client = make_client()
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
