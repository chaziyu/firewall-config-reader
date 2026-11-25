"""Palo Alto & FortiGate workspace flows, parsers, NAT, interfaces, and admin hardening."""

from __future__ import annotations

from tests.helpers import SAMPLE_FG_CONF, SAMPLE_PA_XML, make_client


def test_palo_alto_full_flow():
    client = make_client()
    r = client.post("/api/upload", files={"file": ("running.xml", SAMPLE_PA_XML, "application/xml")})
    assert r.status_code == 200
    assert r.json()["vendor"] == "Palo Alto"

    ws = client.get("/workspace")
    assert ws.status_code == 200
    assert "PA" in ws.text or "Palo Alto" in ws.text

    for sec in (
        "Overview",
        "Security & Health",
        "PM Lookup",
        "Policies & NAT",
        "Objects",
        "Interfaces & Network",
        "Security Profiles",
        "VPN",
        "Users & Auth",
        "System & Logs",
    ):
        res = client.get(f"/api/pa/{sec}")
        assert res.status_code == 200, f"PA section {sec} failed: {res.text}"
        data = res.json()
        assert data["section"] == sec
        assert isinstance(data["blocks"], list)

    # Legacy PA section aliases remain reachable
    for legacy_sec in ("Dashboard", "Policies", "Network", "Device"):
        assert client.get(f"/api/pa/{legacy_sec}").status_code == 200

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
    client = make_client()
    r = client.post("/api/upload", files={"file": ("fgt.conf", SAMPLE_FG_CONF, "text/plain")})
    assert r.status_code == 200
    assert r.json()["vendor"] == "FortiGate"

    for sec in (
        "Overview",
        "Security & Health",
        "PM Lookup",
        "Policies & NAT",
        "Objects",
        "Interfaces & Network",
        "Security Profiles",
        "VPN",
        "Users & Auth",
        "WiFi & Switch",
        "System & Logs",
    ):
        res = client.get(f"/api/fg/{sec}")
        assert res.status_code == 200, f"FG section {sec} failed: {res.text}"
        assert res.json()["section"] == sec

    # Legacy FG section aliases remain reachable
    for legacy_sec in ("Summary", "Interfaces", "Network", "Policy & Objects", "Security", "User & Auth", "System", "Log & Report"):
        assert client.get(f"/api/fg/{legacy_sec}").status_code == 200

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
    client = make_client()
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


def test_fortigate_interface_extended_fields_and_nested_blocks():
    # 1. Minimal config hides empty optional columns
    minimal_conf = b"""#config-version=FGT60F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set status up
    next
end
"""
    min_client = make_client()
    assert min_client.post("/api/upload", files={"file": ("min_if.conf", minimal_conf, "text/plain")}).status_code == 200
    min_tbl = next(b for b in min_client.get("/api/fg/Interfaces").json()["blocks"] if b["type"] == "table")
    for hidden_col in ("Secondary IPs", "IPv6", "VRF", "MTU", "Description"):
        assert hidden_col not in min_tbl["columns"]

    # 2. Full config: status down, nested secondaryip + ipv6, post-nested fields, DHCP/PPPoE, VRF, MTU, relay, SD-WAN zone
    full_conf = b"""#config-version=FGT60F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.10 255.255.255.0
        set allowaccess ping https
        set secondary-IP enable
        config secondaryip
            edit 1
                set ip 203.0.113.11 255.255.255.0
                set allowaccess ping
            next
        end
        config ipv6
            set ip6-address 2001:db8::1/64
        end
        set role wan
        set alias "ISP-Fiber"
        set description "Fiber Circuit 123"
        set vrf 2
        set mtu-override enable
        set mtu 1492
        set status up
    next
    edit "wan2"
        set mode dhcp
        set status down
    next
    edit "wan3"
        set mode pppoe
    next
    edit "lan1"
        set ip 10.10.1.1 255.255.255.0
        set dhcp-relay-service enable
        set dhcp-relay-ip "10.0.0.10"
        set dedicated-to management
    next
end
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set zone "virtual-wan-link"
        next
    end
end
"""
    client = make_client()
    assert client.post("/api/upload", files={"file": ("full_if.conf", full_conf, "text/plain")}).status_code == 200
    res = client.get("/api/fg/Interfaces").json()
    tbl = next(b for b in res["blocks"] if b["type"] == "table")
    by_name = {
        row["Name"].replace("\u00a0", "").replace("\u2517", "").strip(): (row, cls)
        for row, cls in zip(tbl["rows"], tbl["row_classes"])
    }

    wan1, wan1_cls = by_name["wan1"]
    assert wan1_cls == ""
    assert wan1["IP/Netmask"] == "203.0.113.10/255.255.255.0"
    assert wan1["Admin Access"] == "PING, HTTPS"
    assert wan1["Role"] == "Wan"
    assert wan1["Alias"] == "ISP-Fiber"
    assert wan1["Description"] == "Fiber Circuit 123"
    assert wan1["VRF"] == "2"
    assert wan1["MTU"] == "1492"
    assert wan1["Secondary IPs"] == "203.0.113.11/255.255.255.0 (PING)"
    assert wan1["IPv6"] == "2001:db8::1/64"
    assert wan1["Zone"] == "SD-WAN: virtual-wan-link"

    wan2, wan2_cls = by_name["wan2"]
    assert wan2["IP/Netmask"] == "DHCP"
    assert wan2["Status"] == "Disable"
    assert wan2_cls == "row-danger"

    wan3, _ = by_name["wan3"]
    assert wan3["IP/Netmask"] == "PPPoE"

    lan1, _ = by_name["lan1"]
    assert lan1["Role"] == "Management"
    assert lan1["DHCP Range"] == "Relay: 10.0.0.10"


def test_fortigate_nat_extraction_and_resolved_view():
    from parsers.fortigate import FortiGateParser

    fg_nat_conf = b"""#config-version=FGT60F-7.4.4-FW-build2662-240514:opmode=0:vdom=0
config system global
    set hostname "FGT-NAT-LAB"
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
config firewall ippool
    edit "SNAT_POOL_1"
        set type fixed-port-range
        set startip 203.0.113.50
        set endip 203.0.113.55
        set source-startip 10.10.1.0
        set source-endip 10.10.1.255
        set startport 1024
        set endport 65535
        set associated-interface "wan1"
        set comments "Corp outbound pool"
    next
    edit "UNUSED_POOL"
        set startip 203.0.113.60
        set endip 203.0.113.60
    next
end
config firewall vip
    edit "VIP_RANGE_WEB"
        set extip 198.51.100.10-198.51.100.20
        set extintf "wan1"
        set mappedip "10.10.1.10-10.10.1.20"
        set portforward enable
        set protocol tcp
        set extport 8443
        set mappedport 443
        set src-filter "192.0.2.0/24"
        set comment "Web range DNAT"
    next
    edit "VIP_UNUSED"
        set extip 198.51.100.99
        set extintf "wan1"
        set mappedip "10.10.1.99"
    next
end
config firewall vipgrp
    edit "WEB_VIPS"
        set interface "wan1"
        set member "VIP_RANGE_WEB"
        set comments "All web VIPs"
    next
end
config firewall policy
    edit 1
        set name "Out-Interface-IP"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set nat enable
    next
    edit 2
        set name "Out-Pool-Fixed"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "SNAT_POOL_1"
        set fixedport enable
    next
    edit 3
        set name "In-VIP-Group"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "WEB_VIPS"
        set service "HTTPS"
        set nat disable
    next
    edit 4
        set name "Disabled-NAT"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set nat enable
        set status disable
    next
end
"""
    # Backward compatibility: raw parser keeps NAT as Enable/Disable
    raw_p = FortiGateParser(fg_nat_conf.decode("utf-8"))
    raw_pols = {r["ID"]: r for r in raw_p.parse_policies()}
    assert raw_pols["1"]["NAT"] == "Enable"
    assert raw_pols["2"]["NAT"] == "Enable"
    assert raw_pols["2"]["_ippool"] is True
    assert raw_pols["2"]["_poolname"] == ["SNAT_POOL_1"]
    assert raw_pols["2"]["_fixedport"] is True

    client = make_client()
    assert client.post("/api/upload", files={"file": ("fg_nat.conf", fg_nat_conf, "text/plain")}).status_code == 200
    po = client.get("/api/fg/Policy & Objects").json()
    tabs = {t["label"]: t for t in po["blocks"][0]["tabs"]}

    # Enriched NAT labels in Firewall Policy table
    fw_tbl = next(b for b in tabs["Firewall Policy"]["blocks"] if b["type"] == "table")
    fw_by_id = {r["ID"]: r for r in fw_tbl["rows"]}
    assert fw_by_id["1"]["NAT"] == "Enable (Interface IP)"
    assert fw_by_id["2"]["NAT"] == "Enable (Pool: SNAT_POOL_1) · Fixed Port"
    assert fw_by_id["3"]["NAT"] == "Disable"

    # Unified NAT tab
    nat_blocks = tabs["NAT"]["blocks"]
    assert nat_blocks[0]["type"] == "alert"
    assert "Policy-Based NAT mode" in nat_blocks[0]["text"]
    nat_sub = {t["label"].split(" (")[0]: t for t in nat_blocks[1]["tabs"]}

    # Outbound SNAT sub-tab
    snat_tbl = next(b for b in nat_sub["Outbound SNAT"]["blocks"] if b["type"] == "table")
    assert snat_tbl["legend"]
    snat_by_id = {r["Policy ID"]: r for r in snat_tbl["rows"]}
    assert snat_by_id["1"]["NAT Type"] == "Interface IP"
    assert "203.0.113.10" in snat_by_id["1"]["Translated IP(s)"]
    assert snat_by_id["2"]["NAT Type"] == "IP Pool"
    assert snat_by_id["2"]["Pool Name"] == "SNAT_POOL_1"
    assert "203.0.113.50 - 203.0.113.55" in snat_by_id["2"]["Translated IP(s)"]
    assert snat_by_id["2"]["Port Behavior"] == "Fixed Port (No PAT)"

    # Virtual IPs / DNAT sub-tab + VIP Groups
    vip_tbls = [b for b in nat_sub["Virtual IPs / DNAT"]["blocks"] if b["type"] == "table"]
    vip_tbl, vg_tbl = vip_tbls[0], vip_tbls[1]
    assert vip_tbl["legend"] and vg_tbl["legend"]
    vips_by_name = {r["Name"]: r for r in vip_tbl["rows"]}
    assert vips_by_name["VIP_RANGE_WEB"]["Mapped From"] == "198.51.100.10-198.51.100.20:8443"
    assert vips_by_name["VIP_RANGE_WEB"]["Mapped To"] == "10.10.1.10-10.10.1.20:443"
    assert vips_by_name["VIP_RANGE_WEB"]["Port Forward"] == "Enable"
    assert vips_by_name["VIP_RANGE_WEB"]["Src Filter"] == "192.0.2.0/24"
    assert "#3 (In-VIP-Group)" in vips_by_name["VIP_RANGE_WEB"]["Used By Policies"]
    assert vips_by_name["VIP_UNUSED"]["Used By Policies"] == "Unused"
    assert "#3 (In-VIP-Group)" in vg_tbl["rows"][0]["Used By Policies"]

    # IP Pools sub-tab
    pool_tbl = next(b for b in nat_sub["IP Pools"]["blocks"] if b["type"] == "table")
    assert pool_tbl["legend"]
    pools_by_name = {r["Name"]: r for r in pool_tbl["rows"]}
    assert pools_by_name["SNAT_POOL_1"]["Source IP Range"] == "10.10.1.0 - 10.10.1.255"
    assert pools_by_name["SNAT_POOL_1"]["Port Range"] == "1024 - 65535"
    assert pools_by_name["SNAT_POOL_1"]["Associated Interface"] == "wan1"
    assert "Policy #2" in pools_by_name["SNAT_POOL_1"]["Used By Policies"]
    assert pools_by_name["UNUSED_POOL"]["Used By Policies"] == "Unused"

    # Central SNAT mode
    fg_central_conf = fg_nat_conf + b"""
config system settings
    set central-nat enable
end
config firewall central-snat-map
    edit 10
        set srcintf "internal"
        set dstintf "wan1"
        set orig-addr "all"
        set dst-addr "all"
        set nat enable
        set nat-ippool "SNAT_POOL_1"
        set comments "Central outbound"
    next
end
"""
    c_client = make_client()
    assert c_client.post("/api/upload", files={"file": ("fg_central.conf", fg_central_conf, "text/plain")}).status_code == 200
    c_po = c_client.get("/api/fg/Policy & Objects").json()
    c_tabs = {t["label"]: t for t in c_po["blocks"][0]["tabs"]}
    c_fw_tbl = next(b for b in c_tabs["Firewall Policy"]["blocks"] if b["type"] == "table")
    assert c_fw_tbl["rows"][0]["NAT"] == "Central NAT"
    c_nat_blocks = c_tabs["NAT"]["blocks"]
    assert "Central NAT mode is enabled" in c_nat_blocks[0]["text"]
    c_sub = {t["label"].split(" (")[0]: t for t in c_nat_blocks[1]["tabs"]}
    csnat_tbl = next(b for b in c_sub["Outbound SNAT"]["blocks"] if b["type"] == "table")
    assert csnat_tbl["legend"]
    assert csnat_tbl["rows"][0]["ID"] == "10"
    assert csnat_tbl["rows"][0]["IP Pool"] == "SNAT_POOL_1"
    c_pool_tbl = next(b for b in c_sub["IP Pools"]["blocks"] if b["type"] == "table")
    assert "Central SNAT #10" in {r["Name"]: r for r in c_pool_tbl["rows"]}["SNAT_POOL_1"]["Used By Policies"]


def test_unified_ui_semantics_simulators_and_drilldowns():
    # 1. FortiGate: Overview HA card, disabled policy = row-danger, unified simulator block
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-UNIFIED"
end
config system interface
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
end
config firewall policy
    edit 1
        set name "Active-Rule"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set status enable
    next
    edit 2
        set name "Disabled-Rule"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set status disable
    next
end
"""
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("fg_uni.conf", fg_conf, "text/plain")}).status_code == 200

    fg_ov = fg_client.get("/api/fg/Overview").json()
    assert any(b["type"] == "section_header" and b["title"] == "High Availability" for b in fg_ov["blocks"])
    assert any(b["type"] == "card" and b.get("title") == "Standalone Mode" for b in fg_ov["blocks"])

    fg_pol = fg_client.get("/api/fg/Policies & NAT").json()
    fw_tab = next(t for t in fg_pol["blocks"][0]["tabs"] if t["label"] == "Firewall Policy")
    assert fw_tab["count"] == 2
    assert any(b["type"] == "policy_simulator" and b["vendor"] == "fg" for b in fw_tab["blocks"])
    fw_tbl = next(b for b in fw_tab["blocks"] if b["type"] == "table")
    assert fw_tbl["row_classes"] == ["", "row-danger"]
    assert any(item["variant"] == "danger" for item in fw_tbl["legend"])

    # 2. Palo Alto: Overview HA hero badge, superuser = row-warn, sub-interface = row-purple,
    #    Setup uses kv_grid instead of _dict_table_block, IPSec profile_selector drilldown,
    #    and policy-test shadowed rule detection + legend
    pa_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config>
    <users>
      <entry name="readonly_ops"><permissions><role-based><superreader/></role-based></permissions></entry>
      <entry name="netadmin"><permissions><role-based><superuser/></role-based></permissions></entry>
    </users>
  </mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-UNIFIED</hostname>
          <ip-address>192.168.1.10</ip-address>
          <netmask>255.255.255.0</netmask>
          <timezone>UTC</timezone>
        </system>
      </deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <aggregate-group>ae1</aggregate-group>
            </entry>
          </ethernet>
          <aggregate-ethernet>
            <entry name="ae1">
              <layer3>
                <ip><entry name="10.0.0.1/24"/></ip>
                <units>
                  <entry name="ae1.10">
                    <tag>10</tag>
                    <ip><entry name="10.0.10.1/24"/></ip>
                  </entry>
                </units>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="IKE-PROF-1"><encryption><member>aes-256-cbc</member></encryption><hash><member>sha256</member></hash><dh-group><member>group14</member></dh-group></entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="IPSEC-PROF-1"><esp><encryption><member>aes-256-gcm</member></encryption><authentication><member>sha256</member></authentication></esp><dh-group>group14</dh-group></entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="GW-HQ">
              <protocol><version>ikev2</version><ikev2><ike-crypto-profile>IKE-PROF-1</ike-crypto-profile></ikev2></protocol>
              <local-address><interface>ethernet1/1</interface><ip>10.0.0.1/24</ip></local-address>
              <peer-address><ip>198.51.100.2</ip></peer-address>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="TUN-HQ">
              <tunnel-interface>tunnel.1</tunnel-interface>
              <auto-key><ike-gateway><entry name="GW-HQ"/></ike-gateway><ipsec-crypto-profile>IPSEC-PROF-1</ipsec-crypto-profile></auto-key>
            </entry>
          </ipsec>
        </tunnel>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"/>
          </zone>
          <rulebase>
            <security>
              <rules>
                <entry name="Allow-Specific">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>10.0.0.0/24</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                </entry>
                <entry name="Shadowed-Any">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
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
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_uni.xml", pa_xml, "application/xml")}).status_code == 200

    pa_ov = pa_client.get("/api/pa/Overview").json()
    pa_hero = next(b for b in pa_ov["blocks"] if b["type"] == "hero")
    assert any(b["text"] == "Standalone" for b in pa_hero["badges"])

    pa_pol = pa_client.get("/api/pa/Policies & NAT").json()
    sec_tab = next(t for t in pa_pol["blocks"][0]["tabs"] if t["label"] == "Security")
    assert sec_tab["count"] == 2
    assert any(b["type"] == "policy_simulator" and b["vendor"] == "pa" for b in sec_tab["blocks"])

    match = pa_client.post(
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
    ).json()
    assert match["matched"] is True
    assert match["table"]["legend"]
    assert any(b["type"] == "card" and "Allow-Specific" in b["title"] for b in match["blocks"])
    assert any(b["type"] == "alert" and "1 subsequent shadowed" in b["text"] for b in match["blocks"])
    sh_exp = next(b for b in match["blocks"] if b["type"] == "expander")
    assert sh_exp["blocks"][0]["rows"][0]["Rule Name"] == "Shadowed-Any"

    pa_net = pa_client.get("/api/pa/Interfaces & Network").json()
    intf_tab = next(t for t in pa_net["blocks"][0]["tabs"] if t["label"] == "Interfaces")
    eth_tab = next(t for t in intf_tab["blocks"][0]["tabs"] if t["label"] == "Ethernet / Aggregate")
    eth_tbl = next(b for b in eth_tab["blocks"] if b["type"] == "table")
    eth_cls = {r["Interface"].replace("└", "").strip(): cls for r, cls in zip(eth_tbl["rows"], eth_tbl["row_classes"])}
    assert eth_cls["ae1"] == "row-info"
    assert eth_cls["ae1.10"] == "row-purple"

    pa_vpn = pa_client.get("/api/pa/VPN").json()
    tun_tab = next(t for t in pa_vpn["blocks"][0]["tabs"] if t["label"] == "IPSec Tunnels")
    sel = next(b for b in tun_tab["blocks"] if b["type"] == "profile_selector")
    assert sel["options"][0]["name"] == "TUN-HQ"

    pa_sys = pa_client.get("/api/pa/System & Logs").json()
    setup_tab = next(t for t in pa_sys["blocks"][0]["tabs"] if t["label"] == "Setup")
    assert any(b["type"] == "kv_grid" for b in setup_tab["blocks"])
    assert not any(b.get("id") == "pa_gen_settings" for b in setup_tab["blocks"])

    adm_tab = next(t for t in pa_sys["blocks"][0]["tabs"] if t["label"] == "Administrators")
    adm_tbl = next(b for b in adm_tab["blocks"] if b["type"] == "table" and b["id"] == "pa_admins")
    assert adm_tbl["rows"][0]["Name"] == "netadmin"
    assert adm_tbl["row_classes"][0] == "row-warn"
    assert adm_tbl["legend"]


def test_admin_hardening_parsers_display_and_audit():
    # 1. FortiGate: trusthost7, lockout disabled (0), password-policy disabled, super_admin without 2FA
    fg_unhardened = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-ADM-AUDIT"
    set admin-lockout-threshold 0
    set admin-lockout-duration 60
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
    edit "ops_ro"
        set accprofile "read_only"
        set trusthost7 10.10.0.0 255.255.0.0
    next
end
"""
    fg_c1 = make_client()
    assert fg_c1.post("/api/upload", files={"file": ("fg_unh.conf", fg_unhardened, "text/plain")}).status_code == 200

    fg_sys1 = fg_c1.get("/api/fg/System & Logs").json()
    adm_tab1 = next(t for t in fg_sys1["blocks"][0]["tabs"] if t["label"] == "Administrators")
    adm_tbl1 = next(b for b in adm_tab1["blocks"] if b["type"] == "table")
    by_adm1 = {r["Name"]: r for r in adm_tbl1["rows"]}
    assert by_adm1["admin"]["Trusted Hosts"] == "Any"
    assert "10.10.0.0 255.255.0.0" in by_adm1["ops_ro"]["Trusted Hosts"]

    set_tab1 = next(t for t in fg_sys1["blocks"][0]["tabs"] if t["label"] == "Settings")
    kv_items1 = {i["label"]: i["value"] for b in set_tab1["blocks"] if b["type"] == "kv_grid" for i in b["items"]}
    assert kv_items1["Admin Lockout Threshold"] == "Disabled"
    assert kv_items1["Minimum Length"] == "Disabled"

    fg_health1 = fg_c1.get("/api/fg/Security & Health").json()
    audit_exp1 = next(b for b in fg_health1["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    cats1 = {r["Category"]: r for r in audit_exp1["blocks"][1]["rows"]}
    assert "Admin Accounts Without Trusted Hosts" in cats1
    assert "Super-Admin Accounts Without 2FA" in cats1
    assert "Admin Password Policy Disabled" in cats1
    assert "Admin Login Lockout Disabled or Weak" in cats1

    # Hardened FortiGate: trusthost + 2FA + password-policy enabled + lockout=3
    fg_hardened = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-ADM-HARD"
    set admin-lockout-threshold 3
    set admin-lockout-duration 120
end
config system password-policy
    set status enable
    set apply-to admin-password
    set minimum-length 14
    set min-upper-case-letter 1
    set min-lower-case-letter 1
    set min-number 1
    set min-non-alphanumeric 1
    set expire-status enable
    set expire-day 90
    set reuse-password disable
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost7 10.10.0.0/16
        set two-factor fortitoken
    next
end
"""
    fg_c2 = make_client()
    assert fg_c2.post("/api/upload", files={"file": ("fg_hard.conf", fg_hardened, "text/plain")}).status_code == 200
    fg_sys2 = fg_c2.get("/api/fg/System & Logs").json()
    set_tab2 = next(t for t in fg_sys2["blocks"][0]["tabs"] if t["label"] == "Settings")
    kv_items2 = {i["label"]: i["value"] for b in set_tab2["blocks"] if b["type"] == "kv_grid" for i in b["items"]}
    assert kv_items2["Admin Lockout Threshold"] == "3 attempts / 120s"
    assert kv_items2["Minimum Length"] == "14"
    assert kv_items2["Expiry Days"] == "90 days"
    fg_health2 = fg_c2.get("/api/fg/Security & Health").json()
    audit_exp2 = next(b for b in fg_health2["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    assert audit_exp2["blocks"][1]["variant"] == "success"

    # 2. Palo Alto: MGT Permitted IPs display + unrestricted MGT & disabled complexity audit
    pa_unhardened = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config>
    <users>
      <entry name="admin"><permissions><role-based><superuser/></role-based></permissions></entry>
    </users>
  </mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-ADM-UNH</hostname>
          <ip-address>192.168.1.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <password-complexity><enabled>no</enabled></password-complexity>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""
    pa_c1 = make_client()
    assert pa_c1.post("/api/upload", files={"file": ("pa_unh.xml", pa_unhardened, "application/xml")}).status_code == 200
    pa_sys1 = pa_c1.get("/api/pa/System & Logs").json()
    pa_setup1 = next(t for t in pa_sys1["blocks"][0]["tabs"] if t["label"] == "Setup")
    pa_kv1 = {i["label"]: i["value"] for b in pa_setup1["blocks"] if b["type"] == "kv_grid" for i in b["items"]}
    assert pa_kv1["Permitted IPs"] == "Any (Unrestricted)"

    pa_health1 = pa_c1.get("/api/pa/Security & Health").json()
    pa_audit1 = next(b for b in pa_health1["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    pa_cats1 = {r["Category"]: r for r in pa_audit1["blocks"][1]["rows"]}
    assert "Management Interface Unrestricted (Permitted IPs: Any)" in pa_cats1
    assert "Admin Password Complexity Disabled" in pa_cats1
    assert "Admin Login Lockout Not Configured" in pa_cats1
    assert "Local Superuser Without External Auth Profile" in pa_cats1

    # Hardened Palo Alto
    pa_hardened = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config>
    <users>
      <entry name="admin">
        <authentication-profile>LDAP-MFA</authentication-profile>
        <permissions><role-based><superuser/></role-based></permissions>
      </entry>
    </users>
  </mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-ADM-HARD</hostname>
          <ip-address>192.168.1.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <failed-attempts>5</failed-attempts>
          <lockout-time>15</lockout-time>
          <permitted-ip><entry name="10.10.0.0/16"/></permitted-ip>
          <password-complexity><enabled>yes</enabled><minimum-length>12</minimum-length></password-complexity>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
"""
    pa_c2 = make_client()
    assert pa_c2.post("/api/upload", files={"file": ("pa_hard.xml", pa_hardened, "application/xml")}).status_code == 200
    pa_sys2 = pa_c2.get("/api/pa/System & Logs").json()
    pa_setup2 = next(t for t in pa_sys2["blocks"][0]["tabs"] if t["label"] == "Setup")
    pa_kv2 = {i["label"]: i["value"] for b in pa_setup2["blocks"] if b["type"] == "kv_grid" for i in b["items"]}
    assert pa_kv2["Permitted IPs"] == "10.10.0.0/16"
    pa_health2 = pa_c2.get("/api/pa/Security & Health").json()
    pa_audit2 = next(b for b in pa_health2["blocks"] if b["type"] == "expander" and "Quick Security & Hygiene Audit" in b["title"])
    assert pa_audit2["blocks"][1]["variant"] == "success"
