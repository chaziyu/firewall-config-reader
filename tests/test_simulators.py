"""Policy lookup/match, LPM route lookup, where-used, config diff, and packet trace simulators."""

from __future__ import annotations

from fastapi.testclient import TestClient

from server import create_app
from tests.helpers import SAMPLE_PA_XML, make_client


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
    fg_client = make_client()
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
    pa_client = make_client()
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


def test_config_diff_fortigate_and_paloalto():
    fg_before = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-DIFF"
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
end
config firewall policy
    edit 1
        set name "Allow-Web"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTP"
    next
    edit 2
        set name "Legacy-Rule"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "TELNET"
    next
end
"""
    fg_after = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-DIFF"
end
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set status up
    next
end
config firewall policy
    edit 1
        set name "Allow-Web"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
    next
    edit 3
        set name "Allow-DNS"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "DNS"
    next
end
"""
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("before.conf", fg_before, "text/plain")}).status_code == 200
    fg_sum = fg_client.get("/api/fg/Summary").json()
    assert any(b.get("type") == "config_diff" and b.get("vendor") == "fg" for b in fg_sum["blocks"])

    same_res = fg_client.post("/api/fg/config-diff", files={"file": ("same.conf", fg_before, "text/plain")}).json()
    assert same_res["has_diff"] is False

    diff_res = fg_client.post("/api/fg/config-diff", files={"file": ("after.conf", fg_after, "text/plain")}).json()
    assert diff_res["has_diff"] is True
    assert diff_res["summary"] == {"added": 1, "modified": 1, "removed": 1, "total": 3}
    pol_exp = next(b for b in diff_res["blocks"] if b["type"] == "expander" and b["title"].startswith("Firewall Policies"))
    pol_tbl = pol_exp["blocks"][0]
    assert pol_tbl["legend"]
    by_item = {r["Item"]: (r["Change"], pol_tbl["row_classes"][i]) for i, r in enumerate(pol_tbl["rows"])}
    assert by_item["#1 (Allow-Web)"] == ("Modified", "row-warn")
    assert by_item["#2 (Legacy-Rule)"] == ("Removed", "row-danger")
    assert by_item["#3 (Allow-DNS)"] == ("Added", "row-success")

    # Palo Alto Config Diff
    pa_after = SAMPLE_PA_XML.replace(b"<member>web-browsing</member>", b"<member>ssl</member>")
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_before.xml", SAMPLE_PA_XML, "application/xml")}).status_code == 200
    pa_diff = pa_client.post("/api/pa/config-diff", files={"file": ("pa_after.xml", pa_after, "application/xml")}).json()
    assert pa_diff["has_diff"] is True
    assert pa_diff["summary"]["modified"] == 1


def test_packet_trace_simulator_fortigate_and_paloalto():
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-TRACE"
end
config system interface
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
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
config firewall address
    edit "LAN_NET"
        set subnet 10.10.1.0 255.255.255.0
    next
end
config firewall vip
    edit "RDP_VIP"
        set extip 1.1.1.10
        set extintf "wan1"
        set portforward enable
        set mappedip "10.10.1.50"
        set extport 3389
        set mappedport 3389
    next
end
config firewall policy
    edit 1
        set name "Allow-Outbound"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set service "HTTPS"
        set nat enable
    next
    edit 2
        set name "Allow-VIP-RDP"
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "RDP_VIP"
        set service "RDP"
        set nat disable
    next
end
"""
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("fg_trace.conf", fg_conf, "text/plain")}).status_code == 200
    fg_sum = fg_client.get("/api/fg/Summary").json()
    assert any(b.get("type") == "packet_trace" and b.get("vendor") == "fg" for b in fg_sum["blocks"])

    bad = fg_client.post("/api/fg/packet-trace", json={"src_ip": "bad-ip", "dst_ip": "8.8.8.8"}).json()
    assert bad["ok"] is False

    out_trace = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "10.10.1.5", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp"},
    ).json()
    assert out_trace["ok"] is True
    assert out_trace["verdict"] == "ALLOW"
    kv_out = {i["label"]: i["value"] for i in out_trace["blocks"][1]["items"]}
    assert kv_out["Ingress"] == "internal"
    assert kv_out["Egress"] == "wan1"
    assert "#1" in kv_out["Policy Decision"]
    assert "SNAT Enabled" in kv_out["NAT"]
    step_tbl = next(b for b in out_trace["blocks"] if b["type"] == "table")
    assert step_tbl["legend"]

    vip_trace = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "8.8.8.8", "dst_ip": "1.1.1.10", "dst_port": "3389", "protocol": "tcp"},
    ).json()
    assert vip_trace["ok"] is True
    assert vip_trace["verdict"] == "ALLOW"
    kv_vip = {i["label"]: i["value"] for i in vip_trace["blocks"][1]["items"]}
    assert "DNAT (RDP_VIP)" in kv_vip["NAT"]
    assert "#2" in kv_vip["Policy Decision"]

    # Same connected subnet -> L2 DIRECT (not misleading Implicit DENY)
    l2_trace = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "10.10.1.5", "dst_ip": "10.10.1.20", "dst_port": "443", "protocol": "tcp"},
    ).json()
    assert l2_trace["verdict"] == "L2 DIRECT"
    assert l2_trace["blocks"][0]["badge"]["variant"] == "info"

    # Firewall own interface IP -> LOCAL-IN
    local_trace = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "10.10.1.5", "dst_ip": "10.10.1.1", "dst_port": "443", "protocol": "tcp"},
    ).json()
    assert local_trace["verdict"] == "LOCAL-IN"

    # Palo Alto Packet Trace
    pa_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-TRACE</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
            <entry name="ethernet1/2"><layer3><ip><entry name="1.1.1.10/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
            <routing-table><ip><static-route>
              <entry name="Default">
                <destination>0.0.0.0/0</destination>
                <interface>ethernet1/2</interface>
                <nexthop><ip-address>1.1.1.1</ip-address></nexthop>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
          </zone>
          <rulebase>
            <security><rules>
              <entry name="Allow-Internet">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <application><member>any</member></application>
                <service><member>any</member></service>
                <action>allow</action>
              </entry>
            </rules></security>
            <nat><rules>
              <entry name="Outbound-SNAT">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface></interface-address></dynamic-ip-and-port></source-translation>
              </entry>
            </rules></nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_trace.xml", pa_xml, "application/xml")}).status_code == 200
    pa_dash = pa_client.get("/api/pa/Dashboard").json()
    assert any(b.get("type") == "packet_trace" and b.get("vendor") == "pa" for b in pa_dash["blocks"])

    pa_tr = pa_client.post(
        "/api/pa/packet-trace",
        json={"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp", "virtual_router": "default"},
    ).json()
    assert pa_tr["ok"] is True
    assert pa_tr["verdict"] == "ALLOW"
    pa_kv = {i["label"]: i["value"] for i in pa_tr["blocks"][1]["items"]}
    assert "trust" in pa_kv["Ingress"]
    assert "untrust" in pa_kv["Egress"]
    assert "Allow-Internet" in pa_kv["Policy Decision"]
    assert "Outbound-SNAT" in pa_kv["NAT"]

    # Palo Alto same connected subnet -> L2 DIRECT
    pa_l2 = pa_client.post(
        "/api/pa/packet-trace",
        json={"src_ip": "10.0.0.5", "dst_ip": "10.0.0.20", "dst_port": "443", "protocol": "tcp", "virtual_router": "default"},
    ).json()
    assert pa_l2["verdict"] == "L2 DIRECT"


def test_bidirectional_return_path_trace_and_quick_search():
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-RET"
end
config system interface
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set status up
    next
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
config firewall policy
    edit 1
        set name "Allow-Out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
    edit 2
        set name "Hairpin-WAN"
        set srcintf "wan1"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("ret.conf", fg_conf, "text/plain")}).status_code == 200

    # Global Ctrl+K Quick Search elements rendered in /workspace HTML
    ws_html = fg_client.get("/workspace").text
    assert 'id="fw-quicksearch-btn"' in ws_html
    assert 'id="fw-qs-modal"' in ws_html

    # 1. Symmetric return path (check_return=True default)
    sym = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "10.10.1.5", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp"},
    ).json()
    kv_sym = {i["label"]: i["value"] for i in sym["blocks"][1]["items"]}
    assert "Symmetric" in kv_sym["Return Path"]
    tbl_sym = next(b for b in sym["blocks"] if b["type"] == "table")
    ret_idx = next(i for i, r in enumerate(tbl_sym["rows"]) if r["Stage"] == "Return Path & Symmetry Check")
    assert tbl_sym["row_classes"][ret_idx] == "row-success"

    # 2. Asymmetric / hairpin on same interface -> row-warn
    hair = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "9.9.9.9", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp"},
    ).json()
    kv_hair = {i["label"]: i["value"] for i in hair["blocks"][1]["items"]}
    assert "Asymmetric / Hairpin" in kv_hair["Return Path"]
    tbl_hair = next(b for b in hair["blocks"] if b["type"] == "table")
    hair_idx = next(i for i, r in enumerate(tbl_hair["rows"]) if r["Stage"] == "Return Path & Symmetry Check")
    assert tbl_hair["row_classes"][hair_idx] == "row-warn"

    # 3. check_return=False omits return-path check
    no_ret = fg_client.post(
        "/api/fg/packet-trace",
        json={"src_ip": "10.10.1.5", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp", "check_return": False},
    ).json()
    kv_no_ret = {i["label"]: i["value"] for i in no_ret["blocks"][1]["items"]}
    assert "Return Path" not in kv_no_ret
    tbl_no_ret = next(b for b in no_ret["blocks"] if b["type"] == "table")
    assert not any(r["Stage"] == "Return Path & Symmetry Check" for r in tbl_no_ret["rows"])

    # 4. Palo Alto: missing return route -> row-danger + RPF warning
    pa_no_ret_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system><hostname>PA-RET</hostname></system></deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry>
            <entry name="ethernet1/2"><layer3><ip><entry name="1.1.1.10/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
            <routing-table><ip><static-route>
              <entry name="To-Ext">
                <destination>8.8.8.0/24</destination>
                <interface>ethernet1/2</interface>
                <nexthop><ip-address>1.1.1.1</ip-address></nexthop>
              </entry>
            </static-route></ip></routing-table>
          </entry>
        </virtual-router>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
            <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
          </zone>
          <rulebase>
            <security><rules>
              <entry name="Allow-Any">
                <from><member>any</member></from>
                <to><member>untrust</member></to>
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <application><member>any</member></application>
                <service><member>any</member></service>
                <action>allow</action>
              </entry>
            </rules></security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""
    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_ret.xml", pa_no_ret_xml, "application/xml")}).status_code == 200
    pa_ws = pa_client.get("/workspace").text
    assert 'id="fw-quicksearch-btn"' in pa_ws
    assert 'id="fw-qs-modal"' in pa_ws

    pa_miss_ret = pa_client.post(
        "/api/pa/packet-trace",
        json={"src_ip": "172.16.99.5", "dst_ip": "8.8.8.8", "dst_port": "443", "protocol": "tcp", "virtual_router": "default"},
    ).json()
    pa_kv = {i["label"]: i["value"] for i in pa_miss_ret["blocks"][1]["items"]}
    assert "No Return Route" in pa_kv["Return Path"]
    pa_tbl = next(b for b in pa_miss_ret["blocks"] if b["type"] == "table")
    pa_ret_idx = next(i for i, r in enumerate(pa_tbl["rows"]) if r["Stage"] == "Return Path & Symmetry Check")
    assert pa_tbl["row_classes"][pa_ret_idx] == "row-danger"
    assert any(b["type"] == "alert" and b["variant"] == "warn" and "Return path check" in b["text"] for b in pa_miss_ret["blocks"])
