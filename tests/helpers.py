"""Shared fixtures and helpers for Firewall Config Reader test suite."""

from __future__ import annotations

import io
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


def make_client() -> TestClient:
    """Create a TestClient bound to local loopback (127.0.0.1)."""
    return TestClient(create_app(), client=("127.0.0.1", 50000))


def upload_config(filename: str, content: bytes, content_type: str = "text/plain") -> TestClient:
    """Create a loopback TestClient, upload a config file, assert 200, and return the client."""
    client = make_client()
    res = client.post("/api/upload", files={"file": (filename, content, content_type)})
    assert res.status_code == 200, f"Upload failed for {filename}: {res.text}"
    return client


def make_tsf_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("logs/mp-log/authd.log", "2026-01-01 INFO authd started\n2026-01-01 ERROR login failed for admin\n")
        zf.writestr("opt/pancfg/running-config.xml", "<config><hostname>PA-TSF</hostname></config>\n")
    return buf.getvalue()
