"""Tests for backup-config Preventive Maintenance (PM) Lookup for FortiGate and Palo Alto."""

from __future__ import annotations

from datetime import date, timedelta

from tests.helpers import upload_config


def test_fortigate_pm_lookup_api_and_checks():
    # 1. Config with GMT+8 timezone (57), NTP enabled, FortiAnalyzer + Syslog, and unrestricted public WAN HTTP/SSH
    fg_conf = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-PM-01"
    set timezone 57
end
config system ntp
    set status enable
    set server "time.google.com"
end
config system interface
    edit "wan1"
        set ip 8.8.8.8 255.255.255.0
        set allowaccess ping http https ssh
        set status up
    next
    edit "internal"
        set ip 10.10.1.1 255.255.255.0
        set allowaccess ping https ssh
        set status up
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 8.8.8.1
        set device "wan1"
    next
end
config log fortianalyzer setting
    set status enable
    set server "10.10.1.50"
end
config log syslogd setting
    set status enable
    set server "10.10.1.60"
end
"""
    client = upload_config("fg_pm.conf", fg_conf, "text/plain")
    res = client.get("/api/fg/PM Lookup")
    assert res.status_code == 200
    data = res.json()
    assert data["section"] == "PM Lookup"

    blocks = data["blocks"]
    tbl = next(b for b in blocks if b["type"] == "table")
    assert tbl["filter_col"] == "Status"
    assert tbl["legend"]
    assert len(tbl["rows"]) == 15
    assert len(tbl["row_classes"]) == 15

    tasks = {r["Task"] for r in tbl["rows"]}
    # Live-only manual items must NOT be displayed
    for omitted in (
        "CPU Usage",
        "Memory Usage",
        "FortiCare Support",
        "UTM Bundle Update",
        "Firewall System Uptime",
        "Signatures Version",
        "Check Latest Preferred Firmware",
    ):
        assert omitted not in tasks

    by_no = {r["No."]: (r, tbl["row_classes"][i]) for i, r in enumerate(tbl["rows"])}
    assert by_no["6.5"][0]["Status"] == "Pass"
    assert by_no["6.5"][1] == "row-success"
    assert "GMT+8" in by_no["6.5"][0]["Config Finding"]
    assert "time.google.com" in by_no["6.5"][0]["Config Finding"]

    assert by_no["6.9"][0]["Status"] == "Pass"
    assert "FortiAnalyzer (10.10.1.50)" in by_no["6.9"][0]["Config Finding"]
    assert "Syslog (10.10.1.60)" in by_no["6.9"][0]["Config Finding"]

    # Unrestricted public HTTP/HTTPS/SSH on wan1 -> Fail (row-danger)
    assert by_no["6.2"][0]["Status"] == "Fail"
    assert by_no["6.2"][1] == "row-danger"
    assert by_no["6.3"][0]["Status"] == "Fail"
    assert by_no["6.3"][1] == "row-danger"

    # 2. Non-GMT+8 timezone, disabled NTP, and no log manager -> Warn (row-warn)
    fg_warn = b"""#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-PM-WARN"
    set timezone 04
end
config system ntp
    set status disable
end
config log fortianalyzer setting
    set status disable
end
"""
    warn_client = upload_config("fg_pm_warn.conf", fg_warn, "text/plain")
    warn_tbl = next(b for b in warn_client.get("/api/fg/PM Lookup").json()["blocks"] if b["type"] == "table")
    warn_by_no = {r["No."]: (r, warn_tbl["row_classes"][i]) for i, r in enumerate(warn_tbl["rows"])}
    assert warn_by_no["6.5"][0]["Status"] == "Warn"
    assert warn_by_no["6.5"][1] == "row-warn"
    assert warn_by_no["6.9"][0]["Status"] == "Warn"
    assert warn_by_no["6.9"][1] == "row-warn"


def test_paloalto_pm_lookup_api_and_checks():
    pa_xml = b"""<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>PA-PM-01</hostname>
          <ip-address>192.168.10.5</ip-address>
          <netmask>255.255.255.0</netmask>
          <timezone>Asia/Singapore</timezone>
          <permitted-ip>
            <entry name="10.0.0.0/8"/>
          </permitted-ip>
          <service>
            <disable-http>yes</disable-http>
            <disable-https>no</disable-https>
            <disable-ssh>no</disable-ssh>
          </service>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>10.0.0.10</ntp-server-address>
            </primary-ntp-server>
          </ntp-servers>
        </system>
      </deviceconfig>
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="10.1.1.1/24"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""
    client = upload_config("pa_pm.xml", pa_xml, "application/xml")
    res = client.get("/api/pa/PM Lookup")
    assert res.status_code == 200
    data = res.json()
    assert data["section"] == "PM Lookup"

    tbl = next(b for b in data["blocks"] if b["type"] == "table")
    assert tbl["filter_col"] == "Status"
    assert tbl["legend"]
    assert len(tbl["rows"]) == 10
    assert len(tbl["row_classes"]) == 10

    tasks = {r["Task"] for r in tbl["rows"]}
    for omitted in (
        "CPU Usage",
        "Memory Usage",
        "Redundant Power Supply",
        "Hardware Support",
        "Feature License",
        "Firewall System Uptime",
        "Check Latest Preferred Firmware",
    ):
        assert omitted not in tasks

    by_no = {r["No."]: (r, tbl["row_classes"][i]) for i, r in enumerate(tbl["rows"])}
    assert by_no["4.2"][0]["Status"] == "Pass"
    assert by_no["4.2"][1] == "row-success"
    assert by_no["4.3"][0]["Status"] == "Pass"
    assert by_no["4.5"][0]["Status"] == "Pass"
    assert "Asia/Singapore" in by_no["4.5"][0]["Config Finding"]
    assert "10.0.0.10" in by_no["4.5"][0]["Config Finding"]

    expected_90d = (date.today() - timedelta(days=90)).strftime("%Y/%m/%d")
    assert f"receive_time geq '{expected_90d} 00:00:00'" in by_no["4.8"][0]["Recommendation / Follow-up"]
