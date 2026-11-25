"""Hardware and firmware EoL/EoS lifecycle evaluation tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from server import create_app
from tests.helpers import SAMPLE_FG_CONF, SAMPLE_PA_XML


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
    sec_health = client.get("/api/fg/Security & Health").json()
    lc_card = next(b for b in sec_health["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
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

    # Subsequent Security & Health uses warm cache immediately with no async_refresh_url
    health_warm = client.get("/api/fg/Security & Health").json()
    assert fetch_calls == {"eol": 1, "rss": 1}
    lc_card_warm = next(b for b in health_warm["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
    assert "async_refresh_url" not in lc_card_warm
    warm_rows = {r["label"]: r for r in lc_card_warm["rows"]}
    assert "7.2.15" in warm_rows["Latest Firmware in Branch"]["value"]

    # 6. Security & Health API with DISABLE_ONLINE_CHECKS=1 never triggers async refresh
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "1")
    health_off = client.get("/api/fg/Security & Health").json()
    lc_card_off = next(b for b in health_off["blocks"] if b["type"] == "card" and b.get("title") == "Lifecycle & Firmware")
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
    pa_health = client.get("/api/pa/Security & Health").json()
    pa_card = next(b for b in pa_health["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
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

    # Subsequent Security & Health uses warm cache directly
    health_warm = client.get("/api/pa/Security & Health").json()
    assert calls["panos"] == 1
    pa_card_warm = next(b for b in health_warm["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    assert "async_refresh_url" not in pa_card_warm
    assert "11.1.17-h1" in {r["label"]: r["value"] for r in pa_card_warm["rows"]}["Latest Patch in Branch"]

    # 4. Schema-only XML (no detail-version) adds helpful note in Current PAN-OS row
    ls.clear_lifecycle_cache()
    monkeypatch.setenv("DISABLE_ONLINE_CHECKS", "1")
    client2 = TestClient(create_app())
    assert client2.post("/api/upload", files={"file": ("pa_schema.xml", SAMPLE_PA_XML, "text/xml")}).status_code == 200
    health_schema = client2.get("/api/pa/Security & Health").json()
    pa_card_schema = next(b for b in health_schema["blocks"] if b["type"] == "card" and b.get("title") == "PAN-OS Firmware")
    schema_rows = {r["label"]: r["value"] for r in pa_card_schema["rows"]}
    assert "XML schema version" in schema_rows["Current PAN-OS"]
    assert "async_refresh_url" not in pa_card_schema
