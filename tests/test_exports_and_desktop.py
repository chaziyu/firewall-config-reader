"""Excel export, HTML audit report, auto-updater, and desktop window geometry/state tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from server import create_app
from tests.helpers import SAMPLE_FG_CONF, SAMPLE_PA_XML, make_client


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

    client = make_client()
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
    assert wb_pa.sheetnames == [
        "Overview",
        "PM Lookup",
        "Policies & NAT",
        "Objects",
        "Interfaces & Network",
        "Security Profiles",
        "VPN",
        "Users & Auth",
        "System & Logs",
    ]
    assert any(
        cell.fill and cell.fill.fill_type == "solid"
        for row in wb_pa["Policies & NAT"].iter_rows()
        for cell in row
    )
    assert (wb_pa["Policies & NAT"].column_dimensions["A"].width or 0) >= 12

    # 2. FortiGate
    fg_client = TestClient(create_app())
    assert fg_client.post("/api/upload", files={"file": ("fg_sample.conf", SAMPLE_FG_CONF, "text/plain")}).status_code == 200

    fg_res = fg_client.get("/api/export/excel")
    assert fg_res.status_code == 200
    assert "fg_sample_export.xlsx" in fg_res.headers.get("content-disposition", "")
    wb_fg = load_workbook(io.BytesIO(fg_res.content))
    assert wb_fg.sheetnames == [
        "Overview",
        "PM Lookup",
        "Policies & NAT",
        "Objects",
        "Interfaces & Network",
        "Security Profiles",
        "VPN",
        "Users & Auth",
        "WiFi & Switch",
        "System & Logs",
    ]
    assert any(
        cell.fill and cell.fill.fill_type == "solid"
        for row in wb_fg["Policies & NAT"].iter_rows()
        for cell in row
    )


def test_desktop_exe_excel_export_direct_save_with_dedup(monkeypatch, tmp_path):
    import backend.excel_export as excel_mod
    import backend.update_service as upd_mod

    monkeypatch.setattr(upd_mod, "is_frozen_desktop_exe", lambda: True)
    monkeypatch.setattr(excel_mod, "get_downloads_dir", lambda: tmp_path)

    client = make_client()
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


def test_audit_report_html_export_fortigate_and_paloalto():
    fg_xss = SAMPLE_FG_CONF.replace(b'FGT-EDGE-01', b'FGT-<svg>&test')
    fg_client = make_client()
    assert fg_client.post("/api/upload", files={"file": ("edge_fw.conf", fg_xss, "text/plain")}).status_code == 200
    rep = fg_client.get("/api/export/report")
    assert rep.status_code == 200
    assert "text/html" in rep.headers.get("content-type", "")
    assert "edge_fw_audit_report.html" in rep.headers.get("content-disposition", "")
    body = rep.text
    assert "<svg>" not in body
    assert "FGT-&lt;svg&gt;&amp;test" in body
    assert "1. System Overview" in body
    assert "Internet Connectivity" in body
    assert "Local Hard Disk" in body
    assert "Print / Save as PDF" in body

    pa_client = make_client()
    assert pa_client.post("/api/upload", files={"file": ("pa_fw.xml", SAMPLE_PA_XML, "application/xml")}).status_code == 200
    pa_rep = pa_client.get("/api/export/report")
    assert pa_rep.status_code == 200
    assert "pa_fw_audit_report.html" in pa_rep.headers.get("content-disposition", "")
    assert "PA-FW-01" in pa_rep.text
    assert "Palo Alto Networks (PAN-OS)" in pa_rep.text


def test_desktop_window_geometry_uses_native_center_and_logical_dpi_size(monkeypatch):
    from types import SimpleNamespace
    import scripts.desktop_launcher as dl

    monkeypatch.setattr(dl, "_get_windows_dpi_scale", lambda: 1.5)
    monkeypatch.setattr(dl, "_get_windows_work_area", lambda: None)
    fake_webview = SimpleNamespace(
        screens=[SimpleNamespace(width=1920, height=1080, x=0, y=0, scale=1.0)]
    )
    geom = dl._compute_window_geometry(fake_webview)
    assert "x" not in geom
    assert "y" not in geom
    assert "screen" not in geom
    assert geom["width"] == 1088
    assert geom["height"] == 612
    assert geom["maximized"] is False
    assert geom["min_size"] == (860, 600)


def test_desktop_window_state_persistence_and_restore(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import scripts.desktop_launcher as dl

    state_file = tmp_path / "window_state.json"
    dl._save_window_state(1180, 740, maximized=True, path=state_file)
    loaded = dl._load_window_state(path=state_file)
    assert loaded == {"width": 1180, "height": 740, "maximized": True}

    monkeypatch.setattr(dl, "_get_windows_dpi_scale", lambda: 1.5)
    monkeypatch.setattr(dl, "_get_windows_work_area", lambda: (0, 0, 1920, 1020))
    # Work area logical size is 1280x680 -> height 740 gets clamped to 680
    geom = dl._compute_window_geometry(SimpleNamespace(screens=[]), saved_state=loaded)
    assert geom["width"] == 1180
    assert geom["height"] == 680
    assert geom["maximized"] is True

    # Capturing maximized state uses RestoreBounds divided by scale
    fake_native = SimpleNamespace(
        WindowState="Maximized",
        _scale=1.5,
        Width=1920,
        Height=1020,
        RestoreBounds=SimpleNamespace(Width=1650, Height=960),
    )
    fake_window = SimpleNamespace(native=fake_native, width=1280, height=680)
    dl._capture_and_save_window_state(fake_window, path=state_file)
    assert dl._load_window_state(path=state_file) == {
        "width": 1100,
        "height": 640,
        "maximized": True,
    }
