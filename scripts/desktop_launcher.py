"""Desktop launcher for bundling the FastAPI app into a standalone Windows application.

Performance optimizations:
- Runs Uvicorn on an in-process background daemon thread instead of spawning a second
  PyInstaller executable subprocess (eliminates double bootloader init & double AV scan).
- Polls loopback TCP socket readiness every 20ms while importing pywebview concurrently
  on the main thread.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

DEFAULT_PORT = 8501
HEALTH_TIMEOUT_SECONDS = 20.0


def _resolve_app_root() -> Path:
    """Return the application root directory for frozen and source runs."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def _pick_port(preferred: int = DEFAULT_PORT) -> int:
    """Return *preferred* if available on 127.0.0.1, otherwise an OS-assigned free port."""
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return int(sock.getsockname()[1])
    raise RuntimeError("Unable to bind a local loopback port for FastAPI.")


def _get_windows_dpi_scale() -> float:
    """Return the system Windows DPI scale factor (e.g. 1.25, 1.5) or 1.0."""
    if sys.platform != "win32":
        return 1.0
    try:
        import ctypes

        get_dpi = getattr(ctypes.windll.user32, "GetDpiForSystem", None)
        if get_dpi is None:
            return 1.0
        dpi = int(get_dpi())
        return dpi / 96.0 if dpi > 0 else 1.0
    except Exception:
        return 1.0


def _window_state_path() -> Path:
    """Return path to persisted desktop window size/maximized preference JSON."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".config"
    return base / "FirewallConfigReader" / "window_state.json"


def _load_window_state(path: Path | None = None) -> dict[str, Any] | None:
    """Load persisted logical window dimensions and maximized state, or None."""
    target = path or _window_state_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        w = data.get("width")
        h = data.get("height")
        maximized = data.get("maximized", False)
        if (
            isinstance(w, bool)
            or isinstance(h, bool)
            or not isinstance(w, int)
            or not isinstance(h, int)
            or not isinstance(maximized, bool)
        ):
            return None
        if not (400 <= w <= 8192 and 300 <= h <= 4320):
            return None
        return {"width": w, "height": h, "maximized": maximized}
    except Exception:
        return None


def _save_window_state(width: int, height: int, maximized: bool, path: Path | None = None) -> None:
    """Persist logical window dimensions and maximized state to disk."""
    try:
        w = max(400, min(8192, int(width)))
        h = max(300, min(4320, int(height)))
        target = path or _window_state_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"width": w, "height": h, "maximized": bool(maximized)}),
            encoding="utf-8",
        )
    except Exception:
        pass


def _get_windows_work_area() -> tuple[int, int, int, int] | None:
    """Return primary monitor work area (left, top, width, height) in physical pixels."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        rect = wintypes.RECT()
        ok = ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)
        if not ok:
            return None
        w = int(rect.right - rect.left)
        h = int(rect.bottom - rect.top)
        if w <= 0 or h <= 0:
            return None
        return int(rect.left), int(rect.top), w, h
    except Exception:
        return None


def _center_native_window(window: Any) -> bool:
    """Center the native Win32 window on its monitor's work area using physical pixels."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        native = getattr(window, "native", None)
        handle = getattr(native, "Handle", None)
        if handle is None:
            return False
        if hasattr(handle, "ToInt64"):
            hwnd = int(handle.ToInt64())
        elif hasattr(handle, "ToInt32"):
            hwnd = int(handle.ToInt32())
        else:
            hwnd = int(handle)
        if not hwnd:
            return False

        user32 = ctypes.windll.user32

        class MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.MonitorFromWindow.restype = wintypes.HMONITOR
        hmon = user32.MonitorFromWindow(wintypes.HWND(hwnd), 1)
        if not hmon:
            return False

        mi = MONITORINFO()
        mi.cbSize = ctypes.sizeof(MONITORINFO)
        if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            return False

        win_rect = wintypes.RECT()
        if not user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(win_rect)):
            return False

        win_w = int(win_rect.right - win_rect.left)
        win_h = int(win_rect.bottom - win_rect.top)
        work_left = int(mi.rcWork.left)
        work_top = int(mi.rcWork.top)
        work_w = int(mi.rcWork.right - mi.rcWork.left)
        work_h = int(mi.rcWork.bottom - mi.rcWork.top)
        if win_w <= 0 or win_h <= 0 or work_w <= 0 or work_h <= 0:
            return False

        cx = work_left + max(0, (work_w - win_w) // 2)
        cy = work_top + max(0, (work_h - win_h) // 2)
        # SWP_NOSIZE (0x0001) | SWP_NOZORDER (0x0004) | SWP_NOACTIVATE (0x0010)
        return bool(
            user32.SetWindowPos(wintypes.HWND(hwnd), 0, cx, cy, 0, 0, 0x0001 | 0x0004 | 0x0010)
        )
    except Exception:
        return False


def _capture_and_save_window_state(window: Any, path: Path | None = None) -> None:
    """Capture logical window size and maximized state from pywebview and persist it."""
    try:
        native = getattr(window, "native", None)
        state_str = str(getattr(native, "WindowState", "")) if native is not None else ""
        maximized = state_str.endswith("Maximized")
        minimized = state_str.endswith("Minimized")
        scale = float(getattr(native, "_scale", 0) or _get_windows_dpi_scale() or 1.0)
        if scale <= 0:
            scale = 1.0

        logical_w: int | None = None
        logical_h: int | None = None

        if native is not None and (maximized or minimized):
            bounds = getattr(native, "RestoreBounds", None)
            if bounds is not None and getattr(bounds, "Width", 0) > 0 and getattr(bounds, "Height", 0) > 0:
                logical_w = int(round(float(bounds.Width) / scale))
                logical_h = int(round(float(bounds.Height) / scale))

        if logical_w is None and native is not None:
            nw = getattr(native, "Width", 0)
            nh = getattr(native, "Height", 0)
            if nw and nh:
                logical_w = int(round(float(nw) / scale))
                logical_h = int(round(float(nh) / scale))

        if logical_w is None or logical_h is None:
            logical_w = int(getattr(window, "width", 1280) or 1280)
            logical_h = int(getattr(window, "height", 800) or 800)

        _save_window_state(logical_w, logical_h, maximized=maximized and not minimized, path=path)
    except Exception:
        pass


def _compute_window_geometry(
    webview_module: Any,
    saved_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute logical window dimensions from work area and saved state."""
    dpi_scale = _get_windows_dpi_scale()
    work_area = _get_windows_work_area()

    if work_area is not None:
        _, _, phys_w, phys_h = work_area
        work_w = max(1, int(round(phys_w / dpi_scale)))
        work_h = max(1, int(round(phys_h / dpi_scale)))
    else:
        screens = getattr(webview_module, "screens", None) or []
        if screens:
            primary = screens[0]
            work_w = int(getattr(primary, "width", 1440))
            work_h = int(getattr(primary, "height", 900))
            reported_scale = float(getattr(primary, "scale", 1.0) or 1.0)
            if reported_scale <= 1.01 and dpi_scale > 1.01:
                work_w = max(1, int(round(work_w / dpi_scale)))
                work_h = max(1, int(round(work_h / dpi_scale)))
        else:
            work_w, work_h = 1440, 900

    min_w = min(860, work_w)
    min_h = min(600, work_h)
    default_w = max(min_w, min(1440, int(work_w * 0.85)))
    default_h = max(min_h, min(920, int(work_h * 0.85)))

    if saved_state:
        width = max(min_w, min(work_w, int(saved_state["width"])))
        height = max(min_h, min(work_h, int(saved_state["height"])))
        maximized = bool(saved_state.get("maximized", False))
    else:
        width, height, maximized = default_w, default_h, False

    return {
        "width": width,
        "height": height,
        "maximized": maximized,
        "min_size": (min_w, min_h),
    }


def _close_splash() -> None:
    """Close the PyInstaller splash screen if running in a frozen build."""
    try:
        import pyi_splash  # type: ignore[import-not-found]
    except ImportError:
        return
    try:
        pyi_splash.close()
    except Exception:
        pass


def _prepare_app_root() -> None:
    app_root = _resolve_app_root()
    if str(app_root) not in sys.path:
        sys.path.insert(0, str(app_root))
    os.chdir(app_root)


def _create_uvicorn_server(port: int):
    """Create an in-process Uvicorn Server instance configured for fast desktop startup."""
    _prepare_app_root()
    import uvicorn
    from server import app

    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
        loop="asyncio",
        http="h11",
    )
    server = uvicorn.Server(config)
    # Prevent Uvicorn from overriding main-thread signal handlers when running in a background thread
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    return server


def _run_fastapi_server(port: int) -> int:
    """Run the FastAPI/Uvicorn server on the current process's main thread."""
    server = _create_uvicorn_server(port)
    server.run()
    return 0


def _start_inprocess_server(port: int) -> tuple[Any, threading.Thread, list[BaseException]]:
    """Start Uvicorn in a daemon thread inside the current process."""
    errors: list[BaseException] = []
    server_holder: list[Any] = []

    def _worker() -> None:
        try:
            srv = _create_uvicorn_server(port)
            server_holder.append(srv)
            srv.run()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=_worker, name="uvicorn-server", daemon=True)
    thread.start()
    return server_holder, thread, errors


def _wait_for_port(port: int, thread: threading.Thread, errors: list[BaseException]) -> None:
    """Wait until the in-process Uvicorn server accepts TCP connections on 127.0.0.1:port."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if errors:
            raise RuntimeError(f"FastAPI server failed to start: {errors[0]}") from errors[0]
        if not thread.is_alive():
            raise RuntimeError("FastAPI server thread exited unexpectedly.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return
        except OSError:
            time.sleep(0.02)

    raise TimeoutError(f"Timed out waiting for local FastAPI server on 127.0.0.1:{port}.")


def _stop_inprocess_server(server_holder: list[Any], thread: threading.Thread) -> None:
    """Signal the in-process Uvicorn server to shut down cleanly."""
    if server_holder:
        server_holder[0].should_exit = True
    if thread.is_alive():
        thread.join(timeout=3.0)


def main(argv: list[str] | None = None) -> int:
    """Start the local FastAPI server in-process and open the desktop UI."""
    parser = argparse.ArgumentParser(description="Launch Firewall Config Reader desktop app.")
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Preferred loopback port (default: 8501).",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Open in the default web browser instead of a desktop window.",
    )
    args = parser.parse_args(argv)

    if args.serve:
        return _run_fastapi_server(args.port)

    os.environ.setdefault("FW_DESKTOP_MODE", "1")
    port = _pick_port(args.port)
    url = f"http://127.0.0.1:{port}/"

    # Start Uvicorn in a background thread immediately so it boots in parallel with importing pywebview
    server_holder, server_thread, server_errors = _start_inprocess_server(port)

    try:
        webview = None
        if not args.browser:
            try:
                import webview as _webview

                webview = _webview
            except ImportError:
                webview = None

        _wait_for_port(port, server_thread, server_errors)

        if args.browser or webview is None:
            _close_splash()
            webbrowser.open(url)
            while server_thread.is_alive():
                server_thread.join(timeout=0.5)
            return 0

        webview.settings["ALLOW_DOWNLOADS"] = True
        saved_state = _load_window_state()
        geometry = _compute_window_geometry(webview, saved_state=saved_state)
        window = webview.create_window(
            "Firewall Config Reader",
            url,
            resizable=True,
            zoomable=True,
            **geometry,
        )
        events = getattr(window, "events", None)
        if events is not None:
            if hasattr(events, "before_show") and not geometry.get("maximized"):
                events.before_show += lambda: (_center_native_window(window), None)[1]
            if hasattr(events, "closing"):
                events.closing += lambda: _capture_and_save_window_state(window)
        if events is not None and hasattr(events, "shown"):
            events.shown += _close_splash
            webview.start(private_mode=True)
        else:
            webview.start(func=_close_splash, private_mode=True)
        return 0
    finally:
        _close_splash()
        _stop_inprocess_server(server_holder, server_thread)
        try:
            from backend.session_store import store

            store.cleanup_all()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
