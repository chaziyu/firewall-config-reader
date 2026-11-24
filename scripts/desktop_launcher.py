"""Desktop launcher for bundling the FastAPI app into a standalone Windows application.

Performance optimizations:
- Runs Uvicorn on an in-process background daemon thread instead of spawning a second
  PyInstaller executable subprocess (eliminates double bootloader init & double AV scan).
- Polls loopback TCP socket readiness every 20ms while importing pywebview concurrently
  on the main thread.
"""

from __future__ import annotations

import argparse
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


def _compute_window_geometry(webview_module: Any) -> dict[str, Any]:
    """Compute a centered initial window size and position fitted to the primary screen."""
    screens = getattr(webview_module, "screens", None) or []
    if not screens:
        return {"width": 1280, "height": 800, "min_size": (860, 600)}

    primary = screens[0]
    screen_w = int(getattr(primary, "width", 1440))
    screen_h = int(getattr(primary, "height", 900))
    screen_x = int(getattr(primary, "x", 0))
    screen_y = int(getattr(primary, "y", 0))

    width = max(1, min(1440, int(screen_w * 0.88)))
    height = max(1, min(920, int(screen_h * 0.86)))
    x = screen_x + max(0, (screen_w - width) // 2)
    y = screen_y + max(0, (screen_h - height) // 2)
    return {
        "width": width,
        "height": height,
        "x": x,
        "y": y,
        "screen": primary,
        "min_size": (min(860, width), min(600, height)),
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
        geometry = _compute_window_geometry(webview)
        window = webview.create_window(
            "Firewall Config Reader",
            url,
            resizable=True,
            zoomable=True,
            **geometry,
        )
        events = getattr(window, "events", None)
        if events is not None and hasattr(events, "shown"):
            events.shown += _close_splash
            webview.start(private_mode=True)
        else:
            webview.start(func=_close_splash, private_mode=True)
        return 0
    finally:
        _close_splash()
        _stop_inprocess_server(server_holder, server_thread)


if __name__ == "__main__":
    raise SystemExit(main())
