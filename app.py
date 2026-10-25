#!/usr/bin/env python3
"""Start the ReconDeck desktop web server on the loopback interface."""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

from recondeck import create_app

ROOT = Path(__file__).resolve().parent


def _port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _open_gui(url: str) -> None:
    """Prefer a chromeless app window, then fall back to the default browser."""
    no_browser = os.environ.get("RECONDECK_NO_BROWSER", "").lower() in {"1", "true", "yes"}
    if no_browser:
        return
    app_mode = os.environ.get("RECONDECK_APP_WINDOW", "1").lower() not in {
        "0",
        "false",
        "no",
    }
    candidates = [
        ("brave-browser", ["--app=" + url]),
        ("chromium", ["--app=" + url]),
        ("chromium-browser", ["--app=" + url]),
        ("google-chrome", ["--app=" + url]),
    ]
    if app_mode:
        for executable, flags in candidates:
            path = shutil.which(executable)
            if path:
                try:
                    subprocess.Popen(
                        [path, *flags],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    return
                except OSError:
                    pass
    webbrowser.open(url, new=2)


def main() -> int:
    # Scan data and temporary XML belong to this user only.
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Run ReconDeck locally.")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("RECONDECK_PORT", "8777")),
        help="Local port (default: 8777).",
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("RECONDECK_DATA_DIR", str(ROOT / "data")),
        help="Directory for the local scan database.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open a browser window after the server starts.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode.")
    args = parser.parse_args()

    if args.port < 1024 or args.port > 65535:
        print("The local port must be between 1024 and 65535.", file=sys.stderr)
        return 2
    host = "127.0.0.1"
    if not _port_available(host, args.port):
        print(
            f"Port {args.port} is already in use. ReconDeck may already be running:\n"
            f"  http://{host}:{args.port}\n"
            "Set RECONDECK_PORT to use a different port.",
            file=sys.stderr,
        )
        return 2

    Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(args.data_dir, 0o700)
    except OSError:
        pass
    app = create_app(data_dir=args.data_dir)
    try:
        os.chmod(Path(args.data_dir) / "recondeck.db", 0o600)
    except OSError:
        pass
    url = f"http://{host}:{args.port}"
    print()
    print("  ██  ReconDeck")
    print("  ─────────────────────────────────────────")
    print(f"  Local workspace   {url}")
    print(f"  Scan database     {Path(args.data_dir) / 'recondeck.db'}")
    print("  Scope             loopback only · no telemetry")
    print("  Stop              Ctrl+C")
    print()
    if args.open:
        threading.Thread(target=lambda: (time.sleep(0.7), _open_gui(url)), daemon=True).start()
    app.run(
        host=host,
        port=args.port,
        debug=args.debug,
        threaded=True,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
