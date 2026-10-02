#!/usr/bin/env python3
"""Start a detached monitor and open Chrome, or stop this monitor safely."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
LOCAL_HTTP = build_opener(ProxyHandler({}))


def health(port):
    try:
        with LOCAL_HTTP.open("http://127.0.0.1:%s/api/health" % port, timeout=0.6) as response:
            result = json.load(response)
        if result.get("service") == "local-network-monitor" and result.get("root") == str(ROOT):
            return result
    except (OSError, ValueError):
        pass
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop"), nargs="?", default="start")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    if args.action == "stop":
        info = health(args.port)
        if info:
            os.kill(info["pid"], signal.SIGTERM)
            print("Network monitoring stopped. Your history is saved.")
        else:
            print("This monitor is not running on port %s." % args.port)
        return 0
    DATA.mkdir(exist_ok=True)
    if not health(args.port):
        with (DATA / "monitor.log").open("a") as log:
            child = subprocess.Popen([sys.executable, str(ROOT / "monitor.py"), "--port", str(args.port)],
                                     cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                     start_new_session=True, close_fds=True)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if health(args.port):
                break
            if child.poll() is not None:
                print("The local monitor could not start.\n" + (DATA / "monitor.log").read_text()[-1400:])
                return 1
            time.sleep(0.15)
        else:
            print("The monitor has not responded yet. See data/monitor.log.")
            return 1
    url = "http://localhost:%s" % args.port
    if sys.platform == "darwin":
        subprocess.run(["/usr/bin/open", "-a", "Google Chrome", url], check=False)
    else:
        import webbrowser
        webbrowser.open(url)
    print("Network monitor is running at %s\nYou can close this terminal and Chrome; monitoring keeps running.\nUse Stop.command to stop monitoring. It does not run while your Mac is asleep." % url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
