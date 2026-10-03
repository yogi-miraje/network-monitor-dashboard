#!/usr/bin/env python3
"""A loopback-only network monitor, using only the Python standard library."""
import argparse
import math
from collections import deque
from statistics import median
import concurrent.futures
import errno
import fcntl
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
TARGETS = (("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"))
INTERVAL = 1.0
TIMEOUT = 0.8
DROP_STATES = {"offline", "dns"}


def tcp_probe(target, timeout=TIMEOUT):
    started = time.monotonic()
    try:
        with socket.create_connection((target, 443), timeout=timeout):
            return {"ok": True, "ms": round((time.monotonic() - started) * 1000, 1), "blocked": False, "error": None, "errno": None}
    except OSError as exc:
        return {"ok": False, "ms": None, "blocked": exc.errno in (errno.EPERM, errno.EACCES),
                "error": type(exc).__name__, "errno": exc.errno,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1)}


def topology():
    """Find the active route and the system's first default DNS resolver."""
    result = {"gateway": None, "interface": None, "resolver": None, "route_known": False}
    if sys.platform != "darwin":
        return result
    try:
        route = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True, timeout=0.8)
        # A permission failure is unknown topology, not a disconnected adapter.
        result["route_known"] = "Operation not permitted" not in route.stderr
        for key in ("gateway", "interface"):
            match = re.search(r"^\s*" + key + r":\s*(\S+)", route.stdout, re.M)
            if match:
                result[key] = match.group(1)
        dns = subprocess.run(["/usr/sbin/scutil", "--dns"], capture_output=True, text=True, timeout=0.8)
        # Use only the default resolver; scoped split-DNS resolvers may be for a VPN.
        first = dns.stdout.split("resolver #2", 1)[0]
        match = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", first)
        if match:
            result["resolver"] = match.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


def gateway_probe(gateway):
    if not gateway:
        return None
    try:
        ipaddress.ip_address(gateway.split("%", 1)[0])
        command = ["/sbin/ping", "-n", "-c", "1", "-W", "600", "-t", "1", gateway]
        if ":" in gateway:
            return None  # IPv6 gateways are not diagnosed using an IPv4 ping.
        result = subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT)
        if "Operation not permitted" in result.stderr:
            return None
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except (OSError, ValueError):
        return None


def dns_probe(resolver):
    """A bounded DNS query through the Mac's configured resolver."""
    if not resolver:
        return None
    try:
        ipaddress.ip_address(resolver.split("%", 1)[0])
        ident = secrets.randbelow(65536)
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question
        family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(TIMEOUT)
            client.connect((resolver, 53))
            client.send(packet)
            response = client.recv(4096)
        if len(response) < 12:
            return False
        got_ident, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
        # A truncated UDP reply needs TCP, so do not mistake it for DNS downtime.
        if flags & 0x0200:
            return None
        return got_ident == ident and bool(flags & 0x8000) and not (flags & 0x000F) and answers > 0
    except OSError as exc:
        return None if exc.errno in (errno.EPERM, errno.EACCES) else False
    except ValueError:
        return None


def classify(checks, gateway_ok, dns_ok, route):
    successful = [check["ms"] for check in checks if check["ok"]]
    if successful:
        if dns_ok is False:
            return "dns", min(successful), "DNS lookup failed", "Internet IP addresses responded, but the configured DNS resolver did not return an answer."
        return "online", min(successful), "Connected", "Both internet checks responded." if len(successful) == 2 else "One internet check responded; the other did not."
    if any(check.get("blocked") for check in checks):
        return "blocked", None, "Monitoring blocked", "Network checks were denied. Start the monitor using Start.command on your Mac."
    if route.get("route_known") and not route.get("interface"):
        return "offline", None, "No network connection", "The Mac has no active default route, and both internet checks failed."
    if gateway_ok is True:
        return "offline", None, "Reachability checks failed", "Both internet TCP checks failed within the 800 ms limit. A router ping answered, but this does not rule out this Mac, Wi-Fi, router forwarding, or the ISP. Work VPN status is not measured."
    if gateway_ok is False:
        return "offline", None, "Local path or internet issue", "The router ping and both internet TCP checks failed. This Mac, Wi-Fi, or the router may be involved; ping filtering is also possible. The ISP and work VPN are not isolated by these checks."
    return "offline", None, "Reachability checks failed", "Both internet TCP checks failed within the 800 ms limit. The router could not be checked. This does not identify the faulty device or prove an ISP outage."


def smooth_latency(rows, step, start):
    """Ten-second median followed by a 15-second exponential trend; preserve gaps."""
    history = deque()
    buckets = {}
    previous = None
    trend = None
    for row in rows:
        ts = row["ts"]
        if previous is not None and ts - previous > 3.5:
            history.clear()
            trend = None
        while history and history[0][0] <= ts - 10:
            history.popleft()
        if row["state"] in ("offline", "blocked") or row["latency"] is None:
            history.clear()
            value = None
            trend = None
        else:
            history.append((ts, row["latency"]))
            center = median(item[1] for item in history)
            alpha = 1 - math.exp(-max(0, ts - previous) / 15) if previous is not None else 1
            trend = center if trend is None else trend + alpha * (center - trend)
            value = trend
        if ts >= start:
            buckets[int(ts / step)] = value
        previous = ts
    return buckets


def packet_loss(rows, now):
    targets = {"Router": [], "Cloudflare": [], "Google": []}
    latest = None
    for row in rows:
        if row["ts"] < now - 60 or row["completed"] > now:
            continue
        evidence = json.loads(row["evidence"])
        latest = max(latest or row["completed"], row["completed"])
        targets["Router"].append(evidence.get("gateway_ping", {}).get("ok"))
        probes = {probe["target"]: probe.get("ok") for probe in evidence.get("internet_ping", [])}
        for name, ip in TARGETS:
            targets[name].append(probes.get(ip))
    fresh = latest is not None and now - latest < 10
    return {"window_seconds": 60, "fresh": fresh, "last_check": latest,
            "targets": [{"name": name, "sent": sum(value is not None for value in values),
                         "lost": sum(value is False for value in values),
                         "unknown": sum(value is None for value in values),
                         "percent": round(100 * sum(value is False for value in values) / sum(value is not None for value in values), 1)
                         if fresh and any(value is not None for value in values) else None}
                        for name, values in targets.items()]}


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS samples (
                ts REAL PRIMARY KEY, state TEXT NOT NULL, latency REAL,
                gateway_ok INTEGER, dns_ok INTEGER, reason TEXT NOT NULL,
                detail TEXT NOT NULL, successes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, start REAL NOT NULL, end REAL,
                kind TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT NOT NULL,
                end_known INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_events_start ON events(start DESC);
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(samples)")}
        if "evidence" not in columns:
            self.db.execute("ALTER TABLE samples ADD COLUMN evidence TEXT")
        self.db.execute("CREATE TABLE IF NOT EXISTS diagnostics (ts REAL PRIMARY KEY, completed REAL NOT NULL, evidence TEXT NOT NULL)")
        self.db.execute("PRAGMA optimize")
        self.db.commit()
        self.last = self.db.execute("SELECT ts FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
        self.last_ts = self.last[0] if self.last else None
        # On a restart we cannot know when an in-progress outage recovered.
        if self.last_ts is not None:
            self.db.execute("UPDATE events SET end=?, end_known=0 WHERE end IS NULL", (self.last_ts + INTERVAL,))
            self.db.commit()
        self.last_prune = 0
        self.started = time.time()

    def record(self, ts, state, latency, reason, detail, gateway_ok=None, dns_ok=None, successes=0, evidence=None):
        with self.lock, self.db:
            if self.last_ts is not None and ts - self.last_ts > 3.5:
                self.db.execute("UPDATE events SET end=?, end_known=0 WHERE end IS NULL", (self.last_ts + INTERVAL,))
                self.db.execute("INSERT INTO events(start,end,kind,reason,detail) VALUES (?,?,?,?,?)", (
                    self.last_ts + INTERVAL, ts, "pause", "Monitoring paused",
                    "The Mac was asleep or the monitor was stopped. Connection status during this gap is unknown."))
            current = self.db.execute("SELECT id,kind FROM events WHERE end IS NULL ORDER BY id DESC LIMIT 1").fetchone()
            if state in DROP_STATES:
                if current is not None and current["kind"] != state:
                    self.db.execute("UPDATE events SET end=? WHERE id=?", (ts, current["id"]))
                    current = None
                if current is None:
                    self.db.execute("INSERT INTO events(start,kind,reason,detail) VALUES (?,?,?,?)", (ts, state, reason, detail))
            elif current is not None:
                self.db.execute("UPDATE events SET end=?, end_known=? WHERE id=?", (ts, int(state == "online"), current["id"]))
            self.db.execute("INSERT INTO samples (ts,state,latency,gateway_ok,dns_ok,reason,detail,successes,evidence) VALUES (?,?,?,?,?,?,?,?,?)",
                            (ts, state, latency, gateway_ok, dns_ok, reason, detail, successes, json.dumps(evidence) if evidence else None))
            self.last_ts = ts
            if ts - self.last_prune >= 3600:
                # Keep a week of second-by-second samples. Events are never pruned.
                self.db.execute("DELETE FROM samples WHERE ts < ?", (ts - 7 * 86400,))
                self.db.execute("DELETE FROM diagnostics WHERE completed < ?", (ts - 7 * 86400,))
                self.last_prune = ts

    def record_diagnostic(self, ts, evidence):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO diagnostics VALUES (?,?,?)",
                            (ts, time.time(), json.dumps(evidence)))

    def event_evidence(self, event):
        result = dict(event)
        if result["kind"] != "offline":
            return result
        # Keep historical measurements intact, but correct their overconfident interpretation.
        if "likely beyond" in result["detail"]:
            result["reason"] = "Reachability checks failed"
            result["detail"] = "Both internet TCP checks failed within the 800 ms limit. A router ping answered. These historical checks cannot distinguish this Mac, Wi-Fi, router forwarding, or ISP trouble; they did not measure the work VPN."
        end = result["end"] or time.time()
        checks = self.db.execute("SELECT ts,completed,evidence FROM diagnostics WHERE ts<=? AND completed>=? ORDER BY ts LIMIT 8",
                                 (end, result["start"])).fetchall()
        result["diagnostics"] = [{"ts": row["ts"], "completed": row["completed"], **json.loads(row["evidence"])} for row in checks]
        raw = self.db.execute("SELECT ts,evidence FROM samples WHERE ts>=? AND ts<? AND state='offline' AND evidence IS NOT NULL ORDER BY ts LIMIT 5",
                              (result["start"], end)).fetchall()
        result["probe_evidence"] = [{"ts": row["ts"], **json.loads(row["evidence"])} for row in raw]
        if result["probe_evidence"]:
            errors = sorted({check.get("error", "Unknown") or "Unknown" for row in result["probe_evidence"] for check in row["checks"] if not check["ok"]})
            result["detail"] += " Recorded errors: " + ", ".join(errors) + "."
        if checks:
            tcp = [probe for row in result["diagnostics"] for probe in row["tcp"]]
            ping = [probe for row in result["diagnostics"] for probe in row["internet_ping"]]
            successes = sum(bool(probe["ok"]) for probe in tcp)
            replies = sum(probe["ok"] is True for probe in ping)
            result["detail"] += " Overlapping diagnostic rounds: %s/%s longer TCP checks succeeded; %s/%s internet pings answered. These checks overlap the event window but may finish after recovery; they do not locate the fault." % (successes, len(tcp), replies, len(ping))
        return result

    def finish(self):
        with self.lock, self.db:
            if self.last_ts is not None:
                self.db.execute("UPDATE events SET end=?, end_known=0 WHERE end IS NULL", (self.last_ts + INTERVAL,))

    def snapshot(self, window=900, event_limit=50):
        now = time.time()
        start = now - window
        with self.lock:
            latest = self.db.execute("SELECT * FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
            # Preserve the min/max envelope and worst status when grouping a long window.
            step = max(1, int(window / 1500))
            points = self.db.execute("""SELECT MIN(ts) AS ts, AVG(latency) AS latency,
                MIN(latency) AS low, MAX(latency) AS high,
                CASE WHEN SUM(state='offline')>0 THEN 'offline'
                     WHEN SUM(state='dns')>0 THEN 'dns'
                     WHEN SUM(state='blocked')>0 THEN 'blocked' ELSE 'online' END AS state
                FROM samples WHERE ts >= ? GROUP BY CAST(ts / ? AS INTEGER) ORDER BY ts""", (start, step)).fetchall()
            raw = self.db.execute("SELECT ts,state,latency FROM samples WHERE ts>=? ORDER BY ts", (start - 90,)).fetchall()
            smoothed = smooth_latency(raw, step, start)
            points = [{**dict(point), "smooth": smoothed.get(int(point["ts"] / step))} for point in points]
            loss = packet_loss(self.db.execute("SELECT ts,completed,evidence FROM diagnostics WHERE ts>=? ORDER BY ts", (now - 60,)).fetchall(), now)
            bands = self.db.execute("SELECT * FROM events WHERE start<=? AND (end IS NULL OR end>=?) ORDER BY start", (now, start)).fetchall()
            events = self.db.execute("SELECT * FROM events ORDER BY start DESC, id DESC LIMIT ?", (event_limit,)).fetchall()
            events = [self.event_evidence(row) for row in events]
            count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            drops = self.db.execute("SELECT COUNT(*) FROM events WHERE kind='offline'").fetchone()[0]
            issues = self.db.execute("SELECT COUNT(*) FROM events WHERE kind='dns'").fetchone()[0]
            stats = self.db.execute("""SELECT COUNT(*) AS n, SUM(state='online') AS good,
                SUM(state='offline') AS bad, SUM(state='dns') AS dns,
                AVG(latency) AS avg_latency FROM samples WHERE ts>=? AND state!='blocked'""", (start,)).fetchone()
            first = self.db.execute("SELECT MIN(start) FROM events").fetchone()[0]
            earliest_sample = self.db.execute("SELECT MIN(ts) FROM samples").fetchone()[0]
        return {"service": "local-network-monitor", "now": now, "started": self.started,
                "first_seen": min(v for v in (first, earliest_sample, self.started) if v is not None),
                "window": window, "step": step, "latest": dict(latest) if latest else None,
                "points": [dict(row) for row in points], "bands": [dict(row) for row in bands],
                "events": events, "event_count": count,
                "drop_count": drops, "dns_count": issues,
                "uptime": round(100 * (stats["good"] or 0) / stats["n"], 2) if stats["n"] else None,
                "average_latency": round(stats["avg_latency"], 1) if stats["avg_latency"] is not None else None,
                "smoothing_seconds": 10, "trend_seconds": 15, "packet_loss": loss,
                "interval": INTERVAL, "targets": [name for name, _ in TARGETS]}


class Monitor:
    def __init__(self, store):
        self.store = store
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="network-checks", daemon=True)
        self.diagnostic_thread = threading.Thread(target=self.run_diagnostics, name="diagnostics", daemon=True)

    def run_diagnostics(self):
        # A separate pool keeps longer checks from delaying the one-second graph.
        from diagnostics import ping_probe, interface_status
        with concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix="diagnostic") as pool:
            while not self.stop.is_set():
                tick, ts = time.monotonic(), time.time()
                try:
                    route = topology()
                    tcp = [pool.submit(tcp_probe, ip, 3.0) for _, ip in TARGETS]
                    ping = [pool.submit(ping_probe, ip) for _, ip in TARGETS]
                    gateway = pool.submit(ping_probe, route.get("gateway"))
                    evidence = {"tcp_timeout_ms": 3000, "route": route,
                                "interface": interface_status(route.get("interface")),
                                "tcp": [{"target": ip, **future.result()} for (_, ip), future in zip(TARGETS, tcp)],
                                "internet_ping": [{"target": ip, **future.result()} for (_, ip), future in zip(TARGETS, ping)],
                                "gateway_ping": gateway.result()}
                    self.store.record_diagnostic(ts, evidence)
                except Exception:
                    logging.exception("Diagnostic round failed; primary monitoring continues")
                self.stop.wait(max(0, 2.0 - (time.monotonic() - tick)))

    def run(self):
        route = {}
        route_at = 0
        dns_at = 0
        dns_ok = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="probe") as pool:
            while not self.stop.is_set():
                tick = time.monotonic()
                ts = time.time()
                if ts - route_at >= 10:
                    route = topology()
                    route_at = ts
                internet = [pool.submit(tcp_probe, ip) for _, ip in TARGETS]
                router = pool.submit(gateway_probe, route.get("gateway"))
                dns = pool.submit(dns_probe, route.get("resolver")) if ts - dns_at >= 5 else None
                checks = [future.result() for future in internet]
                gateway_ok = router.result()
                if dns is not None:
                    dns_ok = dns.result()
                    dns_at = ts
                # Diagnose with a fresh route if internet checks suddenly fail.
                if not any(c["ok"] for c in checks) and ts - route_at >= 1:
                    route = topology()
                    route_at = ts
                state, latency, reason, detail = classify(checks, gateway_ok, dns_ok, route)
                self.store.record(ts, state, latency, reason, detail, gateway_ok, dns_ok, sum(c["ok"] for c in checks),
                                  {"timeout_ms": 800, "checks": [{"target": ip, **check} for (_, ip), check in zip(TARGETS, checks)],
                                   "route": route, "dns_checked_at": dns_at})
                self.stop.wait(max(0, INTERVAL - (time.monotonic() - tick)))


def make_handler(store, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            if args and str(args[1]) not in ("200", "304"):
                logging.info(fmt, *args)

        def reply(self, status, content, mime):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            # Protect loopback access from DNS rebinding and cross-origin readers.
            host = self.headers.get("Host", "")
            if host not in ("localhost:%s" % port, "127.0.0.1:%s" % port):
                self.reply(403, b"Local access only", "text/plain")
                return
            origin = self.headers.get("Origin")
            if origin and origin not in ("http://localhost:%s" % port, "http://127.0.0.1:%s" % port):
                self.reply(403, b"Local access only", "text/plain")
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/api/health":
                self.reply(200, json.dumps({"service": "local-network-monitor", "pid": os.getpid(), "root": str(ROOT)}).encode(), "application/json")
            elif parsed.path == "/api/state":
                query = parse_qs(parsed.query)
                try:
                    window = max(60, min(86400, int(query.get("window", [900])[0])))
                    limit = max(50, int(query.get("events", [50])[0]))
                except ValueError:
                    self.reply(400, b"Invalid window", "text/plain")
                    return
                self.reply(200, json.dumps(store.snapshot(window, limit)).encode(), "application/json")
            else:
                files = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
                         "/styles.css": ("styles.css", "text/css; charset=utf-8"), "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
                         "/favicon.svg": ("favicon.svg", "image/svg+xml")}
                if parsed.path not in files:
                    self.reply(404, b"Not found", "text/plain")
                    return
                name, mime = files[parsed.path]
                self.reply(200, (ROOT / name).read_bytes(), mime)
    return Handler


def main():
    parser = argparse.ArgumentParser(description="Local network monitor")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True)
    lock = (args.data_dir / "monitor.lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("The monitor is already running.", flush=True)
        return 1
    store = Store(args.data_dir / "history.sqlite3")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(store, args.port))
    except OSError as exc:
        print("Could not start the local server: %s\nRun Start.command directly on your Mac." % exc, flush=True)
        return 1
    server.daemon_threads = True
    server.timeout = 0.5
    monitor = Monitor(store)
    pid_path = args.data_dir / "monitor.pid"
    pid_path.write_text(str(os.getpid()))
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: monitor.stop.set())
    monitor.thread.start()
    monitor.diagnostic_thread.start()
    print("Network monitor: http://localhost:%s\nMonitoring continues when Chrome is closed." % args.port, flush=True)
    try:
        while not monitor.stop.is_set():
            server.handle_request()
            if not monitor.thread.is_alive() and not monitor.stop.is_set():
                raise RuntimeError("Network checks stopped; restart the monitor.")
    finally:
        monitor.stop.set()
        monitor.thread.join(timeout=5)
        monitor.diagnostic_thread.join(timeout=5)
        store.finish()
        server.server_close()
        pid_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    sys.exit(main())
