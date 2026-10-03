import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from monitor import Store, classify, make_handler, tcp_probe, smooth_latency, packet_loss


OK = {"ok": True, "ms": 25.0, "blocked": False}
FAIL = {"ok": False, "ms": None, "blocked": False}
DENIED = {"ok": False, "ms": None, "blocked": True}


class DetectionTests(unittest.TestCase):
    def test_one_endpoint_failure_is_not_an_internet_drop(self):
        state, latency, _, detail = classify([OK, FAIL], False, True, {})
        self.assertEqual((state, latency), ("online", 25.0))
        self.assertIn("One internet check", detail)

    def test_router_responds_but_internet_does_not(self):
        state, _, reason, detail = classify([FAIL, FAIL], True, True, {})
        self.assertEqual((state, reason), ("offline", "Reachability checks failed"))
        self.assertIn("does not rule out this Mac", detail)

    def test_no_default_route(self):
        result = classify([FAIL, FAIL], None, None, {"route_known": True, "interface": None})
        self.assertEqual(result[2], "No network connection")

    def test_dns_outage_is_separate_from_internet_outage(self):
        self.assertEqual(classify([OK, OK], True, False, {})[0], "dns")

    def test_permission_errors_do_not_create_false_outages(self):
        self.assertEqual(classify([DENIED, FAIL], None, None, {})[0], "blocked")
        self.assertEqual(classify([DENIED, DENIED], None, None, {})[0], "blocked")
        with patch("monitor.socket.create_connection", side_effect=PermissionError(1, "denied")):
            self.assertTrue(tcp_probe("1.1.1.1")["blocked"])

    def test_timeout_is_a_failed_probe(self):
        with patch("monitor.socket.create_connection", side_effect=socket.timeout("timeout")):
            result = tcp_probe("1.1.1.1")
            self.assertFalse(result["ok"])
            self.assertFalse(result["blocked"])
            self.assertEqual(result["error"], type(socket.timeout()).__name__)
            self.assertIn("elapsed_ms", result)


class DisplayMetricsTests(unittest.TestCase):
    def test_median_removes_single_spike_and_keeps_failure(self):
        rows = [{"ts": t, "state": "online", "latency": 20 if t != 5 else 900} for t in range(10)]
        rows += [{"ts": 10, "state": "offline", "latency": None}, {"ts": 11, "state": "online", "latency": 80}]
        values = smooth_latency(rows, 1, 0)
        self.assertEqual(values[5], 20)
        self.assertEqual(values[9], 20)
        self.assertIsNone(values[10])
        self.assertEqual(values[11], 80)
        self.assertEqual(rows[5]["latency"], 900)

    def test_time_window_and_gap_reset(self):
        rows = [{"ts": t, "state": "online", "latency": 20 if t < 10 else 80} for t in range(20)]
        rows.append({"ts": 40, "state": "online", "latency": 100})
        values = smooth_latency(rows, 1, 5)
        self.assertNotIn(4, values)
        self.assertGreater(values[19], 20)
        self.assertLess(values[19], 80)
        self.assertLess(max(abs(values[t] - values[t-1]) for t in range(6,20)), 5)
        self.assertEqual(values[40], 100)

    def test_packet_loss_excludes_unknown_old_and_stale_measurements(self):
        def row(ts, router, cloud, google):
            return {"ts": ts, "completed": ts + .5, "evidence": json.dumps({"gateway_ping": {"ok": router}, "internet_ping": [{"target": "1.1.1.1", "ok": cloud}, {"target": "8.8.8.8", "ok": google}]})}
        rows = [row(20, False, False, False), row(96, True, False, None), row(98, True, True, None)]
        stats = packet_loss(rows, 100)
        router, cloud, google = stats["targets"]
        self.assertEqual((router["percent"], router["sent"]), (0, 2))
        self.assertEqual((cloud["percent"], cloud["lost"]), (50, 1))
        self.assertIsNone(google["percent"])
        self.assertEqual(google["unknown"], 2)
        self.assertTrue(all(t["percent"] is None for t in packet_loss(rows, 120)["targets"]))
        self.assertTrue(all(t["percent"] is None for t in packet_loss([], 100)["targets"]))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "test.sqlite3"
        self.store = Store(self.path)
        self.ts = time.time() - 120

    def tearDown(self):
        self.store.db.close()
        self.folder.cleanup()

    def record(self, offset, state="online", latency=25):
        self.store.record(self.ts + offset, state, latency if state in ("online", "dns") else None,
                          "Connected" if state == "online" else "Internet unreachable", "Probe detail", successes=2 if state=="online" else 0)

    def test_three_failed_checks_become_one_event_then_recover(self):
        self.record(0)
        for second in (1, 2, 3):
            self.record(second, "offline")
        self.record(4)
        state = self.store.snapshot()
        self.assertEqual(state["drop_count"], 1)
        event = state["events"][0]
        self.assertEqual(event["end"] - event["start"], 3)
        self.assertEqual(event["end_known"], 1)
        self.assertEqual(state["uptime"], 40.0)

    def test_active_event_remains_open(self):
        self.record(0, "offline")
        self.record(1, "offline")
        self.assertIsNone(self.store.snapshot()["events"][0]["end"])

    def test_sleep_is_a_gap_and_does_not_inflate_a_drop(self):
        self.record(0, "offline")
        self.record(60)
        state = self.store.snapshot()
        self.assertEqual(state["drop_count"], 1)
        self.assertEqual({e["kind"] for e in state["events"]}, {"pause", "offline"})
        outage = next(e for e in state["events"] if e["kind"]=="offline")
        self.assertEqual(outage["end"] - outage["start"], 1)
        self.assertEqual(outage["end_known"], 0)
        self.assertEqual(state["uptime"], 50.0)

    def test_restart_preserves_history_and_marks_unknown_recovery(self):
        self.record(0, "offline")
        self.store.db.close()
        self.store = Store(self.path)
        event = self.store.snapshot()["events"][0]
        self.assertEqual(event["end_known"], 0)
        self.record(10)
        self.assertEqual(self.store.snapshot()["drop_count"], 1)
        self.assertEqual(self.store.snapshot()["events"][0]["kind"], "pause")

    def test_blocked_probes_are_not_counted_as_drops_or_uptime(self):
        self.record(0, "blocked")
        state = self.store.snapshot()
        self.assertEqual(state["drop_count"], 0)
        self.assertEqual(state["event_count"], 0)
        self.assertIsNone(state["uptime"])

    def test_dns_issue_does_not_increment_internet_drop_count(self):
        self.record(0, "dns")
        self.record(1)
        state = self.store.snapshot()
        self.assertEqual(state["drop_count"], 0)
        self.assertEqual(state["dns_count"], 1)

    def test_long_window_keeps_a_one_second_drop_and_latency_peak(self):
        for second in range(60):
            self.record(second, "offline" if second == 22 else "online", 680 if second == 12 else 25)
        state = self.store.snapshot(86400)
        self.assertTrue(any(p["state"]=="offline" for p in state["points"]))
        self.assertEqual(max(p["high"] or 0 for p in state["points"]), 680)
        self.assertEqual(len(state["bands"]), 1)

    def test_sample_retention_does_not_delete_event_history(self):
        old = self.ts - 8 * 86400
        self.store.record(old, "offline", None, "Old drop", "Old event")
        self.store.record(self.ts, "online", 25, "Connected", "Recovered")
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 1)
        self.assertEqual(self.store.snapshot()["drop_count"], 1)

    def test_older_events_remain_retrievable(self):
        for second in range(110):
            self.record(second, "offline" if second % 2 else "online")
        self.assertEqual(len(self.store.snapshot(event_limit=50)["events"]), 50)
        self.assertEqual(len(self.store.snapshot(event_limit=150)["events"]), 55)

    def test_diagnostic_evidence_is_correlated_and_old_verdict_is_corrected(self):
        self.store.record(self.ts, "offline", None, "Internet unreachable",
                          "Your router responded. The problem is likely beyond your Mac's local connection.",
                          evidence={"checks": [{"ok": False, "error": "timeout", "target": "1.1.1.1"}]})
        self.record(1)
        evidence = {"tcp": [{"ok": True}], "internet_ping": [{"ok": True}]}
        with self.store.db:
            self.store.db.execute("INSERT INTO diagnostics VALUES (?,?,?)", (self.ts - .1, self.ts + .9, json.dumps(evidence)))
            self.store.db.execute("INSERT INTO diagnostics VALUES (?,?,?)", (self.ts - 10, self.ts - 9, json.dumps(evidence)))
        event = self.store.snapshot()["events"][0]
        self.assertEqual(len(event["diagnostics"]), 1)
        self.assertIn("cannot distinguish this Mac", event["detail"])
        self.assertIn("timeout", event["detail"])
        self.assertIn("may finish after recovery", event["detail"])
        self.assertIn("likely beyond", self.store.db.execute("SELECT detail FROM events").fetchone()[0])

    def test_schema_upgrade_preserves_existing_samples(self):
        import sqlite3
        path = Path(self.folder.name) / "legacy.sqlite3"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE samples (ts REAL PRIMARY KEY,state TEXT NOT NULL,latency REAL,gateway_ok INTEGER,dns_ok INTEGER,reason TEXT NOT NULL,detail TEXT NOT NULL,successes INTEGER NOT NULL)")
        conn.execute("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?)", (self.ts,"online",20,1,1,"Connected","Connected",2))
        conn.commit(); conn.close()
        upgraded = Store(path)
        try:
            self.assertEqual(upgraded.snapshot()["latest"]["latency"], 20)
            upgraded.record(self.ts + 1, "online", 30, "Connected", "Connected", evidence={"checks": []})
            self.assertEqual(json.loads(upgraded.snapshot()["latest"]["evidence"]), {"checks": []})
        finally:
            upgraded.db.close()

    def test_local_http_routes_and_access_restrictions_without_sockets(self):
        Handler = make_handler(self.store, 8787)
        def request(path, host="localhost:8787", origin=None):
            handler=Handler.__new__(Handler)
            handler.path=path
            handler.headers={"Host":host}
            if origin:
                handler.headers["Origin"]=origin
            captured={}
            handler.reply=lambda status,content,mime:captured.update(status=status,content=content,mime=mime)
            handler.do_GET()
            return captured
        self.record(0)
        self.assertEqual(request("/")["status"], 200)
        self.assertEqual(request("/dashboard.js")["status"], 200)
        self.assertEqual(json.loads(request("/api/state")["content"])["service"], "local-network-monitor")
        self.assertEqual(request("/api/state",host="evil.example:8787")["status"], 403)
        self.assertEqual(request("/api/state",origin="https://evil.example")["status"], 403)
        self.assertEqual(request("/../../monitor.py")["status"], 404)
        self.assertEqual(request("/api/state?window=bad")["status"], 400)


if __name__ == "__main__":
    unittest.main()
