"""Read-only local diagnostics. Raw evidence stays in the ignored data directory."""
import ipaddress
import re
import subprocess
import time


def ping_probe(target):
    if not target:
        return {"ok": None, "error": "No target"}
    try:
        ipaddress.IPv4Address(target)
        started = time.monotonic()
        result = subprocess.run(["/sbin/ping", "-n", "-c", "1", "-W", "1000", "-t", "1", target],
                                capture_output=True, text=True, timeout=1.5)
        match = re.search(r"time[=<]([0-9.]+) ms", result.stdout)
        denied = "Operation not permitted" in result.stderr or "Permission denied" in result.stderr
        return {"ok": None if denied else result.returncode == 0,
                "ms": float(match.group(1)) if match else None,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
                "error": "Permission denied" if denied else None if result.returncode == 0 else "No ICMP reply (loss or filtering)"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": None, "error": "ICMP deadline exceeded (loss or filtering)"}
    except (OSError, ValueError) as exc:
        return {"ok": None, "ms": None, "error": type(exc).__name__}


def interface_status(interface):
    if not interface or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]{0,15}", interface):
        return {"name": interface, "status": "unknown"}
    try:
        result = subprocess.run(["/sbin/ifconfig", interface], capture_output=True, text=True, timeout=0.8)
        match = re.search(r"status: (\w+)", result.stdout)
        return {"name": interface, "status": match.group(1) if match else "unknown"}
    except (OSError, subprocess.TimeoutExpired):
        return {"name": interface, "status": "unknown"}
