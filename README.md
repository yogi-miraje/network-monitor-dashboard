# Network Monitor Dashboard

A simple local dashboard with one connection graph and a saved list of network drops.

## Why I built this

I kept noticing my connection dipping and wanted a simple way to see when it happened, how long it lasted, and what might have caused it. I built this to keep running on my Mac, with one graph and a clear event history instead of a complicated monitoring setup.

## Screenshot

![Network monitor dashboard with a connection graph and event list](docs/dashboard.jpg)

This screenshot shows the live dashboard while the connection was healthy. Drops appear in red and are added to the event list when detected.

## Start on your Mac

Requirements: **Python 3.9 or newer** and **Google Chrome**. No Python packages to install.

```bash
git clone https://github.com/yogi-miraje/network-monitor-dashboard.git
cd network-monitor-dashboard
python3 launcher.py start
```

The launcher starts the background monitor and opens Chrome at **http://localhost:8787/**.

Alternatively, double-click **Start.command** in Finder. The command files use `/usr/bin/python3`; if your Python is installed elsewhere, use the terminal command above.

You can close Chrome and the terminal: monitoring continues. After restarting your Mac, start it again. Monitoring pauses while your Mac sleeps.

## Stop

Double-click **Stop.command**, or run this from the project folder:

```bash
python3 launcher.py stop
```

Your saved history is preserved.

If port 8787 is already in use, choose another port for both commands:

```bash
python3 launcher.py start --port 8788
python3 launcher.py stop --port 8788
```

To run in the foreground instead:

```bash
python3 monitor.py
```

Press Control-C to stop the foreground process.

## What it shows

- One response-time graph for the last 5 minutes, 15 minutes, hour, or 24 hours.
- Network drop times, durations, recovery status, and likely causes.
- DNS failures and monitoring gaps recorded separately.
- Saved events that remain available after stopping and restarting.

## How the backend works

Every second, Python attempts TCP connections to Cloudflare (`1.1.1.1:443`) and Google (`8.8.8.8:443`), with an 800 ms deadline per endpoint. Both must fail to record an internet drop. The graph uses the faster successful response time; it is not a download-speed test.

A router check helps explain failures. If the router responds but the internet checks fail, the problem may be further upstream. Router checks are clues, not proof: some routers block ping.

Every five seconds, it checks the Mac's configured DNS resolver using a query for `example.com`. DNS failures are recorded separately when internet IP checks still work. DNS checks are unavailable when the resolver cannot be discovered.

A local Python HTTP server provides the dashboard and measurements. It binds only to `127.0.0.1`, so other devices cannot access it.

## Saved data and limitations

Measurements live in `data/history.sqlite3`. Detailed samples are retained for seven days; drop and gap events are retained indefinitely. Logs also live in `data/`. This folder is excluded from Git.

Sleep, shutdown, and gaps longer than 3.5 seconds are marked as **Monitoring paused**, not network failures. Unobserved recovery times are marked **Recovery unknown**. Uptime uses actual sampled checks and excludes blocked checks and unsampled gaps.

Drops shorter than the one-second interval may be missed. This checks general internet reachability; failures affecting only a particular website, app, or VPN may not register. Likely causes are estimates.

There are no accounts, cloud uploads, or remote dashboard assets. Reachability checks contact the two public endpoints, and DNS queries go to your configured resolver.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The 16 checks cover drop detection, DNS issues, saved history, monitoring gaps, graph retention, and local HTTP route handling. Live monitoring was also verified on macOS.
