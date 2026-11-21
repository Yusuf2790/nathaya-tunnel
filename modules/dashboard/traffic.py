#!/usr/bin/env python3
"""Collect and report RX/TX on the VPS uplink."""

import argparse
from datetime import datetime, timedelta
import fcntl
import json
from pathlib import Path
import re
import select
import subprocess
import sys
from tempfile import NamedTemporaryFile
import time

STATE_DIR = Path("/var/lib/nathaya-tunnel")
STATE_FILE = STATE_DIR / "traffic.json"
INTERFACE_FILE = Path("/etc/nathaya-tunnel/traffic-interface")
SYS_NET = Path("/sys/class/net")


def sample():
    if INTERFACE_FILE.is_file():
        interface = INTERFACE_FILE.read_text().strip()
    else:
        interface = ""
        for family in ("-4", "-6"):
            routes = subprocess.check_output(
                ["ip", family, "route", "show", "default"], text=True
            )
            match = re.search(r"\bdev (\S+)", routes)
            if match:
                interface = match[1]
                break
    if not re.fullmatch(r"[\w.:-]+", interface) or interface in (".", "..", "lo"):
        raise ValueError("Interface uplink tidak tersedia")

    device = SYS_NET / interface
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    index = (device / "ifindex").read_text().strip()
    counters = [int((device / "statistics" / name).read_text())
                for name in ("rx_bytes", "tx_bytes")]
    return {
        "interface": interface,
        "identity": [boot_id, interface, index],
        "time": time.time(),
        "monotonic": time.monotonic(),
        "counters": counters,
    }


def delta(previous, current):
    if previous.get("identity") != current["identity"]:
        return [0, 0]
    return [new - old if new >= old else new
            for old, new in zip(previous["counters"], current["counters"])]


def project(state, current):
    previous = state.get("sample", {})
    diff = delta(previous, current)
    now = datetime.fromtimestamp(current["time"])
    day = now.date().isoformat()
    month = day[:7]
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = midnight.replace(day=1)

    def total(key, period, start, end):
        old_period, counters = state.get(key, ("", [0, 0]))
        if old_period != period:
            counters = [0, 0]
        elapsed = current["time"] - previous.get("time", current["time"])
        fraction = 1.0
        if elapsed > 0:
            overlap = min(current["time"], end.timestamp()) - max(
                previous["time"], start.timestamp()
            )
            fraction = max(0.0, min(1.0, overlap / elapsed))
        return [period, [saved + round(change * fraction)
                         for saved, change in zip(counters, diff)]]

    next_month = (month_start + timedelta(days=32)).replace(day=1)
    return {
        "sample": current,
        "day": total("day", day, midnight, midnight + timedelta(days=1)),
        "month": total("month", month, month_start, next_month),
    }


def load():
    try:
        return json.loads(STATE_FILE.read_text())
    except FileNotFoundError:
        return {}


def collect():
    STATE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    with (STATE_DIR / "traffic.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = project(load(), sample())
        with NamedTemporaryFile(mode="w", dir=STATE_DIR, delete=False) as temp:
            path = Path(temp.name)
            try:
                json.dump(state, temp)
                temp.flush()
                path.replace(STATE_FILE)
            finally:
                path.unlink(missing_ok=True)


def units(value):
    for name in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or name == "PiB":
            return f"{value:.1f} {name}"
        value /= 1024


def report(previous=None):
    current = sample()
    state = load()
    totals = project(state, current)
    print(f"  Interface {current['interface']} | waktu VPS")
    for key, label in (("day", "Harian"), ("month", "Bulanan")):
        period, (rx, tx) = totals[key]
        if not state:
            print(f"  {label} {period} | belum dicatat")
            continue
        print(f"  {label} {period}")
        print(f"    RX {units(rx)}  TX {units(tx)}")

    if previous and previous["identity"] == current["identity"]:
        seconds = current["monotonic"] - previous["monotonic"]
        rx, tx = (value * 8 / (seconds * 1_000_000)
                  for value in delta(previous, current))
        print(f"  Realtime  RX {rx:.2f} / TX {tx:.2f} Mbps")
    else:
        print("  Realtime  menunggu sampel")
    return current


def wait_live_navigation():
    if not sys.stdin.isatty():
        time.sleep(1)
        return None

    deadline = time.monotonic() + 1
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
            break
        line = sys.stdin.readline()
        choice = line.strip().lower()
        if choice == "z":
            return 0
        if not line or choice in ("x", "exit", "keluar"):
            return 10  # Status Keluar diteruskan ke dashboard oleh traffic.sh.
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("collect", "show", "live"))
    mode = parser.parse_args().mode
    if mode == "collect":
        collect()
        return

    previous = sample()
    time.sleep(1)
    while True:
        if mode == "live":
            print("\033[H\033[JTRAFIK VPS | Ctrl+C untuk kembali\n", end="")
        previous = report(previous)
        if mode == "show":
            return
        print("\n  [z]  Kembali\n  [x]  Keluar\n  Ketik z atau x, lalu tekan Enter.", flush=True)
        status = wait_live_navigation()
        if status is not None:
            return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
