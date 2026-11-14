#!/usr/bin/env bash
# Safety gate, NOT a claim that opaque UDP binaries have been installed.
nt_udp_require() {
    python3 -I -B "$NT_SOURCE/installer/artifacts.py" --lock "$NT_SOURCE/installer/external-lock.json" --check-full
}
