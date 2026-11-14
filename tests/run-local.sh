#!/usr/bin/env bash
# Explicit offline allowlist; no installation/service/tool execution or network.
# installer.sh retains its read-only help/rejected-argument setup checks;
# other shell children perform syntax checks or use isolated mocks only.
# Usage: bash tests/run-local.sh (no root needed, no package installation).
set -euo pipefail
project="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ $# == 0 ]] || { printf 'Usage: bash tests/run-local.sh\n' >&2; exit 2; }
command -v bash >/dev/null || { printf 'Bash required\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf 'Python 3 required\n' >&2; exit 1; }
# No inherited BASH_ENV, exported functions, runtime paths or provider secrets.
clean=(env -i "PATH=$PATH")
[[ -z "${TMPDIR:-}" ]] || clean+=("TMPDIR=$TMPDIR")
# foundation.sh performs bash -n on ALL checkout shell files before its fixtures.
for test in foundation.sh installer.sh expiry.sh full.sh; do
    printf 'Offline shell fixture: %s\n' "$test"
    "${clean[@]}" "$BASH" --noprofile --norc "$project/tests/$test"
done
# -I isolates imports/environment; -B prevents import-created __pycache__.
# integration_test.py additionally compiles every Python source in memory.
for test in update_test.py services_test.py ssh_listeners_test.py haproxy_identity_test.py openvpn_test.py integration_test.py; do
    printf 'Offline Python fixture: %s\n' "$test"
    "${clean[@]}" python3 -I -B "$project/tests/$test"
done
printf 'PASS: local offline fixture suite only; no VPS/service interoperability claim.\n'
