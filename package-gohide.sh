#!/bin/bash
# Nathaya runtime-code adapter. Never runs setup or an external menu.
set -euo pipefail
fail() { printf 'NATHAYA TUNNEL: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' \
        'Usage: bash package-gohide.sh [--source REPOSITORY] [--yes]' \
        '--source: install a complete local repository without network access.' \
        '--yes: explicitly authorize the published snapshot download and runtime update.' \
        'Requires root on Ubuntu 24.04 x86_64. Configs, accounts, CA and services are not changed.'
}
# Help never reads host state, downloads, prompts, or installs anything.
for argument in "$@"; do
    case "$argument" in --help|-h) usage; exit 0 ;; esac
done
source_dir=''
confirmed=0
while (( $# )); do
    case "$1" in
        --source)
            (( $# >= 2 )) && [[ -n "$2" && -z "$source_dir" ]] || fail '--source requires one repository directory.'
            source_dir="$2"; shift 2 ;;
        --yes|-y) confirmed=1; shift ;;
        *) fail "Unknown argument: $1" ;;
    esac
done
umask 077
export PATH='/usr/sbin:/usr/bin:/sbin:/bin' LC_ALL=C
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH
for dependency in bash awk uname stat dirname mktemp rm cmp; do
    command -v "$dependency" >/dev/null 2>&1 || fail "Missing dependency: $dependency"
done
trusted_directory() {
    local path="$1" owner permission
    while :; do
        [[ -d "$path" && ! -L "$path" ]] || fail "Non-directory or symlink in ancestry: $path"
        read -r owner permission < <(stat -c '%u %a' -- "$path")
        [[ "$owner" == 0 && "$permission" =~ ^[0-7]{3,4}$ ]] || fail "Untrusted directory owner/mode: $path"
        (( (8#$permission & 0022) == 0 )) || fail "Writable directory ancestry: $path"
        [[ "$path" != / ]] || break
        path="${path%/*}"; [[ -n "$path" ]] || path=/
    done
}
trusted_file() {
    local path="$1" owner permission links
    trusted_directory "${path%/*}"
    [[ -f "$path" && ! -L "$path" ]] || fail "Missing/non-regular file: $path"
    read -r owner permission links < <(stat -c '%u %a %h' -- "$path")
    [[ "$owner" == 0 && "$permission" =~ ^[0-7]{3,4}$ && "$links" == 1 ]] || fail "Untrusted file owner/mode/link count: $path"
    (( (8#$permission & 0022) == 0 )) || fail "Writable file: $path"
}
require_host() {
    (( EUID == 0 )) || fail 'Root is required on Ubuntu 24.04.'
    [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Linux x86_64 is required.'
    [[ -r /etc/os-release && ! -e /system/build.prop && -z ${ANDROID_ROOT:-} ]] || fail 'Android is unsupported.'
    local os_id os_version
    os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
    os_version=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
    [[ "$os_id:$os_version" == ubuntu:24.04 ]] || fail 'Only Ubuntu 24.04 is supported.'
}
confirm_download() {
    (( confirmed == 0 )) || return 0
    local answer
    printf '%s\n' 'This replaces Nathaya runtime code only; configs, accounts, CA and services are preserved.' >&2
    if ! read -r -p 'Download and install the Nathaya snapshot? Type UPDATE: ' answer </dev/tty; then
        fail 'A terminal confirmation or explicit --yes is required.'
    fi
    [[ "$answer" == UPDATE ]] || fail 'No changes requested.'
}
fetch_snapshot() {
    local destination="$1"
    for dependency in curl python3; do
        command -v "$dependency" >/dev/null 2>&1 || fail "Missing dependency: $dependency"
    done
    # One archive supplies the helper, manifest, commands and modules together.
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 300 --max-filesize 536870912 \
        --output "$destination/source.tar.gz" \
        'https://github.com/Yusuf2790/nathaya-tunnel/archive/refs/heads/main.tar.gz' || fail 'Snapshot download failed.'
    # Inspect every member before extraction; no links, devices or path escapes.
    python3 -I - "$destination/source.tar.gz" "$destination/repository" <<'PY'
import os
import shutil
import sys
import tarfile

archive, output = sys.argv[1:]
root = 'nathaya-tunnel-main'
try:
    with tarfile.open(archive, 'r:gz') as bundle:
        members = []
        seen = set()
        total = 0
        for member in bundle:
            name = member.name.rstrip('/') if member.isdir() else member.name
            parts = name.split('/')
            if (not name or parts[0] != root or
                    any(part in ('', '.', '..') for part in parts) or
                    any(ord(char) < 32 or char == '\\' for char in name) or
                    name in seen or not (member.isdir() or member.isfile()) or
                    member.size < 0 or member.size > 134217728):
                raise ValueError('Unsafe archive member')
            seen.add(name)
            total += member.size
            if len(seen) > 100000 or total > 1073741824:
                raise ValueError('Archive exceeds size limits')
            members.append((member, parts))
        if not members:
            raise ValueError('Empty archive')
        os.mkdir(output, 0o700)
        for member, parts in members:
            target = os.path.join(output, *parts)
            if member.isdir():
                os.makedirs(target, mode=0o700, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError('Missing archive content')
                with stream, open(target, 'xb') as installed:
                    shutil.copyfileobj(stream, installed)
                os.chmod(target, 0o600)
except (OSError, ValueError, tarfile.TarError) as error:
    print('NATHAYA TUNNEL: snapshot extraction refused: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
}
require_host
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=''
cleanup() { [[ -z "$work" ]] || rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z "$source_dir" && -f "$here/lib/install-runtime.sh" ]]; then
    source_dir="$here"
fi
if [[ -z "$source_dir" ]]; then
    confirm_download
    trusted_directory /root
    work=$(mktemp -d /root/.nathaya-snapshot.XXXXXXXX) || fail 'Cannot create private staging directory.'
    fetch_snapshot "$work" || fail 'Cannot unpack the Nathaya snapshot.'
    source_dir="$work/repository/nathaya-tunnel-main"
fi
source_dir=$(cd -- "$source_dir" && pwd -P) || fail 'Source directory not found.'
trusted_directory "$source_dir"
helper="$source_dir/lib/install-runtime.sh"
trusted_file "$helper"
installed_helper=/opt/nathaya/lib/install-runtime.sh
if [[ -e "$installed_helper" || -L "$installed_helper" ]]; then
    trusted_file "$installed_helper"
    # Reuse installed code only when it matches this complete snapshot exactly.
    if cmp -s -- "$helper" "$installed_helper"; then
        helper="$installed_helper"
    fi
fi
# Never fetch a helper independently of its manifest and runtime sources.
bash -n -- "$helper" || fail 'Invalid runtime helper syntax.'
bash "$helper" --source "$source_dir"
