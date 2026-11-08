#!/bin/bash
# Nathaya code-only installer: Alrescha backend, Nathaya UI and Telegram modules.
# Setup calls: bash lib/install-runtime.sh --source /opt/nathaya/source
# No setup, config, account, CA, cron or service operations are performed here.
set -euo pipefail
fail() { printf 'NATHAYA TUNNEL: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' \
        'Usage: bash lib/install-runtime.sh [--source REPOSITORY] [--yes]' \
        '--source: install complete local code without network access or a prompt.' \
        'Without --source: download one complete Nathaya snapshot after confirmation.' \
        '--yes: explicitly authorize that download and runtime replacement.' \
        'Requires root on Ubuntu 24.04 x86_64; only allowlisted runtime files are replaced.' \
        'Configs, accounts, CA and service state are preserved.' \
        'Ownership: /var/lib/nathaya-tunnel/owned-files.tsv, SHA256<TAB>PATH, no header.'
}
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
for dependency in bash awk uname stat mktemp cp mkdir rm mv chmod install flock od tr sha256sum node; do
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
ensure_directory() {
    local path="$1" mode="${2:-755}"
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        ensure_directory "${path%/*}"
        install -d -o root -g root -m "$mode" -- "$path"
    fi
    trusted_directory "$path"
}
require_host
[[ -n "$source_dir" ]] || confirm_download
trusted_directory /root
work=$(mktemp -d /root/.nathaya-runtime.XXXXXXXX) || fail 'Cannot create private staging directory.'
temporary=''
ledger_temporary=''
cleanup() {
    [[ -z "$temporary" ]] || rm -f -- "$temporary"
    [[ -z "$ledger_temporary" ]] || rm -f -- "$ledger_temporary"
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z "$source_dir" ]]; then
    fetch_snapshot "$work" || fail 'Cannot unpack the Nathaya snapshot.'
    source_dir="$work/repository/nathaya-tunnel-main"
fi
source_dir=$(cd -- "$source_dir" && pwd -P) || fail 'Source directory not found.'
trusted_directory "$source_dir"

stage_source() {
    local relative="$1" output="$2"
    trusted_file "$source_dir/$relative"
    mkdir -p -- "${output%/*}"
    cp -- "$source_dir/$relative" "$output" || fail "Cannot stage $relative"
    [[ -s "$output" ]] || fail "Empty source: $relative"
}
reject_nul() {
    od -An -v -tu1 -- "$1" | awk '
        { for (i = 1; i <= NF; i++) if ($i == 0) bad = 1 }
        END { exit bad }' || fail "Unexpected NUL in source: $2"
}
stage_source install-manifest.tsv "$work/files/install-manifest.tsv"
reject_nul "$work/files/install-manifest.tsv" install-manifest.tsv
declare -a modes=() kinds=() sources=() targets=()
declare -A destinations=() staged=() contracts=()
# Exact source/kind/destination contracts prevent overwriting unrelated OS tools.
declare -Ar allowed_commands=(
    ["/usr/bin/addshadowsocks"]="bash:project/addshadowsocks"
    ["/usr/bin/addssh"]="bash:project/addssh"
    ["/usr/bin/addtrojan"]="bash:project/addtrojan"
    ["/usr/bin/addvless"]="bash:project/addvless"
    ["/usr/bin/addvmess"]="bash:project/addvmess"
    ["/usr/bin/autokill"]="bash:project/autokill"
    ["/usr/bin/backuprestore"]="bash:project/backuprestore"
    ["/usr/bin/backuprestore.js"]="node:project/backuprestore.js"
    ["/usr/bin/checkshadowsocks"]="bash:project/checkshadowsocks"
    ["/usr/bin/checkssh"]="bash:project/checkssh"
    ["/usr/bin/checktrojan"]="bash:project/checktrojan"
    ["/usr/bin/checkvless"]="bash:project/checkvless"
    ["/usr/bin/checkvmess"]="bash:project/checkvmess"
    ["/usr/bin/dellshadowsocks"]="bash:project/dellshadowsocks"
    ["/usr/bin/dellssh"]="bash:project/dellssh"
    ["/usr/bin/delltrojan"]="bash:project/delltrojan"
    ["/usr/bin/dellvless"]="bash:project/dellvless"
    ["/usr/bin/dellvmess"]="bash:project/dellvmess"
    ["/usr/bin/exp"]="bash:project/exp"
    ["/usr/bin/features"]="bash:project/features"
    ["/usr/bin/limitip"]="bash:project/limitip"
    ["/usr/bin/limitipssh"]="bash:project/limitipssh"
    ["/usr/bin/limitssh"]="bash:project/limitipssh"
    ["/usr/bin/logclear"]="bash:project/logclear"
    ["/usr/bin/menu"]="bash:project/menu"
    ["/usr/bin/menushadowsocks"]="bash:project/menushadowsocks"
    ["/usr/bin/menussh"]="bash:project/menussh"
    ["/usr/bin/menutrojan"]="bash:project/menutrojan"
    ["/usr/bin/menuvless"]="bash:project/menuvless"
    ["/usr/bin/menuvmess"]="bash:project/menuvmess"
    ["/usr/bin/quota"]="bash:project/quota"
    ["/usr/bin/renewssh"]="bash:project/renewssh"
    ["/usr/bin/renewtrojan"]="bash:project/renewtrojan"
    ["/usr/bin/renewvmess"]="bash:project/renewvmess"
    ["/usr/bin/renewvless"]="bash:project/renewvless"
    ["/usr/bin/trialtrojan"]="bash:project/trialtrojan"
    ["/usr/bin/trialvmess"]="bash:project/trialvmess"
    ["/usr/bin/trialvless"]="bash:project/trialvless"
    ["/usr/bin/trialssh"]="bash:project/trialssh"
    ["/usr/bin/trialshadowsocks"]="bash:project/trialshadowsocks"
    ["/usr/bin/exp-warning"]="bash:project/exp-warning"
    ["/usr/bin/trial"]="bash:project/trial"
    ["/usr/bin/renewshadowsocks"]="bash:project/renewshadowsocks.sh"
    ["/usr/local/bin/add-vmess"]="bash:project/addvmess"
    ["/usr/local/bin/add-vless"]="bash:project/addvless"
    ["/usr/local/bin/add-trojan"]="bash:project/addtrojan"
    ["/usr/local/bin/add-shadowsocks"]="bash:project/addshadowsocks"
    ["/usr/local/bin/add-ssh"]="bash:project/addssh"
    ["/usr/local/bin/del-vmess"]="bash:project/dellaccvmess.sh"
    ["/usr/local/bin/del-trojan"]="bash:project/dellacctrojan.sh"
    ["/usr/local/bin/del-vless"]="bash:project/dellaccvless.sh"
    ["/usr/local/bin/del-shadowsocks"]="bash:project/dellaccshadowsocks.sh"
    ["/usr/local/bin/del-ssh"]="bash:project/dellaccssh.sh"
    ["/usr/local/bin/check-vless"]="bash:project/checkuservless.sh"
    ["/usr/local/bin/check-trojan"]="bash:project/checkusertrojan.sh"
    ["/usr/local/bin/check-shadowsocks"]="bash:project/checkusershadowsocks.sh"
    ["/usr/local/bin/check-ssh"]="bash:project/checkuserssh.sh"
    ["/usr/local/bin/check-vmess"]="bash:project/checkuservmess.sh"
    ["/usr/local/bin/renew-vmess"]="bash:project/renewaccvmess.sh"
    ["/usr/local/bin/renew-ssh"]="bash:project/renewaccssh.sh"
    ["/usr/local/bin/renew-vless"]="bash:project/renewaccvless.sh"
    ["/usr/local/bin/renew-trojan"]="bash:project/renewacctrojan.sh"
    ["/usr/local/bin/renew-shadowsocks"]="bash:project/renewshadowsocks.sh"
    ["/usr/bin/nathaya-update"]="bash:update.sh"
)
declare -Ar allowed_metadata=(
    ["/opt/nathaya/modules/common/account-presentation.sh"]="644:bash:modules/common/account-presentation.sh"
    ["/opt/nathaya/modules/common/functions.sh"]="644:bash:modules/common/functions.sh"
    ["/opt/nathaya/modules/common/runtime-ui.sh"]="644:bash:modules/common/runtime-ui.sh"
    ["/opt/nathaya/modules/common/telegram.sh"]="644:bash:modules/common/telegram.sh"
    ["/opt/nathaya/modules/common/ui.sh"]="644:bash:modules/common/ui.sh"
    ["/opt/nathaya/modules/dashboard/dashboard.sh"]="644:bash:modules/dashboard/dashboard.sh"
    ["/opt/nathaya/modules/menu/domain.sh"]="644:bash:modules/menu/domain.sh"
    ["/opt/nathaya/modules/menu/main.sh"]="644:bash:modules/menu/main.sh"
    ["/opt/nathaya/modules/menu/protocol.sh"]="644:bash:modules/menu/protocol.sh"
    ["/opt/nathaya/modules/menu/set_domain.sh"]="644:bash:modules/menu/set_domain.sh"
    ["/opt/nathaya/modules/menu/shadowsocks-operations.sh"]="644:bash:modules/menu/shadowsocks-operations.sh"
    ["/opt/nathaya/modules/menu/ssh-operations.sh"]="644:bash:modules/menu/ssh-operations.sh"
    ["/opt/nathaya/modules/menu/ssh.sh"]="644:bash:modules/menu/ssh.sh"
    ["/opt/nathaya/modules/menu/trojan-operations.sh"]="644:bash:modules/menu/trojan-operations.sh"
    ["/opt/nathaya/modules/menu/vless-operations.sh"]="644:bash:modules/menu/vless-operations.sh"
    ["/opt/nathaya/modules/menu/vmess-operations.sh"]="644:bash:modules/menu/vmess-operations.sh"
    ["/opt/nathaya/lib/install-runtime.sh"]="644:bash:lib/install-runtime.sh"
    ["/opt/nathaya/install-manifest.tsv"]="644:text:install-manifest.tsv"
    ["/opt/nathaya/LICENSE"]="644:text:LICENSE"
)
while IFS= read -r row || [[ -n "$row" ]]; do
    [[ -n "$row" && "$row" != \#* ]] || continue
    IFS=$'\t' read -r mode kind source target extra <<<"$row"
    [[ -z "${extra:-}" && "$row" == "$mode"$'\t'"$kind"$'\t'"$source"$'\t'"$target" ]] || fail 'Malformed manifest row; four tab-separated fields are required.'
    [[ "$source" =~ ^[A-Za-z0-9_+./-]+$ && "$source" != /* && "$source" != *..* ]] || fail 'Unsafe manifest source.'
    [[ "$target" =~ ^/[A-Za-z0-9_+./-]+$ && "$target" != *..* && "$target" != *//* ]] || fail 'Unsafe manifest destination.'
    if [[ -n "${allowed_commands[$target]:-}" ]]; then
        [[ "$mode" == 755 && "${allowed_commands[$target]}" == "$kind:$source" ]] || fail "Unexpected command mapping: $target"
    else
        [[ "${allowed_metadata[$target]:-}" == "$mode:$kind:$source" ]] || fail "Unexpected runtime mapping: $target"
    fi
    [[ -z "${destinations[$target]:-}" ]] || fail "Duplicate manifest destination: $target"
    [[ -z "${contracts[$source]:-}" || "${contracts[$source]}" == "$mode:$kind" ]] || fail "Conflicting source contract: $source"
    destinations["$target"]="$source"
    contracts["$source"]="$mode:$kind"
    modes+=("$mode"); kinds+=("$kind"); sources+=("$source"); targets+=("$target")
done <"$work/files/install-manifest.tsv"
for required in "${!allowed_commands[@]}" "${!allowed_metadata[@]}"; do
    [[ -n "${destinations[$required]:-}" ]] || fail "Manifest lacks required destination: $required"
done
(( ${#targets[@]} == ${#allowed_commands[@]} + ${#allowed_metadata[@]} )) || fail 'Incomplete runtime manifest.'

# Inspect bytes without placing NUL-containing source in a shell variable.
# The six upstream Bash helpers and any Bash source with ONE final NUL are
# normalized only in staging. Embedded or multiple NUL bytes are refused.
normalize_staged_bash() {
    local file="$1" relative="$2" mode="$3" nul_policy shebang='' normalized
    nul_policy=$(
        od -An -v -tu1 -- "$file" | awk '
            { for (i = 1; i <= NF; i++) { last = $i; if ($i == 0) count++ } }
            END {
                if (count == 0) print "clean"
                else if (count == 1 && last == 0) print "one-final"
                else print "reject"
            }'
    ) || fail "Cannot inspect Bash bytes: $relative"
    case "$nul_policy" in
        clean) ;;
        one-final)
            normalized="$file.nul-normalized"
            tr -d '\000' <"$file" >"$normalized" || fail "Cannot normalize staged source: $relative"
            mv -fT -- "$normalized" "$file"
            normalized_count=$((normalized_count + 1))
            printf 'Normalized one final NUL in staging only: %s\n' "$relative"
            ;;
        *) fail "Invalid NUL bytes in Bash source: $relative" ;;
    esac
    chmod "$mode" -- "$file"
    IFS= read -r shebang <"$file" || [[ -n "$shebang" ]] || fail "Missing Bash shebang: $relative"
    case "$shebang" in
        '#!/bin/bash'|'#!/usr/bin/env bash') ;;
        *) fail "Expected a Bash shebang: $relative" ;;
    esac
}
normalized_count=0
for (( index=0; index<${#sources[@]}; index++ )); do
    source="${sources[index]}"
    [[ -z "${staged[$source]:-}" ]] || continue
    file="$work/files/$source"
    [[ "$source" == install-manifest.tsv ]] || stage_source "$source" "$file"
    case "${kinds[index]}" in
        bash)
            normalize_staged_bash "$file" "$source" "${modes[index]}"
            # Parse staged code; never run or shell-source any payload.
            bash -n -- "$file" || fail "Invalid shell syntax: $source"
            ;;
        node)
            reject_nul "$file" "$source"
            node -c "$file" >/dev/null || fail "Invalid JavaScript syntax: $source"
            ;;
        text) reject_nul "$file" "$source" ;;
        *) fail "Unsupported runtime kind: ${kinds[index]}" ;;
    esac
    staged["$source"]=1
done
# Nothing is installed until the entire allowlisted source set is staged.
ensure_directory /opt/nathaya
lock=/opt/nathaya/.runtime.lock
if [[ -e "$lock" || -L "$lock" ]]; then
    trusted_file "$lock"
    [[ $(stat -c '%a' -- "$lock") == 600 ]] || fail 'Runtime lock must have mode 600.'
fi
# Append avoids truncating an existing lock before acquiring it.
exec 9>>"$lock"
flock -n 9 || fail 'Another runtime deployment is active.'

ensure_directory /var/lib/nathaya-tunnel 700
ledger=/var/lib/nathaya-tunnel/owned-files.tsv
ledger_lock=/var/lib/nathaya-tunnel/owned-files.tsv.lock
if [[ -e "$ledger_lock" || -L "$ledger_lock" ]]; then
    trusted_file "$ledger_lock"
    [[ $(stat -c '%g:%a' -- "$ledger_lock") == 0:600 ]] || fail 'Ownership lock must be private.'
else
    install -o root -g root -m 600 /dev/null "$ledger_lock"
fi
exec {ledger_fd}>>"$ledger_lock"
flock -x "$ledger_fd"
if [[ -e "$ledger" || -L "$ledger" ]]; then
    trusted_file "$ledger"
    # Exactly SHA256<TAB>absolute-path, without a header or additional columns.
    awk -F '\t' '
        NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/ ||
        $2 !~ /^\/[A-Za-z0-9_+.@:\/-]+$/ || $2 ~ /\/\// ||
        $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /\/$/ || seen[$2]++ { bad = 1; exit }
        END { exit bad }' "$ledger" || fail 'Invalid ownership ledger; refusing to discard existing ownership.'
    cp -- "$ledger" "$work/previous-owned.tsv"
else
    : >"$work/previous-owned.tsv"
fi
for target in "${targets[@]}"; do
    ensure_directory "${target%/*}"
    if [[ -e "$target" || -L "$target" ]]; then
        trusted_file "$target"
    fi
done

# Back up all existing code AND the ownership ledger before any replacements.
# Private directories remain available after a deployment error.
backup=$(mktemp -d /opt/nathaya/runtime-backup.XXXXXXXX) || fail 'Cannot create private runtime backup.'
printf 'source\tdestination\tprevious\n' >"$backup/index.tsv"
if [[ -f "$ledger" ]]; then
    cp -p -- "$ledger" "$backup/owned-files.tsv"
    printf 'saved\n' >"$backup/ownership-previous"
else
    printf 'absent\n' >"$backup/ownership-previous"
fi
: >"$work/runtime-owned.tsv"
for (( index=0; index<${#sources[@]}; index++ )); do
    target="${targets[index]}"
    previous=absent
    if [[ -f "$target" ]]; then
        mkdir -p -- "$backup${target%/*}"
        cp -p -- "$target" "$backup$target"
        previous=saved
    fi
    printf '%s\t%s\t%s\n' "${sources[index]}" "$target" "$previous" >>"$backup/index.tsv"
    digest=$(sha256sum -- "$work/files/${sources[index]}")
    digest="${digest%% *}"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail 'Cannot hash staged runtime code.'
    printf '%s\t%s\n' "$digest" "$target" >>"$work/runtime-owned.tsv"
done
# Keep parent-owned entries, updating just this manifest's exact destination set.
awk -F '\t' '
    FILENAME == ARGV[1] { hashes[$2] = $1; paths[++count] = $2; next }
    !($2 in hashes) { print }
    END { for (i = 1; i <= count; i++) printf "%s\t%s\n", hashes[paths[i]], paths[i] }
' "$work/runtime-owned.tsv" "$work/previous-owned.tsv" >"$work/merged-owned.tsv"
cp -- "$work/merged-owned.tsv" "$backup/owned-files.next.tsv"
ledger_temporary=$(mktemp /var/lib/nathaya-tunnel/.owned-files.XXXXXXXX) || fail "Cannot stage ownership ledger; backup: $backup"
install -o root -g root -m 600 -- "$work/merged-owned.tsv" "$ledger_temporary"
# Publish expected hashes first: even an interrupted copy leaves new code owned.
# Unchanged/old files with nonmatching hashes are preserved by hash-based removal.
mv -fT -- "$ledger_temporary" "$ledger"
ledger_temporary=''

# Per-file atomic replacement, not a multi-file filesystem transaction.
# On failure retain the backup and stop; never touch configs or restart services.
for (( index=0; index<${#sources[@]}; index++ )); do
    target="${targets[index]}"
    temporary=$(mktemp "${target%/*}/.nathaya-runtime.XXXXXXXX") || fail "Cannot stage target; backup: $backup"
    if ! install -o root -g root -m "${modes[index]}" -- "$work/files/${sources[index]}" "$temporary" ||
        ! mv -fT -- "$temporary" "$target"; then
        fail "Runtime replacement failed; backup: $backup"
    fi
    temporary=''
done
printf 'NATHAYA TUNNEL: %s runtime destinations installed from %s sources.\n' "${#targets[@]}" "${#staged[@]}"
printf 'Staged final NUL normalization: %s; original sources unchanged.\n' "$normalized_count"
printf 'Ownership ledger: %s\nPrivate runtime backup: %s\n' "$ledger" "$backup"
printf '%s\n' 'Configs, accounts, CA and services were not changed.'
