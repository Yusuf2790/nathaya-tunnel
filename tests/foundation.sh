#!/usr/bin/env bash
# Safe local checks only: no menus, network, services or Linux account operations.
set -euo pipefail

project="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
# A failed traversal must not silently produce a partial syntax PASS.
find "$project" -path "$project/.git" -prune -o -type f -name '*.sh' -print0 > "$work/bash-files"
syntax_count=0
while IFS= read -r -d '' file; do
    bash -n "$file"
    syntax_count=$((syntax_count + 1))
done < "$work/bash-files"
(( syntax_count > 0 ))
mkdir -p -- "$work/config"
cp -- "$project/config/config.conf.example" "$work/config/config.conf"
cd -- "$work"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
# Record attempted forbidden commands, even if the caller ignores their status.
deny_operation() { printf 'blocked\n' >> "$work/blocked"; return 97; }
for cmd in mkdir chown chmod install touch curl wget dig useradd userdel chpasswd chage passwd pkill systemctl reboot shutdown; do
    eval "$cmd() { deny_operation; }"
done

unset _NATHAYA_BOOTSTRAP_LOADED NATHAYA_BASE
unset NATHAYA_CONFIG NATHAYA_CONFIG_FILE CONFIG_FILE NATHAYA_CACHE NATHAYA_LOG_DIR
unset NATHAYA_SSH_DIR NATHAYA_SSH_DB NATHAYA_SSH_LOCK NATHAYA_SSH_OPERATIONS_LOCK
# Default code discovery must not redirect runtime data into the checkout.
(
    source "$project/modules/common/bootstrap.sh"
    [[ "$NATHAYA_BASE" == "$project" ]] || fail 'code discovery'
    [[ "$CONFIG_FILE" == /etc/nathaya-tunnel/config.conf ]] || fail 'default config path'
    [[ "$NATHAYA_SSH_DB" == /opt/nathaya/data/ssh/accounts.db ]] || fail 'default DB path'
    [[ "$NATHAYA_LOG_DIR" == /opt/nathaya/logs ]] || fail 'default log path'
    [[ "$NATHAYA_CACHE" == /var/cache/nathaya-tunnel ]] || fail 'default cache path'
)

export NATHAYA_BASE="$project"
export NATHAYA_CONFIG="$work/config"
export NATHAYA_CACHE="$work/cache"
export NATHAYA_LOG_DIR="$work/logs"
export NATHAYA_SSH_DIR="$work/data/ssh"
source "$project/menu.sh"
source "$project/modules/common/telegram.sh"
for file in "$project"/modules/ssh/*.sh; do
    source "$file"
done
[[ ! -e "$work/cache" && ! -e "$work/logs" && ! -e "$work/data" ]] || fail 'source wrote runtime directories'
[[ ! -e "$NATHAYA_SSH_DB" ]] || fail 'source initialized DB'

load_nathaya_config
[[ -z "$DOMAIN" && "$TELEGRAM_STATUS" == OFF ]] || fail 'safe example defaults'
[[ -z "$TELEGRAM_BOT_TOKEN" && -z "$TELEGRAM_ADMIN_ID" ]] || fail 'empty example credentials'

cat > "$CONFIG_FILE" <<'CONFIG'
DOMAIN="$(touch config-executed)"
TELEGRAM_STATUS="OFF"
NATHAYA_BASE="/untrusted-code"
CONFIG_FILE="/untrusted-config"
NATHAYA_SSH_DB="/untrusted-db"
NATHAYA_TELEGRAM_LOG="/untrusted-log"
PATH="/untrusted-bin"
CONFIG
expected_path="$PATH"
load_nathaya_config
[[ "$DOMAIN" == '$(touch config-executed)' ]] || fail 'literal config values'
[[ ! -e config-executed ]] || fail 'config executed a command'
[[ "$NATHAYA_BASE" == "$project" && "$CONFIG_FILE" == "$work/config/config.conf" ]] || fail 'config changed code or reader path'
[[ "$NATHAYA_SSH_DB" == "$work/data/ssh/accounts.db" && "$NATHAYA_TELEGRAM_LOG" == "$work/logs/telegram.log" ]] || fail 'config changed runtime path'
[[ "$PATH" == "$expected_path" ]] || fail 'config changed command path'

printf "  DOMAIN = 'vpn.example.invalid'\r\nTELEGRAM_STATUS=OFF\r\nTELEGRAM_ADMIN_ID=''" > "$CONFIG_FILE"
load_nathaya_config
[[ "$DOMAIN" == vpn.example.invalid ]] || fail 'quoted values, whitespace, CRLF or final line'

printf 'DOMAIN="vpn.example.invalid"\nTELEGRAM_STATUS=INVALID\n' > "$CONFIG_FILE"
if load_nathaya_config; then fail 'invalid config accepted'; fi
[[ -z "$DOMAIN" && "$TELEGRAM_STATUS" == OFF && -z "$TELEGRAM_BOT_TOKEN" ]] || fail 'invalid config left stale state'
printf 'touch config-executed\n' > "$CONFIG_FILE"
if load_nathaya_config; then fail 'shell command accepted'; fi
rm -- "$CONFIG_FILE"
if load_nathaya_config; then fail 'missing config accepted'; fi
[[ -z "$DOMAIN" && "$TELEGRAM_STATUS" == OFF ]] || fail 'missing config left stale state'
[[ ! -s "$work/blocked" ]] || fail 'source/config attempted forbidden operation'
printf 'PASS: Bash syntax and isolated foundation smoke checks (not a VPS test).\n'
