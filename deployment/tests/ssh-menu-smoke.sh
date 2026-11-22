#!/usr/bin/env bash
set -euo pipefail
NATHAYA_BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
DASHBOARD_EXIT=10
# shellcheck source=../../modules/common/ui.sh
source "$NATHAYA_BASE/modules/common/ui.sh"
# shellcheck source=../../modules/menu/ssh.sh
source "$NATHAYA_BASE/modules/menu/ssh.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

ssh_backend() {
    case "$1" in
        available) [[ "$2" != taken ]] ;;
        create)
            local pw
            read -r pw
            printf '%s:%s:%s:%s\n' "$2" "$pw" "$3" "$4" > "$work/account"
            printf '%s\n' "$2" ;;
        trial) printf '%s:%s\n' "$2" "$3" > "$work/trial"; printf 'trial-fixture\n' ;;
    esac
}
ssh_result() { printf '%s\n' "$2"; }

[[ $(ssh_decode_password '\x') == x && $(ssh_decode_password '\z') == z ]]
[[ $(ssh_limit_value 09) == 9 && $(ssh_limit_value 0) == 0 ]]
! ssh_limit_value 100
! ssh_duration_value 0d d 3650
! ssh_duration_value 999999999999999d d 3650
[[ $(ssh_duration_value 30d d 3650) == 30 ]]
[[ $(ssh_row 'Host server' test) == '  Host server   : test' ]]

# Back from limit to password. Enter retains the previous hidden password.
ssh_create_wizard member > "$work/screen" <<'INPUT'
BAD
member01
\x
z

0
7d
y
INPUT
[[ $(cat "$work/account") == 'member01:x:0:7' ]]
grep -Fq 'Username tidak valid' "$work/screen"
grep -Fq '✓ SSH ACCOUNT CREATED' "$work/screen"
rm -- "$work/account"

rc=0
ssh_create_wizard member > "$work/cancel" <<'INPUT' || rc=$?
member01
\z
2
3d
x
INPUT
[[ $rc == 10 && ! -e "$work/account" ]]
ssh_create_wizard trial > "$work/trial-screen" <<'INPUT'
2
6h
INPUT
[[ $(cat "$work/trial") == '2:6' ]]
grep -Fq '✓ SSH TRIAL CREATED' "$work/trial-screen"

ssh_width=48
ssh_detail_lines() { ssh_row Username "fixture"; }
telegram_send_message() { return 7; }
[[ $(ssh_send_account fixture x 'Fixture') == *'kirim ulang dari List Member'* ]]
printf 'OK: input Create/Trial, z/x, pembatalan, padding, dan kegagalan Telegram (mock).\n'
