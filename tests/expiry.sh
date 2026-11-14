#!/usr/bin/env bash
# Isolated fixtures only. Never invoke host account, service, process or network
# commands. File utilities/awk operate only in mktemp. No VPS validation implied.
# flock is a protocol mock: this checks ordering/rechecks, NOT real concurrency.
set -euo pipefail
project="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/ssh"
export NATHAYA_BASE="$project" NATHAYA_SSH_DIR="$work/ssh"
export NATHAYA_CONFIG="$work/config" NATHAYA_LOG_DIR="$work/logs"
export NATHAYA_SSH_DB="$work/ssh/accounts.db"
export NATHAYA_SSH_LOCK="$work/ssh/accounts.lock"
export NATHAYA_SSH_OPERATIONS_LOCK="$work/ssh/operations.lock"
trace="$work/trace"
: > "$trace"
: > "$NATHAYA_SSH_LOCK"
: > "$NATHAYA_SSH_OPERATIONS_LOCK"
printf 'synthetic-key-state\n' > "$work/key-state"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
record_call() { printf '%s\n' "$*" >> "$trace"; }
deny() { record_call "FORBIDDEN $*"; return 97; }
for cmd in useradd userdel chpasswd curl wget systemctl reboot shutdown ssh-keygen; do
    eval "$cmd() { deny $cmd; }"
done
# Initialization/ownership helpers are mocked; never change host ownership.
install() { deny install; }
chown() { :; }
chmod() { :; }
touch() { deny touch; }

MOCK_OP_HELD=0
FAIL_LOCK=0
FAIL_CHAGE=0
FAIL_DB=0
KILL_RC=0
RACE_MODE=""
flock() {
    record_call "flock $*"
    case "$*" in
        '-x 8')
            (( FAIL_LOCK == 0 )) || return 1
            printf '' >&8 || return 1
            MOCK_OP_HELD=1
            # Emulate Renew winning the operation lock before the monitor reads.
            if [[ "$RACE_MODE" == renewed ]]; then
                printf 'raceuser|2025-05-01|2025-06-02|1|active|0|regular\n' > "$NATHAYA_SSH_DB"
            elif [[ "$RACE_MODE" == expirelock ]]; then
                printf 'lockuser|2025-05-01|2025-05-30|1|expired|0|regular\n' > "$NATHAYA_SSH_DB"
            fi
            ;;
        '-u 8') MOCK_OP_HELD=0 ;;
        '-x 9') (( MOCK_OP_HELD == 1 )) || { deny db-before-operation-lock; return 1; } ;;
        *) deny unexpected-flock; return 1 ;;
    esac
}
# Deterministic GNU-date-shaped mock used by the REAL DB expiry helper.
date() {
    if [[ "$*" == '+%F' ]]; then printf '2025-06-01\n'; return; fi
    if [[ "$*" == '+%s' ]]; then printf '100\n'; return; fi
    [[ "${1:-}" == -d ]] || return 1
    case "$2|${3:-}" in
        '2025-06-01 + 2 days|+%F') printf '2025-06-03\n' ;;
        '2025-06-03 + 1 day|+%F') printf '2025-06-04\n' ;;
        '2025-05-01|+%F'|'2025-05-30|+%F'|'2025-06-01|+%F'|'2025-06-02|+%F'|'2025-06-03|+%F'|'2025-06-04|+%F') printf '%s\n' "$2" ;;
        '2025-06-01 11:59:59|+%F %T'|'2025-06-01 12:00:00|+%F %T'|'2025-06-01 12:00:01|+%F %T') printf '%s\n' "$2" ;;
        '2025-06-01 11:59:59|+%s') printf '99\n' ;;
        '2025-06-01 12:00:00|+%s') printf '100\n' ;;
        '2025-06-01 12:00:01|+%s') printf '101\n' ;;
        *) return 1 ;;
    esac
}
fixture_uid() {
    case "$1" in
        root|zerouid) printf '0\n' ;; lowuid) printf '999\n' ;;
        oldregular) printf '1101\n' ;; oldtrial) printf '1102\n' ;;
        exacttrial) printf '1103\n' ;; oldlocked) printf '1104\n' ;;
        oldexpired) printf '1105\n' ;; 0000) printf '1106\n' ;;
        *) printf '1200\n' ;;
    esac
}
getent() {
    [[ "${1:-}" == passwd ]] || return 1
    local u="$2" uid home="/home/$2" shell=/bin/bash
    uid="$(fixture_uid "$u")"
    case "$u" in
        root|zerouid) uid=0 ;;
        lowuid) uid=999 ;;
        badhome) home=/srv/service ;;
        badshell) shell=/usr/sbin/nologin ;;
        missinguser) return 2 ;;
    esac
    printf '%s:x:%s:1001:fixture:%s:%s\n' "$u" "$uid" "$home" "$shell"
}
id() {
    local u="${2:-${1:-}}"
    [[ "$u" != missinguser ]] || return 1
    if [[ "${1:-}" == -u ]]; then
        fixture_uid "$u"
    fi
}
chage() {
    (( MOCK_OP_HELD == 1 )) || { deny chage-without-lock; return 1; }
    record_call "chage $*"
    (( FAIL_CHAGE == 0 ))
}
pkill() {
    (( MOCK_OP_HELD == 1 )) || { deny kill-without-lock; return 2; }
    [[ "$1" == -KILL && "$2" == -u && "$3" =~ ^[1-9][0-9]{3,9}$ ]] || { deny broad-kill; return 2; }
    record_call "pkill $*"
    return "$KILL_RC"
}
PASSWORD_STATE=P
passwd() {
    [[ "$1" == -S ]] || { deny password-mutation; return 1; }
    record_call "passwd $*"
    printf '%s %s fixture\n' "$2" "$PASSWORD_STATE"
}

# Assert source alone performs no initialization or runtime writes.
source "$project/modules/maintenance/ssh-expire.sh"
[[ ! -e "$NATHAYA_SSH_DB" && ! -s "$trace" ]] || fail 'source had side effects'
source "$project/modules/ssh/account-db.sh"
# Retain real DB update implementation, with safe ownership mocks above.
eval "$(declare -f ssh_db_update_status | sed '1s/ssh_db_update_status/fixture_real_update_status/')"
ssh_db_update_status() {
    (( MOCK_OP_HELD == 1 )) || { deny status-without-lock; return 1; }
    record_call "status $*"
    (( FAIL_DB == 0 )) || return 1
    fixture_real_update_status "$@"
}
ssh_db_init() { record_call init; }
run_fixture_scan() (
    exec 8>>"$NATHAYA_SSH_OPERATIONS_LOCK"
    flock -x 8 || return 1
    ssh_expire_scan_locked
)
reset_trace() { : > "$trace"; }
no_mutation() {
    if grep -Eq '^(chage|pkill|status|FORBIDDEN) ' "$trace"; then fail "$1"; fi
}

cp "$project/tests/expiry-fixtures.txt" "$NATHAYA_SSH_DB"
run_fixture_scan
# Exactly these managed expired accounts may be touched, including exact-second
# trial expiry and already-expired retries. Every other record must stay intact.
for u in oldregular oldtrial exacttrial oldlocked oldexpired 0000; do
    grep -Fxq "chage -E 0 $u" "$trace" || fail "expiry missing: $u"
    grep -Fxq "pkill -KILL -u $(fixture_uid "$u")" "$trace" || fail "session kill missing: $u"
done
[[ "$(grep -c '^chage ' "$trace")" == 6 ]] || fail 'unexpected Linux expiry target'
[[ "$(grep -c '^pkill ' "$trace")" == 6 ]] || fail 'unexpected kill target'
while IFS= read -r row; do
    u="${row%%|*}"
    case "$u" in
        oldregular|oldtrial|exacttrial|oldlocked|oldexpired|0000)
            IFS='|' read -r u created expiry limit status until type <<< "$row"
            grep -Fxq "$u|$created|$expiry|$limit|expired|$until|$type" "$NATHAYA_SSH_DB" || fail 'expiry record/lock metadata'
            ;;
        *) grep -Fxq "$row" "$NATHAYA_SSH_DB" || fail "unrelated record changed: $u" ;;
    esac
done < "$project/tests/expiry-fixtures.txt"
! grep -q '^passwd ' "$trace" || fail 'monitor touched password state'
! grep -q 'unmanageduser' "$trace" || fail 'unmanaged account touched'
[[ "$(<"$work/key-state")" == synthetic-key-state ]] || fail 'key state changed'
! grep -q '^FORBIDDEN ' "$trace" || fail 'host operation attempted'

# Failed lock: no mutation and parent FD not leaked (worker uses subshell).
reset_trace
FAIL_LOCK=1
if run_fixture_scan; then fail 'failed operation lock accepted'; fi
FAIL_LOCK=0
no_mutation 'mutation after failed lock'
[[ "$MOCK_OP_HELD" == 0 ]] || fail 'lock state leaked to caller'

# A renewed record observed after acquiring the lock is not expired.
reset_trace
printf 'raceuser|2025-05-01|2025-05-30|1|active|0|regular\n' > "$NATHAYA_SSH_DB"
RACE_MODE=renewed
run_fixture_scan
RACE_MODE=""
no_mutation 'monitor ignored winning renewal'
# Snapshot stale at the per-account recheck is also rejected.
reset_trace
(
    exec 8>>"$NATHAYA_SSH_OPERATIONS_LOCK"
    flock -x 8
    ssh_expire_one_locked raceuser 'raceuser|2025-05-01|2025-05-30|1|active|0|regular'
)
no_mutation 'stale snapshot changed account'

# Linux failure must not claim DB success or kill; DB failure must be retryable.
printf 'oldtrial|2025-06-01|2025-06-01 11:59:59|1|active|0|trial\n' > "$NATHAYA_SSH_DB"
reset_trace
FAIL_CHAGE=1
if run_fixture_scan; then fail 'Linux failure hidden'; fi
FAIL_CHAGE=0
! grep -Eq '^(pkill|status) ' "$trace" || fail 'mutation continued after chage failure'
grep -q '|active|' "$NATHAYA_SSH_DB" || fail 'Linux failure changed DB'
reset_trace
FAIL_DB=1
if run_fixture_scan; then fail 'DB failure hidden'; fi
FAIL_DB=0
grep -q '|active|' "$NATHAYA_SSH_DB" || fail 'DB failure lost retry record'
reset_trace
KILL_RC=1 # No matching process is not an error.
run_fixture_scan
KILL_RC=0
grep -q '|expired|' "$NATHAYA_SSH_DB" || fail 'retry failed'

# Root boundary/default once path. Never demand root just to run local fixtures.
reset_trace
if (( EUID == 0 )); then
    ssh_expire_once
else
    if ssh_expire_once; then fail 'non-root monitor accepted'; fi
    no_mutation 'non-root monitor mutated state'
fi
if ssh_expire_main --unsupported; then fail 'bad monitor argument accepted'; fi

# UI integration is also fully mocked, but production root checks remain intact.
# Skip only these root-gated branches on non-root development environments.
if (( EUID == 0 )); then
    source "$project/modules/ssh/renew.sh"
    source "$project/modules/ssh/lock.sh"
    source "$project/modules/ssh/unlock.sh"
    clear() { :; }
    get_width() { printf '80\n'; }
    draw_nathaya_header() { :; }
    draw_section_title() { :; }
    # Disable optional Telegram by pointing its *code lookup* at an empty fixture
    # only after all real modules have loaded; no external code is sourced there.
    NATHAYA_BASE="$work"
    for password_state in P L NP; do
        PASSWORD_STATE="$password_state"
        printf 'renewuser|2025-05-01|2025-05-30|1|expired|0|regular\n' > "$NATHAYA_SSH_DB"
        reset_trace
        renew_ssh_account > "$work/ui-output" <<'INPUT'
renewuser
2
y

z
INPUT
        expected=locked
        [[ "$password_state" != P ]] || expected=active
        grep -Fxq "renewuser|2025-05-01|2025-06-03|1|$expected|0|regular" "$NATHAYA_SSH_DB" || fail 'renew expired state'
        grep -Fxq 'chage -E 2025-06-04 renewuser' "$trace" || fail 'renew did not restore Linux expiry'
        ! grep -q '^FORBIDDEN ' "$trace" || fail 'renew attempted password unlock or host operation'
        [[ "$MOCK_OP_HELD" == 0 ]] || fail 'renew leaked operation lock'
    done
    PASSWORD_STATE=P
    printf 'renewuser|2025-05-01|2025-05-30|1|expired|123|regular\n' > "$NATHAYA_SSH_DB"
    reset_trace
    renew_ssh_account > "$work/ui-output" <<'INPUT'
renewuser
2
y

z
INPUT
    grep -Fxq 'renewuser|2025-05-01|2025-06-03|1|locked|123|regular' "$NATHAYA_SSH_DB" || fail 'renew lost admin lock metadata'

    # Manual password changes below remain mocks and require operations.lock.
    passwd() {
        record_call "passwd $*"
        case "$1" in
            -S) printf '%s %s fixture\n' "$2" "$PASSWORD_STATE" ;;
            -l|-u)
                (( MOCK_OP_HELD == 1 )) || { deny password-without-lock; return 1; }
                [[ "$1" != -l ]] || PASSWORD_STATE=L
                [[ "$1" != -u ]] || PASSWORD_STATE=P
                ;;
            *) deny unexpected-passwd; return 1 ;;
        esac
    }
    printf 'lockuser|2025-05-01|2025-06-02|1|active|0|regular\n' > "$NATHAYA_SSH_DB"
    PASSWORD_STATE=P
    reset_trace
    lock_ssh_account > "$work/ui-output" <<'INPUT'
lockuser
y

z
INPUT
    grep -Fxq 'passwd -l lockuser' "$trace" || fail 'manual lock absent'
    grep -Fxq 'pkill -KILL -u 1200' "$trace" || fail 'manual lock kill UID'
    grep -q '|locked|0|regular$' "$NATHAYA_SSH_DB" || fail 'manual lock DB'
    [[ "$MOCK_OP_HELD" == 0 ]] || fail 'manual lock leaked FD state'

    PASSWORD_STATE=L
    reset_trace
    unlock_ssh_account > "$work/ui-output" <<'INPUT'
lockuser
y

z
INPUT
    grep -Fxq 'passwd -u lockuser' "$trace" || fail 'manual unlock absent'
    grep -q '|active|0|regular$' "$NATHAYA_SSH_DB" || fail 'manual unlock DB'
    [[ "$MOCK_OP_HELD" == 0 ]] || fail 'manual unlock leaked FD state'

    # Expiry winning after user confirmation blocks stale manual Lock.
    PASSWORD_STATE=P
    RACE_MODE=expirelock
    reset_trace
    lock_ssh_account > "$work/ui-output" <<'INPUT'
lockuser
y

z
INPUT
    RACE_MODE=""
    ! grep -Eq '^passwd -[lu] ' "$trace" || fail 'manual lock ignored expiry race'
    no_mutation 'manual lock mutated stale account'
    ! grep -q '^FORBIDDEN ' "$trace" || fail 'UI host operation attempted'
else
    printf 'SKIP: root-gated Renew/Lock/Unlock UI branches (monitor fixtures still ran).\n'
fi
[[ "$(<"$work/key-state")" == synthetic-key-state ]] || fail 'UI changed key state'
printf 'PASS: isolated expiry fixtures and mocked locking protocol (not real concurrency or VPS tests).\n'
