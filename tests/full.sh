#!/usr/bin/env bash
# Pure predicates and isolated mocks ONLY. No preflight/worker/main/finalizer,
# countdown, package manager, account operations, services or power operations.
set -euo pipefail
umask 077
project="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
work="$(CDPATH= cd -- "$work" && pwd -P)"
trap 'rm -rf -- "$work"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
expect_fail() { if "$@"; then fail 'unexpected success'; fi; }
deny() { printf 'forbidden\n' >> "$work/forbidden"; return 97; }
for cmd in apt apt-get dpkg dpkg-query systemctl systemd-analyze useradd userdel usermod \
    chpasswd chage passwd pkill killall reboot shutdown poweroff halt curl wget dig \
    ssh-keygen dropbearkey openssl certbot nginx haproxy nft ufw firewall-cmd sync sleep; do
    eval "$cmd() { deny; }"
done
# A source-only helper must not even create/chmod/chown a fixture directory.
for cmd in mkdir rmdir touch install chown chmod cp mv rm tee python3; do
    eval "$cmd() { deny; }"
done
export NATHAYA_BASE="$project" NATHAYA_CONFIG="$work/config"
export NATHAYA_CONFIG_FILE="$work/config/config.conf" NATHAYA_CACHE="$work/cache"
export NATHAYA_LOG_DIR="$work/logs" NATHAYA_SSH_DIR="$work/ssh"
export NATHAYA_SSH_DB="$work/ssh/accounts.db" NATHAYA_SSH_LOCK="$work/ssh/accounts.lock"
export NATHAYA_SSH_OPERATIONS_LOCK="$work/ssh/operations.lock"
unset _NATHAYA_BOOTSTRAP_LOADED
source "$project/setup.sh"  # loads all orchestrator helpers, never invokes main
# These two installer entrypoints are NOT source-only libraries: tls-renew.sh
# and menu-wrapper.sh. Likewise do not source the live profile dashboard hook.
for file in "$project"/installer/*.sh; do
    case "${file##*/}" in tls-renew.sh|menu-wrapper.sh) continue ;; esac
    source "$file"
done
source "$project/menu.sh"
for file in "$project"/modules/*/*.sh; do source "$file"; done
source "$project/services/login-policy.sh"
[[ ! -e "$work/forbidden" ]] || fail 'helper source attempted operations'
[[ ! -e "$work/config" && ! -e "$work/cache" && ! -e "$work/logs" && ! -e "$work/ssh" ]] || fail 'helper source wrote runtime state'
for cmd in mkdir rmdir touch install chmod cp mv rm tee; do unset -f "$cmd"; done
# Keep ownership, Python, networking and host-operation guards in place.

# Unit failures must identify the unit/log BEFORE simulated cleanup. Only the
# orchestrator is tested: strict mock providers, no systemd/setuid/proc execution.
(
    NT_RUN="$work/unit-diagnostics" NT_SOURCE="$project" NT_LOG="$work/worker.log"
    mkdir -m 700 -- "$NT_RUN"
    unit_active=0 status_failure=0 pid_failure=0 validator_rc=1
    nt_set_owner() { [[ "$1" == "$work/"* ]] || fail 'owner outside fixture'; }
    systemctl() {
        printf '%s\n' "$*" >> "$NT_RUN/events"
        case "$*" in
            'is-active --quiet nathaya-haproxy.service') [[ "$unit_active" == 1 ]] ;;
            'show nathaya-haproxy.service -p MainPID --value')
                [[ "$pid_failure" == 0 ]] || return 45
                printf '4242\n' ;;
            'show nathaya-haproxy.service -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p MainPID')
                printf 'ActiveState=failed\nResult=exit-code\nExecMainStatus=3\n'
                printf 'fixture-private-marker\n'
                return "$status_failure" ;;
            *) deny; return 97 ;;
        esac
    }
    python3() {
        [[ $# == 5 && "$1" == -I && "$2" == -B && "$3" == "$project/installer/checks.py" &&
           "$4" == verify-haproxy-identity && "$5" == 4242 ]] || { deny; return 97; }
        printf 'fixture identity result\n'
        return "$validator_rc"
    }
    expect_fail nt_require_unit_active nathaya-haproxy.service 2> "$NT_RUN/message"
    grep -Fq 'unit=nathaya-haproxy.service' "$NT_RUN/message" || fail 'unit failure unnamed'
    grep -Fq '/opt/nathaya/logs/nathaya-haproxy.log' "$NT_RUN/message" || fail 'wrong %N log path'
    grep -Fq 'journalctl -u nathaya-haproxy.service' "$NT_RUN/message" || fail 'journal pointer missing'
    if grep -Fq 'fixture-private-marker' "$NT_RUN/message"; then fail 'private status dumped'; fi
    [[ -f "$NT_RUN/unit-nathaya-haproxy.service.failure" ]] || fail 'no pre-cleanup status snapshot'
    [[ "$(stat -c %a "$NT_RUN/unit-nathaya-haproxy.service.failure")" == 600 ]] || fail 'status not private'
    printf 'simulated-cleanup\n' >> "$NT_RUN/events"
    [[ "$(tail -n 1 "$NT_RUN/events")" == simulated-cleanup ]] || fail 'diagnostics not before cleanup'
    status_failure=1
    expect_fail nt_require_unit_active nathaya-haproxy.service 2> "$NT_RUN/message"
    grep -Fq 'snapshot read failed' "$NT_RUN/unit-nathaya-haproxy.service.failure" || fail 'status-read failure hidden'
    unit_active=1 status_failure=0
    nt_require_unit_active nathaya-haproxy.service
    expect_fail nt_verify_haproxy_identity 2> "$NT_RUN/message"
    grep -Fq 'haproxy-identity-check.log' "$NT_RUN/message" || fail 'identity diagnostics missing'
    [[ "$(stat -c %a "$NT_RUN/haproxy-identity-check.log")" == 600 ]] || fail 'identity log not private'
    validator_rc=0
    nt_verify_haproxy_identity
    pid_failure=1
    expect_fail nt_verify_haproxy_identity 2> "$NT_RUN/message"
    grep -Fq 'MainPID tidak dapat dibaca' "$NT_RUN/message" || fail 'PID query failure hidden'
)

# All seven login policy inputs are data: root + interactive + SSH + tty +
# login shell + not already shown + no forced command. No live hook is sourced.
nathaya_login_policy 0 himBH 'fixture ssh connection' yes -bash '' ''
expect_fail nathaya_login_policy 1000 himBH ssh yes -bash '' ''
expect_fail nathaya_login_policy 0 hBc ssh yes -bash '' ''
expect_fail nathaya_login_policy 0 himBH '' yes -bash '' ''
expect_fail nathaya_login_policy 0 himBH ssh no -bash '' ''
expect_fail nathaya_login_policy 0 himBH ssh yes bash '' ''
expect_fail nathaya_login_policy 0 himBH ssh yes -bash 1 ''
expect_fail nathaya_login_policy 0 himBH ssh yes -bash '' 'scp -t fixture'
nathaya_login_policy 0 i ssh yes -sh '' ''

# Check marker ownership/conflicts using fixture paths, not /etc/profile.d.
hook="$work/hook.sh"
nt_check_hook "$hook"
printf '#!/bin/sh\n# foreign hook\n' > "$hook"
cp -- "$hook" "$work/hook-before"
expect_fail nt_check_hook "$hook"
cmp -s -- "$hook" "$work/hook-before" || fail 'foreign hook changed'
printf '#!/bin/sh\n# Nathaya Tunnel managed dashboard hook v1\n' > "$hook"
nt_check_hook "$hook"
ln -s -- "$hook" "$work/hook-link"
expect_fail nt_check_hook "$work/hook-link"
ln -- "$hook" "$work/hook-hardlink"
expect_fail nt_check_hook "$hook"
rm -- "$work/hook-hardlink"
nt_check_hook "$hook"
[[ ! -e "$work/forbidden" ]] || fail 'hook checks attempted operations'

# Renewal must not start or validate an intentionally stopped nginx (its /run
# directory can be absent); active HAProxy still receives the renewed certificate.
(
    nginx_active=0 nginx_bad=0
    systemctl() {
        case "$*" in
            'is-active --quiet nathaya-nginx.service') [[ "$nginx_active" == 1 ]] ;;
            'is-active --quiet nathaya-haproxy.service') return 0 ;;
            'reload nathaya-nginx.service'|'reload nathaya-haproxy.service') printf '%s\n' "$*" >> "$work/reloads" ;;
            *) deny; return 97 ;;
        esac
    }
    nginx() { [[ "$nginx_active" == 1 && "$nginx_bad" == 0 ]] || return 19; }
    haproxy() { [[ "$*" == '-c -f /etc/nathaya-tunnel/services/haproxy.cfg' ]] || { deny; return 97; }; }
    nt_reload_active_proxies
    [[ "$(cat "$work/reloads")" == 'reload nathaya-haproxy.service' ]] || fail 'inactive proxy affected renewal'
    : > "$work/reloads"
    nginx_active=1 nginx_bad=1
    expect_fail nt_reload_active_proxies
    [[ "$(cat "$work/reloads")" == 'reload nathaya-haproxy.service' ]] || fail 'unrelated parser failure blocked active HAProxy'
)

# Dashboard status uses the real predicates with strict unit-name providers.
(
    service_active=0 socket_active=1 xray_down=''
    systemctl() {
        [[ "$1" == is-active && "$2" == --quiet && $# == 3 ]] || { deny; return 97; }
        printf '%s\n' "$3" >> "$work/unit-queries"
        case "$3" in
            ssh.service) [[ "$service_active" == 1 ]] ;;
            ssh.socket) [[ "$socket_active" == 1 ]] ;;
            vmess@config.service|vless@config.service|trojan@config.service|shadowsocks@config.service)
                [[ "$3" != "$xray_down" ]] ;;
            *) deny; return 97 ;;
        esac
    }
    [[ "$(get_ssh_status)" == ON ]] || fail 'SSH socket not counted'
    service_active=1 socket_active=0
    [[ "$(get_ssh_status)" == ON ]] || fail 'SSH service not counted'
    service_active=0
    [[ "$(get_ssh_status)" == OFF ]] || fail 'inactive SSH reported on'
    [[ "$(get_xray_status)" == ON ]] || fail 'all Xray instances not counted'
    for unit in vmess vless trojan shadowsocks; do
        xray_down="$unit@config.service"
        [[ "$(get_xray_status)" == OFF ]] || fail 'partial Xray reported on'
    done
    for unit in ssh.service ssh.socket vmess@config.service vless@config.service trojan@config.service shadowsocks@config.service; do
        grep -Fxq "$unit" "$work/unit-queries" || fail 'expected unit never queried'
    done
)
mkdir -p -- "$work/ssh"
cat > "$NATHAYA_SSH_DB" <<'DB'
alice|2025-01-01|2026-01-01|1|active|0|regular
bob1|2025-01-01|2026-01-01|1|locked|0|regular
trial1|2025-01-01|2026-01-01 12:00:00|1|expired|0|trial
legacy|2025-01-01|2026-01-01|1|active|0
bad-name|2025-01-01|2026-01-01|1|active|0|regular
aaa|2025-01-01|2026-01-01|1|active|0|regular
other1|2025-01-01|2026-01-01|1|unknown|0|regular
other2|2025-01-01|2026-01-01|1|active|0|other
extra1|2025-01-01|2026-01-01|1|active|0|regular|extra
DB
cp -- "$NATHAYA_SSH_DB" "$work/db-before"
[[ "$(count_ssh_accounts)" == 3 ]] || fail 'seven-column dashboard DB count'
cmp -s -- "$NATHAYA_SSH_DB" "$work/db-before" || fail 'dashboard mutated DB'
NATHAYA_SSH_DB="$work/missing-db"
[[ "$(count_ssh_accounts)" == 0 ]] || fail 'missing DB count'

# Exercise only the pure reboot predicate, NEVER countdown/finalize/power ops.
for profile in full core update help tests; do
    for result in FULL_SUCCESS CORE_SUCCESS GAGAL BERJALAN MENUNGGU; do
        for gates in 0 1 23 ''; do
            if [[ "$profile" == full && "$result" == FULL_SUCCESS && "$gates" == 0 ]]; then
                nt_can_reboot "$profile" "$result" "$gates" || fail 'full gate denied'
            else
                expect_fail nt_can_reboot "$profile" "$result" "$gates"
            fi
        done
    done
done

# APT plan parser with real metadata predicate, mocked dpkg-query ONLY.
(
    dpkg-query() {
        [[ $# == 3 && "$1" == -W ]] || { deny; return 97; }
        printf '%s\n' "$2 $3" >> "$work/dpkg-queries"
        case "$2|$3" in
            '-f=${Status}|fixture-existing') printf 'install ok installed' ;;
            '-f=${Essential} ${Protected}|fixture-essential') printf 'yes no' ;;
            '-f=${Essential} ${Protected}|fixture-protected') printf 'no yes' ;;
            '-f=${Essential} ${Protected}|fixture-removable') printf 'no no' ;;
            '-f=${Status}|fixture-new') return 1 ;;
            *) deny; return 97 ;;
        esac
    }
    nt_package_installed fixture-existing || fail 'dpkg provider installed state'
    printf 'Inst fixture-existing [old] (new repo [amd64])\n' > "$work/plan"
    nt_check_apt_plan "$work/plan" os
    expect_fail nt_check_apt_plan "$work/plan" app
    printf 'Inst fixture-new (1 repo [amd64])\n' > "$work/plan"
    nt_check_apt_plan "$work/plan" app
    printf 'Remv fixture-removable [old]\n' > "$work/plan"
    nt_check_apt_plan "$work/plan" os
    expect_fail nt_check_apt_plan "$work/plan" app
    for critical in openssh-server libc6 fixture-essential fixture-protected:amd64; do
        printf 'Remv %s [old]' "$critical" > "$work/plan"  # final line without newline
        expect_fail nt_check_apt_plan "$work/plan" os
    done
    grep -Fq 'fixture-essential' "$work/dpkg-queries" || fail 'Essential metadata not queried'
    grep -Fq 'fixture-protected' "$work/dpkg-queries" || fail 'Protected metadata not queried'
)

# Existing dig means no bind9-dnsutils request, and no apt/policy operations.
(
    dig() {
        [[ "$*" == '+time=3 +tries=1 +short vpn.example.invalid A' ]] || { deny; return 97; }
        printf '192.0.2.10\n'
    }
    expect_fail nt_dns_package_needed
    nt_package_installed() { return 0; }
    nt_apt() { deny; }
    nt_hold_services() { deny; }
    nt_restore_policy() { deny; }
    NT_RUN="$work" NT_DOMAIN=vpn.example.invalid NT_PUBLIC_IP=192.0.2.10 NT_SSH_EXISTED=0
    nt_dependencies
)
mkdir -- "$work/no-commands"
(
    unset -f dig
    PATH="$work/no-commands"
    nt_dns_package_needed || fail 'missing dig did not require bind9-dnsutils'
)

# Errexit must be active INSIDE nt_run_stage. Do not wrap its invocation in an
# if/!/&&/|| test (that would suppress errexit throughout the called function).
mkdir -- "$work/stage"
cat > "$work/stage-child.sh" <<'CHILD'
set -Eeuo pipefail
source "$1"
NT_RUN="$2"
nt_setup_stage() { :; }
nt_state() { printf '%s\n' "$1" >> "$NT_RUN/states"; }
fixture_failure() { return 23; }
nt_run_stage fixture fixture_failure
printf 'unreachable\n' > "$NT_RUN/reached"
CHILD
set +e
env -i PATH="$PATH" "$BASH" --noprofile --norc "$work/stage-child.sh" "$project/installer/ui.sh" "$work/stage"
rc=$?
set -e
[[ "$rc" == 23 && ! -e "$work/stage/reached" ]] || fail 'failed stage continued'
[[ "$(cat "$work/stage/states")" == BERJALAN ]] || fail 'failed stage marked complete'

# Test EXIT status publication, NOT nt_worker. Every system operation reachable
# in nt_worker_exit is mocked/guarded and every journal is inside a temp root.
cat > "$work/exit-child.sh" <<'CHILD'
set -Eeuo pipefail
source "$1/setup.sh"
NT_RUN="$2" NT_LOG="$2/log" NT_STAGE=fixture NT_STARTED=$SECONDS
NT_RESULT=BERJALAN NT_FINALIZED=0 NT_POLICY_TMP='' NT_POLICY_ACTIVE=0 NT_LOCK_HELD=0
NT_GATES_RC="$3" MOCK_CLEANUP_FAIL="$4"
NT_STARTED_UNITS=fixture.service NT_NEW_ENABLED_UNITS=fixture.timer
nt_state() { printf '%s\n' "$1" >> "$NT_RUN/states"; }
systemctl() {
    case "$*" in 'stop fixture.service'|'disable fixture.timer') ;; *) exit 97 ;; esac
    printf '%s\n' "$*" >> "$NT_RUN/services"
    [[ "$MOCK_CLEANUP_FAIL" == 0 ]]
}
sync() { printf 'mock sync\n' >> "$NT_RUN/sync"; }
rm() { exit 97; }
rmdir() { exit 97; }
nt_restore_policy() { exit 97; }
nt_finalize_success() { exit 97; }
trap nt_worker_exit EXIT
exit 23
CHILD
for fixture in early after-gates cleanup-failure; do
    mkdir -- "$work/$fixture"
    gates=1 cleanup=0 expected=23
    [[ "$fixture" != after-gates ]] || gates=0
    if [[ "$fixture" == cleanup-failure ]]; then cleanup=1; expected=1; fi
    set +e
    env -i PATH="$PATH" "$BASH" --noprofile --norc "$work/exit-child.sh" "$project" "$work/$fixture" "$gates" "$cleanup" > "$work/$fixture/output" 2>&1
    rc=$?
    set -e
    [[ "$rc" == "$expected" ]] || fail 'failure handler exit status'
    [[ "$(cat "$work/$fixture/exit-code")" == "$expected" ]] || fail 'failure journal status'
    [[ "$(cat "$work/$fixture/result")" == GAGAL ]] || fail 'failure result not GAGAL'
    [[ "$(cat "$work/$fixture/states")" == GAGAL ]] || fail 'failure state missing'
    [[ -f "$work/$fixture/sync" ]] || fail 'mock sync not reached'
    if [[ "$gates" == 0 ]]; then
        [[ ! -e "$work/$fixture/services" ]] || fail 'verified units stopped after gates'
    else
        [[ "$(cat "$work/$fixture/services")" == $'stop fixture.service\ndisable fixture.timer' ]] || fail 'partial units cleanup not tracked'
    fi
done
[[ ! -e "$work/forbidden" ]] || fail 'unexpected host operation attempted'
printf 'PASS: isolated full predicates/mocks only; not an installer or VPS run.\n'
