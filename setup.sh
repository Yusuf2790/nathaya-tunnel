#!/usr/bin/env bash
# Nathaya Tunnel orchestrator. Source loads definitions only; --help/--plan read-only.
if [[ "${BASH_SOURCE[0]}" == "$0" && "${1:-}" != --help && "${1:-}" != -h && "${1:-}" != --plan && "${_NT_CLEAN:-}" != 1 ]]; then
    [[ -x /usr/bin/env && -x /bin/bash ]] || { printf 'ERROR: Android/Termux bukan target instalasi.\n' >&2; exit 1; }
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 TERM="${TERM:-dumb}" _NT_CLEAN=1 /bin/bash --noprofile --norc "${BASH_SOURCE[0]}" "$@"
fi
_NT_SOURCE="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for _nt_module in lib policy openssh domain dependencies firewall dropbear websocket udp openvpn ui runtime tls xray proxies maintenance verify preflight; do
    source "$_NT_SOURCE/installer/$_nt_module.sh" || { return 1 2>/dev/null || exit 1; }
done
unset _nt_module

nt_setup_help() {
    cat <<'HELP'
NATHAYA TUNNEL — modular installer 2.0.0
Target: root VPS Ubuntu 24.04 amd64, systemd PID1. NOT Android/Termux.
bash setup.sh [--profile full|core] --domain vpn.example.org --accept-acme-tos
bash setup.sh --help | --plan
Default full currently BLOCKED by unaudited OpenVPN server archive and opaque
UDP Custom/BadVPN provenance. This is not a completed full install.
Explicit core installs SSH/Dropbear/WS/TLS/Nginx/HAProxy/Xray + SSH expiry;
Xray account panel/IP limiter/OpenVPN/UDP are NOT supplied by core.
Both installation profiles authorize apt update/upgrade/dist-upgrade, inventory
and removal of UFW/firewalld, and public/drop mode 777 (nonsecret, not served).
No recursive 777. Preserve admin SSH port/auth, private config/DB/host keys.
Full reboot only after every mandatory full gate passes; core never reboots.
Detached worker writes private permanent logs; closing viewer does not stop it.
Use separate trusted source outside /opt/nathaya. No destination override.
See docs/install.md and docs/alrescha-parity.md before using on a rebuilt VPS.
HELP
}

nt_write_result() {
    printf '%s\n' "$1" > "$NT_RUN/exit-code" || return 1
    printf '%s\n' "$NT_RESULT" > "$NT_RUN/result" || return 1
}
nt_finalize_success() {
    [[ "$NT_GATES_RC" == 0 && ( "$NT_RESULT" == CORE_SUCCESS || "$NT_RESULT" == FULL_SUCCESS ) ]] || return 1
    if [[ "${NT_POLICY_ACTIVE:-0}" == 1 ]]; then nt_restore_policy || return 1; fi
    if [[ "${NT_LOCK_HELD:-0}" == 1 ]]; then
        rmdir /run/nathaya-tunnel-setup.lock || return 1
        NT_LOCK_HELD=0
    fi
    nt_write_result 0 || return 1
    printf 'Durasi %s detik. Status=%s. Log privat=%s\n' "$((SECONDS - NT_STARTED))" "$NT_RESULT" "$NT_LOG"
    sync
    NT_FINALIZED=1
}
nt_worker_exit() {
    local rc=$? cleanup_failed=0
    if [[ "${NT_FINALIZED:-0}" == 1 && "$rc" == 0 ]]; then trap - EXIT; exit 0; fi
    trap - EXIT ERR INT TERM
    set +e
    if [[ -n "${NT_POLICY_TMP:-}" ]]; then rm -f -- "$NT_POLICY_TMP" || cleanup_failed=1; fi
    if [[ "${NT_POLICY_ACTIVE:-0}" == 1 ]]; then nt_restore_policy || cleanup_failed=1; fi
    if (( rc != 0 )) && [[ "${NT_GATES_RC:-1}" != 0 ]]; then
        local unit
        for unit in ${NT_STARTED_UNITS:-}; do systemctl stop "$unit" || cleanup_failed=1; done
        for unit in ${NT_NEW_ENABLED_UNITS:-}; do systemctl disable "$unit" || cleanup_failed=1; done
    fi
    if [[ "${NT_LOCK_HELD:-0}" == 1 ]]; then rmdir /run/nathaya-tunnel-setup.lock || cleanup_failed=1; fi
    (( cleanup_failed == 0 )) || rc=1
    if (( rc != 0 )); then
        NT_RESULT=GAGAL
        nt_state GAGAL
        printf 'GAGAL tahap %s exit=%s. Log=%s Backup=%s\n' "$NT_STAGE" "$rc" "$NT_LOG" "$NT_RUN"
        printf 'Perubahan OS/firewall/layanan/kode dapat parsial; tidak ada rollback OS atau akun otomatis.\n'
    elif [[ "$NT_RESULT" != CORE_SUCCESS && "$NT_RESULT" != FULL_SUCCESS ]]; then
        NT_RESULT=GAGAL; rc=1
    fi
    nt_write_result "$rc" || rc=1
    sync
    printf 'Durasi %s detik. Status=%s. Log privat=%s\n' "$((SECONDS - NT_STARTED))" "$NT_RESULT" "$NT_LOG"
    exit "$rc"
}

nt_stage_source() {
    local relative
    nt_directory "$NT_RUN/stage" 700
    ( cd -- "$NT_SOURCE"
      while IFS= read -r relative; do sha256sum -- "$relative"; done < <(nt_source_files)
    ) > "$NT_RUN/source.sha256"
    while IFS= read -r relative; do
        nt_directory "$(dirname -- "$NT_RUN/stage/$relative")" 700
        install -o root -g root -m 600 -- "$NT_SOURCE/$relative" "$NT_RUN/stage/$relative"
    done < <(nt_source_files)
    ( cd -- "$NT_RUN/stage"; sha256sum -c "$NT_RUN/source.sha256" )
    nt_validate_source "$NT_RUN/stage"
    NT_SOURCE="$NT_RUN/stage"
    python3 -I -B "$NT_SOURCE/installer/state.py" validate-prepared "$NT_SOURCE" "$NT_RUN/updater-before.json"
    if [[ "$NT_SSH_EXISTED" == 1 ]]; then nt_directory /run/sshd 755; /usr/sbin/sshd -t; fi
    nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-before"
}

nt_worker() {
    set -Eeuo pipefail
    trap '' HUP
    trap nt_worker_exit EXIT
    trap 'printf "Perintah gagal tahap=%s baris=%s\n" "$NT_STAGE" "$LINENO" >&2' ERR
    trap 'exit 130' INT
    trap 'if [[ ${NT_REBOOT_REQUESTED:-0} == 1 && $NT_RESULT == FULL_SUCCESS && $NT_GATES_RC == 0 ]]; then exit 0; else exit 143; fi' TERM
    NT_STARTED=$SECONDS NT_RESULT=BERJALAN NT_STAGE=staging NT_STARTED_UNITS='' NT_NEW_ENABLED_UNITS=''
    NT_GATES_RC=1 NT_FINALIZED=0 NT_REBOOT_REQUESTED=0
    NT_POLICY_ACTIVE=0 NT_POLICY_TMP='' NT_POLICY_EXISTED=0 NT_POLICY_MODE='' NT_POLICY_GROUP=''
    printf 'NATHAYA TUNNEL %s | Ubuntu 24.04 amd64 | IP=%s | domain=%s | profile=%s\n' "$(cat "$NT_SOURCE/VERSION")" "$NT_PUBLIC_IP" "$NT_DOMAIN" "$NT_PROFILE"
    local stage
    for stage in staging OS dependencies firewall host-keys runtime TLS Xray proxies maintenance verification; do NT_STAGE="$stage"; nt_state MENUNGGU; done
    nt_ssh_assert_baseline
    nt_run_stage staging nt_stage_source
    NT_OS_MAINTENANCE=1
    nt_run_stage OS nt_os_maintenance
    nt_run_stage dependencies nt_dependencies
    nt_run_stage host-keys nt_openssh_keys
    nt_dropbear_key
    nt_run_stage firewall nt_firewall_remove
    nt_websocket_verify_source
    nt_run_stage runtime nt_deploy "$NT_SOURCE" / "$NT_RUN"
    nt_domain_save
    nt_runtime_tools
    nt_run_stage TLS nt_tls_issue
    nt_run_stage Xray nt_xray_install
    nt_run_stage proxies nt_proxies_install
    nt_run_stage maintenance nt_maintenance_install
    python3 -I -B "$NT_SOURCE/installer/state.py" record-services --backup "$NT_RUN"
    nt_run_stage verification nt_core_verify
    if [[ "$NT_PROFILE" == full ]]; then
        # Additional mandatory gates deliberately fail closed until the server
        # archive/binaries are audited. JSON edits alone cannot claim completion.
        nt_openvpn_require
        nt_udp_require
        NT_RESULT=FULL_SUCCESS
    else
        NT_RESULT=CORE_SUCCESS
        printf 'DILEWATI/BLOCKED: OpenVPN server, UDP Custom, BadVPN, limiter IP. Panel Xray belum tersedia.\n'
    fi
    python3 -I -B "$NT_SOURCE/installer/state.py" commit "$NT_SOURCE" "$NT_RUN/updater-before.json"
    NT_GATES_RC=0
    nt_reboot_countdown
}

nt_setup_main() {
    local arg
    NT_PROFILE=full NT_DOMAIN='' NT_ACCEPT_ACME=no
    while (( $# )); do
        arg="$1"; shift
        case "$arg" in
            --help|-h) nt_setup_help; return 0 ;;
            --plan) python3 -I -B "$_NT_SOURCE/installer/artifacts.py" --lock "$_NT_SOURCE/installer/external-lock.json" --check-full; return $? ;;
            --profile) (( $# )) || return 2; NT_PROFILE="$1"; shift ;;
            --domain) (( $# )) || return 2; NT_DOMAIN="${1,,}"; shift ;;
            --accept-acme-tos) NT_ACCEPT_ACME=yes ;;
            *) printf 'ERROR: Opsi tidak dikenal; gunakan --help.\n' >&2; return 2 ;;
        esac
    done
    [[ "$NT_PROFILE" == full || "$NT_PROFILE" == core ]] || return 2
    # All install state/paths are initialized locally, never inherited from test env.
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    [[ $EUID == 0 ]] || { printf 'ERROR: Instalasi hanya root pada VPS target.\n' >&2; return 1; }
    set -Eeuo pipefail
    umask 077
    NT_SOURCE="$_NT_SOURCE" NT_STAGE=preflight NT_RESULT=MENUNGGU NT_LOCK_HELD=0
    NT_POLICY_ACTIVE=0 NT_POLICY_TMP='' NT_RUN='' NT_LOG='' NT_CONFIG_DOMAIN=''
    nt_preflight
    mkdir -m 700 /run/nathaya-tunnel-setup.lock || { nt_error 'Installer/updater aktif atau lock stale; jangan hapus lock aktif.'; return 75; }
    NT_LOCK_HELD=1
    # Failures before worker launch still release the lock; worker owns it afterwards.
    trap 'if [[ "$NT_LOCK_HELD" == 1 ]]; then rmdir /run/nathaya-tunnel-setup.lock; fi' EXIT
    nt_directory /var/backups/nathaya-tunnel 700
    nt_directory /opt/nathaya 755
    nt_directory /opt/nathaya/logs 700
    NT_RUN="$(mktemp -d /var/backups/nathaya-tunnel/run.XXXXXXXX)"
    nt_ssh_persist_baseline
    python3 -I -B "$NT_SOURCE/installer/state.py" prepare "$NT_SOURCE" "$NT_RUN/updater-before.json"
    # Under the shared lock: ownership/hash only, not another global port check.
    python3 -I -B "$NT_SOURCE/installer/checks.py" check-haproxy-unit
    NT_LOG="/opt/nathaya/logs/install-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
    nt_private_file "$NT_LOG"
    # Transfer before forking: once a worker may exist the viewer NEVER releases
    # its lock, including PID-journal failures. Failed fork leaves a safe stale lock.
    NT_LOCK_HELD=0
    trap - EXIT
    trap '' HUP
    ( NT_LOCK_HELD=1; nt_worker ) < /dev/null >> "$NT_LOG" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" > "$NT_RUN/worker.pid"
    trap 'printf "Penampil ditutup; worker tetap berjalan. Log: %s\n" "$NT_LOG"; exit 0' HUP INT TERM
    printf 'Worker PID=%s. Log=%s. Status=%s/result\n' "$pid" "$NT_LOG" "$NT_RUN"
    tail --pid="$pid" -n +1 -f "$NT_LOG" || true
    local rc=0
    wait "$pid" || rc=$?
    return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    nt_setup_main "$@"
fi
