#!/usr/bin/env bash
# Report only selected status properties to a private file, never journal/key
# contents to chat/stdout. This runs BEFORE worker EXIT cleanup stops new units.
nt_report_unit_failure() {
    local unit="$1" reason="$2" snapshot='unavailable'
    [[ "$unit" =~ ^[a-z0-9@.-]+\.(service|timer)$ ]] || return 1
    printf 'ERROR: unit=%s; %s\n' "$unit" "$reason" >&2 || return 1
    case "$unit" in
        nathaya-ssh-expire.*|nathaya-cert-renew.*) ;;
        *) printf 'Log privat unit (specifier %%N): /opt/nathaya/logs/%s.log\n' "${unit%.*}" >&2 || return 1 ;;
    esac
    printf 'Journal lokal (simpan privat): journalctl -u %s --no-pager -n 80\n' "$unit" >&2 || return 1
    if [[ -n "${NT_RUN:-}" && -d "$NT_RUN" ]]; then
        snapshot="$NT_RUN/unit-$unit.failure"
        nt_private_file "$snapshot" || return 1
        if systemctl show "$unit" -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus -p MainPID > "$snapshot" 2>&1; then :; else
            printf '\nStatus snapshot read failed; inspect journal locally.\n' >> "$snapshot" || return 1
        fi
    fi
    printf 'Snapshot status=%s; log worker=%s\n' "$snapshot" "${NT_LOG:-unavailable}" >&2 || return 1
    return 1
}
nt_require_unit_active() {
    if systemctl is-active --quiet "$1"; then return 0; fi
    nt_report_unit_failure "$1" 'unit tidak aktif / pemeriksaan status gagal'
}
nt_verify_haproxy_identity() {
    local pid
    if ! pid="$(systemctl show nathaya-haproxy.service -p MainPID --value)"; then
        nt_report_unit_failure nathaya-haproxy.service 'MainPID tidak dapat dibaca'; return 1
    fi
    nt_private_file "$NT_RUN/haproxy-identity-check.log" || return 1
    if ! python3 -I -B "$NT_SOURCE/installer/checks.py" verify-haproxy-identity "$pid" > "$NT_RUN/haproxy-identity-check.log" 2>&1; then
        printf 'Detail gate identitas privat: %s/haproxy-identity-check.log\n' "$NT_RUN" >&2 || return 1
        nt_report_unit_failure nathaya-haproxy.service 'master/worker tidak memenuhi kontrak privilege'; return 1
    fi
}

nt_core_verify() {
    local unit protocol
    /usr/sbin/sshd -t
    nt_verify_preserved_ssh
    [[ "$(nt_unit_active ssh.service)" == active || "$(nt_unit_active ssh.socket)" == active ]] || { nt_error 'Admin SSH tidak aktif setelah provisioning.'; return 1; }
    nt_require_unit_active nathaya-ssh-expire.timer || return 1
    nt_require_unit_active nathaya-cert-renew.timer || return 1
    local expiry_result
    if ! expiry_result="$(systemctl show nathaya-ssh-expire.service -p Result --value)" || [[ "$expiry_result" != success ]]; then
        nt_report_unit_failure nathaya-ssh-expire.service 'expiry Result bukan success / pembacaan gagal'; return 1
    fi
    while IFS= read -r unit; do nt_require_unit_active "$unit.service" || return 1; done < <(nt_core_units)
    nt_verify_haproxy_identity || return 1
    for protocol in vmess vless trojan shadowsocks; do
        /opt/nathaya/bin/xray run -test -config "/etc/nathaya-tunnel/xray/$protocol/config.json" >/dev/null 2>&1
    done
    python3 -I -B "$NT_SOURCE/installer/checks.py" verify-listeners
    curl --fail --silent --show-error --connect-timeout 5 --max-time 15         --resolve "$NT_DOMAIN:443:127.0.0.1" "https://$NT_DOMAIN/healthz" >/dev/null
    printf 'Core unit/parser/listener/TLS lokal diperiksa; login klien eksternal belum diuji.\n'
}
