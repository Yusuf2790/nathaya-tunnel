#!/usr/bin/env bash
nt_core_verify() {
    local unit protocol
    /usr/sbin/sshd -t
    nt_verify_preserved_ssh
    [[ "$(nt_unit_active ssh.service)" == active || "$(nt_unit_active ssh.socket)" == active ]] || { nt_error 'Admin SSH tidak aktif setelah provisioning.'; return 1; }
    systemctl is-active --quiet nathaya-ssh-expire.timer
    systemctl is-active --quiet nathaya-cert-renew.timer
    [[ "$(systemctl show nathaya-ssh-expire.service -p Result --value)" == success ]]
    while IFS= read -r unit; do systemctl is-active --quiet "$unit.service"; done < <(nt_core_units)
    for protocol in vmess vless trojan shadowsocks; do
        /opt/nathaya/bin/xray run -test -config "/etc/nathaya-tunnel/xray/$protocol/config.json" >/dev/null 2>&1
    done
    python3 -I -B "$NT_SOURCE/installer/checks.py" verify-listeners
    curl --fail --silent --show-error --connect-timeout 5 --max-time 15         --resolve "$NT_DOMAIN:443:127.0.0.1" "https://$NT_DOMAIN/healthz" >/dev/null
    printf 'Core unit/parser/listener/TLS lokal diperiksa; login klien eksternal belum diuji.\n'
}
