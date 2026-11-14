#!/usr/bin/env bash
nt_dropbear_key() {
    local key=/etc/dropbear/dropbear_ed25519_host_key
    nt_safe_path /etc/dropbear dir
    nt_directory /etc/dropbear 700
    nt_safe_path "$key" file
    if [[ -e "$key" ]]; then
        dropbearkey -y -f "$key" >/dev/null 2>&1 || { nt_error 'Dropbear key existing invalid; tidak diregenerasi otomatis.'; return 1; }
    else
        dropbearkey -t ed25519 -f "$key" >/dev/null 2>&1
    fi
    chown root:root "$key"; chmod 600 "$key"
    # Only package-new defaults, not an existing admin Dropbear installation.
    if [[ "$NT_DROPBEAR_NEW" == 1 ]]; then systemctl disable --now dropbear.service; fi
}
