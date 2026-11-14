#!/usr/bin/env bash
# Source-only adapters, no operations on load.
nt_package_installed() {
    [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" == 'install ok installed' ]]
}
nt_unit_active() { systemctl is-active "$1" 2>/dev/null || true; }
nt_unit_enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }

nt_ssh_snapshot() {
    NT_SERVICE_BEFORE="$(nt_unit_active ssh.service)"
    NT_SOCKET_BEFORE="$(nt_unit_active ssh.socket)"
    NT_SERVICE_ENABLE_BEFORE="$(nt_unit_enabled ssh.service)"
    NT_SOCKET_ENABLE_BEFORE="$(nt_unit_enabled ssh.socket)"
    NT_SSH_EXISTED=0
    if nt_package_installed openssh-server; then
        NT_SSH_EXISTED=1
        if [[ "$NT_SERVICE_BEFORE" != active && "$NT_SOCKET_BEFORE" != active ]]; then
            nt_error 'OpenSSH sudah terpasang tetapi tidak aktif. Periksa/aktifkan sendiri melalui konsol VPS; installer tidak mengubah keputusan admin.'
            return 1
        fi
    elif [[ -e /etc/ssh/sshd_config || "$NT_SERVICE_BEFORE" == active || "$NT_SOCKET_BEFORE" == active ]]; then
        nt_error 'SSH/config terdeteksi tanpa paket openssh-server terkelola. Rekonsiliasi manual diperlukan.'
        return 1
    fi
    NT_SSH_START_BEFORE="$(systemctl show ssh.service -p ExecMainStartTimestampMonotonic --value 2>/dev/null || true)"
    NT_SOCKET_IDENTITY_BEFORE="$(systemctl show ssh.socket -p ActiveEnterTimestampMonotonic -p InvocationID -p Listen 2>/dev/null || true)"
    NT_SOCKET_LISTEN_BEFORE="$(systemctl show ssh.socket -p Listen --value 2>/dev/null || true)"
}

nt_ssh_config_fingerprint() {
    # Only hashes of public server configuration; never read/copy private host keys.
    if [[ -f /etc/ssh/sshd_config ]]; then
        sha256sum -- /etc/ssh/sshd_config
        /usr/sbin/sshd -T | awk '$1 ~ /^(port|listenaddress|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|authenticationmethods|usepam|authorizedkeysfile|allowusers|denyusers|allowgroups|denygroups)$/ {print}' | sort | sha256sum
    fi
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        find /etc/ssh/sshd_config.d -type f -name '*.conf' -exec sha256sum -- {} + | sort
    fi
}

nt_verify_preserved_ssh() {
    [[ "$NT_SSH_EXISTED" == 1 ]] || return 0
    [[ "$(nt_unit_enabled ssh.service)" == "$NT_SERVICE_ENABLE_BEFORE" &&
       "$(nt_unit_enabled ssh.socket)" == "$NT_SOCKET_ENABLE_BEFORE" ]] || {
        nt_error 'Enablement SSH berubah selama pemasangan paket; periksa manual.'; return 1;
    }
    if [[ "$NT_SERVICE_BEFORE" == active && "${NT_OS_MAINTENANCE:-0}" != 1 ]]; then
        [[ "$(nt_unit_active ssh.service)" == active &&
           "$(systemctl show ssh.service -p ExecMainStartTimestampMonotonic --value)" == "$NT_SSH_START_BEFORE" ]] || {
            nt_error 'Proses SSH awal berubah/tidak aktif; hentikan dan periksa akses admin.'; return 1;
        }
    fi
    [[ "$(nt_unit_active ssh.socket)" == "$NT_SOCKET_BEFORE" ]] || { nt_error 'Status socket SSH berubah.'; return 1; }
    if [[ "$NT_SOCKET_BEFORE" == active ]]; then
        [[ "$(systemctl show ssh.socket -p Listen --value)" == "$NT_SOCKET_LISTEN_BEFORE" ]] || { nt_error 'Listener socket admin berubah selama maintenance.'; return 1; }
    fi
    if [[ "$NT_SOCKET_BEFORE" == active && "${NT_OS_MAINTENANCE:-0}" != 1 ]]; then
        [[ "$(systemctl show ssh.socket -p ActiveEnterTimestampMonotonic -p InvocationID -p Listen)" == "$NT_SOCKET_IDENTITY_BEFORE" ]] || {
            nt_error 'Identitas/listener socket SSH berubah; periksa manual.'; return 1;
        }
    fi
    [[ "$(nt_unit_active ssh.service)" == active || "$(nt_unit_active ssh.socket)" == active ]] || { nt_error 'SSH tidak memiliki service/socket aktif setelah maintenance.'; return 1; }
    nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-after"
    cmp -s -- "$NT_RUN/ssh-config-before" "$NT_RUN/ssh-config-after" || {
        nt_error 'Konfigurasi SSH berubah selama pemasangan paket; tidak ada rollback otomatis.'; return 1;
    }
}


nt_openssh_keys() {
    local key
    nt_directory /run/sshd 755
    for key in /etc/ssh/ssh_host_*_key; do
        [[ -e "$key" || -L "$key" ]] || continue
        nt_safe_path "$key" file
        ssh-keygen -y -P '' -f "$key" >/dev/null 2>&1 || { nt_error 'Host key existing invalid; tidak diregenerasi otomatis.'; return 1; }
        chown root:root "$key"; chmod 600 "$key"
    done
    ssh-keygen -A >/dev/null 2>&1
    /usr/sbin/sshd -t
    if [[ "$(nt_unit_active ssh.service)" != active && "$(nt_unit_active ssh.socket)" != active ]]; then
        [[ "$NT_SSH_EXISTED" == 0 ]] || return 1
        systemctl start ssh.service
    fi
    nt_verify_preserved_ssh
}
