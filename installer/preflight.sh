#!/usr/bin/env bash
nt_preflight() {
    [[ $EUID == 0 ]] || { nt_error 'Root VPS diperlukan, bukan instalasi Termux.'; return 1; }
    local command_name key value os_id='' os_version='' path audit relative enabled
    for command_name in bash python3 apt-get dpkg dpkg-query systemctl systemd-analyze ss ip stat df sha256sum find sort         tar mkdir rmdir mktemp cp mv rm cat chmod chown install cmp dirname touch tee tail readlink; do
        command -v "$command_name" >/dev/null || { nt_error "Prasyarat preflight hilang: $command_name"; return 1; }
    done
    [[ "$(uname -m)" == x86_64 && "$(dpkg --print-architecture)" == amd64 ]] || { nt_error 'Hanya Ubuntu amd64/x86_64.'; return 1; }
    while IFS='=' read -r key value; do
        value="${value#\"}"; value="${value%\"}"
        case "$key" in ID) os_id="$value" ;; VERSION_ID) os_version="$value" ;; esac
    done < /etc/os-release
    [[ "$os_id" == ubuntu && "$os_version" == 24.04 && -d /run/systemd/system && "$(cat /proc/1/comm)" == systemd ]] || {
        nt_error 'Target wajib Ubuntu 24.04 dengan systemd PID1; Android/proot/chroot ditolak.'; return 1;
    }
    [[ "$NT_SOURCE" != /opt/nathaya && "$NT_SOURCE" != /opt/nathaya/* ]] || { nt_error 'Gunakan source terpisah di luar /opt/nathaya.'; return 1; }
    nt_validate_source "$NT_SOURCE"
    python3 -I -B "$NT_SOURCE/installer/state.py" check "$NT_SOURCE"
    nt_validate_config "$NT_SOURCE/config/config.conf.example" "$NT_SOURCE/modules/common/bootstrap.sh" yes
    nt_check_targets /
    nt_check_hook /etc/profile.d/nathaya-dashboard.sh
    nt_check_owned_marker /usr/local/bin/nathaya-update '# Nathaya fixed-path updater launcher. No caller environment enters Python.'
    for path in /run/nathaya-tunnel-setup.lock /run/sshd /etc/ssh/sshd_config.d /etc/dropbear         /etc/nathaya-tunnel/services /etc/nathaya-tunnel/tls /etc/nathaya-tunnel/xray /opt/nathaya/bin; do
        nt_safe_path "$path" dir
        nt_secure_parents "$path"
    done
    for path in /etc/ssh/sshd_config /usr/sbin/policy-rc.d /etc/nathaya-tunnel/managed-services.json /opt/nathaya/bin/xray; do nt_safe_path "$path" file; done
    for path in /opt/nathaya /etc/nathaya-tunnel /usr/local/bin /etc/profile.d /etc/systemd/system /var/backups/nathaya-tunnel /var/cache/nathaya-tunnel /usr/sbin /run /etc/letsencrypt; do nt_safe_path "$path" dir; nt_secure_parents "$path"; done
    for path in /etc/nathaya-tunnel/tls/fullchain.pem /etc/nathaya-tunnel/tls/privkey.pem /etc/nathaya-tunnel/tls/haproxy.pem /etc/nathaya-tunnel/services/nginx.conf /etc/nathaya-tunnel/services/haproxy.cfg /etc/dropbear/dropbear_ed25519_host_key; do nt_safe_path "$path" file; done
    for path in vmess vless trojan shadowsocks; do
        nt_safe_path "/etc/nathaya-tunnel/xray/$path/config.json" file
        nt_secure_parents "/etc/nathaya-tunnel/xray/$path"
    done
    for path in /etc/ssh/ssh_host_*_key; do [[ -e "$path" || -L "$path" ]] || continue; nt_safe_path "$path" file; done
    if [[ -e /usr/sbin/policy-rc.d ]]; then
        [[ "$(stat -c %u /usr/sbin/policy-rc.d)" == 0 ]] && (( (8#$(stat -c %a /usr/sbin/policy-rc.d) & 0022) == 0 )) || { nt_error 'Policy apt root tidak tepercaya.'; return 1; }
    fi
    while IFS= read -r relative; do nt_secure_parents "/opt/nathaya/$relative"; done < <(nt_program_files)
    audit="$(dpkg --audit)"
    [[ -z "$audit" ]] || { nt_error 'dpkg tidak konsisten; selesaikan transaksi paket secara manual.'; return 1; }
    (( $(df -Pk / | awk 'END {print $4}') >= 3145728 )) || { nt_error 'Minimal 3 GiB ruang kosong root sebelum upgrade; rencana apt dapat membutuhkan lebih.'; return 1; }
    if [[ -e /etc/nathaya-tunnel/config.conf ]]; then
        nt_validate_config /etc/nathaya-tunnel/config.conf "$NT_SOURCE/modules/common/bootstrap.sh"
        local configured
        configured="$(env -i PATH="$PATH" "$BASH" --noprofile --norc -c 'source "$1"; load_nathaya_config || exit; printf "%s" "$DOMAIN"' bash "$NT_SOURCE/modules/common/bootstrap.sh")"
        NT_CONFIG_DOMAIN="$configured"
        [[ -z "$NT_DOMAIN" ]] && NT_DOMAIN="$configured"
        [[ -z "$configured" || "$configured" == "$NT_DOMAIN" ]] || { nt_error 'Domain berbeda dari config existing; perubahan identitas/TLS perlu prosedur terpisah.'; return 1; }
    fi
    if [[ "$NT_PROFILE" == full ]]; then
        python3 -I -B "$NT_SOURCE/installer/artifacts.py" --lock "$NT_SOURCE/installer/external-lock.json" --check-full
    fi
    [[ "$NT_ACCEPT_ACME" == yes ]] || { nt_error 'Tambahkan --accept-acme-tos untuk penerbitan ACME.'; return 1; }
    nt_domain_check
    nt_ssh_snapshot
    NT_NGINX_NEW=1 NT_HAPROXY_NEW=1 NT_DROPBEAR_NEW=1
    nt_package_installed nginx && NT_NGINX_NEW=0
    nt_package_installed haproxy && NT_HAPROXY_NEW=0
    nt_package_installed dropbear && NT_DROPBEAR_NEW=0
    for path in nginx haproxy dropbear; do
        if [[ ! -e /etc/nathaya-tunnel/managed-services.json ]] && nt_package_installed "$path"; then
            enabled="$(nt_unit_enabled "$path.service")"
            case "$enabled" in enabled|enabled-runtime) nt_error "Unit stock $path enabled; konflik kepemilikan harus diselesaikan manual."; return 1 ;; esac
        fi
    done
    python3 -I -B "$NT_SOURCE/installer/checks.py" preflight
    python3 -I -B "$NT_SOURCE/installer/artifacts.py" --lock "$NT_SOURCE/installer/external-lock.json" --probe-xray
}
