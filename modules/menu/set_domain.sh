#!/bin/bash
# Do not write an unrelated Nathaya DOMAIN setting: accounts use /etc/xray/domain.
# The features domain section owns DNS verification, acme.sh issuance/install,
# /etc/xray/xray.{crt,key}, /etc/haproxy/yha.pem and service restarts.
# Calling it retains the actual upstream operation rather than a config-only UI.
set_domain_vps() {
    nathaya_features_section domain
    local status=$?
    (( status != 0 )) && pause_return
    return "$status"
}

renew_domain_certificate() {
    local domain=""
    [[ -r /etc/xray/domain ]] && IFS= read -r domain < /etc/xray/domain
    if [[ -z "$domain" ]]; then
        printf '\n  Domain belum diatur. Gunakan Set Domain VPS terlebih dahulu.\n'
        pause_return
        return 1
    fi
    # Upstream change_domain renews SSL when the entered domain is unchanged.
    printf '\n  Untuk renew SSL, masukkan domain saat ini: %s\n' "$(nathaya_plain_text "$domain")"
    printf '  Lalu konfirmasi pembaruan sertifikat di langkah berikutnya.\n'
    pause_return
    set_domain_vps
}
