#!/usr/bin/env bash
nt_maintenance_install() {
    local unit
    for unit in nathaya-ssh-expire.service nathaya-ssh-expire.timer nathaya-cert-renew.service nathaya-cert-renew.timer; do
        nt_replace_file "$NT_SOURCE/services/$unit" "/etc/systemd/system/$unit" 644 "$NT_RUN" "etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    nt_track_unit_change nathaya-ssh-expire.timer yes
    nt_track_unit_change nathaya-cert-renew.timer yes
    nt_track_unit_change nathaya-ssh-expire.service no
    systemctl enable --now nathaya-ssh-expire.timer nathaya-cert-renew.timer
    systemctl start nathaya-ssh-expire.service
    printf 'Expiry SSH timer terpasang (15s), bukan limiter IP atau monitor OpenVPN/Xray.\n'
}
