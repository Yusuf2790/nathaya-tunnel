#!/usr/bin/env bash
nt_check_owned_marker() {
    local path="$1" marker="$2" first second
    nt_safe_path "$path" file || return 1
    [[ -e "$path" ]] || return 0
    { IFS= read -r first; IFS= read -r second; } < "$path" || true
    [[ "$second" == "$marker" ]] || { nt_error "Konflik file asing: $path"; return 1; }
}
nt_check_hook() { nt_check_owned_marker "$1" '# Nathaya Tunnel managed dashboard hook v1'; }
nt_runtime_tools() {
    local file
    nt_check_hook /etc/profile.d/nathaya-dashboard.sh
    nt_replace_file "$NT_SOURCE/services/nathaya-dashboard.sh" /etc/profile.d/nathaya-dashboard.sh 644 "$NT_RUN" etc/profile.d/nathaya-dashboard.sh
    nt_replace_file "$NT_SOURCE/updater/update.sh" /usr/local/bin/nathaya-update 755 "$NT_RUN" usr/local/bin/nathaya-update
    for file in nathaya-update.service nathaya-update.timer; do
        nt_replace_file "$NT_SOURCE/updater/$file" "/etc/systemd/system/$file" 644 "$NT_RUN" "etc/systemd/system/$file"
    done
    nt_directory /opt/nathaya/updater-state 700
    # Publish installed.json only after all verification gates in setup worker.
    # Do not enable the updater timer here. Manual verification must precede opt-in.
    printf 'Updater manual terpasang; auto-update tidak diaktifkan oleh installer.\n'
    nt_directory /opt/nathaya/public 755
    nt_directory /opt/nathaya/public/openvpn 755
    # Nonsecret drop area is NOT web-served, executed, sourced or consumed as root.
    nt_directory /opt/nathaya/public/drop 777
}
