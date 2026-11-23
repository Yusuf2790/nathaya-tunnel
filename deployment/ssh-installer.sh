#!/usr/bin/env bash
# Helpers inside the dashboard installer transaction; not an entry point.

select_ssh_module() {
    managed_units=("$service" "$timer")
    staged_deployment=("${deploy_files[@]}")
    check_parent_dirs "$unit_dir/$ssh_service"
    check_parent_dirs "$ssh_link"
    if exists "$unit_dir/$ssh_service"; then
        [[ -f "$unit_dir/$ssh_service" && ! -L "$unit_dir/$ssh_service" ]] && owned "$unit_dir/$ssh_service" &&
            cmp -s -- "$unit_dir/$ssh_service" "$source_dir/deployment/$ssh_service" || conflict "$unit_dir/$ssh_service"
    fi
    if exists "$ssh_link"; then
        [[ -L "$ssh_link" && -f "$unit_dir/$ssh_service" ]] && owned "$ssh_link" &&
            [[ $(readlink -f -- "$ssh_link") == "$unit_dir/$ssh_service" ]] || conflict "$ssh_link"
    fi
    managed_units+=("$ssh_service")
    staged_deployment+=("deployment/$ssh_service")
}

check_ssh_ports() {
    local port
    local -a ports=(109) fields=()
    check_parent_dirs "$ssh_ports_file"
    if exists "$ssh_ports_file"; then
        [[ -f "$ssh_ports_file" && ! -L "$ssh_ports_file" ]] && owned "$ssh_ports_file" || conflict "$ssh_ports_file"
        ports=()
        while read -ra fields || (( ${#fields[@]} )); do ports+=("${fields[@]}"); done < "$ssh_ports_file"
    fi
    case "${ports[*]}" in 109|'109 143'|'143 109') ;; *) die "port tidak valid: $ssh_ports_file (gunakan 109 atau 109 143)" ;; esac
    for port in "${ports[@]}"; do check_listener "$port" "$ssh_service" "${1:-0}"; done
}

ssh_dependencies() {
    if [[ ! -x /usr/sbin/dropbear || ! -x /usr/bin/dropbearkey ]]; then packages+=(dropbear-bin); fi
    [[ -x /usr/bin/bwrap ]] || packages+=(bubblewrap)
    [[ -x /usr/bin/openssl ]] || packages+=(openssl)
    "$python_bin" -IB -c 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM' >/dev/null 2>&1 ||
        packages+=(python3-cryptography)
    return 0
}

stage_ssh_outputs() {
    inputs+=("$stage/deployment/$ssh_service")
    outputs+=("$unit_dir/$ssh_service")
    if ! exists "$ssh_link"; then
        ln -s -- "../$ssh_service" "$stage/ssh-link" || die 'tidak dapat menyiapkan symlink Dropbear'
        inputs+=("$stage/ssh-link")
        outputs+=("$ssh_link")
    fi
}

activate_ssh_unit() {
    unit_action start "$ssh_service" || die "gagal memulai $ssh_service"
    [[ $(unit_property "$ssh_service" UnitFileState) == enabled &&
        $(unit_property "$ssh_service" ActiveState) == active ]] || die "$ssh_service belum enabled/active"
}
