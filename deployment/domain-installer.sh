#!/usr/bin/env bash
# Domain/TLS preflight and staged files; invoked by install-dashboard.sh only.

domain_file_safe() {
    if ! exists "$ws_config"; then return 0; fi
    [[ -r "$ws_config" && -f "$ws_config" && ! -L "$ws_config" ]] && owned "$ws_config" || conflict "$ws_config"
    check_parent_dirs "$ws_config"
    local mode
    mode=$(stat -c '%a' -- "$ws_config")
    (( (8#$mode & 0022) == 0 )) || conflict "$ws_config"
}

valid_domain() {
    local LC_ALL=C value="$1" label
    local -a labels=()
    [[ ${#value} -le 253 && "$value" == *.* && "$value" != .* && "$value" != *. && "$value" != *..* ]] || return 1
    IFS=. read -ra labels <<< "$value"
    for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
    done
    [[ ${labels[${#labels[@]}-1]} =~ [a-z] ]]
}

configured_domain() {
    local line field value= found=0 assignments='^[[:space:]]*(export[[:space:]]+)?DOMAIN[[:space:]]*='
    local assignment='^[[:space:]]*(export[[:space:]]+)?DOMAIN[[:space:]]*=[[:space:]]*([^[:space:]#]+)[[:space:]]*(#.*)?$'
    [[ -f "$ws_config" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ $assignments ]]; then
            [[ "$line" =~ $assignment ]] || return 1
            field=${BASH_REMATCH[2]}
            case "$field" in \"*\") field=${field:1:-1} ;; \'*\') field=${field:1:-1} ;; esac
            value=${field,,}; found=$((found + 1))
        fi
    done < "$ws_config"
    (( found == 1 )) && valid_domain "$value" || return 1
    printf '%s\n' "$value"
}

domain_resolution() {
    # Resolve using the VPS resolver. This does not prove Internet reachability for ACME.
    getent ahosts "$1" | awk '$2 == "STREAM" && !seen[$1]++ {print $1}'
}

cancel_setup() { printf '\nSetup dibatalkan; konfigurasi belum ditulis.\n'; exit 0; }

setup_domain() {
    [[ "$mode_install" == install ]] || return 0
    domain_file_safe
    local saved= value dns answer width
    saved=$(configured_domain) || saved=
    if (( set_domain )); then
        [[ -t 0 && -t 1 ]] || die '--set-domain memerlukan terminal interaktif; untuk noninteraktif siapkan DOMAIN di config.conf'
    elif [[ -n "$saved" || ! -t 0 || ! -t 1 ]]; then
        return 0
    fi
    read_ssh_ports
    while true; do
        clear_screen
        width=$(get_width)
        draw_nathaya_header "$width"
        draw_section_title 'SETUP DOMAIN' "$width"
        printf '\n  Contoh: sg1.nathaya.web.id\n'
        if [[ -n "$saved" ]]; then printf '  Domain saat ini : %s\n' "$saved"; fi
        IFS= read -r -p '  Domain : ' value || cancel_setup
        value=${value,,}
        if ! valid_domain "$value"; then
            printf '  Hostname tidak valid. Gunakan nama DNS tanpa skema atau port.\n'
        elif dns=$(domain_resolution "$value") && [[ -n "$dns" ]]; then
            break
        else
            printf '  DNS belum menghasilkan alamat untuk %s. Periksa DNS.\n' "$value"
        fi
        IFS= read -r -p '  Coba lagi? [y/n]: ' answer || cancel_setup
        [[ ${answer,,} == y ]] || cancel_setup
    done
    printf '\n  Hasil resolusi DNS:\n'
    while IFS= read -r answer; do printf '  - %s\n' "$answer"; done <<< "$dns"
    printf '\n  TCP %s : SSH langsung\n  TCP 80  : WS /\n  TCP 443 : WSS /\n' "$ssh_ports_display"
    printf '  TCP 8080: HTTP redirect\n  TCP 1194 / UDP 2200: OpenVPN\n'
    if exists "$connect_key"; then printf '  TCP 8443: HTTPS CONNECT (opsional)\n'; fi
    while true; do
        IFS= read -r -p '  Gunakan domain ini? [y/n]: ' answer || cancel_setup
        case "${answer,,}" in y) requested_domain=$value; return 0 ;; n) cancel_setup ;; esac
    done
}

read_ssh_tls_sni() {
    ssh_tls_sni=
    check_parent_dirs "$ssh_tls_sni_file"
    if ! exists "$ssh_tls_sni_file"; then return 0; fi
    [[ -f "$ssh_tls_sni_file" && ! -L "$ssh_tls_sni_file" ]] && owned "$ssh_tls_sni_file" || conflict "$ssh_tls_sni_file"
    local mode
    mode=$(stat -c '%a' -- "$ssh_tls_sni_file")
    (( (8#$mode & 0022) == 0 )) || conflict "$ssh_tls_sni_file"
    ssh_tls_sni=$(cat -- "$ssh_tls_sni_file")
    ssh_tls_sni=${ssh_tls_sni,,}
    valid_domain "$ssh_tls_sni" && [[ "$ssh_tls_sni" != "$ws_domain" ]] ||
        die "SNI SSH harus satu hostname DNS yang berbeda dari $ws_domain ($ssh_tls_sni_file)."
    [[ -n $(domain_resolution "$ssh_tls_sni") ]] || die "DNS belum menghasilkan alamat untuk $ssh_tls_sni"
}

valid_tls_pair() {
    local cert key mode cert_pub key_pub
    cert=$(readlink -f -- "$1") && key=$(readlink -f -- "$2") &&
        [[ -f "$cert" && -r "$cert" && -s "$cert" && -f "$key" && -r "$key" && -s "$key" ]] || return 1
    owned "$cert" && owned "$key" || return 1
    mode=$(stat -c '%a' -- "$key") || return 1
    (( (8#$mode & 0077) == 0 )) || return 1
    openssl verify -verify_hostname "$ws_domain" -purpose sslserver -partial_chain -trusted "$cert" "$cert" >/dev/null 2>&1 || return 1
    if [[ -n "${ssh_tls_sni:-}" ]]; then
        openssl verify -verify_hostname "$ssh_tls_sni" -purpose sslserver -partial_chain -trusted "$cert" "$cert" >/dev/null 2>&1 || return 1
    fi
    cert_pub=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null) &&
        key_pub=$(openssl pkey -in "$key" -passin pass: -pubout 2>/dev/null) &&
        [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || return 1
    check_parent_dirs "$cert"; check_parent_dirs "$key"
    tls_source_cert=$cert; tls_source_key=$key
}

choose_tls() {
    local lineage
    tls_source_cert= tls_source_key=
    if (( ! use_certbot )) && valid_tls_pair "$ws_cert" "$ws_key"; then return 0; fi
    for lineage in "$certbot_live/nathaya-$ws_domain" "$certbot_live/$ws_domain" \
        "$certbot_live/$ws_domain"-[0-9][0-9][0-9][0-9]; do
        if valid_tls_pair "$lineage/fullchain.pem" "$lineage/privkey.pem"; then return 0; fi
    done
    return 1
}

missing_tls() {
    die "TLS belum siap untuk $ws_domain${ssh_tls_sni:+ dan SNI SSH $ssh_tls_sni}. Sediakan $ws_cert dan $ws_key atau lineage Certbot yang valid. Jika TCP 80 tidak bebas/terjangkau, terbitkan via DNS-01 (plugin/kredensial dikelola admin). Installer tidak menghentikan layanan lain."
}

confirm_issuance() {
    local answer
    [[ "$mode_install" == install && -t 0 && -t 1 && ! -f "$unit_dir/$proxy_service" ]] || missing_tls
    if [[ -n "$certbot_email" ]]; then return 0; fi
    printf '\n  Tidak ada sertifikat valid. Certbot standalone perlu TCP 80 bebas\n  dan dapat dijangkau publik. Let’s Encrypt akan memeriksa domain.\n'
    printf '  Dengan memilih y, Anda menyetujui ketentuan Let’s Encrypt.\n  https://letsencrypt.org/repository/\n'
    while true; do
        IFS= read -r -p '  Terbitkan sertifikat Let’s Encrypt? [y/n]: ' answer || cancel_setup
        case "${answer,,}" in y) break ;; n) cancel_setup ;; esac
    done
    IFS= read -r -p '  Email akun ACME : ' certbot_email || cancel_setup
    [[ "$certbot_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die 'Email akun ACME tidak valid'
}

issue_ws_certificate() {
    if [[ -n "$tls_source_cert" ]]; then return 0; fi
    [[ -n "$certbot_email" ]] || missing_tls
    # Recheck immediately; no service is stopped to free the challenge port.
    check_listener 80 "$proxy_service"
    [[ ! -f "$unit_dir/$proxy_service" ]] || missing_tls
    local -a domains=(-d "$ws_domain")
    if [[ -n "$ssh_tls_sni" ]]; then domains+=(-d "$ssh_tls_sni"); fi
    certbot certonly --standalone --non-interactive --agree-tos --email "$certbot_email" \
        --cert-name "nathaya-$ws_domain" "${domains[@]}" > "$backup/certbot.log" 2>&1 ||
        die "Penerbitan Let’s Encrypt gagal; cek DNS/akses publik TCP 80 dan $backup/certbot.log"
    choose_tls || missing_tls
}

stage_domain_outputs() {
    local line assignments='^[[:space:]]*(export[[:space:]]+)?DOMAIN[[:space:]]*='
    if [[ -n "$requested_domain" ]] && [[ $(configured_domain || true) != "$ws_domain" ]]; then
        {
            if [[ -f "$ws_config" ]]; then
                while IFS= read -r line || [[ -n "$line" ]]; do
                    if [[ ! "$line" =~ $assignments ]]; then printf '%s\n' "$line"; fi
                done < "$ws_config"
            fi
            printf 'DOMAIN="%s"\n' "$ws_domain"
        } > "$stage/ws/config.conf"
        inputs+=("$stage/ws/config.conf"); outputs+=("$ws_config")
    fi
    if ! cmp -s -- "$stage/ws/fullchain.pem" "$ws_cert" || [[ -L "$ws_cert" ]]; then
        inputs+=("$stage/ws/fullchain.pem"); outputs+=("$ws_cert")
    fi
    if ! cmp -s -- "$stage/ws/privkey.pem" "$ws_key" || [[ -L "$ws_key" ]] || [[ $(stat -c '%a' -- "$ws_key") != 600 ]]; then
        inputs+=("$stage/ws/privkey.pem"); outputs+=("$ws_key")
    fi
}
