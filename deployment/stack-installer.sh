#!/usr/bin/env bash
# Nathaya-owned units, configuration, and credentials; use the caller's transaction.

verified_stack_binary() {
    local name="$1" binary="$stack_bins/$1" checksum="$stack_bins/$1.sha256" expected actual
    check_parent_dirs "$binary"
    [[ -f "$binary" && ! -L "$binary" && -f "$checksum" && ! -L "$checksum" ]] &&
        owned "$binary" && owned "$checksum" || die "Sediakan binari amd64 $binary dan SHA-256 terverifikasi di $checksum."
    local file mode
    for file in "$binary" "$checksum"; do
        mode=$(stat -c '%a' -- "$file")
        (( (8#$mode & 0022) == 0 )) || conflict "$file"
    done
    expected=$(cat -- "$checksum")
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || die "Isi $checksum dengan SHA-256 saja."
    actual=$(sha256sum -- "$binary") || die "Tidak dapat membaca $name"
    [[ "${actual%% *}" == "${expected,,}" ]] || die "Checksum $name tidak cocok."
}

select_stack() {
    local unit file link name mode
    stack_units=(nathaya-xray.service nathaya-nginx.service nathaya-openvpn-tcp.service nathaya-openvpn-udp.service)
    badvpn_enabled=0
    verified_stack_binary xray
    if exists "$stack_bins/badvpn-udpgw" || exists "$stack_bins/badvpn-udpgw.sha256" || exists "$unit_dir/nathaya-badvpn.service"; then
        verified_stack_binary badvpn-udpgw
        badvpn_enabled=1
        stack_units+=(nathaya-badvpn.service)
    fi
    for unit in "${stack_units[@]}"; do
        file="$unit_dir/$unit"; link="$unit_dir/multi-user.target.wants/$unit"
        check_parent_dirs "$file"; check_parent_dirs "$link"
        if exists "$file"; then
            [[ -f "$file" && ! -L "$file" ]] && owned "$file" &&
                cmp -s -- "$file" "$source_dir/deployment/$unit" || conflict "$file"
        fi
        if exists "$link"; then
            [[ -L "$link" && -f "$file" ]] && owned "$link" &&
                [[ $(readlink -f -- "$link") == "$file" ]] || conflict "$link"
        fi
        managed_units+=("$unit"); staged_deployment+=("deployment/$unit")
    done
    for name in xray-credentials.json ca.key ca.crt server.key server.crt client.key client.crt tls-crypt.key \
        xray.json nginx.conf openvpn-{tcp,udp}.conf client-{tcp,udp}.ovpn; do
        file="$stack_config/$name"
        check_parent_dirs "$file"
        if exists "$file"; then
            [[ -f "$file" && ! -L "$file" && -f "$unit_dir/nathaya-xray.service" ]] && owned "$file" || conflict "$file"
            mode=$(stat -c '%a' -- "$file")
            if [[ "$name" == nginx.conf ]]; then [[ "$mode" == 644 ]] || conflict "$file"
            else [[ "$mode" == 600 ]] || conflict "$file"; fi
        fi
    done
    for name in xray badvpn-udpgw; do
        file="$target/bin/$name"
        check_parent_dirs "$file"
        if exists "$file"; then
            unit=nathaya-xray.service
            [[ "$name" != badvpn-udpgw ]] || unit=nathaya-badvpn.service
            [[ -f "$file" && ! -L "$file" && -f "$unit_dir/$unit" ]] && owned "$file" || conflict "$file"
        fi
    done
}

check_stack_ports() {
    local port required="${1:-0}"
    for port in {10001..10008}; do check_listener "$port" nathaya-xray.service "$required"; done
    check_listener 1010 nathaya-nginx.service "$required"
    check_listener 1013 nathaya-nginx.service "$required"
    check_listener 1194 nathaya-openvpn-tcp.service "$required"
    check_listener 2200 nathaya-openvpn-udp.service "$required" udp
    if (( badvpn_enabled )); then
        for port in 7100 7200 7300; do check_listener "$port" nathaya-badvpn.service "$required"; done
    fi
}

stack_dependencies() {
    [[ -x /usr/sbin/nginx ]] || packages+=(nginx)
    [[ -x /usr/sbin/openvpn ]] || packages+=(openvpn)
    return 0
}

vpn_credentials() {
    local directory="$1" name present=0
    local -a names=(ca.key ca.crt server.key server.crt client.key client.crt tls-crypt.key)
    for name in "${names[@]}"; do
        if exists "$stack_config/$name"; then
            install -m 0600 -- "$stack_config/$name" "$directory/$name"
            present=$((present + 1))
        fi
    done
    if (( present == ${#names[@]} )); then return 0; fi
    (( present == 0 )) || die 'PKI OpenVPN tidak lengkap; pulihkan file lama, installer tidak mengganti identitas VPN.'
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -days 3650 -subj /CN=Nathaya-OpenVPN-CA -addext basicConstraints=critical,CA:TRUE \
        -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$directory/ca.key" -out "$directory/ca.crt"
    for name in server client; do
        local cn="nathaya-$name" serial
        [[ "$name" != server ]] || cn=nathaya-openvpn
        serial=$(openssl rand -hex 16)
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -subj "/CN=$cn" -keyout "$directory/$name.key" -out "$directory/$name.csr"
        printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%sAuth\n' "$name" > "$directory/$name.ext"
        openssl x509 -req -days 825 -set_serial "0x$serial" -in "$directory/$name.csr" \
            -CA "$directory/ca.crt" -CAkey "$directory/ca.key" -extfile "$directory/$name.ext" -out "$directory/$name.crt"
    done
    /usr/sbin/openvpn --genkey secret "$directory/tls-crypt.key"
    chmod 0600 "$directory"/{ca.key,ca.crt,server.key,server.crt,client.key,client.crt,tls-crypt.key}
}

run_stack_validator() {
    local binary="$1"; shift
    # The staged directory is root-only; bind just the binary and pass credentials explicitly.
    systemd-run --system --quiet --wait --pipe --collect \
        -p DynamicUser=yes -p NoNewPrivileges=yes -p PrivateNetwork=yes \
        -p ProtectSystem=strict -p ProtectHome=yes \
        -p "BindReadOnlyPaths=$binary:/run/nathaya-stack-validator" "$@"
}

check_stack_host() {
    [[ -c /dev/net/tun ]] || die 'OpenVPN memerlukan /dev/net/tun; aktifkan TUN di VM sebelum instalasi.'
    command -v systemd-run >/dev/null || die 'systemd-run diperlukan untuk validasi binari tanpa root.'
}

validate_stack() {
    local d="$1" proto identity cert_pub key_pub
    if ! run_stack_validator "$d/xray" -p "LoadCredential=config.json:$d/xray.json" \
        /bin/sh -c 'exec /run/nathaya-stack-validator run -test -format=json -config "$CREDENTIALS_DIRECTORY/config.json"'; then
        printf 'Konfigurasi Xray ditolak oleh binari yang disediakan.\n' >&2
        return 1
    fi
    /usr/sbin/nginx -t -p "$d/" -c "$d/nginx.conf" || return 1
    for proto in tcp udp; do
        # Resolve paths to staged credentials, then parse the config without starting a listener.
        "$python_bin" -IB -c 'import sys; from pathlib import Path
src, live, stage = sys.argv[1:]
print(Path(src).read_text().replace(live + "/", stage + "/"), end="")' "$d/openvpn-$proto.conf" "$stack_config" "$d" > "$d/verify-$proto.conf" || return 1
        /usr/sbin/openvpn --config "$d/verify-$proto.conf" --show-ciphers || return 1
    done
    openssl verify -purpose sslserver -CAfile "$d/ca.crt" "$d/server.crt" || return 1
    openssl verify -purpose sslclient -CAfile "$d/ca.crt" "$d/client.crt" || return 1
    for identity in ca server client; do
        cert_pub=$(openssl x509 -in "$d/$identity.crt" -pubkey -noout) &&
            key_pub=$(openssl pkey -in "$d/$identity.key" -passin pass: -pubout) &&
            [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || return 1
    done
    /usr/sbin/openvpn --test-crypto --secret "$d/tls-crypt.key" --cipher AES-256-CBC --auth SHA256 || return 1
    if (( badvpn_enabled )); then
        local help
        help=$(run_stack_validator "$d/badvpn-udpgw" /bin/sh -c \
            '/run/nathaya-stack-validator --help || true' 2>&1) || return 1
        [[ "$help" == *--listen-addr* ]] || return 1
    fi
}

stage_stack() {
    local d="$stage/stack"
    mkdir -m 0700 -- "$d"
    install -m 0755 -- "$stack_bins/xray" "$d/xray"
    if (( badvpn_enabled )); then install -m 0755 -- "$stack_bins/badvpn-udpgw" "$d/badvpn-udpgw"; fi
    if exists "$stack_config/xray-credentials.json"; then
        install -m 0600 -- "$stack_config/xray-credentials.json" "$d/xray-credentials.json"
    fi
    vpn_credentials "$d" > "$backup/openvpn-pki.log" 2>&1
    "$python_bin" -IB "$source_dir/deployment/render-stack.py" "$d" "$stack_config" "$ws_domain" \
        > "$backup/stack-render.log" 2>&1 || die 'Gagal menyiapkan konfigurasi/kredensial stack; lihat stack-render.log'
    validate_stack "$d" > "$backup/stack-verify.log" 2>&1 || die 'Validasi stack gagal; lihat stack-verify.log (root).'
}

stage_stack_outputs() {
    local name unit link
    for name in xray-credentials.json ca.key ca.crt server.key server.crt client.key client.crt tls-crypt.key \
        xray.json nginx.conf openvpn-{tcp,udp}.conf client-{tcp,udp}.ovpn; do
        inputs+=("$stage/stack/$name"); outputs+=("$stack_config/$name")
    done
    inputs+=("$stage/stack/xray"); outputs+=("$target/bin/xray")
    if (( badvpn_enabled )); then inputs+=("$stage/stack/badvpn-udpgw"); outputs+=("$target/bin/badvpn-udpgw"); fi
    for unit in "${stack_units[@]}"; do
        inputs+=("$stage/deployment/$unit"); outputs+=("$unit_dir/$unit")
        link="$unit_dir/multi-user.target.wants/$unit"
        if ! exists "$link"; then
            ln -s -- "../$unit" "$stage/link-$unit" || die "gagal menyiapkan $unit"
            inputs+=("$stage/link-$unit"); outputs+=("$link")
        fi
    done
}

activate_stack() {
    local unit
    for unit in "${stack_units[@]}"; do
        runtime_touched[$unit]=1
        unit_action start "$unit" || die "gagal memulai $unit"
    done
    # Type=simple is not a listener readiness signal. Give startup a bounded window.
    sleep 2
    for unit in "${stack_units[@]}"; do
        [[ $(unit_property "$unit" UnitFileState) == enabled && $(unit_property "$unit" ActiveState) == active ]] ||
            die "$unit belum enabled/active"
    done
    check_stack_ports 1
}
