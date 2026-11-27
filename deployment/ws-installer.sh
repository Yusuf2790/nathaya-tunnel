#!/usr/bin/env bash
# WS/WSS artifacts participate in the main installer transaction.

select_ws_units() {
    local unit file link key mode
    local -a units=("$ws_service" "$proxy_service")
    connect_enabled=0
    if exists "$connect_key"; then
        check_parent_dirs "$connect_key"
        [[ -f "$connect_key" && ! -L "$connect_key" ]] && owned "$connect_key" || conflict "$connect_key"
        mode=$(stat -c '%a' -- "$connect_key")
        (( (8#$mode & 0077) == 0 )) || die "Beri izin 0600 pada $connect_key"
        key=$(cat -- "$connect_key")
        [[ "$key" =~ ^[a-f0-9]{48,128}$ ]] || die "Gunakan 48–128 karakter heksadesimal acak di $connect_key"
        connect_enabled=1
    fi
    if (( connect_enabled )) || exists "$unit_dir/$connect_service" || exists "$unit_dir/multi-user.target.wants/$connect_service"; then
        units+=("$connect_service")
    fi
    for unit in "${units[@]}"; do
        file="$unit_dir/$unit"; link="$unit_dir/multi-user.target.wants/$unit"
        check_parent_dirs "$file"; check_parent_dirs "$link"
        if exists "$file"; then
            [[ -f "$file" && ! -L "$file" ]] && owned "$file" &&
                { cmp -s -- "$file" "$source_dir/deployment/$unit" ||
                    cmp -s -- "$file" "$source_dir/deployment/legacy/$unit"; } || conflict "$file"
        fi
        if exists "$link"; then
            [[ -L "$link" && -f "$file" ]] && owned "$link" &&
                [[ $(readlink -f -- "$link") == "$file" ]] || conflict "$link"
        fi
        managed_units+=("$unit")
        staged_deployment+=("deployment/$unit")
    done
    for file in "$ws_managed"/{haproxy.cfg,tls.pem,relay.key,domain}; do
        check_parent_dirs "$file"
        if exists "$file"; then
            [[ -f "$file" && ! -L "$file" && -f "$unit_dir/$proxy_service" ]] && owned "$file" || conflict "$file"
            [[ $(stat -c '%a' -- "$file") == 600 ]] || conflict "$file"
        fi
    done
    if exists "$ws_managed/haproxy.cfg"; then
        grep -Fxq '# Managed by Nathaya Tunnel (WS frontend v1)' "$ws_managed/haproxy.cfg" || conflict "$ws_managed/haproxy.cfg"
    fi
}

check_vendor_proxy() {
    local state enabled
    state=$(unit_property haproxy.service ActiveState) || die 'tidak dapat membaca status HAProxy distro'
    enabled=$(unit_property haproxy.service UnitFileState) || die 'tidak dapat membaca enablement HAProxy distro'
    case "$state:$enabled" in
        inactive:|inactive:not-found|inactive:disabled|inactive:masked|inactive:masked-runtime|inactive:static|inactive:alias) ;;
        *) die 'haproxy.service milik distro masih berjalan atau enabled. Pindahkan layanan itu lebih dahulu; Nathaya memakai nathaya-haproxy.service.' ;;
    esac
}

check_ws_tls() {
    domain_file_safe
    ws_domain=$requested_domain
    if [[ -z "$ws_domain" ]]; then
        ws_domain=$(configured_domain) || die "Siapkan DOMAIN di $ws_config atau jalankan instalasi interaktif dengan --set-domain."
    fi
    read_ssh_tls_sni
    [[ -n $(domain_resolution "$ws_domain") ]] || die "DNS tidak menghasilkan alamat untuk $ws_domain"
    command -v openssl >/dev/null || die 'OpenSSL diperlukan untuk preflight TLS. Pasang openssl lalu ulangi --check.'
    check_parent_dirs "$ws_cert"; check_parent_dirs "$ws_key"
    if ! choose_tls; then confirm_issuance; fi
    if exists "$ws_managed/relay.key"; then
        local token
        token=$(cat -- "$ws_managed/relay.key")
        [[ "$token" =~ ^[a-f0-9]{64}$ ]] || conflict "$ws_managed/relay.key"
    fi
    if exists "$apt_policy" && { [[ ! -x "$haproxy_bin" || ! -x /usr/sbin/nginx || ! -x /usr/sbin/openvpn ]]; }; then
        die "$apt_policy dikelola admin; siapkan paket haproxy/nginx/openvpn tanpa mengaktifkan unit distro yang tidak diperlukan, lalu ulangi --check"
    fi
}

ws_dependencies() {
    [[ -x "$haproxy_bin" ]] || packages+=(haproxy)
    if [[ -n "$certbot_email" ]] && ! command -v certbot >/dev/null; then packages+=(certbot); fi
    "$python_bin" -IB -c 'import aiohttp' >/dev/null 2>&1 || packages+=(python3-aiohttp)
    return 0
}

tcp_conflict() {
    local port="$1" reason="$2"
    if [[ "$port" == 80 ]]; then
        die "Benturan TCP 80: $reason. Untuk TLS gunakan PEM admin atau DNS-01 bila 80 tidak dapat dipakai ACME; HAProxy tetap memerlukan port 80 bebas."
    fi
    die "Benturan TCP $port: $reason"
}

check_listener() {
    local port="$1" unit="$2" must_exist="${3:-0}" protocol="${4:-tcp}" pid=0 group listeners line address tail owner cgroup belongs found=0
    local ss_proto=t net=tcp listen_state=0A
    if [[ "$protocol" == udp ]]; then ss_proto=u; net=udp; listen_state=07; fi
    if command -v ss >/dev/null; then
        listeners=$(ss -H "-l${ss_proto}np") || die 'tidak dapat membaca daftar listener dari ss'
        pid=$(unit_property "$unit" MainPID) || die "tidak dapat membaca PID $unit"
        group=$(unit_property "$unit" ControlGroup) || die "tidak dapat membaca cgroup $unit"
        while IFS= read -r line; do
            read -r _ _ _ address _ tail <<< "$line"
            if [[ "$address" != *":$port" ]]; then continue; fi
            found=1
            [[ "$pid" =~ ^[1-9][0-9]*$ && "$tail" =~ pid=([0-9]+), ]] ||
                tcp_conflict "$port" "listener bukan milik $unit (cek ss -ltnp sebagai root)"
            while [[ "$tail" =~ pid=([0-9]+), ]]; do
                owner=${BASH_REMATCH[1]}; belongs=0
                if [[ "$owner" == "$pid" ]]; then belongs=1
                elif [[ -n "$group" && -r "/proc/$owner/cgroup" ]]; then
                    while IFS=: read -r _ _ cgroup; do
                        if [[ "$cgroup" == "$group" ]]; then belongs=1; break; fi
                    done < "/proc/$owner/cgroup"
                fi
                (( belongs )) || tcp_conflict "$port" "listener memiliki PID di luar $unit"
                tail=${tail#*"pid=$owner,"}
            done
        done <<< "$listeners"
    else
        local table hex state
        [[ -r /proc/net/$net ]] || die 'tidak dapat memeriksa listener; pasang iproute2 lalu ulangi --check'
        printf -v hex '%04X' "$port"
        for table in "/proc/net/$net" "/proc/net/${net}6"; do
            [[ -r "$table" ]] || continue
            while read -r _ address _ state _; do
                [[ "$state" != "$listen_state" || "$address" != *":$hex" ]] || tcp_conflict "$port" "pasang ss untuk mengidentifikasi listener"
            done < "$table"
        done
    fi
    (( !must_exist || found )) || die "${protocol^^} $port tidak aktif untuk $unit"
}

check_ws_ports() {
    check_listener 80 "$proxy_service" "${1:-0}"
    check_listener 443 "$proxy_service" "${1:-0}"
    check_listener 8080 "$proxy_service" "${1:-0}"
    check_listener 18080 "$ws_service" "${1:-0}"
    check_listener 18091 "$ssh_service" "${1:-0}"
    if (( connect_enabled )) && (( ! ${1:-0} )); then check_listener 8443 "$connect_service"; fi
}

prepare_proxy_apt() {
    local package state enabled
    vendor_added=()
    for package in "${packages[@]}"; do
        case "$package" in haproxy|nginx|openvpn) ;; *) continue ;; esac
        state=$(unit_property "$package.service" ActiveState) || die "status unit distro $package tidak tersedia"
        enabled=$(unit_property "$package.service" UnitFileState) || die "enablement unit distro $package tidak tersedia"
        case "$state:$enabled" in inactive:|inactive:not-found) vendor_added+=("$package.service") ;;
            *) die "unit distro $package sudah dikelola; selesaikan paket secara manual sebelum instalasi" ;;
        esac
    done
    (( ${#vendor_added[@]} )) || return 0
    cat > "$stage/policy-proxy" <<'POLICY'
#!/bin/sh
for arg do
    case "${arg##*/}" in haproxy|haproxy.service|nginx|nginx.service|openvpn|openvpn.service|openvpn-*@*|openvpn@*) exit 101 ;; esac
done
exit 0
POLICY
    chmod 0755 "$stage/policy-proxy"
    ln -s -- "$stage/policy-proxy" "$apt_policy" || die "tidak dapat memasang guard APT sementara: $apt_policy"
    vendor_fresh=1
}

finish_proxy_apt() {
    local rc=0 unit enabled state
    if (( !vendor_fresh )); then return 0; fi
    for unit in "${vendor_added[@]}"; do
        enabled=$(unit_property "$unit" UnitFileState) || { rc=1; continue; }
        state=$(unit_property "$unit" ActiveState) || { rc=1; continue; }
        case "$state:$enabled" in inactive:|inactive:not-found|inactive:disabled|inactive:masked) ;;
            *) systemctl --system disable --now "$unit" >> "$backup/apt.log" 2>&1 || rc=1 ;;
        esac
    done
    if [[ -L "$apt_policy" && $(readlink -- "$apt_policy") == "$stage/policy-proxy" ]]; then
        rm -- "$apt_policy" || return 1
    fi
    vendor_fresh=0
    return "$rc"
}

render_proxy() {
    local cert="$1" line token sni_route='# No dedicated SSH TLS SNI configured'
    if [[ -n "$ssh_tls_sni" ]]; then
        sni_route="use_backend nathaya_internal_tls_ssh if { req.ssl_sni -i $ssh_tls_sni }"
    fi
    token=$(cat -- "$stage/ws/relay.key")
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//@DOMAIN@/$ws_domain}; line=${line//@CERT@/$cert}; line=${line//@TOKEN@/$token}
        line=${line//@SSH_SNI_ROUTE@/$sni_route}
        printf '%s\n' "$line"
    done < "$source_dir/deployment/nathaya-haproxy.cfg.in"
}

stage_ws_config() {
    install -d -m 0700 "$stage/ws"
    if exists "$ws_managed/relay.key"; then
        install -m 0600 "$ws_managed/relay.key" "$stage/ws/relay.key"
    else
        (umask 077; openssl rand -hex 32 > "$stage/ws/relay.key") || die 'gagal membuat kunci relay'
    fi
    printf '%s\n' "$ws_domain" > "$stage/ws/domain"
    install -m 0644 -- "$tls_source_cert" "$stage/ws/fullchain.pem"
    install -m 0600 -- "$tls_source_key" "$stage/ws/privkey.pem"
    { cat -- "$stage/ws/fullchain.pem"; printf '\n'; cat -- "$stage/ws/privkey.pem"; printf '\n'; } > "$stage/ws/tls.pem"
    render_proxy "$stage/ws/tls.pem" > "$stage/ws/verify.cfg"
    "$haproxy_bin" -c -f "$stage/ws/verify.cfg" > "$backup/haproxy-verify.log" 2>&1 ||
        die "konfigurasi HAProxy tidak valid; lihat $backup/haproxy-verify.log"
    render_proxy "$ws_managed/tls.pem" > "$stage/ws/haproxy.cfg"
}

stage_ws_outputs() {
    local unit name link
    stage_domain_outputs
    for name in relay.key domain tls.pem haproxy.cfg; do
        inputs+=("$stage/ws/$name"); outputs+=("$ws_managed/$name")
    done
    local -a units=("$ws_service" "$proxy_service")
    if (( connect_enabled )); then units+=("$connect_service"); fi
    for unit in "${units[@]}"; do
        inputs+=("$stage/deployment/$unit"); outputs+=("$unit_dir/$unit")
        link="$unit_dir/multi-user.target.wants/$unit"
        if ! exists "$link"; then
            ln -s -- "../$unit" "$stage/link-$unit" || die "tidak dapat menyiapkan symlink $unit"
            inputs+=("$stage/link-$unit"); outputs+=("$link")
        fi
    done
}

relay_config_is_running() {
    local pid
    pid=$(unit_property "$ssh_service" MainPID) || return 1
    "$python_bin" -IB -c '
import hashlib, json, pathlib, sys
info, port_file, staged_key, pid = sys.argv[1:]
try:
    ports = pathlib.Path(port_file).read_text().split()
except FileNotFoundError:
    ports = ["109"]
try:
    state = json.loads(pathlib.Path(info).read_text())
    expected = [int(pid), sorted(map(int, ports)), hashlib.sha256(pathlib.Path(staged_key).read_bytes().strip()).hexdigest()]
    sys.exit(0 if state == expected else 1)
except (OSError, ValueError):
    sys.exit(1)
' "$ws_runtime/relay-info" "$ssh_ports_file" "$stage/ws/relay.key" "$pid" 2>/dev/null
}

verify_relay() {
    "$python_bin" -IB -c '
import pathlib, socket, sys
key = pathlib.Path(sys.argv[1]).read_bytes().strip()
with socket.create_connection(("127.0.0.1", 18091), timeout=3) as probe:
    probe.sendall(b"NATHAYA1 " + key + b" 127.0.0.1\n")
    with probe.makefile("rb") as reply:
        sys.exit(0 if reply.readline(4) == b"OK\n" else 1)
' "$ws_managed/relay.key" >> "$backup/deployment.log" 2>&1 || die 'relay SSH gagal memvalidasi metadata internal'
}

activate_connect_unit() {
    runtime_touched[$connect_service]=1
    unit_action start "$connect_service" || die "gagal memulai $connect_service"
    [[ $(unit_property "$connect_service" UnitFileState) == enabled && $(unit_property "$connect_service" ActiveState) == active ]] ||
        die "$connect_service belum enabled/active"
    check_listener 8443 "$connect_service" 1
}

check_raw_gateway_socket() {
    [[ -S "$ws_raw_socket" && ! -L "$ws_raw_socket" && $(stat -c '%a' -- "$ws_raw_socket") == 660 ]] ||
        die "Gateway tidak membuat socket relay SSH internal yang aman: $ws_raw_socket"
}

activate_ws_units() {
    local unit
    for unit in "$ws_service" "$proxy_service"; do
        runtime_touched[$unit]=1
        unit_action start "$unit" || die "gagal memulai $unit"
        [[ $(unit_property "$unit" UnitFileState) == enabled && $(unit_property "$unit" ActiveState) == active ]] ||
            die "$unit belum enabled/active"
    done
    # HAProxy can create its master and worker separately; ss on some versions lists both PIDs.
    check_listener 80 "$proxy_service" 1
    check_listener 443 "$proxy_service" 1
    check_listener 18080 "$ws_service" 1
    check_raw_gateway_socket
}
