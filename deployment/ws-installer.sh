#!/usr/bin/env bash
# WS/WSS artifacts participate in the main installer transaction.

select_ws_units() {
    local unit file link
    for unit in "$ws_service" "$proxy_service"; do
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

read_ws_domain() {
    local line value= field mode found=0 pattern='^[[:space:]]*DOMAIN[[:space:]]*=[[:space:]]*([^[:space:]#]+)[[:space:]]*(#.*)?$'
    [[ -r "$ws_config" && -f "$ws_config" && ! -L "$ws_config" ]] && owned "$ws_config" ||
        die "domain belum dikonfigurasi; isi DOMAIN=nama.domain pada $ws_config (milik root)"
    check_parent_dirs "$ws_config"
    mode=$(stat -c '%a' -- "$ws_config")
    (( (8#$mode & 0022) == 0 )) || conflict "$ws_config"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ $pattern ]]; then
            field=${BASH_REMATCH[1]}
            case "$field" in \"*\") field=${field:1:-1} ;; \'*\') field=${field:1:-1} ;; esac
            value=$field; found=$((found + 1))
        fi
    done < "$ws_config"
    local LC_ALL=C label
    local -a labels=()
    value=${value,,}
    [[ $found == 1 && ${#value} -le 253 && "$value" == *.* && "$value" != .* && "$value" != *. &&
       "$value" != *..* ]] || die "DOMAIN tidak valid di $ws_config; gunakan satu nama DNS tanpa skema atau port"
    IFS=. read -ra labels <<< "$value"
    for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "DOMAIN tidak valid di $ws_config"
    done
    [[ ${labels[${#labels[@]}-1]} =~ [a-z] ]] || die 'DOMAIN harus nama DNS, bukan alamat IP'
    ws_domain=$value
}

check_ws_tls() {
    local real_cert real_key key_mode cert_pub key_pub
    read_ws_domain
    command -v openssl >/dev/null || die 'OpenSSL diperlukan untuk preflight TLS. Pasang openssl lalu jalankan --check lagi.'
    real_cert=$(readlink -f -- "$ws_cert") && real_key=$(readlink -f -- "$ws_key") &&
        [[ -f "$real_cert" && -r "$real_cert" && -s "$real_cert" && -f "$real_key" && -r "$real_key" && -s "$real_key" ]] ||
        die "TLS belum lengkap: sediakan fullchain di $ws_cert dan private key di $ws_key, lalu ulangi --check"
    owned "$real_cert" && owned "$real_key" || die 'Sertifikat dan private key harus milik root'
    check_parent_dirs "$ws_cert"; check_parent_dirs "$ws_key"; check_parent_dirs "$real_cert"; check_parent_dirs "$real_key"
    key_mode=$(stat -c '%a' -- "$real_key")
    (( (8#$key_mode & 0077) == 0 )) || die "Private key tidak aman: beri izin 0600 atau 0400 pada $real_key"
    openssl verify -verify_hostname "$ws_domain" -purpose sslserver -partial_chain -trusted "$real_cert" "$real_cert" >/dev/null 2>&1 ||
        die 'Sertifikat TLS tidak berlaku atau tidak cocok dengan DOMAIN. Perbaiki fullchain sebelum instalasi.'
    cert_pub=$(openssl x509 -in "$real_cert" -pubkey -noout 2>/dev/null) &&
        key_pub=$(openssl pkey -in "$real_key" -passin pass: -pubout 2>/dev/null) &&
        [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || die 'Private key TLS tidak valid, terenkripsi, atau tidak cocok dengan sertifikat'
    if exists "$ws_managed/relay.key"; then
        local token
        token=$(cat -- "$ws_managed/relay.key")
        [[ "$token" =~ ^[a-f0-9]{64}$ ]] || conflict "$ws_managed/relay.key"
    fi
    if [[ ! -x "$haproxy_bin" ]] && exists "$apt_policy"; then
        die "HAProxy belum terpasang dan $apt_policy sudah ada; instal HAProxy dengan unit distro nonaktif, lalu ulangi --check"
    fi
}

ws_dependencies() {
    [[ -x "$haproxy_bin" ]] || packages+=(haproxy)
    "$python_bin" -IB -c 'import aiohttp' >/dev/null 2>&1 || packages+=(python3-aiohttp)
    return 0
}

check_listener() {
    local port="$1" unit="$2" must_exist="${3:-0}" pid=0 group listeners line address tail owner cgroup belongs found=0
    if command -v ss >/dev/null; then
        listeners=$(ss -H -ltnp) || die 'tidak dapat membaca daftar listener dari ss'
        pid=$(unit_property "$unit" MainPID) || die "tidak dapat membaca PID $unit"
        group=$(unit_property "$unit" ControlGroup) || die "tidak dapat membaca cgroup $unit"
        while IFS= read -r line; do
            read -r _ _ _ address _ tail <<< "$line"
            if [[ "$address" != *":$port" ]]; then continue; fi
            found=1
            [[ "$pid" =~ ^[1-9][0-9]*$ && "$tail" =~ pid=([0-9]+), ]] ||
                die "Benturan TCP $port; listener bukan milik $unit (cek ss -ltnp sebagai root)."
            while [[ "$tail" =~ pid=([0-9]+), ]]; do
                owner=${BASH_REMATCH[1]}; belongs=0
                if [[ "$owner" == "$pid" ]]; then belongs=1
                elif [[ -n "$group" && -r "/proc/$owner/cgroup" ]]; then
                    while IFS=: read -r _ _ cgroup; do
                        if [[ "$cgroup" == "$group" ]]; then belongs=1; break; fi
                    done < "/proc/$owner/cgroup"
                fi
                (( belongs )) || die "Benturan TCP $port; listener memiliki PID di luar $unit."
                tail=${tail#*"pid=$owner,"}
            done
        done <<< "$listeners"
    else
        local table hex state
        [[ -r /proc/net/tcp ]] || die 'tidak dapat memeriksa listener; pasang iproute2 lalu ulangi --check'
        printf -v hex '%04X' "$port"
        for table in /proc/net/tcp /proc/net/tcp6; do
            [[ -r "$table" ]] || continue
            while read -r _ address _ state _; do
                [[ "$state" != 0A || "$address" != *":$hex" ]] || die "Benturan TCP $port; pasang ss untuk mengidentifikasi listener."
            done < "$table"
        done
    fi
    (( !must_exist || found )) || die "TCP $port tidak aktif untuk $unit"
}

check_ws_ports() {
    check_listener 80 "$proxy_service" "${1:-0}"
    check_listener 443 "$proxy_service" "${1:-0}"
    check_listener 18080 "$ws_service" "${1:-0}"
    check_listener 18091 "$ssh_service" "${1:-0}"
}

prepare_proxy_apt() {
    local package
    for package in "${packages[@]}"; do [[ "$package" != haproxy ]] || break; done
    [[ ${package:-} == haproxy ]] || return 0
    vendor_fresh=1
    cat > "$stage/policy-proxy" <<'POLICY'
#!/bin/sh
for arg do
    case "${arg##*/}" in haproxy|haproxy.service) exit 101 ;; esac
done
exit 0
POLICY
    chmod 0755 "$stage/policy-proxy"
    ln -s -- "$stage/policy-proxy" "$apt_policy" || die "tidak dapat memasang guard APT sementara: $apt_policy"
}

finish_proxy_apt() {
    local rc=0
    if (( !vendor_fresh )); then return 0; fi
    if [[ -x "$haproxy_bin" ]]; then
        systemctl --system disable --now haproxy.service >> "$backup/apt.log" 2>&1 || rc=1
    fi
    if [[ -L "$apt_policy" && $(readlink -- "$apt_policy") == "$stage/policy-proxy" ]]; then
        rm -- "$apt_policy" || return 1
    fi
    vendor_fresh=0
    return "$rc"
}

render_proxy() {
    local cert="$1" line token
    token=$(cat -- "$stage/ws/relay.key")
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//@DOMAIN@/$ws_domain}; line=${line//@CERT@/$cert}; line=${line//@TOKEN@/$token}
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
    { cat -- "$ws_cert"; printf '\n'; cat -- "$ws_key"; printf '\n'; } > "$stage/ws/tls.pem"
    render_proxy "$stage/ws/tls.pem" > "$stage/ws/verify.cfg"
    "$haproxy_bin" -c -f "$stage/ws/verify.cfg" > "$backup/haproxy-verify.log" 2>&1 ||
        die "konfigurasi HAProxy tidak valid; lihat $backup/haproxy-verify.log"
    render_proxy "$ws_managed/tls.pem" > "$stage/ws/haproxy.cfg"
}

stage_ws_outputs() {
    local unit name link
    for name in relay.key domain tls.pem haproxy.cfg; do
        inputs+=("$stage/ws/$name"); outputs+=("$ws_managed/$name")
    done
    for unit in "$ws_service" "$proxy_service"; do
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
}
