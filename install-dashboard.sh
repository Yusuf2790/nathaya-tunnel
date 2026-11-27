#!/usr/bin/env bash

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
service=nathaya-traffic.service
timer=nathaya-traffic.timer
ssh_service=nathaya-dropbear.service
ws_service=nathaya-ws.service
proxy_service=nathaya-haproxy.service
connect_service=nathaya-connect.service
app_files=(
    menu.sh
    modules/common/{functions,telegram,ui}.sh
    modules/dashboard/{dashboard.sh,traffic.sh,traffic.py,ports.sh}
    modules/stack/badvpn.py
    modules/menu/{domain,main,set_domain,ssh}.sh
    modules/ssh/{backend,ws_gateway,connect_gateway}.py
)
deploy_files=(deployment/menu deployment/nathaya-login.sh "deployment/$service" "deployment/$timer")
local_uid=0

# Hanya dipanggil tanpa awalan oleh CLI. Awalan privat ini untuk fixture pengujian.
set_paths() {
    local base=${1:-}
    target="$base/opt/nathaya"
    wrapper="$base/usr/local/bin/menu"
    hook="$base/etc/profile.d/nathaya-login.sh"
    unit_dir="$base/etc/systemd/system"
    timer_link="$unit_dir/timers.target.wants/$timer"
    ssh_link="$unit_dir/multi-user.target.wants/$ssh_service"
    ssh_ports_file="$base/etc/nathaya-tunnel/ssh-ports.conf"
    ws_config="$base/etc/nathaya-tunnel/config.conf"
    ws_managed="$base/etc/nathaya-tunnel/managed-ws"
    ws_runtime="$base/run/nathaya-ssh"
    ws_raw_socket="$base/run/nathaya-ws/raw.sock"
    ssh_tls_sni_file="$base/etc/nathaya-tunnel/ssh-tls-sni.conf"
    ws_cert="$base/etc/nathaya-tunnel/tls/fullchain.pem"
    ws_key="$base/etc/nathaya-tunnel/tls/privkey.pem"
    certbot_live="$base/etc/letsencrypt/live"
    connect_key="$base/etc/nathaya-tunnel/connect.key"
    stack_config="$base/etc/nathaya-tunnel/managed-stack"
    stack_bins="$base/etc/nathaya-tunnel/bin"
    haproxy_bin=/usr/sbin/haproxy
    apt_policy="$base/usr/sbin/policy-rc.d"
    os_release="$base/etc/os-release"
    systemd_runtime="$base/run/systemd/system"
    lock_file="$base/run/nathaya-install.lock"
    backup_root="$base/var/backups"
    python_bin=/usr/bin/python3
    path_boundary=${base:-/}
}

usage() {
    cat <<'USAGE'
Pemakaian: bash install-dashboard.sh [--check] [--enable-login-menu] [--set-domain] [--use-certbot]
  --help               Tampilkan bantuan ini.
  --check              Jalankan preflight saja; tidak menulis file, memakai APT,
                       mengunci installer, atau mengubah unit systemd.
  --enable-login-menu  Aktifkan menu otomatis pada login SSH root interaktif
                       untuk instalasi baru. Instal ulang mempertahankan pilihan lama.
  --enable-ssh         Kompatibilitas; SSH 109 dan WS/WSS 80/443 selalu dipasang.
  --set-domain         Tampilkan setup interaktif untuk mengganti domain.
  --use-certbot        Prioritaskan lineage Certbot yang valid (termasuk saat pembaruan).
USAGE
}

die() { printf 'Gagal: %s\n' "$*" >&2; exit 1; }
exists() { [[ -e "$1" || -L "$1" ]]; }
conflict() { die "Benturan pada $1; kepemilikan atau formatnya bukan instalasi Nathaya yang dikenali. Tidak ditimpa."; }

owned() { [[ $(stat -c '%u' -- "$1") == "$local_uid" ]]; }

check_parent_dirs() {
    local dir="${1%/*}" mode
    while [[ -n "$dir" && "$dir" != "$path_boundary" ]]; do
        if exists "$dir"; then
            [[ -d "$dir" && ! -L "$dir" ]] && owned "$dir" || conflict "$dir"
            mode=$(stat -c '%a' -- "$dir") || die "tidak dapat memeriksa izin: $dir"
            (( (8#$mode & 0022) == 0 )) || conflict "$dir"
        fi
        dir=${dir%/*}
    done
}

validate_host() {
    local ID= VERSION_ID= command
    [[ -r "$os_release" ]] || die "file identitas OS tidak terbaca: $os_release"
    # shellcheck disable=SC1090
    source "$os_release" || die "tidak dapat membaca $os_release"
    case "$ID:$VERSION_ID" in
        ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
        *) die "distro/versi di luar target: ${ID:-?} ${VERSION_ID:-?}" ;;
    esac
    for command in apt-get dpkg uname systemctl systemd-analyze flock stat cmp grep \
        readlink cp mv ln rm rmdir mktemp install sleep cat; do
        command -v "$command" >/dev/null || die "alat dasar tidak tersedia: $command"
    done
    [[ $(uname -m) == x86_64 && $(dpkg --print-architecture) == amd64 ]] ||
        die 'arsitektur harus amd64 (kernel x86_64 dan paket dpkg amd64)'
    if [[ $mode_install == install ]] && (( EUID != local_uid )); then
        die 'instalasi memerlukan root; jalankan sebagai root atau dengan sudo'
    fi
    [[ -d "$systemd_runtime" ]] || die 'systemd sistem tidak aktif'
    systemctl --system show --property=Version --value >/dev/null 2>&1 ||
        die 'systemd sistem tidak dapat diakses (periksa PID 1 dan bus systemd)'
    printf 'Target terdeteksi: %s %s (amd64).\n' "$ID" "$VERSION_ID"
}

validate_sources() {
    local f
    for f in "${app_files[@]}" "${staged_deployment[@]}" deployment/nathaya-haproxy.cfg.in deployment/render-stack.py \
        deployment/legacy/{nathaya-ws,nathaya-haproxy}.service; do
        [[ -f "$source_dir/$f" && ! -L "$source_dir/$f" && -r "$source_dir/$f" ]] ||
            die "file sumber hilang, bukan file biasa, atau tidak terbaca: $f"
    done
}

unit_property() {
    systemctl --system show "--property=$2" --value -- "$1" 2>/dev/null
}

check_unit_conflicts() {
    local paths unit dir file fragment dropins
    paths=$(systemd-analyze --system unit-paths 2>/dev/null) && [[ -n "$paths" ]] ||
        die 'tidak dapat membaca jalur unit systemd'
    for unit in "${managed_units[@]}"; do
        fragment=$(unit_property "$unit" FragmentPath) || die "tidak dapat membaca lokasi unit $unit"
        [[ -z "$fragment" || "$fragment" == "$unit_dir/$unit" ]] || conflict "$fragment"
        dropins=$(unit_property "$unit" DropInPaths) || die "tidak dapat memeriksa drop-in $unit"
        [[ -z "$dropins" ]] || conflict "$dropins"
        while IFS= read -r dir; do
            [[ -n "$dir" ]] || continue
            file="$dir/$unit"
            if [[ "$dir" != "$unit_dir" ]] && exists "$file"; then conflict "$file"; fi
            for file in "$dir/$unit.d/"*.conf; do
                if exists "$file"; then conflict "$file"; fi
            done
        done <<< "$paths"
    done
}

# shellcheck source=deployment/ssh-installer.sh
source "$source_dir/deployment/ssh-installer.sh" || exit 1
# shellcheck source=deployment/ws-installer.sh
source "$source_dir/deployment/ws-installer.sh" || exit 1
# shellcheck source=deployment/domain-installer.sh
source "$source_dir/deployment/domain-installer.sh" || exit 1
# shellcheck source=deployment/stack-installer.sh
source "$source_dir/deployment/stack-installer.sh" || exit 1

check_conflicts() {
    local f dst existing=0 have_app_files=0
    for dst in "$wrapper" "$hook" "$unit_dir/$service" "$unit_dir/$timer" "$timer_link" \
        "$lock_file" "$backup_root/.nathaya"; do
        check_parent_dirs "$dst"
    done
    for f in "${app_files[@]}"; do
        dst="$target/$f"
        check_parent_dirs "$dst"
        if exists "$dst"; then
            [[ -f "$dst" && ! -L "$dst" ]] && owned "$dst" || conflict "$dst"
            have_app_files=1
            if [[ "$f" == menu.sh ]]; then
                # Menu lama ikut berubah antarrilis; kenali header dan sumber dashboard yang digunakan repo.
                if ! cmp -s -- "$dst" "$source_dir/menu.sh"; then
                    grep -Fxq '# NATHAYA TUNNEL' "$dst" &&
                        grep -Fxq 'source "$NATHAYA_BASE/modules/dashboard/dashboard.sh"' "$dst" || conflict "$dst"
                fi
                existing=1
            fi
        fi
    done
    if exists "$wrapper"; then
        owned "$wrapper" || conflict "$wrapper"
        if [[ -L "$wrapper" ]]; then
            [[ $(readlink -- "$wrapper") == "$target/menu.sh" ||
                $(readlink -f -- "$wrapper") == "$target/menu.sh" ]] || conflict "$wrapper"
        else
            [[ -f "$wrapper" ]] && cmp -s -- "$wrapper" "$source_dir/deployment/menu" || conflict "$wrapper"
        fi
        existing=1
    fi
    for f in "$hook" "$unit_dir/$service" "$unit_dir/$timer"; do
        if exists "$f"; then
            [[ -f "$f" && ! -L "$f" ]] && owned "$f" &&
                cmp -s -- "$f" "$source_dir/deployment/${f##*/}" || conflict "$f"
            existing=1
        fi
    done
    if exists "$timer_link"; then
        [[ -L "$timer_link" ]] && owned "$timer_link" &&
            [[ $(readlink -f -- "$timer_link") == "$unit_dir/$timer" && -f "$unit_dir/$timer" ]] || conflict "$timer_link"
    fi
    if exists "$lock_file"; then
        [[ -f "$lock_file" && ! -L "$lock_file" ]] && owned "$lock_file" || conflict "$lock_file"
    fi
    (( !have_app_files || existing )) || conflict "$target"
    select_ssh_module
    select_stack
    select_ws_units
    check_unit_conflicts
    check_ssh_ports
    check_ws_ports
    check_stack_ports
    check_stack_host
    check_vendor_proxy
    check_ws_tls

    login_enabled=0
    if exists "$hook" || (( !existing && request_login )); then login_enabled=1; fi
    if (( existing && request_login && !login_enabled )); then
        printf 'Instal ulang: pilihan login otomatis yang nonaktif dipertahankan.\n'
    fi
}

missing_dependencies() {
    packages=()
    if [[ ! -x "$python_bin" ]] || ! "$python_bin" -IB -c 'import sys; sys.exit(sys.version_info < (3, 8))'; then
        packages+=(python3)
    fi
    command -v ip >/dev/null || packages+=(iproute2)
    command -v curl >/dev/null || packages+=(curl)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
    command -v dig >/dev/null || packages+=(bind9-dnsutils)
    command -v free >/dev/null || packages+=(procps)
    command -v hostname >/dev/null || packages+=(hostname)
    command -v awk >/dev/null || packages+=(mawk)
    if ! command -v tput >/dev/null || ! command -v clear >/dev/null; then packages+=(ncurses-bin); fi
    ssh_dependencies
    ws_dependencies
    stack_dependencies
    return 0
}

snapshot_states() {
    local n active enabled unit
    for unit in "${managed_units[@]}"; do
        # Kolektor oneshot dapat sedang mengambil sampel. Tunggu sejenak, jangan merekam status transien.
        for (( n=0; n<20; n++ )); do
            active=$(unit_property "$unit" ActiveState) || die "tidak dapat membaca status $unit"
            case "$active" in
                active|inactive) break ;;
                activating|deactivating|reloading) sleep 0.25 ;;
                *) die "status awal $unit tidak dapat dipulihkan secara aman: ${active:-tidak diketahui}" ;;
            esac
        done
        [[ "$active" == active || "$active" == inactive ]] || die "status $unit masih transien: $active"
        enabled=$(unit_property "$unit" UnitFileState) || die "tidak dapat membaca status enable $unit"
        prior_active[$unit]=$active
        prior_enabled[$unit]=${enabled:-not-found}
        printf '%s active=%s unit-file=%s\n' "$unit" "$active" "${enabled:-not-found}" >> "$backup/unit-state"
    done
}

stage_files() {
    local f perm unit
    local -a verify_units=()
    for f in "${app_files[@]}" "${staged_deployment[@]}"; do
        perm=0644
        case "$f" in menu.sh|deployment/menu) perm=0755 ;; esac
        install -D -m "$perm" -- "$source_dir/$f" "$stage/$f" || die "tidak dapat menyiapkan $f"
        case "$f" in
            *.sh|deployment/menu) bash -n "$stage/$f" || die "sintaks Bash tidak valid: $f" ;;
            *.py)
                "$python_bin" -I -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$stage/$f" ||
                    die "sintaks Python tidak valid: $f"
                ;;
        esac
    done
    for unit in "${managed_units[@]}"; do verify_units+=("$stage/deployment/$unit"); done
    systemd-analyze --system verify "${verify_units[@]}" \
        > "$backup/unit-verify.log" 2>&1 || die "validasi unit gagal; lihat $backup/unit-verify.log"
}

record_file() {
    local dst="$1"
    if exists "$dst"; then
        local saved="$backup/files/$backup_count"
        cp -aT -- "$dst" "$saved" || die "backup gagal: $dst"
        backup_count=$((backup_count + 1))
        originals[$dst]=$saved
        printf '%s\t%s\n' "$dst" "$saved" >> "$backup/original-files"
    else
        printf '%s\n' "$dst" >> "$backup/new-files"
    fi
}

ensure_dir() {
    local dir="$1"
    if [[ -d "$dir" ]]; then return 0; fi
    ensure_dir "${dir%/*}"
    created_dirs+=("$dir")
    install -d -m 0755 -- "$dir" || die "tidak dapat membuat direktori: $dir"
}

put_file() {
    local input="$1" dst="$2"
    ensure_dir "${dst%/*}"
    pending_temp=$(mktemp "${dst%/*}/.nathaya.XXXXXX") || die "file sementara gagal: $dst"
    cp -aT -- "$input" "$pending_temp" || die "salin gagal: $dst"
    touched+=("$dst")
    mv -fT -- "$pending_temp" "$dst" || die "pasang gagal: $dst"
    pending_temp=
}

unit_action() { systemctl --system "$@" >> "$backup/deployment.log" 2>&1; }

rollback() {
    local i dst saved unit state enabled failed=0
    printf 'Deployment gagal; memulihkan file dan unit Nathaya.\n' >&2
    if (( units_touched )); then
        # Stop frontend before backend, and leave an untouched TCP 109 listener alone.
        for ((i=${#managed_units[@]}-1; i>=0; i--)); do
            unit=${managed_units[i]}
            [[ ${runtime_touched[$unit]:-0} == 1 ]] || continue
            state=$(unit_property "$unit" ActiveState) || { failed=1; continue; }
            case "$state" in active|activating|deactivating|reloading)
                unit_action stop "$unit" || failed=1 ;;
            esac
        done
    fi
    for (( i=${#touched[@]}-1; i>=0; i-- )); do
        dst=${touched[i]}
        saved=${originals[$dst]:-}
        if [[ -n "$saved" ]]; then
            cp -aT --remove-destination -- "$saved" "$dst" || failed=1
        else
            rm -f -- "$dst" || failed=1
        fi
    done
    if (( units_touched )); then
        unit_action daemon-reload || failed=1
        for unit in "${managed_units[@]}"; do
            if [[ ${runtime_touched[$unit]:-0} == 1 ]]; then
                if [[ ${prior_active[$unit]} == active ]]; then
                    unit_action start "$unit" || failed=1
                elif [[ $(unit_property "$unit" ActiveState) == failed ]]; then
                    unit_action reset-failed "$unit" || failed=1
                fi
            fi
            state=$(unit_property "$unit" ActiveState) || failed=1
            enabled=$(unit_property "$unit" UnitFileState) || failed=1
            [[ "$state" == "${prior_active[$unit]}" && "${enabled:-not-found}" == "${prior_enabled[$unit]}" ]] || failed=1
        done
    fi
    for (( i=${#created_dirs[@]}-1; i>=0; i-- )); do
        rmdir -- "${created_dirs[i]}" 2>/dev/null || true  # Jangan hapus direktori yang sudah dipakai pihak lain.
    done
    if (( failed )); then
        printf 'Rollback tidak lengkap. Periksa backup dan log: %s\n' "$backup" >&2
    else
        printf 'Rollback deployment selesai. Paket APT tidak dihapus. Backup: %s\n' "$backup" >&2
    fi
}

on_exit() {
    local rc=$1
    trap - EXIT
    trap '' INT TERM HUP
    set +e
    if [[ -n "$pending_temp" ]]; then rm -f -- "$pending_temp"; fi
    finish_proxy_apt || printf 'Gagal membereskan HAProxy distro; lihat log APT.\n' >&2
    if (( rc != 0 && deployment_started )); then rollback; fi
    if [[ -n "$stage" ]]; then rm -rf -- "$stage"; fi
    if (( rc != 0 )) && [[ -n "$backup" ]]; then printf 'Log/backup: %s\n' "$backup" >&2; fi
    exit "$rc"
}

deploy() {
    local f i unit restart_ssh=1
    local -a inputs=() outputs=()
    for f in "${app_files[@]}"; do
        inputs+=("$stage/$f"); outputs+=("$target/$f")
    done
    inputs+=("$stage/deployment/$service" "$stage/deployment/$timer" "$stage/deployment/menu")
    outputs+=("$unit_dir/$service" "$unit_dir/$timer" "$wrapper")
    if (( login_enabled )); then
        inputs+=("$stage/deployment/nathaya-login.sh"); outputs+=("$hook")
    fi
    stage_ssh_outputs
    stage_ws_outputs
    stage_stack_outputs
    if ! exists "$timer_link"; then
        # Symlink WantedBy=timers.target; hanya symlink ini yang diubah untuk enablement.
        ln -s -- "../$timer" "$stage/timer-link" || die 'tidak dapat menyiapkan symlink timer'
        inputs+=("$stage/timer-link"); outputs+=("$timer_link")
    fi
    install -d -m 0700 -- "$backup/files" || die 'tidak dapat menyiapkan direktori backup'
    snapshot_states
    for f in "${outputs[@]}"; do record_file "$f"; done

    if [[ ${prior_active[$ssh_service]} == active ]] &&
       cmp -s -- "$target/modules/ssh/backend.py" "$stage/modules/ssh/backend.py" && relay_config_is_running; then
        restart_ssh=0
    fi
    deployment_started=1
    units_touched=1
    for unit in "$connect_service" "$proxy_service" "$ws_service" "${stack_units[@]}" "$timer"; do
        if [[ ${prior_active[$unit]:-inactive} == active ]]; then
            runtime_touched[$unit]=1
            unit_action stop "$unit" || die "gagal menghentikan $unit sebelum deployment"
        fi
    done
    for i in "${!inputs[@]}"; do put_file "${inputs[i]}" "${outputs[i]}"; done
    unit_action daemon-reload || die 'systemctl daemon-reload gagal'
    runtime_touched[$timer]=1
    unit_action start "$timer" || die "gagal memulai $timer"
    [[ $(unit_property "$timer" UnitFileState) == enabled ]] || die "$timer belum aktif saat boot (enabled)"
    [[ $(unit_property "$timer" ActiveState) == active ]] || die "$timer tidak berjalan (active)"
    # Keep direct SSH running while validating the replacement frontends.
    activate_stack
    activate_ws_units
    if (( restart_ssh )); then
        runtime_touched[$ssh_service]=1
        if [[ ${prior_active[$ssh_service]} == active ]]; then
            unit_action stop "$ssh_service" || die "gagal menghentikan $ssh_service sebelum pembaruan"
        fi
    fi
    activate_ssh_unit
    check_ssh_ports 1
    check_ws_ports 1
    verify_relay
    if (( connect_enabled )); then activate_connect_unit; fi
    deployment_started=0
}

main() {
    local mode_install=install request_login=0 login_enabled=0 option ws_domain= vendor_fresh=0 badvpn_enabled=0
    local -a stack_units=() vendor_added=()
    local set_domain=0 use_certbot=0 requested_domain= certbot_email= tls_source_cert= tls_source_key= ssh_tls_sni=
    local fresh_ports=0 ssh_ports_display= connect_enabled=0
    local -a ssh_ports=()
    local -a packages=() managed_units=() staged_deployment=()
    local backup= stage= pending_temp= backup_count=0 deployment_started=0 units_touched=0 lock_fd
    local -a touched=() created_dirs=()
    local -A originals=() prior_active=() prior_enabled=() runtime_touched=()
    for option in "$@"; do
        case "$option" in
            --help|-h) usage; return 0 ;;
            --check) mode_install=check ;;
            --enable-login-menu) request_login=1 ;;
            --set-domain) set_domain=1 ;;
            --use-certbot) use_certbot=1 ;;
            --enable-ssh) : ;;  # Compatibility only; all SSH routes are mandatory.
            *) die "opsi tidak dikenal: $option (lihat --help)" ;;
        esac
    done
    validate_host
    if [[ "$mode_install" == install ]]; then
        # shellcheck source=modules/common/ui.sh
        source "$source_dir/modules/common/ui.sh"
        trap 'cancel_setup' INT
        setup_domain
    fi
    check_conflicts
    validate_sources
    missing_dependencies
    if [[ "$mode_install" == check ]]; then
        printf 'Preflight OK. Dependensi yang perlu dipasang: %s. Login otomatis: %s.\n' \
            "${packages[*]:-tidak ada}" "$login_enabled"
        printf 'Target: SSH %s, WS 80 dan WSS 443 (%s/).\n' "$ssh_ports_display" "$ws_domain"
        if (( EUID != local_uid )); then printf 'Instalasi tetap harus dijalankan sebagai root.\n'; fi
        return 0
    fi

    umask 077
    exec {lock_fd}>> "$lock_file" || die "tidak dapat membuka lock: $lock_file"
    flock -n "$lock_fd" || die 'installer lain sedang berjalan'
    check_conflicts
    trap 'on_exit "$?"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    if [[ ! -d "$backup_root" ]]; then
        install -d -m 0755 -- "$backup_root" || die "tidak dapat menyiapkan $backup_root"
    fi
    backup=$(mktemp -d "$backup_root/nathaya-install.XXXXXX") || die 'tidak dapat membuat backup'
    stage=$(mktemp -d "$backup/stage.XXXXXX") || die 'tidak dapat membuat direktori persiapan'
    missing_dependencies
    if (( ${#packages[@]} )); then
        printf 'Memasang dependensi: %s\n' "${packages[*]}"
        prepare_proxy_apt
        apt-get update > "$backup/apt.log" 2>&1 || die "APT update gagal; lihat $backup/apt.log"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" \
            >> "$backup/apt.log" 2>&1 || die "APT install gagal; lihat $backup/apt.log"
        finish_proxy_apt || die "gagal menonaktifkan unit HAProxy distro; lihat $backup/apt.log"
        missing_dependencies
        (( ${#packages[@]} == 0 )) || die "dependensi masih belum tersedia setelah APT: ${packages[*]}"
    fi
    stage_files
    check_conflicts
    issue_ws_certificate
    stage_ws_config
    stage_stack
    deploy
    printf 'Dashboard terpasang: %s. Jalankan menu.\n' "$target"
    printf 'Timer %s: enabled, active. Login otomatis: %s.\n' "$timer" "$login_enabled"
    printf 'Dropbear TCP %s, WS TCP 80, WSS TCP 443: enabled, active (%s/).\n' "$ssh_ports_display" "$ws_domain"
    printf 'SSH TCP 80: aktif melalui HAProxy (inspeksi hingga 5 detik).\n'
    if [[ -n "$ssh_tls_sni" ]]; then printf 'SSH TLS 443: SNI %s.\n' "$ssh_tls_sni"
    else printf 'SSH TLS 443: belum aktif (SNI khusus belum dikonfigurasi).\n'; fi
    if (( connect_enabled )); then printf 'HTTPS CONNECT TCP 8443: enabled, active.\n'; fi
    printf 'HAProxy HTTP TCP 8080; Nginx/Xray internal; OpenVPN TCP 1194 dan UDP 2200.\n'
    if (( badvpn_enabled )); then printf 'BadVPN TCP internal 7100/7200/7300 aktif.\n'; else printf 'BadVPN belum aktif (binari terverifikasi tidak disediakan).\n'; fi
    printf 'UDP Custom: belum diimplementasikan.\n'
    printf 'Log/backup (akses root): %s\n' "$backup"
    exit 0  # Jalankan EXIT trap selagi variabel transaksi masih dalam lingkup main.
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    set_paths
    main "$@"
fi
