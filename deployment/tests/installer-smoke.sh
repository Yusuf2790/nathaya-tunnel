#!/usr/bin/env bash
# Fixture tanpa root, APT nyata, systemd nyata, atau penulisan di luar direktori sementara.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python=$(command -v python3) || { printf 'Tes memerlukan python3.\n' >&2; exit 1; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
    local case_path="$1" expected="$2" pid
    shift 2
    # Uji exit status tanpa meletakkan fungsi installer dalam kondisi if (yang menonaktifkan errexit).
    run_installer "$case_path" "$@" > "$work/output" 2>&1 &
    pid=$!
    if wait "$pid"; then
        fail "installer seharusnya gagal: $expected"
    fi
    grep -Fq -- "$expected" "$work/output" || fail "pesan gagal tidak ditemukan: $expected"
}

fixture() {
    local root="$work/$1"
    mkdir -p "$root"/{etc/systemd/system,etc/profile.d,run/systemd/system,usr/local/bin,var/backups,state}
    printf 'ID=debian\nVERSION_ID=12\n' > "$root/etc/os-release"
    printf '%s\n' "$root"
}

run_installer() (
    local root="$1"
    shift
    # shellcheck source=../../install-dashboard.sh
    source "$repo/install-dashboard.sh"
    set_paths "$root"
    local_uid=$EUID
    python_bin=$python
    check_ws_tls() {
        [[ ! -e "$root/state/no-tls" ]] || die 'TLS belum lengkap'
        ws_domain=tunnel.example.test
    }
    check_listener() {
        [[ ! -e "$root/state/conflict-$1" ]] || die "Benturan TCP $1"
        if [[ "${3:-0}" == 1 ]]; then
            [[ $(cat "$root/state/$2") == active ]] || die "TCP $1 tidak aktif"
        fi
    }
    verified_stack_binary() { :; }
    check_stack_host() { :; }
    stage_stack() {
        mkdir "$stage/stack"
        local f
        for f in xray-credentials.json ca.key ca.crt server.key server.crt client.key client.crt tls-crypt.key \
            xray.json nginx.conf openvpn-{tcp,udp}.conf client-{tcp,udp}.ovpn xray; do
            printf 'fixture\n' > "$stage/stack/$f"
        done
        chmod 0644 "$stage/stack/nginx.conf"
    }
    verify_relay() { :; }
    issue_ws_certificate() { :; }
    stage_ws_config() {
        [[ ! -e "$root/state/bad-proxy-config" ]] || die 'konfigurasi HAProxy tidak valid'
        mkdir "$stage/ws"
        printf 'fixture\n' > "$stage/ws/domain"
        printf 'fixture\n' > "$stage/ws/tls.pem"
        printf 'fixture certificate\n' > "$stage/ws/fullchain.pem"
        printf 'fixture key\n' > "$stage/ws/privkey.pem"
        printf '%064d\n' 1 > "$stage/ws/relay.key"
        printf '# Managed by Nathaya Tunnel (WS frontend v1)\n' > "$stage/ws/haproxy.cfg"
    }
    uname() { printf 'x86_64\n'; }
    dpkg() { printf 'amd64\n'; }
    missing_dependencies() {
        packages=()
        if [[ -e "$root/state/want-package" && ! -e "$root/state/package-installed" ]]; then packages+=(curl); fi
    }
    apt-get() {
        printf '%s\n' "$*" >> "$root/state/apt"
        if [[ "$1" == install ]]; then touch "$root/state/package-installed"; fi
    }
    systemd-analyze() {
        [[ $1 == --system ]] || return 1
        case "$2" in
            unit-paths) printf '%s\n' "$unit_dir" "$root/lib/systemd/system" ;;
            verify) [[ -f "$3" && -f "$4" && ! -e "$root/state/fail-verify" ]] ;;
            *) return 1 ;;
        esac
    }
    systemctl() {
        [[ $1 == --system ]] || return 1
        shift
        local unit name
        case "$1" in
            show)
                unit=${5:-}
                case "$2" in
                    --property=Version) printf 'mock\n' ;;
                    --property=FragmentPath)
                        if [[ -f "$unit_dir/$unit" ]]; then printf '%s\n' "$unit_dir/$unit"; fi ;;
                    --property=DropInPaths) : ;;
                    --property=ActiveState)
                        if [[ -f "$root/state/$unit" ]]; then cat "$root/state/$unit"; else printf 'inactive\n'; fi ;;
                    --property=UnitFileState)
                        if [[ "$unit" == "$timer" && -e "$timer_link" ]]; then printf 'enabled\n'
                        elif [[ -e "$unit_dir/multi-user.target.wants/$unit" ]]; then printf 'enabled\n'
                        elif [[ "$unit" == "$service" && -f "$unit_dir/$unit" ]]; then printf 'static\n'
                        elif [[ -f "$unit_dir/$unit" ]]; then printf 'disabled\n'; fi ;;
                    *) return 1 ;;
                esac
                ;;
            daemon-reload) printf '%s\n' "$1" >> "$root/state/actions" ;;
            start|stop|reset-failed)
                name=$1 unit=$2
                printf '%s %s\n' "$name" "$unit" >> "$root/state/actions"
                if [[ "$name" == start ]]; then
                    if [[ "$unit" == "$timer" && -e "$root/state/fail-start" ]]; then
                        rm -- "$root/state/fail-start"
                        printf 'failed\n' > "$root/state/$unit"
                        return 1
                    fi
                    if [[ -e "$root/state/fail-$unit" ]]; then
                        rm -- "$root/state/fail-$unit"
                        printf 'failed\n' > "$root/state/$unit"
                        return 1
                    fi
                    printf 'active\n' > "$root/state/$unit"
                else
                    printf 'inactive\n' > "$root/state/$unit"
                fi
                ;;
            *) return 1 ;;
        esac
    }
    main "$@"
)

host=$(fixture fresh)
touch "$host/state/want-package"
run_installer "$host" --help > "$work/help"
grep -Fq -- '--enable-login-menu' "$work/help" || fail 'bantuan tidak memuat opsi login'
run_installer "$host" --check > "$work/check"
grep -Fq 'curl' "$work/check" || fail 'preflight tidak melaporkan paket kurang'
[[ ! -e "$host/state/apt" && ! -e "$host/state/actions" && ! -e "$host/run/nathaya-install.lock" &&
   ! -e "$host/opt/nathaya" && -z $(ls -A "$host/var/backups") ]] || fail 'preflight menulis fixture'
printf 'aplikasi lain\n' > "$host/usr/local/bin/menu"
expect_failure "$host" "$host/usr/local/bin/menu"
[[ ! -e "$host/state/apt" && $(cat "$host/usr/local/bin/menu") == 'aplikasi lain' ]] || fail 'benturan ditimpa atau APT berjalan'
rm -- "$host/usr/local/bin/menu"
for conflict in etc/profile.d/nathaya-login.sh etc/systemd/system/nathaya-traffic.timer; do
    printf 'aplikasi lain\n' > "$host/$conflict"
    expect_failure "$host" "$host/$conflict"
    [[ ! -e "$host/state/apt" ]] || fail 'APT berjalan sebelum pemeriksaan benturan selesai'
    rm -- "$host/$conflict"
done
(
    exec 9>> "$host/run/nathaya-install.lock"
    flock -n 9
    expect_failure "$host" 'installer lain sedang berjalan'
)
run_installer "$host" > "$work/install"
[[ -x "$host/usr/local/bin/menu" && ! -e "$host/etc/profile.d/nathaya-login.sh" &&
   -L "$host/etc/systemd/system/timers.target.wants/nathaya-traffic.timer" &&
   $(cat "$host/state/nathaya-traffic.timer") == active ]] || fail 'instalasi fresh'
[[ $(cat "$host/etc/nathaya-tunnel/ssh-ports.conf") == "109 143" ]] || fail 'port SSH fresh bukan 109/143'
for unit in nathaya-dropbear.service nathaya-ws.service nathaya-haproxy.service \
    nathaya-nginx.service nathaya-xray.service nathaya-openvpn-tcp.service nathaya-openvpn-udp.service; do
    [[ $(cat "$host/state/$unit") == active ]] || fail "layanan wajib tidak aktif: $unit"
done
grep -Fxq 'update' "$host/state/apt" || fail 'APT update tidak dipanggil'
grep -Fxq 'install -y --no-install-recommends curl' "$host/state/apt" || fail 'APT memasang paket yang salah'
mkdir -p "$host"/{etc/nathaya-tunnel,var/lib/nathaya-tunnel,etc,opt/nathaya/logs}
persist=(etc/nathaya-tunnel/config.conf etc/nathaya-tunnel/traffic-interface var/lib/nathaya-tunnel/traffic.json etc/passwd opt/nathaya/logs/telegram.log)
for f in "${persist[@]}"; do printf 'fixture %s\n' "$f" > "$host/$f"; done
apt_before=$(cat "$host/state/apt")
run_installer "$host" --enable-login-menu > "$work/reinstall"
[[ ! -e "$host/etc/profile.d/nathaya-login.sh" && $(cat "$host/state/apt") == "$apt_before" ]] || fail 'instal ulang mengubah pilihan login atau mengulang APT'
for f in "${persist[@]}"; do [[ $(cat "$host/$f") == "fixture $f" ]] || fail "data berubah: $f"; done

# Upgrade dari wrapper symlink yang diterima installer lama. Gagal start sekali,
# lalu rollback harus memulihkan berkas lama dan timer yang tadinya aktif.
rm -- "$host/usr/local/bin/menu"
ln -s "$host/opt/nathaya/menu.sh" "$host/usr/local/bin/menu"
printf '# versi terpasang\n' > "$host/opt/nathaya/modules/dashboard/traffic.sh"
touch "$host/state/fail-start"
expect_failure "$host" 'Rollback deployment selesai'
[[ -L "$host/usr/local/bin/menu" && $(cat "$host/opt/nathaya/modules/dashboard/traffic.sh") == '# versi terpasang' &&
   $(cat "$host/state/nathaya-traffic.timer") == active ]] || fail 'rollback upgrade tidak memulihkan berkas/timer'
for f in "${persist[@]}"; do [[ $(cat "$host/$f") == "fixture $f" ]] || fail "data berubah sesudah rollback: $f"; done

# HAProxy failure during an upgrade must not restart a still-working TCP 109 service.
: > "$host/state/actions"
touch "$host/state/fail-nathaya-haproxy.service"
expect_failure "$host" 'Rollback deployment selesai'
if grep -Fxq 'stop nathaya-dropbear.service' "$host/state/actions"; then fail 'TCP 109 ikut dihentikan'; fi
[[ $(cat "$host/state/nathaya-dropbear.service") == active && $(cat "$host/state/nathaya-haproxy.service") == active ]] ||
    fail 'rollback frontend gagal memulihkan layanan'

host=$(fixture ws-preflight)
touch "$host/state/want-package" "$host/state/conflict-80"
expect_failure "$host" 'Benturan TCP 80'
rm "$host/state/conflict-80"
for port in 8080 1010 10005 1194 2200; do
    touch "$host/state/conflict-$port"
    expect_failure "$host" "Benturan TCP $port"
    rm "$host/state/conflict-$port"
done
touch "$host/state/conflict-143"
expect_failure "$host" 'Benturan TCP 143'
rm "$host/state/conflict-143"
touch "$host/state/no-tls"
expect_failure "$host" 'TLS belum lengkap'
[[ ! -e "$host/state/apt" && ! -e "$host/state/actions" ]] || fail 'preflight melakukan perubahan'
rm "$host/state/no-tls"
touch "$host/state/bad-proxy-config"
expect_failure "$host" 'konfigurasi HAProxy tidak valid'
[[ ! -e "$host/state/actions" ]] || fail 'HAProxy diaktifkan sebelum validasi'

host=$(fixture invalid-unit)
touch "$host/state/fail-verify"
expect_failure "$host" 'validasi unit gagal'
[[ ! -e "$host/state/actions" && ! -e "$host/opt/nathaya" ]] || fail 'deployment dimulai sebelum validasi unit'

host=$(fixture fresh-failure)
touch "$host/state/fail-start" "$host/state/want-package"
expect_failure "$host" 'Rollback deployment selesai' --enable-login-menu
[[ ! -e "$host/usr/local/bin/menu" && ! -e "$host/etc/profile.d/nathaya-login.sh" && ! -e "$host/opt/nathaya" &&
   ! -e "$host/etc/systemd/system/nathaya-traffic.timer" && ! -e "$host/etc/systemd/system/timers.target.wants" &&
   -e "$host/state/package-installed" ]] || fail 'rollback fresh menghapus paket atau menyisakan deployment'

host=$(fixture explicit-ports)
mkdir -p "$host/etc/nathaya-tunnel"
printf '109\n' > "$host/etc/nathaya-tunnel/ssh-ports.conf"
printf '%064d\n' 7 > "$host/etc/nathaya-tunnel/connect.key"
run_installer "$host" > "$work/explicit-ports.out"
[[ $(cat "$host/etc/nathaya-tunnel/ssh-ports.conf") == 109 ]] || fail 'port admin tertimpa'
[[ $(cat "$host/state/nathaya-connect.service") == active ]] || fail 'CONNECT opsional tidak aktif'
rm -- "$host/etc/nathaya-tunnel/connect.key"
run_installer "$host" > "$work/connect-disabled.out"
[[ $(cat "$host/state/nathaya-connect.service") == inactive ]] || fail 'CONNECT tanpa kunci masih aktif'

host=$(fixture login)
run_installer "$host" --enable-login-menu > "$work/login-install.out"
run_installer "$host" > "$work/login-reinstall.out"
[[ -f "$host/etc/profile.d/nathaya-login.sh" ]] || fail 'pilihan login aktif tidak dipertahankan'
# Shell noninteraktif harus diam, bahkan bila variabel SSH terisi.
output=$(SSH_CONNECTION='fixture' SSH_TTY='/dev/pts/fixture' bash -c 'source "$1"' bash "$host/etc/profile.d/nathaya-login.sh")
[[ -z "$output" ]] || fail 'hook login menghasilkan output noninteraktif'
printf 'OK: help, check, konflik, lock, validasi unit, fresh, reinstall, rollback, dan hook noninteraktif (mock).\n'
