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

host=$(fixture login)
run_installer "$host" --enable-login-menu > "$work/login-install.out"
run_installer "$host" > "$work/login-reinstall.out"
[[ -f "$host/etc/profile.d/nathaya-login.sh" ]] || fail 'pilihan login aktif tidak dipertahankan'
# Shell noninteraktif harus diam, bahkan bila variabel SSH terisi.
output=$(SSH_CONNECTION='fixture' SSH_TTY='/dev/pts/fixture' bash -c 'source "$1"' bash "$host/etc/profile.d/nathaya-login.sh")
[[ -z "$output" ]] || fail 'hook login menghasilkan output noninteraktif'
printf 'OK: help, check, konflik, lock, validasi unit, fresh, reinstall, rollback, dan hook noninteraktif (mock).\n'
