#!/usr/bin/env bash
set -euo pipefail
NATHAYA_BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
DASHBOARD_EXIT=10
# shellcheck source=../../modules/common/ui.sh
source "$NATHAYA_BASE/modules/common/ui.sh"
# shellcheck source=../../modules/menu/ssh.sh
source "$NATHAYA_BASE/modules/menu/ssh.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

ssh_backend() {
    case "$1" in
        available) [[ "$2" != taken ]] ;;
        list) printf '%s\n' member01 0001 1234 member02 ;;
        detail)
            case "$2" in member01|0001|1234|member02) printf '%s\n' "$2" ;; *) return 1 ;; esac ;;
        lock|unlock) printf '%s:%s\n' "$1" "$2" >> "$work/actions" ;;
        create)
            local pw
            read -r pw
            printf '%s:%s:%s:%s\n' "$2" "$pw" "$3" "$4" > "$work/account"
            printf '%s\n' "$2" ;;
        trial) printf '%s:%s\n' "$2" "$3" > "$work/trial"; printf 'trial-fixture\n' ;;
    esac
}
ssh_result() { printf '%s\n' "$2"; }
ssh_member_detail() { printf 'Detail fixture: %s\n' "$1"; }

assert_block() {
    local file="$1" block ending=""
    if [[ $# == 2 ]]; then ending=$'\n\n'; fi
    block=$(cat)
    if [[ $(cat "$file") != *"$block$ending"* ]]; then
        printf 'Blok tata letak tidak ditemukan di %s\n' "$file" >&2
        exit 1
    fi
}

[[ $(ssh_decode_password '\x') == x && $(ssh_decode_password '\z') == z ]]
[[ $(ssh_limit_value 09) == 9 && $(ssh_limit_value 0) == 0 ]]
if ssh_limit_value 100 || ssh_duration_value 0 '' 3650 || ssh_duration_value 3651 '' 3650 ||
   ssh_duration_value 7d '' 3650 || ssh_duration_value 999999999999999 '' 3650 ||
   ssh_duration_value 6 h 720; then
    printf 'Input tidak valid diterima.\n' >&2
    exit 1
fi
[[ $(ssh_duration_value 30 '' 3650) == 30 && $(ssh_duration_value 6h h 720) == 6 ]]
[[ $(ssh_row 'Host server' test) == '  Host server   : test' ]]

# Kembali dari Limit IP ke password, lalu Enter mempertahankan nilai yang terlihat.
ssh_create_wizard member > "$work/screen" <<'INPUT'
BAD
member01
\x
z

0
7d
7
y
INPUT
[[ $(cat "$work/account") == 'member01:x:0:7' ]]
grep -Fq 'Username tidak valid' "$work/screen"
grep -Fq '✓ SSH ACCOUNT CREATED' "$work/screen"
grep -Eq 'Password lama +: x$' "$work/screen"
grep -Fq 'Masukkan angka 1–3650 tanpa akhiran.' "$work/screen"
if grep -Fq $'\033' "$work/screen"; then
    printf 'Escape sequence ditemukan pada input noninteraktif.\n' >&2
    exit 1
fi
awk '/┤ Create ├/ { seen=1; if ((getline) <= 0 || length($0)) bad=1 } END { exit (!seen || bad) }' "$work/screen"
for prompt in Username Password 'Limit IP' 'Masa aktif dalam hari'; do
    assert_block "$work/screen" blank <<BLOCK
  $prompt:

  [z]   Kembali
  [x]   Keluar
BLOCK
done
assert_block "$work/screen" blank <<'BLOCK'
  Username      : member01

  Limit IP      : Unlimited

  Masa aktif    : 7 hari

  Konfirmasi:

  [y]   Buat akun
  [z]   Kembali
  [x]   Keluar
BLOCK
rm -- "$work/account"

rc=0
ssh_create_wizard member > "$work/cancel" <<'INPUT' || rc=$?
member01
\z
2
3
x
INPUT
[[ $rc == 10 && ! -e "$work/account" ]]
ssh_create_wizard trial > "$work/trial-screen" <<'INPUT'
2
6h
INPUT
[[ $(cat "$work/trial") == '2:6' ]]
grep -Fq '✓ SSH TRIAL CREATED' "$work/trial-screen"

# Nomor diprioritaskan untuk 0001; @ memilih nama numerik persis.
ssh_account_menu lock Lock > "$work/lock-screen" <<'INPUT'
999999999999999999999999999
0001
y
z
INPUT
[[ $(cat "$work/actions") == 'lock:member01' ]]
grep -Fq 'Nomor atau username tidak ditemukan.' "$work/lock-screen"
grep -Fq 'Gunakan @1234' "$work/lock-screen"
assert_block "$work/lock-screen" <<'BLOCK'
  [1]   member01
  [2]   0001
  [3]   1234
  [4]   member02

  [z]   Kembali
  [x]   Keluar
BLOCK
awk '/┤ Lock ├/ { seen=1; if ((getline) <= 0 || length($0)) bad=1 } END { exit (!seen || bad) }' "$work/lock-screen"
assert_block "$work/lock-screen" <<'BLOCK'
  Username      : member01
  [y]   Konfirmasi
BLOCK
ssh_account_menu unlock Unlock > "$work/unlock-screen" <<'INPUT'
@0001
y
z
INPUT
ssh_account_menu unlock Unlock > "$work/unlock-name" <<'INPUT'
member02
y
z
INPUT
ssh_account_menu unlock Unlock > "$work/unlock-number" <<'INPUT'
3
y
z
INPUT
[[ $(cat "$work/actions") == $'lock:member01\nunlock:0001\nunlock:member02\nunlock:1234' ]]
assert_block "$work/unlock-screen" <<'BLOCK'
  Username      : 0001
  [y]   Konfirmasi
BLOCK
ssh_account_menu list 'List Member' > "$work/members-screen" <<'INPUT'
2
z
INPUT
grep -Fq '[2]   0001' "$work/members-screen"
grep -Fq 'Detail fixture: 0001' "$work/members-screen"

ssh_width=48
ssh_detail_lines() { ssh_row Username 'fixture'; }
telegram_send_message() { return 7; }
[[ $(ssh_send_account fixture x 'Fixture') == *'kirim ulang dari List Member'* ]]
printf 'OK: Create/Trial, tata letak, z/x, pilihan akun, dan kegagalan Telegram (mock).\n'
