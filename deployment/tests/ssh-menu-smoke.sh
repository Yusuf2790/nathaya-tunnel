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

get_width() { printf '%s\n' "${test_width:-50}"; }
ssh_backend() {
    case "$1" in
        available) [[ "$2" != taken ]] ;;
        table)
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                member01 member 1 4102444800 0 2 0 0 \
                0001 trial 1 4102444800 1 2 1 0 \
                1234 member 1 4102444800 2 2 0 0 \
                member02 member 1 4102444800 3 2 1 0 \
                expired1 member 1 2 0 2 1 0 \
                autolock member 1 4102444800 0 2 1 4102444800 ;;
        expired-table)
            case "${expired_fixture:-normal}" in
                unavailable) printf 'fixture backend offline\n' >&2; return 1 ;;
                empty) printf '0\tempty-token\n'; return 0 ;;
            esac
            if [[ -f "$work/bulk-done" ]]; then printf '0\tempty-token\n'; return 0; fi
            if [[ -f "$work/single-done" ]]; then
                printf '1\tremaining-batch\nexpired1\tmember\t1\t2\t0\t2\t0\t0\tid-expired1\n'
                return 0
            fi
            printf '2\t%s\n' "$([[ -f "$work/bulk-stale" ]] && printf new-batch || printf old-batch)"
            printf '0001\ttrial\t1\t2\t1\t2\t1\t0\tid-0001\nexpired1\tmember\t1\t2\t0\t2\t0\t0\tid-expired1\n' ;;
        expired-view) [[ "$3" == "id-$2" ]] || return 4; printf '2\t1\tExpired\texpired-token\t0\n' ;;
        delete-expired)
            [[ "$3" == "id-$2" && "$4" == expired-token ]] || return 4
            if [[ "${expired_fixture:-normal}" == renewed ]]; then
                printf 'Akun tidak lagi expired. Tidak ada akun yang dihapus.\n' >&2
                return 3
            fi
            printf 'single:%s\n' "$2" >> "$work/expired-actions"
            touch "$work/single-done" ;;
        delete-all-expired)
            if [[ "$2" == old-batch ]]; then
                touch "$work/bulk-stale"
                printf 'Daftar expired berubah. Tidak ada akun yang dihapus.\n' >&2
                return 3
            fi
            [[ "$2" == new-batch ]] || return 4
            printf 'bulk:%s\n' "$2" >> "$work/expired-actions"
            touch "$work/bulk-done"
            printf '2\n' ;;
        action-table) ssh_backend table | awk '{ print $0 "\tid-" $1 }' ;;
        action-view)
            [[ "$3" == "id-$2" ]] || return 4
            if [[ -f "$work/stale" ]]; then
                printf '4102444900\t1\tLocked\tnew-token\t4105036900\n'
            else
                printf '4102444800\t1\tLocked\told-token\t4105036800\n'
            fi ;;
        delete)
            [[ "$3" == "id-$2" && "$4" == old-token ]] || return 4
            printf 'delete:%s\n' "$2" >> "$work/mutations" ;;
        renew)
            [[ "$3" == "id-$2" && "$5" == 30 ]] || return 4
            if [[ "$4" == old-token ]]; then touch "$work/stale"; return 3; fi
            [[ "$4" == new-token ]] || return 3
            printf 'renew:%s:%s\n' "$2" "$5" >> "$work/mutations"
            printf '4105037000\tLocked\n' ;;
        detail)
            case "$2" in
                member01|1234) printf '%s\n' "$2" member 1 4102444800 0 2 0 0 ;;
                0001|member02) printf '%s\n' "$2" member 1 4102444800 1 2 1 0 ;;
                *) return 1 ;;
            esac ;;
        create)
            local pw
            IFS= read -r pw
            printf '%s:%s:%s:%s\n' "$2" "$pw" "$3" "$4" >> "$work/created"
            printf '%s\n' "$2" ;;
        trial)
            printf '%s:%s\n' "$2" "$3" >> "$work/trials"
            printf 'trial-fixture\n' ;;
        lock|unlock) printf '%s:%s\n' "$1" "$2" >> "$work/actions" ;;
    esac
}
ssh_result() { printf '%s\n' "$2"; }
ssh_member_detail() { printf 'Detail fixture: %s\n' "$1"; }

[[ $(ssh_limit_value 09) == 9 && $(ssh_limit_value 0) == 0 ]]
[[ $(ssh_duration_value 30 '' 3650) == 30 && $(ssh_duration_value 3650 '' 3650) == 3650 ]]
[[ $(ssh_trial_duration 30m) == 30m && $(ssh_trial_duration 1h) == 1h ]]
[[ $(ssh_duration_label trial 1800) == '30 menit' && $(ssh_duration_label trial 3600) == '1 jam' ]]
for bad in 0m 0h -1m 30 43201m 721h; do
    if ssh_trial_duration "$bad"; then printf 'Durasi tidak valid diterima: %s\n' "$bad" >&2; exit 1; fi
done

# 30d ditolak. x bukan navigasi saat menjadi password. n mempertahankan isian.
ssh_create_wizard member > "$work/create-screen" <<'INPUT'
BAD
member01
x
0
30d
30
n





x
y
INPUT
[[ $(cat "$work/created") == 'member01:x:0:30' ]]
grep -Fq 'Username tidak valid.' "$work/create-screen"
grep -Fq 'Masukkan angka 1–3650 tanpa akhiran, misalnya 30.' "$work/create-screen"
grep -Eq 'Password +: \[x\]' "$work/create-screen"
grep -Fq 'CONFIRM CREATE' "$work/create-screen"
grep -Fq 'Buat akun ini? [y/n]' "$work/create-screen"
if grep -Eq '\[[zx]\].*(Kembali|Keluar)' "$work/create-screen"; then
    printf 'Formulir masih menampilkan navigasi z/x.\n' >&2
    exit 1
fi
awk '/┤ (CREATE SSH ACCOUNT|CONFIRM CREATE) ├/ { seen=1; if ((getline) <= 0 || length($0)) bad=1 }
     /^  (Username|Password|Limit IP|Masa aktif)( |\()/ && index($0, ":") { if (index($0, ":") != 21) bad=1 }
     END { exit (!seen || bad) }' "$work/create-screen"

ssh_create_wizard member > "$work/create-z" <<'INPUT'
member02
z
2
30
y
INPUT
[[ $(tail -n 1 "$work/created") == 'member02:z:2:30' ]]
ssh_create_wizard trial > "$work/trial-screen" <<'INPUT'
2
0m
-1h
30
30m
y
INPUT
ssh_create_wizard trial > "$work/trial-hour" <<'INPUT'
0
1h
y
INPUT
[[ $(cat "$work/trials") == $'2:30m\n0:1h' ]]
grep -Fq 'CONFIRM TRIAL' "$work/trial-screen"
grep -Fq '30m = 30 menit; 1h = 1 jam.' "$work/trial-screen"
grep -Eq 'Masa aktif +: 30 menit$' "$work/trial-screen"
grep -Eq 'Masa aktif +: 1 jam$' "$work/trial-hour"

ssh_account_menu lock 'Lock SSH' > "$work/lock-screen" <<'INPUT'
999999999999999999999999999
0001
n
0001
y
z
INPUT
[[ $(cat "$work/actions") == 'lock:member01' ]]
grep -Fq 'Nomor atau username tidak ditemukan.' "$work/lock-screen"
grep -Fq 'CONFIRM LOCK' "$work/lock-screen"
grep -Eq 'Username +: member01$' "$work/lock-screen"
ssh_account_menu unlock 'Unlock SSH' > "$work/unlock-screen" <<'INPUT'
@0001
y
z
INPUT
ssh_account_menu unlock 'Unlock SSH' > "$work/unlock-name" <<'INPUT'
member02
y
z
INPUT
ssh_account_menu unlock 'Unlock SSH' > "$work/unlock-number" <<'INPUT'
2
y
z
INPUT
[[ $(cat "$work/actions") == $'lock:member01\nunlock:0001\nunlock:member02\nunlock:member02' ]]
grep -Fq 'CONFIRM UNLOCK' "$work/unlock-screen"
grep -Eq 'Username +: 0001$' "$work/unlock-screen"
if grep -Eq 'expired1|autolock' "$work/unlock-screen"; then
    printf 'Unlock mencantumkan akun yang tidak memenuhi syarat.\n' >&2
    exit 1
fi
ssh_account_menu list 'List Member' > "$work/members" <<'INPUT'
@0001
z
INPUT
grep -Fq 'Detail fixture: 0001' "$work/members"
grep -Eq 'Total Member +: 6$' "$work/members"
grep -Eq 'Aktif +: 2$' "$work/members"
grep -Eq 'Locked +: 3$' "$work/members"
grep -Eq 'Expired +: 1$' "$work/members"
rc=0
test_width=32 ssh_account_menu list 'List Member' > "$work/narrow" <<'INPUT' || rc=$?
x
INPUT
[[ $rc == 10 ]]
grep -Fq 'EXPIRED  | STATUS | LIMIT IP' "$work/narrow"
grep -Fq 'z. Kembali ke menu SSH' "$work/narrow"
grep -Fq 'x. Keluar' "$work/narrow"
grep -Fq 'Pilihan:' "$work/narrow"
if grep -Eq '(^|[[:space:]])Type([[:space:]:]|$)' "$work/members"; then exit 1; fi

ssh_account_menu delete 'DELETE SSH' > "$work/delete-screen" <<'INPUT'
@0001
n
expired1

y
z
INPUT
[[ $(cat "$work/mutations") == 'delete:expired1' ]]
grep -Fq 'CONFIRM DELETE' "$work/delete-screen"
grep -Fq 'Hapus akun ini? [y/n]:' "$work/delete-screen"
grep -Fq 'Masukkan y atau n.' "$work/delete-screen"
grep -Fq 'HASIL DELETE' "$work/delete-screen"
ssh_account_menu renew 'RENEW SSH' > "$work/renew-screen" <<'INPUT'
2
30
n
2
30
y
y
z
INPUT
[[ $(cat "$work/mutations") == $'delete:expired1\nrenew:0001:30' ]]
grep -Fq 'DAFTAR AKUN SSH AKTIF' "$work/renew-screen"
grep -Fq 'DAFTAR AKUN SSH EXPIRED' "$work/renew-screen"
grep -Eq '^ *6\. +expired1' "$work/renew-screen"
grep -Fq 'Perpanjang akun ini? [y/n]:' "$work/renew-screen"
[[ $(grep -c 'CONFIRM RENEW' "$work/renew-screen") == 3 ]]
grep -Fq 'HASIL RENEW' "$work/renew-screen"
grep -Fq "$(ssh_expiry 4105037000)" "$work/renew-screen"

check_table_style() {
    local ssh_width="$1" i line cyan=$'\033[1;36m' orange=$'\033[38;5;208m' reset=$'\033[0m'
    local CYAN=$cyan ORANGE=$orange RESET=$reset
    local -a accounts=() dates=() limits=() statuses=()
    for ((i=1; i<=105; i++)); do
        printf -v line 'member%03d' "$i"
        accounts+=("$line"); dates+=(21/11/26); statuses+=(Aktif); limits+=(Unlimited)
    done
    ssh_account_table 0 105 > "$work/style"
    grep -Fq "$orange"'100.'"$cyan" "$work/style"
    grep -Fq "$cyan"' NO.  USERNAME' "$work/style"
    line=$cyan$(repeat_char '─' "$ssh_width")$reset
    [[ $(head -n 1 "$work/style") == "$line" ]]
    [[ $(tail -n 1 "$work/style") == *"$line" ]]
    [[ $(grep -Fc "$line" "$work/style") == 3 ]]
    sed 's/'$'\033''\[[0-9;]*m//g' "$work/style" |
        awk '/member[0-9]+/ && match($0, /member[0-9]+/) != 7 { bad=1 } END { exit bad }'
}
check_table_style 50
check_table_style 32

expired_fixture=empty ssh_expired_menu > "$work/expired-empty" <<'INPUT'
z
INPUT
grep -Fq 'Tidak ada akun SSH expired' "$work/expired-empty"
if grep -Eq '^  [da]\.' "$work/expired-empty"; then exit 1; fi
expired_fixture=unavailable ssh_expired_menu > "$work/expired-error" <<'INPUT'
z
INPUT
grep -Fq 'fixture backend offline' "$work/expired-error"
ssh_expired_menu > "$work/expired-cancel" <<'INPUT'
d
1
n
a
n
z
INPUT
[[ ! -e "$work/expired-actions" ]]
expired_fixture=renewed ssh_expired_menu > "$work/expired-renewed" <<'INPUT'
d
@0001
y
z
INPUT
[[ ! -e "$work/expired-actions" ]]
grep -Fq 'Akun tidak lagi expired.' "$work/expired-renewed"
ssh_expired_menu > "$work/expired-single" <<'INPUT'
d
member01
@0001

y
z
INPUT
[[ $(cat "$work/expired-actions") == 'single:0001' ]]
grep -Fq 'Akun tidak ditemukan dalam daftar expired.' "$work/expired-single"
grep -Fq 'Hapus akun expired ini? [y/n]:' "$work/expired-single"
grep -Fq 'Akun 0001 berhasil dihapus.' "$work/expired-single"
grep -Eq 'Total akun expired +: 1$' "$work/expired-single"
rm -- "$work/single-done"  # Mulai fixture massal yang terpisah.
ssh_expired_menu > "$work/expired-all" <<'INPUT'
a
y
a
y
z
INPUT
[[ $(cat "$work/expired-actions") == $'single:0001\nbulk:new-batch' ]]
grep -Fq 'CONFIRM DELETE ALL EXPIRED' "$work/expired-all"
grep -Fq 'Hapus semua 2 akun expired ini? [y/n]:' "$work/expired-all"
grep -Fq 'Daftar expired berubah.' "$work/expired-all"
grep -Fq '2 akun expired berhasil dihapus.' "$work/expired-all"
grep -Fq 'Tidak ada akun SSH expired' "$work/expired-all"

ssh_width=48
ssh_detail_lines() { ssh_row Username 'fixture'; }
telegram_send_message() { return 7; }
[[ $(ssh_send_account fixture x 'Fixture') == *'kirim ulang dari List Member'* ]]
printf 'OK: Create/Trial, tabel, konfirmasi y/n, pilihan akun, dan Telegram (mock).\n'
