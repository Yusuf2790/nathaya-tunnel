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
grep -Fq 'Expired  | Limit IP | Status' "$work/narrow"
grep -Fq 'z. Kembali ke menu SSH' "$work/narrow"
grep -Fq 'x. Keluar' "$work/narrow"
grep -Fq 'Pilihan:' "$work/narrow"
if grep -Eq '(^|[[:space:]])Type([[:space:]:]|$)' "$work/members"; then exit 1; fi

ssh_width=48
ssh_detail_lines() { ssh_row Username 'fixture'; }
telegram_send_message() { return 7; }
[[ $(ssh_send_account fixture x 'Fixture') == *'kirim ulang dari List Member'* ]]
printf 'OK: Create/Trial, tabel, konfirmasi y/n, pilihan akun, dan Telegram (mock).\n'
