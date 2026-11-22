#!/usr/bin/env bash

# shellcheck source=../common/telegram.sh
source "$NATHAYA_BASE/modules/common/telegram.sh"

ssh_page() {
    clear_screen
    ssh_width=$(get_width)
    draw_nathaya_header "$ssh_width"
    draw_section_title "$1" "$ssh_width"
}

ssh_row() { printf '  %-13s : %s\n' "$1" "$2"; }
ssh_rule() { printf '  '; repeat_char '═' "$((ssh_width - 2))"; printf '\n'; }
ssh_backend() { /usr/bin/python3 -I "$NATHAYA_BASE/modules/ssh/backend.py" "$@"; }
ssh_ready() { systemctl is-active --quiet nathaya-dropbear.service; }

ssh_read() {
    local label="$1" hint="${2:-}"
    draw_submenu_navigation
    if [[ -n "$hint" ]]; then printf '  %s\n' "$hint"; fi
    IFS= read -r -p "  $label: " ssh_input || return "$DASHBOARD_EXIT"
    case "${ssh_input,,}" in
        z) return 1 ;;
        x) return "$DASHBOARD_EXIT" ;;
        exit|keluar) [[ -n "$hint" ]] || return "$DASHBOARD_EXIT" ;;
    esac
    return 0
}

ssh_create_read() {
    local label="$1" confirmation="${2:-0}" rows=5 rc=0 move_cursor=0
    printf '  %s:\n\n' "$label"
    if (( confirmation )); then
        draw_menu_item y 'Buat akun'
        rows=$((rows + 1))
    fi
    draw_submenu_navigation
    printf '\n'
    if [[ -t 0 && -t 1 && ${TERM:-dumb} != dumb ]]; then
        # Simpan posisi di bawah pilihan, lalu pindah ke akhir prompt.
        printf '\0337\033[%dA\r\033[%dC' "$rows" "$((${#label} + 4))"
        move_cursor=1
    fi
    IFS= read -r ssh_input || rc=$?
    if (( move_cursor )); then printf '\0338'; fi
    if (( rc )); then return "$DASHBOARD_EXIT"; fi
    case "${ssh_input,,}" in
        z) return 1 ;;
        x) return "$DASHBOARD_EXIT" ;;
    esac
    return 0
}

ssh_limit_value() {
    local LC_ALL=C
    [[ "$1" =~ ^[0-9]{1,2}$ ]] || return 1
    printf '%d\n' "$((10#$1))"
}

ssh_duration_value() {
    local LC_ALL=C suffix="$2" maximum="$3"
    [[ "$1" =~ ^([0-9]{1,4})$suffix$ ]] || return 1
    local n=$((10#${BASH_REMATCH[1]}))
    (( n > 0 && n <= maximum )) || return 1
    printf '%s\n' "$n"
}

ssh_decode_password() {
    local LC_ALL=C value="$1"
    case "$value" in '\x'|'\z') value=${value:1} ;; esac
    [[ "$value" =~ ^[a-z0-9]{1,64}$ ]] || return 1
    printf '%s' "$value"
}

ssh_expiry() {
    local zone=${NATHAYA_TZ:-}
    if [[ -n "$zone" && "$zone" != /* && "$zone" != *..* && -f "/usr/share/zoneinfo/$zone" ]]; then
        TZ="$zone" LC_ALL=C date -d "@$1" '+%d %b %Y, %H.%M %Z'
    else
        LC_ALL=C date -d "@$1" '+%d %b %Y, %H.%M %Z'
    fi
}

ssh_detail_lines() {
    local name="$1" secret="$2" telegram="$3" line host ports port label value
    local -a account=()
    line=$(ssh_backend detail "$name" 2>/dev/null) || return 1
    mapfile -t account <<< "$line"
    (( ${#account[@]} == 8 )) || return 1
    host=${DOMAIN:-${PUBLIC_IP:-—}}
    ssh_rule
    ssh_row ISP "${ISP:-—}"
    ssh_row CITY "${CITY:-—}"
    ssh_rule
    ssh_row 'Host server' "$host"
    ssh_row Username "$name"
    if [[ -n "$secret" ]]; then ssh_row Password "$secret"; fi
    ssh_rule
    if ssh_ready && ports=$(ssh_backend ports 2>/dev/null); then
        # Only display configured listeners belonging to the active Nathaya service.
        local main_pid listeners
        main_pid=$(systemctl show -p MainPID --value nathaya-dropbear.service) || main_pid=
        listeners=$(ss -H -ltnp 2>/dev/null) || listeners=
        for port in $ports; do
            if [[ -n "$main_pid" ]] && grep -Eq ":$port[[:space:]].*pid=$main_pid," <<< "$listeners"; then
                ssh_row Dropbear "$port/TCP"
            fi
        done
    fi
    ssh_rule
    value='Unlimited'
    if [[ ${account[4]} != 0 ]]; then value="${account[4]} IP"; fi
    ssh_row 'Limit IP' "$value"
    ssh_row 'Batas sesi' "${account[5]} koneksi aktif"
    if [[ ${account[1]} == trial ]]; then
        label="$(( (account[3] - account[2]) / 3600 )) jam"
    else
        label="$(( (account[3] - account[2]) / 86400 )) hari"
    fi
    ssh_row 'Masa aktif' "$label"
    value=$(ssh_expiry "${account[3]}") || value='—'
    ssh_row Kedaluwarsa "$value"
    value='Aktif'
    if (( account[3] <= $(date +%s) )); then value='Expired'
    elif (( account[6] )); then value='Terkunci manual'
    elif (( account[7] > $(date +%s) )); then value='Terkunci otomatis'; fi
    ssh_row Status "$value"
    if [[ -n "$telegram" ]]; then ssh_row Telegram "$telegram"; fi
    printf '  Limit IP / sesi belum diterapkan\n'
}

ssh_send_account() {
    local name="$1" secret="$2" title="$3" raw rc=0
    raw=$(ssh_detail_lines "$name" "$secret" '') || { printf 'Gagal — kirim ulang dari List Member'; return; }
    telegram_send_message "$title"$'\n'"$raw" || rc=$?
    case "$rc" in
        0) printf '✓ Terkirim' ;;
        2) printf 'Belum dikonfigurasi' ;;
        *) printf 'Gagal — kirim ulang dari List Member' ;;
    esac
}

ssh_result() {
    local name="$1" title="$2" secret delivery
    secret=$(ssh_backend password "$name" 2>/dev/null) || secret='Tidak tersedia'
    if [[ "$secret" == 'Tidak tersedia' ]]; then
        delivery='Password tidak tersedia; tidak dikirim'
    else
        delivery=$(ssh_send_account "$name" "$secret" "$title")
    fi
    ssh_page "$title"
    ssh_detail_lines "$name" "$secret" "$delivery" || printf '  Detail akun tidak dapat dibaca.\n'
    wait_submenu_navigation "$ssh_width"
}

ssh_create_wizard() {
    local kind="$1" title='Create' username= password= ip= duration= step=1 rc=0 n output error= suffix= max=3650
    local ssh_width ssh_input LC_ALL=C
    if [[ "$kind" == trial ]]; then title='Trial'; step=3; suffix=h; max=720; fi
    while true; do
        ssh_page "$title"
        if [[ "$kind" == member ]]; then printf '\n'; fi
        if [[ -n "$error" ]]; then
            printf '  %s\n' "$error"
            if [[ "$kind" == member ]]; then printf '\n'; fi
            error=
        fi
        rc=0
        case "$step" in
            1)
                printf '  Gunakan 4–32 huruf kecil atau angka.\n\n'
                if [[ -n "$username" ]]; then ssh_row Username "$username"; printf '\n'; fi
                ssh_create_read 'Username' || rc=$? ;;
            2)
                printf '%s\n\n' '  Huruf kecil/angka (1–64). \x dan \z = literal.'
                if [[ -n "$password" ]]; then
                    ssh_row 'Password lama' "$password"
                    printf '\n  Tekan Enter untuk mempertahankan.\n\n'
                fi
                ssh_create_read 'Password' || rc=$? ;;
            3)
                if [[ "$kind" == member ]]; then
                    printf '  Rentang 0–99. 0 = Unlimited.\n\n'
                    if [[ -n "$ip" ]]; then ssh_row 'Limit IP' "${ip/#0/Unlimited}"; printf '\n'; fi
                    ssh_create_read 'Limit IP' || rc=$?
                else
                    [[ -z "$ip" ]] || ssh_row 'Limit IP' "${ip/#0/Unlimited}"
                    ssh_read 'Limit IP (0–99, 0 = Unlimited)' || rc=$?
                fi ;;
            4)
                if [[ "$kind" == member ]]; then
                    printf '  Contoh: 7. Rentang: 1–3650 hari.\n\n'
                    if [[ -n "$duration" ]]; then ssh_row 'Masa aktif' "$duration hari"; printf '\n'; fi
                    ssh_create_read 'Masa aktif dalam hari' || rc=$?
                else
                    [[ -z "$duration" ]] || ssh_row 'Masa aktif' "$duration$suffix"
                    ssh_read "Masa aktif (contoh 1$suffix, maksimum $max$suffix)" || rc=$?
                fi ;;
            5)
                ssh_row Username "$username"; printf '\n'
                ssh_row 'Limit IP' "${ip/#0/Unlimited}"; printf '\n'
                ssh_row 'Masa aktif' "$duration hari"; printf '\n'
                ssh_create_read 'Konfirmasi' 1 || rc=$? ;;
        esac
        if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
        if (( rc == 1 )); then
            if (( step == 1 )) || [[ "$kind" == trial && "$step" == 3 ]]; then return 0; fi
            step=$((step - 1))
            continue
        fi
        case "$step" in
            1)
                n=${ssh_input:-$username}
                if [[ ! "$n" =~ ^[a-z0-9]{4,32}$ ]]; then error='Username tidak valid.'; continue; fi
                if ! output=$(ssh_backend available "$n" 2>&1); then error=$output; continue; fi
                username=$n ;;
            2)
                if [[ -n "$ssh_input" || -z "$password" ]]; then
                    if ! n=$(ssh_decode_password "$ssh_input"); then error='Password tidak valid.'; continue; fi
                    password=$n
                fi ;;
            3)
                if ! n=$(ssh_limit_value "${ssh_input:-$ip}"); then error='Limit IP harus bilangan bulat 0–99.'; continue; fi
                ip=$n ;;
            4)
                if [[ -z "$ssh_input" && -n "$duration" ]]; then ssh_input=$duration$suffix; fi
                if ! n=$(ssh_duration_value "$ssh_input" "$suffix" "$max"); then
                    if [[ "$kind" == member ]]; then error='Masukkan angka 1–3650 tanpa akhiran.'
                    else error="Masa aktif harus 1$suffix–$max$suffix."; fi
                    continue
                fi
                duration=$n
                if [[ "$kind" == trial ]]; then
                    if output=$(ssh_backend trial "$ip" "$duration" 2>&1); then
                        ssh_result "$output" '✓ SSH TRIAL CREATED'; return $?
                    fi
                    error=$output; continue
                fi ;;
            5)
                if [[ ${ssh_input,,} != y ]]; then error='Pilih y, z, atau x.'; continue; fi
                if output=$(printf '%s\n' "$password" | ssh_backend create "$username" "$ip" "$duration" 2>&1); then
                    password= ssh_input=
                    ssh_result "$output" '✓ SSH ACCOUNT CREATED'; return $?
                fi
                error=$output
                if [[ "$error" == *'sudah dipakai'* ]]; then step=1; fi
                continue ;;
        esac
        step=$((step + 1))
    done
}

ssh_member_detail() {
    local name="$1" ssh_width ssh_input rc secret= delivery=
    while true; do
        ssh_page 'Detail akun SSH'
        ssh_detail_lines "$name" "$secret" "$delivery" || printf '  Detail akun tidak dapat dibaca.\n'
        draw_menu_item 1 'Lihat Password'
        draw_menu_item 2 'Kirim Ulang ke Telegram'
        rc=0; ssh_read 'Pilih' || rc=$?
        if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
        if (( rc == 1 )); then return 0; fi
        case "$ssh_input" in
            1) secret=$(ssh_backend password "$name" 2>/dev/null) || secret='Tidak tersedia' ;;
            2)
                local saved
                if saved=$(ssh_backend password "$name" 2>/dev/null); then
                    delivery=$(ssh_send_account "$name" "$saved" 'Detail akun SSH Nathaya')
                else
                    delivery='Password tidak tersedia; tidak dikirim'
                fi ;;
        esac
    done
}

# Resolve against exactly the snapshot displayed on the current page.
ssh_select_account() {
    local choice="$1" number= name index=0
    shift
    if [[ "$choice" == @* ]]; then
        choice=${choice#@}
    elif [[ "$choice" =~ ^[0-9]+$ ]]; then
        # Strip leading zeros without evaluating untrusted input as arithmetic.
        number=${choice#"${choice%%[!0]*}"}
        for name in "$@"; do
            index=$((index + 1))
            if [[ "$number" == "$index" ]]; then printf '%s\n' "$name"; return 0; fi
        done
    fi
    for name in "$@"; do
        if [[ "$choice" == "$name" ]]; then printf '%s\n' "$name"; return 0; fi
    done
    return 1
}

ssh_account_menu() {
    local operation="$1" label="$2" ssh_width ssh_input rc names name output index message=
    local -a accounts=()
    while true; do
        ssh_page "$label"
        printf '\n'
        if [[ -n "$message" ]]; then printf '  %s\n\n' "$message"; fi
        accounts=()
        if names=$(ssh_backend list 2>/dev/null); then
            if [[ -n "$names" ]]; then
                mapfile -t accounts <<< "$names"
                for index in "${!accounts[@]}"; do
                    draw_menu_item "$((index + 1))" "${accounts[index]}"
                done
            else
                printf '  Belum ada akun Nathaya.\n'
            fi
        else
            printf '  Data akun tidak dapat dibaca.\n'
        fi
        printf '\n'
        rc=0; ssh_read 'Nomor atau username' 'Pilih nomor atau username. Gunakan @1234 untuk username numerik.' || rc=$?
        if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
        if (( rc == 1 )); then return 0; fi
        if ! name=$(ssh_select_account "$ssh_input" "${accounts[@]}"); then
            message='Nomor atau username tidak ditemukan.'
            continue
        fi
        if ! output=$(ssh_backend detail "$name" 2>&1); then message=$output; continue; fi
        if [[ "$operation" == list ]]; then
            ssh_member_detail "$name" || return $?
            message=
            continue
        fi
        while true; do
            ssh_page "Konfirmasi $label"
            ssh_row Username "$name"
            draw_menu_item y 'Konfirmasi'
            rc=0; ssh_read 'Pilih' || rc=$?
            if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
            if (( rc == 1 )); then break; fi
            if [[ ${ssh_input,,} != y ]]; then continue; fi
            if output=$(ssh_backend "$operation" "$name" 2>&1); then
                if [[ "$operation" == lock ]]; then output='Akun terkunci; sesi akun dihentikan oleh layanan.'
                else output='Akses akun dipulihkan.'; fi
            fi
            ssh_page "Hasil $label"
            ssh_row Username "$name"
            printf '  %s\n' "$output"
            wait_submenu_navigation "$ssh_width"
            return $?
        done
    done
}

show_ssh_menu() {
    # Jangan jejak nilai input atau payload kredensial jika Bash dijalankan dengan -x.
    set +x
    local ssh_width ssh_input rc index
    local -a labels=(Create Delete Renew Trial 'Check User Login' 'List Member' 'List User Expired' Lock Unlock 'Limit IP')
    while true; do
        ssh_page 'MANAJEMEN SSH'
        for index in "${!labels[@]}"; do
            case "$index" in
                1|2|4|6|9) draw_menu_item "$((index + 1))" "${labels[index]} — Belum tersedia" ;;
                *) draw_menu_item "$((index + 1))" "${labels[index]}" ;;
            esac
        done
        rc=0; ssh_read 'Pilih menu SSH' || rc=$?
        if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
        if (( rc == 1 )); then return 0; fi
        case "$ssh_input" in
            2|3|5|7|10)
                ssh_page "${labels[ssh_input - 1]}"
                printf '  Belum tersedia\n'
                wait_submenu_navigation "$ssh_width" || return $? ;;
            1|4|6|8|9)
                if ! ssh_ready; then
                    ssh_page "${labels[ssh_input - 1]}"
                    printf '  Modul Dropbear belum aktif. Gunakan installer --enable-ssh pada VPS uji.\n'
                    wait_submenu_navigation "$ssh_width" || return $?
                    continue
                fi
                case "$ssh_input" in
                    1) ssh_create_wizard member || return $? ;;
                    4) ssh_create_wizard trial || return $? ;;
                    6) ssh_account_menu list 'List Member' || return $? ;;
                    8) ssh_account_menu lock Lock || return $? ;;
                    9) ssh_account_menu unlock Unlock || return $? ;;
                esac ;;
        esac
    done
}
