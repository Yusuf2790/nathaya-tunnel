#!/usr/bin/env bash

# shellcheck source=../common/telegram.sh
source "$NATHAYA_BASE/modules/common/telegram.sh"

ssh_page() {
    clear_screen
    ssh_width=$(get_width)
    draw_nathaya_header "$ssh_width"
    draw_section_title "$1" "$ssh_width" "${2:-$CYAN}"
    printf '\n'
}

ssh_row() { printf '  %-17s : %s\n' "$1" "$2"; }
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

# Only the form/confirmation owns SIGINT. Do not run this function in a subshell.
ssh_cancel_scope() {
    local saved_int ssh_interrupted=0 rc=0
    saved_int=$(trap -p INT)
    trap 'ssh_interrupted=1' INT
    "$@" || rc=$?
    if [[ -n "$saved_int" ]]; then eval "$saved_int"; else trap - INT; fi
    if (( ssh_interrupted )); then return 2; fi
    return "$rc"
}

ssh_prompt() {
    local prompt="$1" rc=0
    if (( ${ssh_interrupted:-0} )); then return 2; fi
    if [[ -t 0 && -v ssh_interrupted ]]; then
        printf '%s' "$prompt"
        # A SIGINT near the start of read may leave it waiting for a newline.
        # Bound each wait so cancellation is noticed without another keystroke.
        while (( ! ssh_interrupted )); do
            rc=0
            IFS= read -r -t 0.25 ssh_input || rc=$?
            if (( rc <= 128 )); then break; fi
        done
    elif [[ -t 0 ]]; then
        IFS= read -r -p "$prompt" ssh_input || rc=$?
    else
        printf '%s' "$prompt"
        IFS= read -r ssh_input || rc=$?
        printf '\n'
    fi
    if (( ${ssh_interrupted:-0} )); then return 2; fi
    if (( rc )); then return "$DASHBOARD_EXIT"; fi
    return 0
}

ssh_confirm() {
    local action="$1" question="$2"
    shift 2
    ssh_page "CONFIRM $action" "$ORANGE"
    while (( $# )); do ssh_row "$1" "$2"; shift 2; done
    printf '\n'
    while true; do
        ssh_prompt "  $question [y/n]: " || return $?
        case "${ssh_input,,}" in
            y) return 0 ;;
            n) return 1 ;;
            *) printf '  Masukkan y atau n.\n' ;;
        esac
    done
}

ssh_limit_value() {
    local LC_ALL=C
    [[ "$1" =~ ^[0-9]{1,2}$ ]] || return 1
    printf '%d\n' "$((10#$1))"
}

ssh_duration_value() {
    local LC_ALL=C suffix="$2" maximum="$3"
    [[ "$1" =~ ^([0-9]{1,5})$suffix$ ]] || return 1
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

ssh_trial_duration() {
    local unit="${1: -1}" maximum
    case "$unit" in m) maximum=43200 ;; h) maximum=720 ;; *) return 1 ;; esac
    local quantity
    quantity=$(ssh_duration_value "$1" "$unit" "$maximum") || return 1
    printf '%s%s\n' "$quantity" "$unit"
}

ssh_duration_label() {
    local kind="$1" seconds="$2"
    if [[ "$kind" != trial ]]; then printf '%s hari\n' "$(( seconds / 86400 ))"
    elif (( seconds % 3600 == 0 )); then printf '%s jam\n' "$(( seconds / 3600 ))"
    else printf '%s menit\n' "$(( seconds / 60 ))"; fi
}

ssh_expiry() {
    local zone=${NATHAYA_TZ:-} format="${2:-%d %b %Y, %H.%M %Z}"
    if [[ -n "$zone" && "$zone" != /* && "$zone" != *..* && -f "/usr/share/zoneinfo/$zone" ]]; then
        TZ="$zone" LC_ALL=C date -d "@$1" "+$format"
    else
        LC_ALL=C date -d "@$1" "+$format"
    fi
}

ssh_limit_label() {
    if [[ "$1" == 0 ]]; then printf 'Unlimited\n'; else printf '%s IP\n' "$1"; fi
}

ssh_account_status() {
    if (( $1 <= $4 )); then printf 'Expired\n'
    elif (( $2 || $3 > $4 )); then printf 'Locked\n'
    else printf 'Aktif\n'; fi
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
    ssh_row 'Limit IP' "$(ssh_limit_label "${account[4]}")"
    ssh_row 'Batas sesi' "${account[5]} koneksi aktif"
    label=$(ssh_duration_label "${account[1]}" "$(( account[3] - account[2] ))")
    ssh_row 'Masa aktif' "$label"
    value=$(ssh_expiry "${account[3]}") || value='—'
    ssh_row Kedaluwarsa "$value"
    ssh_row Status "$(ssh_account_status "${account[3]}" "${account[6]}" "${account[7]}" "$(date +%s)")"
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

ssh_create_form() {
    local kind="$1" n label previous prompt error
    local -a fields=(Username Password 'Limit IP' 'Masa aktif (hari)')
    if [[ "$kind" == trial ]]; then
        ssh_page 'TRIAL SSH'
        printf '  %bTekan Ctrl+C untuk membatalkan pembuatan akun trial.%b\n\n' "$GREEN" "$RESET"
        printf '  Limit IP 0–99; 0 = Unlimited.\n  30m = 30 menit; 1h = 1 jam.\n\n'
        fields=('Limit IP' 'Masa aktif trial')
    else
        ssh_page 'CREATE SSH ACCOUNT'
        printf '  %bTekan Ctrl+C untuk membatalkan pembuatan akun.%b\n\n' "$GREEN" "$RESET"
        printf '  Username 4–32; password 1–64.\n  Huruf kecil dan angka saja.\n  Limit IP 0–99; 0 = Unlimited.\n  Masa aktif 1–3650 hari (contoh 30).\n\n'
    fi
    for label in "${fields[@]}"; do
        case "$label" in
            Username) previous=$username ;;
            Password) previous=$password ;;
            'Limit IP') previous=$ip; [[ "$kind" != member ]] || printf '\n' ;;
            *) previous=$duration ;;
        esac
        printf -v prompt '  %-17s : ' "$label"
        if [[ -n "$previous" ]]; then prompt+="[$previous] "; fi
        while true; do
            ssh_prompt "$prompt" || return $?
            n=${ssh_input:-$previous}
            error=
            case "$label" in
                Username)
                    if [[ ! "$n" =~ ^[a-z0-9]{4,32}$ ]]; then error='Username tidak valid.'
                    elif error=$(ssh_backend available "$n" 2>&1); then username=$n; error=;
                    else error=${error:-Username tidak dapat diperiksa.}; fi ;;
                Password)
                    if n=$(ssh_decode_password "$n"); then password=$n; else error='Password tidak valid.'; fi ;;
                'Limit IP')
                    if n=$(ssh_limit_value "$n"); then ip=$n; else error='Limit IP harus bilangan bulat 0–99.'; fi ;;
                'Masa aktif (hari)')
                    if n=$(ssh_duration_value "$n" '' 3650); then duration=$n
                    else error='Masukkan angka 1–3650 tanpa akhiran, misalnya 30.'; fi ;;
                'Masa aktif trial')
                    if n=$(ssh_trial_duration "$n"); then duration=$n
                    else error='Gunakan 1–43200m atau 1–720h (contoh 30m atau 1h).'; fi ;;
            esac
            if (( ssh_interrupted )); then return 2; fi
            if [[ -z "$error" ]]; then break; fi
            printf '  %b%s%b\n' "$RED" "$error" "$RESET"
        done
    done
    if [[ "$kind" == trial ]]; then
        # Keep the unit the admin entered on the confirmation page.
        label='jam'; [[ "$duration" != *m ]] || label='menit'
        ssh_confirm TRIAL 'Buat akun trial ini?' 'Limit IP' "$(ssh_limit_label "$ip")" \
            'Masa aktif' "${duration%?} $label"
    else
        ssh_confirm CREATE 'Buat akun ini?' Username "$username" 'Limit IP' "$(ssh_limit_label "$ip")" \
            'Masa aktif' "$duration hari"
    fi
}

ssh_create_wizard() {
    local kind="$1" username= password= ip= duration= output title rc ssh_width ssh_input LC_ALL=C
    while true; do
        rc=0; ssh_cancel_scope ssh_create_form "$kind" || rc=$?
        case "$rc" in
            1) continue ;;  # n: go back with the form values intact.
            2) return 0 ;;  # Ctrl+C: return to the SSH menu.
            0) break ;;
            *) return "$rc" ;;
        esac
    done
    if [[ "$kind" == trial ]]; then
        title='✓ SSH TRIAL CREATED'
        rc=0; output=$(ssh_backend trial "$ip" "$duration" 2>&1) || rc=$?
    else
        title='✓ SSH ACCOUNT CREATED'
        rc=0; output=$(printf '%s\n' "$password" | ssh_backend create "$username" "$ip" "$duration" 2>&1) || rc=$?
    fi
    password= ssh_input=
    if (( rc == 0 )); then ssh_result "$output" "$title"; return $?; fi
    ssh_page 'Pembuatan akun gagal'
    printf '  %s\n' "${output:-Operasi tidak berhasil.}"
    wait_submenu_navigation "$ssh_width"
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

ssh_action_eligible() {
    local operation="$1" expires="$2" manual="$3" automated="$4" now="$5"
    case "$operation" in
        lock) (( expires > now && !manual )) ;;
        unlock) (( expires > now && manual && automated <= now )) ;;
        *) return 0 ;;
    esac
}

ssh_table_line() {
    printf '%b' "$CYAN"
    repeat_char '─' "$ssh_width"
    printf '%b\n' "$RESET"
}

ssh_account_table() {
    local start="$1" end="$2" i marker no_width=3 name_width=8 name room count
    count=${#accounts[@]}
    if (( ${#count} + 1 > no_width )); then no_width=$((${#count} + 1)); fi
    for name in "${accounts[@]}"; do
        if (( ${#name} > name_width )); then name_width=${#name}; fi
    done
    local fmt='%-*s  %-8s  %-7s  %s\n' wide=0
    ssh_table_line
    if (( no_width + name_width + 32 <= ssh_width )); then
        wide=1
        printf '%b%*s  %-*s  %-8s  %-7s  %s%b\n' "$CYAN" "$no_width" 'NO.' \
            "$name_width" USERNAME EXPIRED STATUS 'LIMIT IP' "$RESET"
    else
        printf '%b%*s  USERNAME\n  EXPIRED  | STATUS | LIMIT IP%b\n' "$CYAN" "$no_width" 'NO.' "$RESET"
    fi
    ssh_table_line
    room=$((ssh_width - no_width - 2))
    for ((i=start; i<end; i++)); do
        marker="$((i + 1))."
        printf '%*s%b%s%b  ' "$((no_width - ${#marker}))" '' "$ORANGE" "$marker" "$CYAN"
        name=${accounts[i]}
        if (( wide )); then
            printf "$fmt" "$name_width" "$name" "${dates[i]}" "${statuses[i]}" "${limits[i]}"
        else
            printf '%s\n' "${name:0:room}"
            if (( ${#name} > room )); then printf '%*s  %s\n' "$no_width" '' "${name:room}"; fi
            printf '  %s | %s | %s\n' "${dates[i]}" "${statuses[i]}" "${limits[i]}"
        fi
        printf '%b' "$RESET"
    done
    ssh_table_line
}

# Load and confirm against the same account identity shown in the selected row.
ssh_mutation_confirm() {
    local action="$1" name="$2" identity="$3" raw expires ip status proposed rc=0
    local -a args=("$name" "$identity")
    local view=action-view question='Hapus akun ini?'
    if [[ "$action" == expired ]]; then
        view=expired-view; question='Hapus akun expired ini?'
    fi
    if [[ "$action" == renew ]]; then
        if [[ -z "$days" ]]; then
            ssh_page 'RENEW SSH'
            ssh_row Username "$name"
            printf '\n  %bTekan Ctrl+C untuk membatalkan perpanjangan akun.%b\n\n' "$GREEN" "$RESET"
            while true; do
                ssh_prompt '  Tambah durasi (hari): ' || return $?
                if days=$(ssh_duration_value "$ssh_input" '' 3650); then break; fi
                printf '  Masukkan angka 1–3650, misalnya 30.\n'
            done
        fi
        args+=("$days")
    fi
    raw=$(ssh_backend "$view" "${args[@]}" 2>&1) || rc=$?
    if (( rc )); then
        mutation_message=$raw
        return 1
    fi
    IFS=$'\t' read -r expires ip status action_token proposed <<< "$raw"
    if [[ ! "$expires" =~ ^[0-9]+$ || ! "$proposed" =~ ^[0-9]+$ || -z "$action_token" ]]; then
        mutation_message='Data konfirmasi tidak dapat dibaca.'
        return 1
    fi
    if [[ "$action" == delete || "$action" == expired ]]; then
        ssh_confirm DELETE "$question" Username "$name" \
            Expired "$(ssh_expiry "$expires" || printf '—')" Status "$status" 'Limit IP' "$(ssh_limit_label "$ip")"
    else
        local new_date
        new_date=$(ssh_expiry "$proposed") || new_date='—'
        if [[ "$status" == Expired ]]; then new_date+=' (perkiraan)'; fi
        ssh_confirm RENEW 'Perpanjang akun ini?' Username "$name" \
            'Expired lama' "$(ssh_expiry "$expires" || printf '—')" 'Tambah durasi' "$days hari" 'Expired baru' "$new_date"
    fi
}

ssh_account_mutation() {
    local action="$1" name="$2" identity="$3" days= action_token= mutation_message= rc output saved status
    while true; do
        rc=0; ssh_cancel_scope ssh_mutation_confirm "$action" "$name" "$identity" || rc=$?
        (( rc == 0 )) || { message=$mutation_message; return "$rc"; }
        rc=0
        if [[ "$action" == delete ]]; then output=$(ssh_backend delete "$name" "$identity" "$action_token" 2>&1) || rc=$?
        else output=$(ssh_backend renew "$name" "$identity" "$action_token" "$days" 2>&1) || rc=$?; fi
        case "$rc" in
            3) continue ;;  # Mutable state changed: redraw and require a fresh y.
            4) message=$output; return 1 ;;  # Replaced incarnation: do not retarget it.
            *) break ;;
        esac
    done
    ssh_page "HASIL ${action^^}"
    ssh_row Username "$name"
    if (( rc != 0 )); then
        ssh_row Hasil "${output:-Operasi tidak berhasil.}"
    elif [[ "$action" == delete ]]; then
        ssh_row Hasil 'Akun dihapus; akses dicabut.'
    else
        IFS=$'\t' read -r saved status <<< "$output"
        ssh_row 'Expired baru' "$(ssh_expiry "$saved" || printf '—')"
        ssh_row Status "$status"
    fi
    wait_submenu_navigation "$ssh_width"
}

ssh_account_menu() {
    local operation="$1" label="$2" ssh_width ssh_input rc data name output message= now identity kind_index query split i
    local stored_kind created expires ip sessions manual automated status active locked expired
    local -a accounts=() dates=() limits=() statuses=() identities=() account=()
    while true; do
        ssh_page "$label"
        if [[ -n "$message" ]]; then printf '  %s\n\n' "$message"; message=; fi
        accounts=(); dates=(); limits=(); statuses=(); identities=()
        active=0 locked=0 expired=0
        now=$(date +%s)
        query=table
        if [[ "$operation" == delete || "$operation" == renew ]]; then query=action-table; fi
        if data=$(ssh_backend "$query" 2>/dev/null); then
            split=0
            local -a groups=(all)
            if [[ "$operation" == renew ]]; then groups=(current expired); fi
            for kind_index in "${groups[@]}"; do
                if [[ "$kind_index" == expired ]]; then split=${#accounts[@]}; fi
                while IFS=$'\t' read -r name stored_kind created expires ip sessions manual automated identity; do
                    [[ -n "$name" ]] || continue
                    if [[ "$kind_index" == current ]] && (( expires <= now )); then continue; fi
                    if [[ "$kind_index" == expired ]] && (( expires > now )); then continue; fi
                    if ! ssh_action_eligible "$operation" "$expires" "$manual" "$automated" "$now"; then continue; fi
                    status=$(ssh_account_status "$expires" "$manual" "$automated" "$now")
                    accounts+=("$name"); identities+=("$identity")
                    dates+=("$(ssh_expiry "$expires" '%d/%m/%y' || printf '—')")
                    limits+=("$(ssh_limit_label "$ip")")
                    statuses+=("$status")
                    case "$status" in
                        Aktif) active=$((active + 1)) ;;
                        Locked) locked=$((locked + 1)) ;;
                        Expired) expired=$((expired + 1)) ;;
                    esac
                done <<< "$data"
            done
            if [[ "$operation" == renew ]]; then
                printf '  %bDAFTAR AKUN SSH AKTIF%b\n' "$CYAN" "$RESET"
                if (( split )); then ssh_account_table 0 "$split"; else printf '  Tidak ada akun.\n'; fi
                printf '\n  %bDAFTAR AKUN SSH EXPIRED%b\n' "$CYAN" "$RESET"
                if (( split < ${#accounts[@]} )); then ssh_account_table "$split" "${#accounts[@]}"; else printf '  Tidak ada akun.\n'; fi
            elif (( ${#accounts[@]} )); then
                ssh_account_table 0 "${#accounts[@]}"
            else
                printf '  Tidak ada akun yang dapat ditampilkan.\n'
            fi
            printf '\n'
            if [[ "$operation" == list ]]; then
                ssh_row 'Total Member' "${#accounts[@]}"
                ssh_row Aktif "$active"
                ssh_row Locked "$locked"
                ssh_row Expired "$expired"
            else
                ssh_row 'Total akun' "${#accounts[@]}"
            fi
        else
            printf '  Data akun tidak dapat dibaca.\n'
        fi
        printf '\n'
        if (( ${#accounts[@]} )); then printf '  Nomor atau username; @1234 untuk username numerik.\n'; fi
        printf '  %bz.%b Kembali ke menu SSH\n  %bx.%b Keluar\n\n' "$GREEN" "$RESET" "$RED" "$RESET"
        ssh_prompt '  Pilihan: ' || return $?
        case "${ssh_input,,}" in
            z) return 0 ;;
            x) return "$DASHBOARD_EXIT" ;;
        esac
        if ! name=$(ssh_select_account "$ssh_input" "${accounts[@]}"); then
            message='Nomor atau username tidak ditemukan.'
            continue
        fi
        if [[ "$operation" == list ]]; then
            ssh_member_detail "$name" || return $?
            continue
        fi
        if [[ "$operation" == delete || "$operation" == renew ]]; then
            for i in "${!accounts[@]}"; do
                if [[ "${accounts[i]}" == "$name" ]]; then identity=${identities[i]}; break; fi
            done
            rc=0; ssh_account_mutation "$operation" "$name" "$identity" || rc=$?
            case "$rc" in 1) continue ;; 2) return 0 ;; *) return "$rc" ;; esac
        fi
        if ! output=$(ssh_backend detail "$name" 2>&1); then message=$output; continue; fi
        mapfile -t account <<< "$output"
        now=$(date +%s)
        if (( ${#account[@]} != 8 )) ||
           ! ssh_action_eligible "$operation" "${account[3]}" "${account[6]}" "${account[7]}" "$now"; then
            message='Akun tidak lagi memenuhi syarat. Pilih akun lain.'
            continue
        fi
        rc=0
        ssh_cancel_scope ssh_confirm "${operation^^}" 'Lanjutkan aksi ini?' Username "$name" \
            Expired "$(ssh_expiry "${account[3]}" || printf '—')" \
            'Limit IP' "$(ssh_limit_label "${account[4]}")" \
            Status "$(ssh_account_status "${account[3]}" "${account[6]}" "${account[7]}" "$now")" || rc=$?
        case "$rc" in
            1) continue ;;
            2) return 0 ;;
            0) ;;
            *) return "$rc" ;;
        esac
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
}

ssh_pick_expired() {
    local i
    printf '  Nomor atau username; @1234 untuk username numerik.\n'
    while true; do
        ssh_prompt '  Akun expired: ' || return $?
        if target=$(ssh_select_account "$ssh_input" "${accounts[@]}"); then break; fi
        printf '  Akun tidak ditemukan dalam daftar expired.\n'
    done
    for i in "${!accounts[@]}"; do
        if [[ "${accounts[i]}" == "$target" ]]; then
            target_identity=${identities[i]}
            break
        fi
    done
    ssh_mutation_confirm expired "$target" "$target_identity"
}

ssh_expired_mutation() {
    local choice="$1" fingerprint="$2" rc=0 output target= target_identity= action_token= mutation_message=
    if [[ "$choice" == d ]]; then
        ssh_cancel_scope ssh_pick_expired || rc=$?
    else
        ssh_cancel_scope ssh_confirm 'DELETE ALL EXPIRED' "Hapus semua ${#accounts[@]} akun expired ini?" \
            'Total akun expired' "${#accounts[@]}" || rc=$?
    fi
    if (( rc )); then
        if [[ -n "$mutation_message" ]]; then message=$mutation_message; fi
        return "$rc"
    fi
    if [[ "$choice" == d ]]; then
        if output=$(ssh_backend delete-expired "$target" "$target_identity" "$action_token" 2>&1); then
            message="Akun $target berhasil dihapus."
        else
            message=${output:-Penghapusan akun expired gagal.}
        fi
    elif output=$(ssh_backend delete-all-expired "$fingerprint" 2>&1); then
        message="$output akun expired berhasil dihapus."
    else
        message=${output:-Penghapusan semua akun expired gagal.}
    fi
    return 0
}

ssh_expired_menu() {
    local ssh_width ssh_input data snapshot expected_count fingerprint message= rc ready
    local name kind created expires ip sessions manual automated identity
    local -a accounts=() dates=() limits=() statuses=() identities=()
    while true; do
        ssh_page 'LIST USER EXPIRED'
        if [[ -n "$message" ]]; then printf '  %s\n\n' "$message"; message=; fi
        accounts=(); dates=(); limits=(); statuses=(); identities=(); ready=0
        if data=$(ssh_backend expired-table 2>&1); then
            snapshot=${data%%$'\n'*}
            IFS=$'\t' read -r expected_count fingerprint <<< "$snapshot"
            if [[ "$data" == *$'\n'* ]]; then
                while IFS=$'\t' read -r name kind created expires ip sessions manual automated identity; do
                    [[ -n "$name" && -n "$identity" ]] || continue
                    accounts+=("$name"); identities+=("$identity")
                    dates+=("$(ssh_expiry "$expires" '%d/%m/%y' || printf '—')")
                    limits+=("$(ssh_limit_label "$ip")")
                    statuses+=(Expired)
                done <<< "${data#*$'\n'}"
            fi
            if [[ "$expected_count" != "${#accounts[@]}" || -z "$fingerprint" ]]; then
                printf '  Data akun SSH expired tidak lengkap. Daftar tidak dapat dihapus.\n'
            elif (( ${#accounts[@]} )); then
                ready=1
                ssh_account_table 0 "${#accounts[@]}"
                ssh_row 'Total akun expired' "${#accounts[@]}"
            else
                printf '  Tidak ada akun SSH expired\n'
            fi
        else
            printf '  Data akun SSH expired tidak dapat dibaca: %s\n' "${data:-backend gagal.}"
        fi
        printf '\n'
        if (( ready )); then
            printf '  %bd.%b Hapus satu akun expired\n  %ba.%b Hapus semua akun expired\n' "$ORANGE" "$RESET" "$ORANGE" "$RESET"
        fi
        printf '  %bz.%b Kembali ke menu SSH\n  %bx.%b Keluar\n\n' "$GREEN" "$RESET" "$RED" "$RESET"
        rc=0; ssh_cancel_scope ssh_prompt '  Pilihan: ' || rc=$?
        case "$rc" in 0) ;; 2) return 0 ;; *) return "$rc" ;; esac
        case "${ssh_input,,}" in
            z) return 0 ;;
            x) return "$DASHBOARD_EXIT" ;;
            d|a)
                if (( ready )); then
                    rc=0; ssh_expired_mutation "${ssh_input,,}" "$fingerprint" || rc=$?
                    case "$rc" in 0|1) continue ;; 2) return 0 ;; *) return "$rc" ;; esac
                fi ;;
        esac
        message='Pilihan tidak valid.'
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
                4|9) draw_menu_item "$((index + 1))" "${labels[index]} — Belum tersedia" ;;
                *) draw_menu_item "$((index + 1))" "${labels[index]}" ;;
            esac
        done
        rc=0; ssh_read 'Pilih menu SSH' || rc=$?
        if (( rc == DASHBOARD_EXIT )); then return "$rc"; fi
        if (( rc == 1 )); then return 0; fi
        case "$ssh_input" in
            5|10)
                ssh_page "${labels[ssh_input - 1]}"
                printf '  Belum tersedia\n'
                wait_submenu_navigation "$ssh_width" || return $? ;;
            1|2|3|4|6|7|8|9)
                if ! ssh_ready; then
                    ssh_page "${labels[ssh_input - 1]}"
                    printf '  Modul Dropbear belum aktif. Gunakan installer --enable-ssh pada VPS uji.\n'
                    wait_submenu_navigation "$ssh_width" || return $?
                    continue
                fi
                case "$ssh_input" in
                    1) ssh_create_wizard member || return $? ;;
                    2) ssh_account_menu delete 'DELETE SSH' || return $? ;;
                    3) ssh_account_menu renew 'RENEW SSH' || return $? ;;
                    4) ssh_create_wizard trial || return $? ;;
                    6) ssh_account_menu list 'List Member' || return $? ;;
                    7) ssh_expired_menu || return $? ;;
                    8) ssh_account_menu lock 'Lock SSH' || return $? ;;
                    9) ssh_account_menu unlock 'Unlock SSH' || return $? ;;
                esac ;;
        esac
    done
}
