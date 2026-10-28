#!/usr/bin/env bash

# NATHAYA_BASE diwarisi dari menu.sh.

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/ssh/account-db.sh"

create_trial_account() {
    if [[ $EUID -ne 0 ]]; then
        printf '%bERROR: Jalankan sebagai root.%b\n' "$RED" "$RESET"
        return 1
    fi

    local width username password limit_ip duration_input duration_seconds
    local created expiry expiry_epoch linux_expiry domain public_ip
    local isp="Tidak diketahui" city="Tidak diketahui"
    local attempt duration_value duration_unit
    local operations_lock=/opt/nathaya/data/ssh/operations.lock
    local operations_locked=0

    ssh_db_init

    while true; do
        clear
        width="$(get_width)"

        draw_nathaya_header "$width"
        draw_section_title "TRIAL SSH" "$width"
        printf '\n'

        read -r -p "Limit IP (1-100): " limit_ip || return 0

        if [[ "$limit_ip" =~ ^[1-9][0-9]*$ ]] &&
           (( limit_ip <= 100 )); then
            break
        fi

        printf '%bLimit IP harus 1-100.%b\n' "$RED" "$RESET"
        read -r -p "Tekan Enter untuk mengulang..." _
    done

    while true; do
        printf 'Contoh input:\n'
        printf '30m = 30 menit\n'
        printf '1h = 1 jam\n'
        read -r -p "Masa aktif trial: " duration_input || return 0

        if [[ "$duration_input" =~ ^([1-9][0-9]{0,5})([mMhH])$ ]]; then
            duration_value="${BASH_REMATCH[1]}"
            duration_unit="${BASH_REMATCH[2],,}"

            if [[ "$duration_unit" == "m" ]] &&
               (( duration_value <= 525600 )); then
                duration_seconds=$((duration_value * 60))
                break
            elif [[ "$duration_unit" == "h" ]] &&
                 (( duration_value <= 8760 )); then
                duration_seconds=$((duration_value * 3600))
                break
            fi
        fi

        printf '%bFormat tidak valid. Gunakan menit (contoh 30m) atau jam (contoh 1h). Maksimum 1 tahun.%b\n' "$RED" "$RESET"
    done

    # Serialisasi pembuatan trial dengan Delete/Auto-expire/Renew.
    exec 8>>"$operations_lock"
    if ! flock -x 8; then
        exec 8>&-
        printf '%bGagal memperoleh lock operasi akun.%b\\n' "$RED" "$RESET"
        return 1
    fi
    operations_locked=1

    # Username trial acak dan password tepat 6 karakter.
    username=""
    for ((attempt=1; attempt<=20; attempt++)); do
        username="trial$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"

        if [[ ${#username} -eq 13 ]] &&
           ! ssh_username_exists "$username" &&
           ! ssh_db_has_username "$username"; then
            break
        fi

        username=""
    done

    if [[ -z "$username" ]]; then
        printf '%bGagal membuat username trial unik.%b\n' "$RED" "$RESET"
        flock -u 8
        exec 8>&-
        return 1
    fi

    password="$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)"

    if [[ ${#password} -ne 6 ]]; then
        printf '%bGagal membuat password trial.%b\n' "$RED" "$RESET"
        flock -u 8
        exec 8>&-
        return 1
    fi

    created="$(date +%F)"
    expiry_epoch=$(( $(date +%s) + duration_seconds ))
    expiry="$(date -d "@${expiry_epoch}" '+%F %T')" || {
        printf '%bGagal menghitung waktu expiry trial.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    }
    linux_expiry="$(date -d "${expiry%% *} +1 day" +%F)" || {
        printf '%bGagal menghitung expiry Linux trial.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    }

    domain="$(sed -n 's/^DOMAIN="\([^"]*\)"/\1/p' \
        /etc/nathaya-tunnel/config.conf | head -1)"
    public_ip="$(curl -4 -fsS --max-time 5 \
        https://api.ipify.org 2>/dev/null || true)"

    [[ -n "$public_ip" ]] || public_ip="Tidak diketahui"
    [[ -n "$domain" ]] || domain="$public_ip"

    if ! useradd -m -s /bin/bash "$username"; then
        printf '%bGagal membuat akun Linux trial.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    fi

    if ! printf '%s:%s\n' "$username" "$password" | chpasswd; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal mengatur password trial.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    fi

    if ! chage -E "$linux_expiry" "$username"; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal mengatur masa aktif trial.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    fi

    if ! ssh_db_add_trial_account "$username" "$created" "$expiry" "$limit_ip"; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal menyimpan akun trial ke database.%b\n' "$RED" "$RESET"
        unset password
        flock -u 8
        exec 8>&-
        return 1
    fi

    # Record database dan user Linux sudah sinkron; lepas lock sebelum UI/Telegram.
    flock -u 8
    exec 8>&-

    clear
    width="$(get_width)"

    draw_nathaya_header "$width"
    draw_section_title "TRIAL SSH CREATED" "$width" "$GREEN"
    printf '\n'

    printf '%bSERVER INFORMATION%b\n' "$CYAN" "$RESET"
    printf '%b%s%b\n' "$CYAN" \
        "────────────────────────────────────────────────" "$RESET"
    printf 'Hostname  : %s\n' "$domain"
    printf 'IP Address: %s\n' "$public_ip"
    printf 'ISP       : %s\n' "$isp"
    printf 'City      : %s\n' "$city"

    printf '\n%bACCOUNT INFORMATION%b\n' "$CYAN" "$RESET"
    printf '%b%s%b\n' "$CYAN" \
        "────────────────────────────────────────────────" "$RESET"
    printf 'Username  : %s\n' "$username"
    printf 'Password  : %s\n' "$password"
    printf '%bExpired   : %s%b\n' "$YELLOW" "$expiry" "$RESET"
    printf 'Limit IP  : %s\n' "$limit_ip"

    printf '\n%bCONNECTION INFORMATION%b\n' "$CYAN" "$RESET"
    printf '%b%s%b\n' "$CYAN" \
        "────────────────────────────────────────────────" "$RESET"
    printf 'SSH Ports : 22, 2222, 2223\n'
    printf 'WebSocket : Belum diaktifkan\n'

    printf '\n%bCATATAN%b\n' "$YELLOW" "$RESET"
    printf 'Akun trial dibuat otomatis.\n'
    printf 'Penghapusan otomatis aktif setelah modul auto-expire diperbarui.\n'

    printf '\n'
    printf '\n%b%s%b\n' "$C_CYAN" "────────────────────────────────────────────────" "$C_RESET"
    printf '%bNathaya Tunnel | Version 1.0.0%b\n' "$C_CYAN" "$C_RESET"
    printf 'Ketik "z" untuk kembali ke menu SSH.\n'
    printf 'Ketik "x" untuk keluar.\n'
    printf '%b%s%b\n\n' "$C_CYAN" "────────────────────────────────────────────────" "$C_RESET"

    # Kirim notifikasi Telegram setelah akun trial berhasil dibuat.
    if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
        source /opt/nathaya/modules/common/telegram.sh

        telegram_message="&#128640; <b>NATHAYA TUNNEL</b>
&#128994; <b>TRIAL SSH CREATED</b>

━━━━━━━━━━━━━━━━━━━━
<b>SERVER INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
<code>ISP     :</code> <code>${isp}</code>
<code>CITY    :</code> <code>${city}</code>
<code>Host    :</code> <code>${domain}</code>
<code>IP      :</code> <code>${public_ip}</code>

━━━━━━━━━━━━━━━━━━━━
<b>ACCOUNT INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
<code>User    :</code> <code>${username}</code>
<code>Pass    :</code> <code>${password}</code>
<code>Expired :</code> <code>${expiry}</code>
<code>Limit IP:</code> <code>${limit_ip}</code>

━━━━━━━━━━━━━━━━━━━━
<b>CONNECTION</b>
━━━━━━━━━━━━━━━━━━━━
<code>SSH Port:</code> <code>22, 2222, 2223</code>
<code>WebSocket:</code> <code>Belum diaktifkan</code>

━━━━━━━━━━━━━━━━━━━━
<b>CATATAN</b>
Akun trial berhasil dibuat.
Penghapusan otomatis aktif setelah modul auto-expire diperbarui.

━━━━━━━━━━━━━━━━━━━━
<i>Nathaya Tunnel | Version 1.0.0</i>"

        if telegram_send_message "$telegram_message"; then
            printf '%bNotifikasi Telegram terkirim.%b\n' "$GREEN" "$RESET"
        else
            printf '%bNotifikasi Telegram gagal dikirim; akun tetap aktif.%b\n' "$YELLOW" "$RESET"
        fi
    fi

    unset password

    local action
    while true; do
        read -r -p "Pilihan: " action || return 0

        case "${action,,}" in
            z)
                return 0
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf '%bKetik z atau x.%b\n' "$YELLOW" "$RESET"
                ;;
        esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    create_trial_account
fi
