#!/usr/bin/env bash

SCRIPT_DIR="/opt/nathaya/modules/ssh"
source "$SCRIPT_DIR/account-db.sh"
source "/opt/nathaya/modules/common/ui.sh"

create_ssh_account() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Jalankan sebagai root."
        return 1
    fi

    local old_set
    old_set="$(set +o)"
    set -Eeuo pipefail

    local C_RESET=$'\033[0m'
    local C_CYAN=$'\033[36m'
    local C_GREEN=$'\033[32m'
    local C_YELLOW=$'\033[33m'
    local C_WHITE=$'\033[97m'
    local C_RED=$'\033[31m'
    local LINE="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    clear
    ssh_db_init

    local username="" password="" limit_ip="" days=""
    local created="" expiry="" linux_expiry=""
    local domain="" public_ip=""
    local isp="Tidak diketahui" city="Tidak diketahui"
    local next_action=""

    domain="$(sed -n 's/^DOMAIN="\([^"]*\)"/\1/p' \
        /etc/nathaya-tunnel/config.conf | head -1)"
    public_ip="$(curl -4 -fsS --max-time 5 \
        https://api.ipify.org 2>/dev/null || true)"

    [[ -n "$public_ip" ]] || public_ip="Tidak diketahui"
    [[ -n "$domain" ]] || domain="$public_ip"

    local width
    width="$(get_width)"
    
    draw_nathaya_header "$width"
    draw_section_title "CREATE SSH ACCOUNT" "$width"
    printf '\n'
    printf '%bTekan Ctrl+C untuk membatalkan pembuatan akun.%b\n\n' \
        "$GREEN" "$RESET"

    while true; do
        read -r -p "Username          : " username || {
            eval "$old_set"
            return 1
        }

        if [[ ! "$username" =~ ^[a-z0-9]{4,32}$ ]]; then
            printf '%bUsername: huruf kecil dan angka, 4-32 karakter.%b\n' \
                "$C_RED" "$C_RESET"
            continue
        fi

        if ssh_username_exists "$username" ||
           ssh_db_has_username "$username"; then
            printf '%bUsername sudah digunakan.%b\n' \
                "$C_RED" "$C_RESET"
            continue
        fi
        break
    done

    while true; do
        read -r -p "Password          : " password || {
            printf '\n'
            eval "$old_set"
            return 1
        }
        printf '\n'

        if [[ ! "$password" =~ ^[a-z0-9]+$ ]]; then
            printf '%bPassword hanya boleh huruf kecil dan angka.%b\n' \
                "$C_RED" "$C_RESET"
            continue
        fi
        break
    done

    while true; do
        read -r -p "Limit IP          : " limit_ip || {
            unset password
            eval "$old_set"
            return 1
        }

        if [[ "$limit_ip" =~ ^[1-9][0-9]*$ ]] &&
           (( limit_ip <= 100 )); then
            break
        fi
        printf '%bLimit IP harus angka 1-100.%b\n' "$C_RED" "$C_RESET"
    done

    while true; do
        read -r -p "Masa aktif (hari) : " days || {
            unset password
            eval "$old_set"
            return 1
        }

        if [[ "$days" =~ ^[1-9][0-9]*$ ]] &&
           (( days <= 3650 )); then
            break
        fi
        printf '%bMasa aktif harus angka 1-3650.%b\n' "$C_RED" "$C_RESET"
    done

    created="$(date +%F)"
    expiry="$(date -d "+${days} days" +%F)"
    linux_expiry="$(date -d "${expiry} +1 day" +%F)"

    if ! useradd -m -s /bin/bash "$username"; then
        printf '%bGagal membuat akun Linux.%b\n' "$C_RED" "$C_RESET"
        unset password
        eval "$old_set"
        return 1
    fi

    if ! printf '%s:%s\n' "$username" "$password" | chpasswd; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal mengatur password.%b\n' "$C_RED" "$C_RESET"
        unset password
        eval "$old_set"
        return 1
    fi

    if ! chage -E "$linux_expiry" "$username"; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal mengatur masa aktif.%b\n' "$C_RED" "$C_RESET"
        unset password
        eval "$old_set"
        return 1
    fi

    if ! ssh_db_add_account "$username" "$created" "$expiry" "$limit_ip"; then
        userdel -r "$username" 2>/dev/null || true
        printf '%bGagal menyimpan database akun.%b\n' "$C_RED" "$C_RESET"
        unset password
        eval "$old_set"
        return 1
    fi

    printf '\n'
    draw_nathaya_header "$width"
    draw_section_title "SSH ACCOUNT CREATED" "$width" "$GREEN"
    printf '\n'

    printf '%bSERVER INFORMATION%b\n' "$C_CYAN" "$C_RESET"
    printf '%b%s%b\n' "$C_CYAN" "$LINE" "$C_RESET"
    printf '%bHostname  :%b %s\n' "$C_WHITE" "$C_RESET" "$domain"
    printf '%bIP Address:%b %s\n' "$C_WHITE" "$C_RESET" "$public_ip"
    printf '%bISP       :%b %s\n' "$C_WHITE" "$C_RESET" "$isp"
    printf '%bCity      :%b %s\n' "$C_WHITE" "$C_RESET" "$city"

    printf '\n%bACCOUNT INFORMATION%b\n' "$C_CYAN" "$C_RESET"
    printf '%b%s%b\n' "$C_CYAN" "$LINE" "$C_RESET"
    printf '%bUsername  :%b %s\n' "$C_WHITE" "$C_RESET" "$username"
    printf '%bPassword  :%b %s\n' "$C_WHITE" "$C_RESET" "$password"
    printf '%bExpired   :%b %s\n' "$C_WHITE" "$C_RESET" "$expiry"
    printf '%bLimit IP  :%b %s\n' "$C_WHITE" "$C_RESET" "$limit_ip"

    printf '\n%bCONNECTION INFORMATION%b\n' "$C_CYAN" "$C_RESET"
    printf '%b%s%b\n' "$C_CYAN" "$LINE" "$C_RESET"
    printf 'SSH Ports : 22, 2222, 2223\n'
    printf 'UDP       : Belum dikonfigurasi\n'

    printf '\n%bPAYLOAD HTTP%b\n' "$C_CYAN" "$C_RESET"
    printf '%b%s%b\n' "$C_CYAN" "$LINE" "$C_RESET"
    printf 'Belum tersedia - WebSocket belum diaktifkan.\n'

    printf '\n%bCATATAN%b\n' "$C_YELLOW" "$C_RESET"
    printf 'Limit IP tersimpan, tetapi enforcement monitor belum aktif.\n'
    printf 'Akun Linux telah dibuat dan tanggal kedaluwarsa diterapkan.\n'

    printf '\n%b%s%b\n' "$C_CYAN" "$LINE" "$C_RESET"
    printf '%bNathaya Tunnel | Version 1.0.0%b\n' "$C_CYAN" "$C_RESET"
    printf 'Ketik "z" untuk kembali ke menu SSH.\n'
    printf 'Ketik "x" untuk keluar.\n'
    printf '%b%s%b\n\n' "$C_CYAN" "$LINE" "$C_RESET"

    # Notifikasi Telegram: label seragam, nilai monospace.
    if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
        source /opt/nathaya/modules/common/telegram.sh

        telegram_message="&#128640; <b>NATHAYA TUNNEL</b>
&#128994; <b>SSH ACCOUNT CREATED</b>

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
<code>UDP     :</code> <code>Belum dikonfigurasi</code>

━━━━━━━━━━━━━━━━━━━━
<b>PAYLOAD HTTP</b>
━━━━━━━━━━━━━━━━━━━━
<code>Belum tersedia - WebSocket belum diaktifkan.</code>

&#9888;&#65039; <b>CATATAN</b>
Limit IP tersimpan, tetapi monitor belum aktif.
Akun Linux berhasil dibuat.

━━━━━━━━━━━━━━━━━━━━
<i>Nathaya Tunnel | Version 1.0.0</i>"

        if telegram_send_message "$telegram_message"; then
            printf '%bNotifikasi Telegram terkirim.%b\n' "$C_GREEN" "$C_RESET"
        else
            printf '%bNotifikasi Telegram gagal dikirim; akun tetap aktif.%b\n' "$C_YELLOW" "$C_RESET"
        fi
    fi

    unset password

    while true; do
        read -r -p "Pilihan: " next_action || {
            eval "$old_set"
            return 0
        }

      case "${next_action,,}" in
          z)
              eval "$old_set"
              return 0
              ;;
          x|exit|keluar)
              eval "$old_set"
              exit 0
              ;;
          *)
              printf '%bKetik "z" atau "x".%b\n' \
                  "$C_YELLOW" "$C_RESET"
              ;;
      esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    create_ssh_account
fi
