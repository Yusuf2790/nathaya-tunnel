#!/usr/bin/env bash

# NATHAYA_BASE diwarisi dari menu.sh.
source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/ssh/account-db.sh"

renew_ssh_account() {
    local width username created expiry limit_ip status lock_until account_type extra
    local choice days new_expiry linux_expiry confirm uid shell today base_expiry
    local current_record current_user current_created current_expiry current_limit
    local current_status current_lock current_type current_extra
    local domain public_ip
    local -a accounts=()

    ssh_db_init

    while true; do
        clear
        width="$(get_width)"
        today="$(date +%F)"
        accounts=()

        draw_nathaya_header "$width"
        draw_section_title "RENEW SSH" "$width"
        printf '\n'

        printf '%bDAFTAR AKUN SSH AKTIF%b\n' "$CYAN" "$RESET"
        printf '%b%s%b\n' "$CYAN" \
            "────────────────────────────────────────────────" "$RESET"
        printf '%b%-4s %-16s %-12s %-8s%b\n' \
            "$WHITE" "NO." "USERNAME" "EXPIRED" "LIMIT IP" "$RESET"
        printf '%b%s%b\n' "$CYAN" \
            "────────────────────────────────────────────────" "$RESET"

        local i=0
        while IFS='|' read -r username created expiry limit_ip status lock_until account_type extra; do
            [[ -n "${username:-}" ]] || continue
            [[ -z "${extra:-}" ]] || continue

            # Renew hanya tersedia untuk akun reguler pada skema 7 kolom.
            [[ "${account_type:-}" == "regular" ]] || continue
            ssh_valid_date "$expiry" || continue
            [[ "$status" == "active" || "$status" == "locked" ]] || continue
            id "$username" >/dev/null 2>&1 || continue
            [[ "$username" != "root" ]] || continue

            uid="$(id -u "$username" 2>/dev/null || echo 0)"
            shell="$(getent passwd "$username" | cut -d: -f7)"
            [[ "$uid" =~ ^[0-9]+$ ]] || continue
            (( uid >= 1000 )) || continue
            [[ "$shell" == "/bin/bash" ]] || continue

            ((i += 1))
            accounts+=("$username")
            printf '%b%-4s%b %-16s %-12s %-8s\n' \
                "$ORANGE" "${i}." "$RESET" "$username" "$expiry" "$limit_ip"
        done < "$NATHAYA_SSH_DB"

        printf '%b%s%b\n' "$CYAN" \
            "────────────────────────────────────────────────" "$RESET"
        printf 'Total akun reguler yang dapat diperpanjang: %d\n' "${#accounts[@]}"

        printf '\nMasukkan nomor urut atau username.\n'
        printf '%b z.%b Kembali ke menu SSH\n' "$ORANGE" "$RESET"
        printf '%b x.%b Exit\n\n' "$RED" "$RESET"

        read -r -p "Pilihan: " choice || return 0
        case "${choice,,}" in
            z) return 0 ;;
            x|exit|keluar) exit 0 ;;
        esac

        username=""
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            if (( choice >= 1 && choice <= ${#accounts[@]} )); then
                username="${accounts[$((choice - 1))]}"
            else
                printf '\nNomor urut tidak valid.\n'
                read -r -p "Tekan Enter untuk lanjut..." _
                continue
            fi
        else
            for item in "${accounts[@]}"; do
                if [[ "$item" == "$choice" ]]; then
                    username="$item"
                    break
                fi
            done
        fi

        if [[ -z "$username" ]]; then
            printf '\nAkun reguler tidak ditemukan atau tidak memenuhi syarat Renew.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        current_record="$(ssh_db_get_account "$username" 2>/dev/null)" || {
            printf '\nRecord akun tidak ditemukan.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        }
        IFS='|' read -r username created expiry limit_ip status lock_until account_type extra <<< "$current_record"

        if [[ -n "${extra:-}" || "$account_type" != "regular" ]] ||
           ! ssh_valid_date "$expiry" ||
           [[ "$status" != "active" && "$status" != "locked" ]] ||
           ! id "$username" >/dev/null 2>&1; then
            printf '\nAkun bukan reguler atau record tidak valid; Renew dibatalkan.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        clear
        draw_nathaya_header "$width"
        draw_section_title "RENEW SSH ACCOUNT" "$width"
        printf '\n'
        printf 'Username : %s\n' "$username"
        printf 'Type     : %s\n' "$account_type"
        printf 'Expired  : %s\n' "$expiry"
        printf 'Limit IP : %s\n\n' "$limit_ip"

        read -r -p "Masa perpanjangan (hari): " days || return 0
        if [[ ! "$days" =~ ^[1-9][0-9]*$ ]] || (( days > 3650 )); then
            printf '\nMasa perpanjangan harus 1-3650 hari.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        # Jika sudah expired, hitung dari hari ini; jika belum, dari expiry saat ini.
        base_expiry="$expiry"
        [[ "$base_expiry" > "$today" ]] || base_expiry="$today"
        new_expiry="$(date -d "$base_expiry + $days days" +%F)" || {
            printf '\nGagal menghitung tanggal kedaluwarsa.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        }
        linux_expiry="$(date -d "$new_expiry + 1 day" +%F)" || {
            printf '\nGagal menghitung tanggal Linux.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        }

        printf '\nTanggal kedaluwarsa baru: %s\n' "$new_expiry"
        read -r -p "Konfirmasi Renew? [y/n]: " confirm || return 0

        case "${confirm,,}" in
            y|yes)
                # Serialisasi dengan auto-expire dan delete.
                exec 8>>/opt/nathaya/data/ssh/operations.lock
                if ! flock -x 8; then
                    exec 8>&-
                    printf '\nGagal memperoleh lock operasi akun.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                current_record="$(ssh_db_get_account "$username" 2>/dev/null || true)"
                IFS='|' read -r current_user current_created current_expiry current_limit current_status current_lock current_type current_extra <<< "$current_record"
                if [[ -n "${current_extra:-}" ||
                      "$current_user" != "$username" ||
                      "$current_created" != "$created" ||
                      "$current_expiry" != "$expiry" ||
                      "$current_limit" != "$limit_ip" ||
                      "$current_status" != "$status" ||
                      "$current_lock" != "$lock_until" ||
                      "$current_type" != "regular" ||
                      "$current_type" != "$account_type" ]] ||
                   ! id "$username" >/dev/null 2>&1; then
                    flock -u 8
                    exec 8>&-
                    printf '\nData akun berubah atau akun tidak lagi valid. Renew dibatalkan.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                # Update Linux expiry lebih dulu. Jika database gagal, laporkan untuk rekonsiliasi.
                if ! chage -E "$linux_expiry" "$username"; then
                    flock -u 8
                    exec 8>&-
                    printf '\nGagal memperbarui masa aktif Linux.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                if ! ssh_db_update_expiry "$username" "$new_expiry"; then
                    flock -u 8
                    exec 8>&-
                    printf '\nDatabase gagal diperbarui setelah Linux expiry berubah. Periksa akun %s sebelum mencoba lagi.\n' "$username"
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                flock -u 8
                exec 8>&-

                printf '\n%bRenew SSH berhasil.%b\n' "$GREEN" "$RESET"
                printf 'Username      : %s\n' "$username"
                printf 'Expired lama  : %s\n' "$expiry"
                printf 'Expired baru  : %s\n' "$new_expiry"

                if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
                    source /opt/nathaya/modules/common/telegram.sh
                    domain="${DOMAIN:-id1.nathaya.web.id}"
                    public_ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || printf 'Tidak diketahui')"

                    telegram_message="&#128640; <b>NATHAYA TUNNEL</b>
&#9989; <b>SSH ACCOUNT RENEWED</b>

━━━━━━━━━━━━━━━━━━━━
<b>SERVER INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
<code>Host :</code> <code>${domain}</code>
<code>IP   :</code> <code>${public_ip}</code>

━━━━━━━━━━━━━━━━━━━━
<b>RENEW INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
<code>User      :</code> <code>${username}</code>
<code>Old Expiry:</code> <code>${expiry}</code>
<code>Duration  :</code> <code>${days} hari</code>
<code>New Expiry:</code> <code>${new_expiry}</code>

━━━━━━━━━━━━━━━━━━━━
&#9989; Masa aktif berhasil diperpanjang.
<i>Nathaya Tunnel | Version 1.0.0</i>"

                    if telegram_send_message "$telegram_message"; then
                        printf '%bNotifikasi Telegram terkirim.%b\n' "$GREEN" "$RESET"
                    else
                        printf '%bNotifikasi Telegram gagal; Renew tetap berhasil.%b\n' "$YELLOW" "$RESET"
                    fi
                fi
                ;;
            *)
                printf '\nRenew dibatalkan.\n'
                ;;
        esac

        read -r -p "Tekan Enter untuk kembali ke daftar..." _
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    renew_ssh_account
fi
