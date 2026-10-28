#!/usr/bin/env bash

# NATHAYA_BASE diwarisi dari menu.sh.
source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/ssh/account-db.sh"

NATHAYA_SSH_RECONCILE_LOG="/opt/nathaya/logs/ssh-reconcile.log"

ssh_reconcile_log() {
    local operation="$1" username="$2" phase="$3" detail="$4"
    mkdir -p /opt/nathaya/logs 2>/dev/null || true
    printf '%s operation=%s username=%s phase=%s detail=%s\n' \
        "$(date '+%F %T')" "$operation" "$username" "$phase" "$detail" \
        >> "$NATHAYA_SSH_RECONCILE_LOG" 2>/dev/null || true
    chmod 600 "$NATHAYA_SSH_RECONCILE_LOG" 2>/dev/null || true
}

delete_ssh_account() {
    local width
    local choice username created expiry limit_ip status lock_until account_type extra
    local confirm uid shell current_record
    local current_user current_created current_expiry current_limit current_status current_lock current_type current_extra
    local raw_line field_count current_fields
    local -a accounts=()
    local -a rows=()

    while true; do
        clear
        width="$(get_width)"
        accounts=()
        rows=()

        ssh_db_init

        draw_nathaya_header "$width"
        draw_section_title "DELETE SSH" "$width"
        printf '\n'

        if [[ ! -s "$NATHAYA_SSH_DB" ]]; then
            printf '%bBelum ada akun di database Nathaya.%b\n' \
                "$YELLOW" "$RESET" 2>/dev/null ||
                printf 'Belum ada akun di database Nathaya.\n'
        else
            printf '%bDAFTAR AKUN SSH%b\n' "$CYAN" "$RESET"
            printf '%b%s%b\n' "$CYAN" \
                "────────────────────────────────────────────────" "$RESET"
            printf '%b%-4s %-16s %-19s %-9s %-8s %-10s%b\n' \
                "$WHITE" "NO." "USERNAME" "EXPIRED" "TYPE" "LIMIT IP" "STATUS" "$RESET"
            printf '%b%s%b\n' "$CYAN" \
                "────────────────────────────────────────────────" "$RESET"

            local i=0
            while IFS= read -r raw_line; do
                [[ -n "${raw_line:-}" ]] || continue
                field_count="$(awk -F '|' '{print NF}' <<< "$raw_line")"
                IFS='|' read -r username created expiry limit_ip status lock_until account_type extra <<< "$raw_line"
                [[ -n "${username:-}" ]] || continue

                if [[ "$field_count" == "6" ]]; then
                    account_type="legacy"
                    [[ -z "${extra:-}" ]] || continue
                    ssh_valid_date "$expiry" || continue
                elif [[ "$field_count" == "7" ]]; then
                    [[ -z "${extra:-}" ]] || continue
                    case "${account_type:-}" in
                        regular) ssh_valid_date "$expiry" || continue ;;
                        trial) ssh_valid_datetime "$expiry" || continue ;;
                        *) continue ;;
                    esac
                else
                    continue
                fi

                if ! id "$username" >/dev/null 2>&1; then
                    continue
                fi

                [[ "$username" == "root" ]] && continue

                uid="$(id -u "$username" 2>/dev/null || echo 0)"
                shell="$(getent passwd "$username" | cut -d: -f7)"
                [[ "$uid" =~ ^[0-9]+$ ]] || continue
                (( uid >= 1000 )) || continue
                [[ "$shell" == "/bin/bash" ]] || continue

                ((i += 1))
                accounts+=("$username")
                rows+=("$username|$created|$expiry|$limit_ip|$status|$lock_until|$account_type|$field_count")

                printf '%b%-4s%b %-16s %-19s %-9s %-8s %-10s\n' \
                    "$ORANGE" "${i}." "$RESET" \
                    "$username" "$expiry" "$account_type" "$limit_ip" "$status"
            done < "$NATHAYA_SSH_DB"

            printf '%b%s%b\n' "$CYAN" \
                "────────────────────────────────────────────────" "$RESET"
            printf 'Total akun terdaftar: %d\n' "${#accounts[@]}"
        fi

        printf '\nMasukkan nomor urut atau username.\n'
        printf '%b z.%b Kembali ke menu SSH\n' "$ORANGE" "$RESET"
        printf '%b x.%b Keluar\n\n' "$RED" "$RESET"

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
            for username_item in "${accounts[@]}"; do
                if [[ "$username_item" == "$choice" ]]; then
                    username="$username_item"
                    break
                fi
            done
        fi

        if [[ -z "$username" ]]; then
            printf '\nAkun tidak ditemukan dalam database Nathaya.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        if [[ "$username" == "root" ]] || ! id "$username" >/dev/null 2>&1; then
            printf '\nAkun root atau akun Linux yang tidak ditemukan tidak dapat dihapus dari menu ini.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        # Ambil snapshot record terpilih dari daftar yang sudah ditampilkan.
        field_count=""
        for row in "${rows[@]}"; do
            IFS='|' read -r row_user row_created row_expiry row_limit row_status row_lock row_type row_fields <<< "$row"
            if [[ "$row_user" == "$username" ]]; then
                created="$row_created"
                expiry="$row_expiry"
                limit_ip="$row_limit"
                status="$row_status"
                lock_until="$row_lock"
                account_type="$row_type"
                field_count="$row_fields"
                break
            fi
        done

        current_record="$(ssh_db_get_account "$username" 2>/dev/null)" || {
            printf '\nRecord akun tidak ditemukan. Muat ulang daftar.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        }
        current_fields="$(awk -F '|' '{print NF}' <<< "$current_record")"
        IFS='|' read -r _ created expiry limit_ip status lock_until account_type extra <<< "$current_record"
        if [[ "$current_fields" == "6" ]]; then
            account_type="legacy"
        elif [[ "$current_fields" != "7" || -n "${extra:-}" ]]; then
            printf '\nFormat record database tidak valid.\n'
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        clear
        draw_nathaya_header "$width"
        draw_section_title "CONFIRM DELETE" "$width" "$ORANGE"
        printf '\n'
        printf '%bUsername :%b %s\n' "$WHITE" "$RESET" "$username"
        printf '%bType     :%b %s\n' "$WHITE" "$RESET" "${account_type:-Tidak diketahui}"
        printf '%bExpired  :%b %s\n' "$WHITE" "$RESET" "${expiry:-Tidak diketahui}"
        printf '%bLimit IP :%b %s\n' "$WHITE" "$RESET" "${limit_ip:-Tidak diketahui}"
        printf '%bStatus   :%b %s\n' "$WHITE" "$RESET" "${status:-Tidak diketahui}"
        printf '\n'

        read -r -p "Hapus akun ini? [y/n]: " confirm || return 0
        case "${confirm,,}" in
            y|yes)
                exec 8>>/opt/nathaya/data/ssh/operations.lock
                if ! flock -x 8; then
                    exec 8>&-
                    printf '\nGagal memperoleh lock operasi akun.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                current_record="$(ssh_db_get_account "$username" 2>/dev/null || true)"
                current_fields="$(awk -F '|' '{print NF}' <<< "$current_record")"
                IFS='|' read -r current_user current_created current_expiry current_limit current_status current_lock current_type current_extra <<< "$current_record"
                if [[ "$current_fields" == "6" ]]; then
                    current_type="legacy"
                fi

                if [[ "$current_fields" != "$field_count" ||
                      -n "${current_extra:-}" ||
                      "$current_user" != "$username" ||
                      "$current_created" != "$created" ||
                      "$current_expiry" != "$expiry" ||
                      "$current_limit" != "$limit_ip" ||
                      "$current_status" != "$status" ||
                      "$current_lock" != "$lock_until" ||
                      "$current_type" != "$account_type" ]] ||
                   ! id "$username" >/dev/null 2>&1; then
                    flock -u 8
                    exec 8>&-
                    printf '\nData akun berubah atau akun Linux sudah tidak ada. Muat ulang daftar sebelum menghapus.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                uid="$(id -u "$username" 2>/dev/null || echo 0)"
                shell="$(getent passwd "$username" | cut -d: -f7)"
                if [[ ! "$uid" =~ ^[0-9]+$ || "$uid" -lt 1000 || "$shell" != "/bin/bash" ]]; then
                    flock -u 8
                    exec 8>&-
                    printf '\nIdentitas Linux akun berubah; penghapusan dibatalkan.\n'
                    read -r -p "Tekan Enter untuk lanjut..." _
                    continue
                fi

                pkill -KILL -u "$username" 2>/dev/null || true

                if userdel -r "$username" 2>/dev/null; then
                    if ssh_db_remove_account "$username"; then
                        flock -u 8
                        exec 8>&-
                        printf '\n%bAkun %s berhasil dihapus.%b\n' \
                            "$GREEN" "$username" "$RESET"

                        if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
                            source /opt/nathaya/modules/common/telegram.sh

                            telegram_message="&#128640; <b>NATHAYA TUNNEL</b>
&#128308; <b>SSH ACCOUNT DELETED</b>

━━━━━━━━━━━━━━━━━━━━
<b>DELETE INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
<code>User   :</code> <code>${username}</code>
<code>Type   :</code> <code>${account_type}</code>
<code>Expiry :</code> <code>${expiry:-Tidak diketahui}</code>
<code>Time   :</code> <code>$(date '+%Y-%m-%d %H:%M:%S')</code>
<code>Status :</code> <code>Deleted</code>

━━━━━━━━━━━━━━━━━━━━
Akun Linux dan database berhasil dihapus.
<i>Nathaya Tunnel | Version 1.0.0</i>"

                            if telegram_send_message "$telegram_message"; then
                                printf '%bNotifikasi Telegram terkirim.%b\n' "$GREEN" "$RESET"
                            else
                                printf '%bNotifikasi Telegram gagal; penghapusan tetap berhasil.%b\n' "$YELLOW" "$RESET"
                            fi
                        fi
                    else
                        ssh_reconcile_log "delete" "$username" "db_remove_failed" \
                            "linux_userdel_succeeded; database_record_retained; manual_reconciliation_required"
                        flock -u 8
                        exec 8>&-
                        printf '\n%bAkun Linux terhapus, tetapi database gagal diperbarui. Record dipertahankan; perlu rekonsiliasi.%b\n' \
                            "$RED" "$RESET"
                    fi
                else
                    ssh_reconcile_log "delete" "$username" "linux_userdel_failed" \
                        "database_record_retained; inspect_linux_and_database_before_retry"
                    flock -u 8
                    exec 8>&-
                    printf '\n%bGagal menghapus akun Linux %s. Record database dipertahankan; periksa kondisi akun sebelum mencoba lagi.%b\n' \
                        "$RED" "$username" "$RESET"
                fi
                ;;
            *)
                printf '\nPenghapusan dibatalkan.\n'
                ;;
        esac

        read -r -p "Tekan Enter untuk kembali ke daftar..." _
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    delete_ssh_account
fi
