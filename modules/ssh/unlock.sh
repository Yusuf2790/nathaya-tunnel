#!/usr/bin/env bash

NATHAYA_BASE="${NATHAYA_BASE:-/opt/nathaya}"
source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/ssh/account-db.sh"

unlock_ssh_account() {
    [[ $EUID -eq 0 ]] || { echo "ERROR: Jalankan sebagai root."; return 1; }

    local width choice username created expiry limit_ip status lock_until account_type
    local uid shell confirm today record item current_type
    local -a accounts=()

    ssh_db_init || return 1

    while true; do
        clear
        width="$(get_width)"
        today="$(date +%F)"
        accounts=()

        draw_nathaya_header "$width"
        draw_section_title "UNLOCK SSH" "$width"
        printf '\n'
        printf '%bDAFTAR AKUN SSH (REGULAR)%b\n' "$CYAN" "$RESET"
        printf '%b%s%b\n' "$CYAN" "────────────────────────────────────────────────" "$RESET"
        printf '%b%-4s %-16s %-12s %-8s %-10s%b\n' \
            "$WHITE" "NO." "USERNAME" "EXPIRED" "LIMIT IP" "STATUS" "$RESET"
        printf '%b%s%b\n' "$CYAN" "────────────────────────────────────────────────" "$RESET"

        while IFS='|' read -r username created expiry limit_ip status lock_until account_type; do
            [[ -n "$username" ]] || continue
            [[ "$account_type" == "regular" ]] || continue
            ssh_valid_date "$expiry" || continue
            id "$username" >/dev/null 2>&1 || continue
            [[ "$username" != "root" ]] || continue

            uid="$(id -u "$username" 2>/dev/null || echo 0)"
            shell="$(getent passwd "$username" | cut -d: -f7)"
            [[ "$uid" =~ ^[0-9]+$ ]] || continue
            (( uid >= 1000 )) || continue
            [[ "$shell" == "/bin/bash" ]] || continue
            [[ "$status" == "active" || "$status" == "locked" ]] || continue

            accounts+=("$username")
            printf '%b%-4d%b %-16s %-12s %-8s %-10s\n' \
                "$ORANGE" "${#accounts[@]}" "$RESET" \
                "$username" "$expiry" "$limit_ip" "$status"
        done < "$NATHAYA_SSH_DB"

        printf '%b%s%b\n' "$CYAN" "────────────────────────────────────────────────" "$RESET"
        printf 'Total akun regular tersedia: %d\n' "${#accounts[@]}"
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
            fi
        else
            for item in "${accounts[@]}"; do
                [[ "$item" == "$choice" ]] && { username="$item"; break; }
            done
        fi

        if [[ -z "$username" ]]; then
            echo "Pilihan tidak valid atau akun regular tidak ditemukan."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        record="$(ssh_db_get_account "$username")" || {
            echo "Record database tidak ditemukan."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        }
        IFS='|' read -r username created expiry limit_ip status lock_until account_type <<< "$record"

        if [[ "$account_type" != "regular" ]] || ! ssh_valid_date "$expiry"; then
            echo "Hanya akun regular dengan expiry tanggal valid yang bisa di-Unlock."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        uid="$(id -u "$username" 2>/dev/null || echo 0)"
        shell="$(getent passwd "$username" | cut -d: -f7)"
        if [[ "$username" == "root" ]] || (( uid < 1000 )) || [[ "$shell" != "/bin/bash" ]]; then
            echo "Akun tidak memenuhi syarat pengelolaan Nathaya."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi
        if [[ "$status" != "locked" ]]; then
            echo "Akun berstatus '$status'; hanya akun locked yang bisa di-Unlock."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi
        if [[ "$expiry" < "$today" ]]; then
            echo "Akun expired atau tanggal expiry tidak valid."
            echo "Perpanjang akun melalui Renew sebelum Unlock."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi
        if ! passwd -S "$username" | awk '$2=="L"{ok=1} END{exit !ok}'; then
            echo "Password Linux tidak terdeteksi terkunci; tidak diubah."
            read -r -p "Tekan Enter untuk lanjut..." _
            continue
        fi

        clear
        draw_nathaya_header "$width"
        draw_section_title "CONFIRM UNLOCK" "$width" "$ORANGE"
        printf '\nUsername : %s\nExpired  : %s\nLimit IP : %s\nStatus   : %s\nType     : %s\n\n' \
            "$username" "$expiry" "$limit_ip" "$status" "$account_type"
        read -r -p "Buka kunci password akun ini? [y/n]: " confirm || return 0

        case "${confirm,,}" in
            y|yes)
                # Recheck type/status immediately before changing the Linux password.
                record="$(ssh_db_get_account "$username")" || {
                    echo "ERROR: Record database tidak ditemukan; operasi dibatalkan."
                    read -r -p "Tekan Enter untuk kembali..." _
                    continue
                }
                IFS='|' read -r username created expiry limit_ip status lock_until current_type <<< "$record"
                if [[ "$current_type" != "regular" || "$status" != "locked" ]] || ! ssh_valid_date "$expiry"; then
                    echo "ERROR: Data akun berubah atau bukan akun regular locked; operasi dibatalkan."
                    read -r -p "Tekan Enter untuk kembali..." _
                    continue
                fi
                if passwd -u "$username"; then
                    if ssh_db_update_status "$username" active 0; then
                        printf '\n%bUnlock berhasil: %s%b\n' "$GREEN" "$username" "$RESET"
                        echo "Status password Linux: terbuka."
                        echo "Catatan: pastikan kebijakan akses SSH server sesuai kebutuhan."
                    else
                        if passwd -l "$username"; then
                            echo "ERROR: Database gagal; password dikunci kembali."
                        else
                            echo "PERINGATAN: Database dan rollback gagal; periksa akun segera."
                        fi
                    fi
                else
                    echo "ERROR: Gagal membuka kunci password Linux."
                fi
                ;;
            *) echo "Unlock dibatalkan." ;;
        esac
        read -r -p "Tekan Enter untuk kembali ke daftar..." _
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    unlock_ssh_account
fi
