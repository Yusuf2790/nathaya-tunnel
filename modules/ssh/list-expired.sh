#!/usr/bin/env bash

NATHAYA_EXPIRED_BASE="/opt/nathaya"

source "$NATHAYA_EXPIRED_BASE/modules/ssh/account-db.sh"
source "$NATHAYA_EXPIRED_BASE/modules/common/ui.sh"

list_expired_ssh_users() {
    clear

    local width today
    width="$(get_width)"
    today="$(date +%F)"

    draw_nathaya_header
    draw_section_title "LIST USER EXPIRED" "$width"

    printf '\n'
    printf '%b%-4s %-20s %-19s %-9s %-10s %-8s%b\n' \
        "$CYAN" "No." "Username" "Expired" "Limit IP" "Status" "Type" "$RESET"
    printf '%s\n' '-------------------------------------------------------------------------------'

    local number=0
    local username created expiry limit_ip status lock_until account_type extra
    local status_text status_color now_epoch expiry_epoch expiry_display

    now_epoch="$(date +%s)"

    if [[ -f "$NATHAYA_SSH_DB" ]]; then
        while IFS='|' read -r username created expiry limit_ip status lock_until account_type extra; do
            [[ -n "$username" ]] || continue
            [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || continue
            [[ "$status" =~ ^(active|locked|expired)$ ]] || continue
            [[ "$account_type" == "regular" || "$account_type" == "trial" ]] || continue
            [[ -z "$extra" ]] || continue

            if [[ "$account_type" == "regular" ]]; then
                ssh_valid_date "$expiry" || continue
                # Regular accounts remain valid through their expiry date.
                [[ "$expiry" < "$today" ]] || continue
                expiry_display="$expiry"
            else
                ssh_valid_datetime "$expiry" || continue
                expiry_epoch="$(date -d "$expiry" +%s 2>/dev/null)" || continue
                (( expiry_epoch <= now_epoch )) || continue
                expiry_display="$expiry"
            fi

            number=$((number + 1))
            status_text="expired"
            status_color="$RED"

            printf '%b%-4s%b %-20s %-19s %-9s ' \
                "$ORANGE" "$number" "$RESET" \
                "$username" "$expiry_display" "${limit_ip:--}"
            printf '%b%-10s%b %-8s\n' \
                "$status_color" "$status_text" "$RESET" "$account_type"
        done < "$NATHAYA_SSH_DB"
    fi

    if [[ "$number" -eq 0 ]]; then
        printf 'Tidak ada akun SSH yang expired.\n'
    else
        printf '%s\n' '-------------------------------------------------------------------------------'
        printf 'Total User Expired : %s\n' "$number"
    fi

    printf '\n'
    printf '%b z.%b Kembali ke menu SSH\n' "$ORANGE" "$RESET"
    printf '%b x.%b Exit\n\n' "$RED" "$RESET"

    local choice
    while true; do
        read -r -p "Pilihan: " choice || return 0

        case "${choice,,}" in
            z)
                return 0
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf 'Pilihan tidak valid. Masukkan z atau x.\n'
                ;;
        esac
    done
}
