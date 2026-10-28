#!/usr/bin/env bash

NATHAYA_LIST_BASE="/opt/nathaya"

source "$NATHAYA_LIST_BASE/modules/ssh/account-db.sh"
source "$NATHAYA_LIST_BASE/modules/common/ui.sh"

list_ssh_members() {
    clear

    local width
    width="$(get_width)"

    draw_nathaya_header
    draw_section_title "LIST MEMBER" "$width"

    printf '\n'
    printf '%b%-4s %-20s %-19s %-9s %-9s %-10s%b\n' \
        "$CYAN" "No." "Username" "Expired" "Type" "Limit IP" "Status" "$RESET"
    printf '%s\n' '----------------------------------------------------------------------------------------'

    local number=0
    local total=0
    local locked=0
    local active=0
    local expired_count=0
    local username created expiry limit_ip status lock_until account_type extra
    local status_text status_color today now_epoch expiry_epoch expiry_rc

    today="$(date +%F)"
    now_epoch="$(date +%s)"

    if [[ -f "$NATHAYA_SSH_DB" ]]; then
        while IFS='|' read -r username created expiry limit_ip status lock_until account_type extra; do
            [[ -n "${username:-}" ]] || continue
            [[ -z "${extra:-}" ]] || continue
            [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || continue

            # Format kolom harus sesuai skema baru; jangan menebak tipe akun lama.
            case "${account_type:-}" in
                regular)
                    ssh_valid_date "$expiry" || continue
                    ;;
                trial)
                    ssh_valid_datetime "$expiry" || continue
                    ;;
                *)
                    continue
                    ;;
            esac

            total=$((total + 1))
            number=$((number + 1))
            status_text=""
            status_color="$RESET"

            if [[ "$status" == "locked" ]]; then
                status_text="lock"
                status_color="$RED"
                locked=$((locked + 1))
            elif [[ "$status" == "active" ]]; then
                ssh_account_expiry_reached "$account_type" "$expiry"
                expiry_rc=$?
                if (( expiry_rc == 0 )); then
                    status_text="expired"
                    status_color="$RED"
                    expired_count=$((expired_count + 1))
                elif (( expiry_rc == 1 )); then
                    active=$((active + 1))
                    status_text="active"
                else
                    status_text="invalid"
                    status_color="$RED"
                fi
            else
                status_text="${status:--}"
                status_color="$RESET"
            fi

            printf '%-4s %-20s %-19s %-9s %-9s ' \
                "$number" "$username" "${expiry:--}" "$account_type" "${limit_ip:--}"

            printf '%b%-10s%b\n' "$status_color" "$status_text" "$RESET"
        done < "$NATHAYA_SSH_DB"
    fi

    if [[ "$total" -eq 0 ]]; then
        printf 'Belum ada akun SSH dengan format database yang valid.\n'
    fi

    printf '%s\n' '----------------------------------------------------------------------------------------'
    printf 'Total Member : %s\n' "$total"
    printf 'Aktif        : %s\n' "$active"
    printf 'Locked       : %s\n' "$locked"
    printf 'Expired      : %s\n' "$expired_count"

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
