#!/usr/bin/env bash

NATHAYA_LOGIN_BASE="/opt/nathaya"
source "$NATHAYA_LOGIN_BASE/modules/ssh/account-db.sh"
source "$NATHAYA_LOGIN_BASE/modules/common/ui.sh"

check_ssh_user_login() {
    clear
    draw_nathaya_header
    draw_section_title "CHECK USER LOGIN"
    printf '\n'
    printf '%-4s %-24s %s\n' "No." "Username" "Limit IP"
    printf '%s\n' '-----------------------------------------------'

    local number=0
    local username created expiry limit_ip status lock_until account_type
    local process_args choice

    if [[ ! -f "$NATHAYA_SSH_DB" ]]; then
        printf 'Database akun SSH belum tersedia.\n'
    else
        while IFS='|' read -r username created expiry limit_ip status lock_until account_type extra; do
            [[ -n "$username" ]] || continue
            [[ "$account_type" == "regular" || "$account_type" == "trial" ]] || continue
            [[ "$username" =~ ^[a-z0-9]{1,32}$ ]] || continue
            [[ "$status" == "active" ]] || continue
            id "$username" >/dev/null 2>&1 || continue

            process_args="$(
                ps -u "$username" -o args= 2>/dev/null |
                    grep -E '[s]shd: .*@' || true
            )"

            [[ -n "$process_args" ]] || continue

            number=$((number + 1))
            printf '%-4s %-24s %s\n' \
                "$number" "$username" "${limit_ip:-Tidak diketahui}"
        done < "$NATHAYA_SSH_DB"
    fi

    if [[ "$number" -eq 0 ]]; then
        printf 'Tidak ada user SSH yang online.\n'
    fi

    printf '%s\n' '-----------------------------------------------'
    printf '\n'
    printf '%b z.%b Kembali ke menu SSH\n' "$ORANGE" "$RESET"
    printf '%b x.%b Exit\n\n' "$RED" "$RESET"

    while true; do
        read -r -p "Pilihan: " choice || return 0

        case "${choice,,}" in
            z)
                return 0
                ;;
            x)
                exit 0
                ;;
            *)
                printf 'Pilihan tidak valid. Masukkan Z atau X.\n'
                ;;
        esac
    done
}
