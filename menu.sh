#!/bin/bash

# ==========================================
# NATHAYA TUNNEL
# Main Entry Point
# ==========================================

NATHAYA_BASE="${NATHAYA_BASE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
CONFIG_FILE="/etc/nathaya-tunnel/config.conf"

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/common/functions.sh"
source "$NATHAYA_BASE/modules/dashboard/dashboard.sh"
source "$NATHAYA_BASE/modules/menu/main.sh"
source "$NATHAYA_BASE/modules/menu/ssh.sh"
source "$NATHAYA_BASE/modules/menu/domain.sh"
source "$NATHAYA_BASE/modules/menu/set_domain.sh"

# ---------- Informasi versi ----------
SCRIPT_VERSION="1.0.0"

if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# ---------- Pesan fitur sementara ----------
feature_not_ready() {
    clear
    local width
    width=$(get_width)

    draw_nathaya_header
    draw_section_title "INFORMATION" "$width"

    printf "  ${WHITE}Fitur ini belum tersedia.${RESET}\n"
    printf "  ${WHITE}Modul akan dibuat pada tahap berikutnya.${RESET}\n"

    draw_box_bottom "$width" "$CYAN" "$RESET"
    pause_return
}

# ---------- Dashboard ----------
dashboard_loop() {
    while true; do
        clear
        draw_dashboard_info

        read -r choice

        case "${choice,,}" in
            menu)
                main_menu_loop
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf "\\nPilihan tidak dikenal.\\n"
                sleep 1
                ;;
        esac
    done
}

# ---------- Menu utama ----------
main_menu_loop() {
    while true; do
        show_main_menu
        read -r -p "  Pilih menu: " choice

        case "${choice,,}" in
            1)
                ssh_menu_loop
                ;;
            2|3|4|5|6|7|8|9)
                feature_not_ready
                ;;
            10)
                domain_menu_loop
                ;;
            z)
                return
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf "\n  Pilihan tidak valid.\n"
                sleep 1
                ;;
        esac
    done
}

# ---------- Submenu SSH ----------
ssh_menu_loop() {
    while true; do
        show_ssh_menu
        read -r -p "  Pilih menu SSH: " choice

        case "${choice,,}" in
            1)
                source "$NATHAYA_BASE/modules/ssh/create.sh"
                create_ssh_account
                ;;
                2)
                source "$NATHAYA_BASE/modules/ssh/delete.sh"
                delete_ssh_account
                ;;
                3)
                source "$NATHAYA_BASE/modules/ssh/renew.sh"
                renew_ssh_account
                ;;
                4)
                source "$NATHAYA_BASE/modules/ssh/trial.sh"
                create_trial_account
                ;;
                5)
                    source "$NATHAYA_BASE/modules/ssh/login.sh"
                    check_ssh_user_login
                    ;;
                6)
                    source "$NATHAYA_BASE/modules/ssh/list-member.sh"
                    list_ssh_members
                    ;;
                7)
                    source "$NATHAYA_BASE/modules/ssh/list-expired.sh"
                    list_expired_ssh_users
                    ;;
                8)
                    source "$NATHAYA_BASE/modules/ssh/lock.sh"
                    lock_ssh_account
                    ;;
                9)
                    source "$NATHAYA_BASE/modules/ssh/unlock.sh"
                    unlock_ssh_account
                    ;;
                10)
                    feature_not_ready
                    ;;
            z)
                return
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf "\n  Pilihan tidak valid.\n"
                sleep 1
                ;;
        esac
    done
}

# ---------- Submenu Domain ----------
domain_menu_loop() {
    while true; do
        show_domain_menu
        read -r -p "  Pilih menu Domain: " choice

        case "${choice,,}" in
            1)
                set_domain_vps
                ;;
            2)
                feature_not_ready
                ;;
            z)
                return
                ;;
            x|exit|keluar)
                exit 0
                ;;
            *)
                printf "\n  Pilihan tidak valid.\n"
                sleep 1
                ;;
        esac
    done
}

# ---------- Jalankan aplikasi ----------
dashboard_loop
