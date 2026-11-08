#!/bin/bash

show_domain_menu() {
    nathaya_show_menu "DOMAIN MENU" "Set Domain VPS / SSL" "Renew Sertifikat SSL"
}

domain_menu_loop() {
    local choice
    while true; do
        show_domain_menu
        read -r -p "  Pilih menu Domain: " choice || return 0
        choice=$(nathaya_normalize_choice "$choice")
        case "$choice" in
            1) set_domain_vps ;;
            2) renew_domain_certificate ;;
            z|0) return 0 ;;
            x|exit|keluar) return 100 ;;
            *) printf '\n  Pilihan tidak valid.\n'; pause_return ;;
        esac
    done
}
