#!/bin/bash

show_main_menu() {
    nathaya_show_menu "MAIN MENU" "SSH" "VMESS" "VLESS" "TROJAN" "SETUP BOT" "FEATURES" "SET BANNER" "CHECK BANDWIDTH" "CHECK SERVICES" "MENU DOMAIN" "SHADOWSOCKS"
}

main_menu_loop() {
    local choice status
    while true; do
        show_main_menu
        read -r -p "  Pilih menu: " choice || return 0
        choice=$(nathaya_normalize_choice "$choice")
        status=0
        case "$choice" in
            1) nathaya_run_command menussh; status=$? ;;
            2) nathaya_run_command menuvmess; status=$? ;;
            3) nathaya_run_command menuvless; status=$? ;;
            4) nathaya_run_command menutrojan; status=$? ;;
            5) nathaya_features_section telegram; status=$? ;;
            6) nathaya_run_action features; status=$? ;;
            7) nathaya_features_section banner; status=$? ;;
            8) nathaya_features_section bandwidth; status=$? ;;
            9) nathaya_features_section services; status=$? ;;
            10) domain_menu_loop; status=$? ;;
            11) nathaya_run_command menushadowsocks; status=$? ;;
            z|0) return 0 ;;
            x|exit|keluar) return 100 ;;
            *) printf '\n  Pilihan tidak valid.\n'; pause_return; continue ;;
        esac
        (( status == 100 )) && return 100
        (( status != 0 )) && pause_return
    done
}

dashboard_loop() {
    local choice status
    while true; do
        [[ -t 1 ]] && clear
        draw_dashboard_info
        read -r choice || return 0
        case "${choice,,}" in
            menu)
                main_menu_loop
                status=$?
                (( status == 100 )) && return 0
                ;;
            x|exit|keluar) return 0 ;;
            *) printf '\n  Ketik menu atau x.\n'; pause_return ;;
        esac
    done
}
