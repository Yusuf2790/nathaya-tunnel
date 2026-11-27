#!/bin/bash

# ==========================================
# NATHAYA TUNNEL
# Main Entry Point
# ==========================================

NATHAYA_BASE="${NATHAYA_BASE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/common/functions.sh"
source "$NATHAYA_BASE/modules/dashboard/dashboard.sh"
source "$NATHAYA_BASE/modules/dashboard/traffic.sh"
source "$NATHAYA_BASE/modules/dashboard/ports.sh"
source "$NATHAYA_BASE/modules/menu/main.sh"
source "$NATHAYA_BASE/modules/menu/ssh.sh"
source "$NATHAYA_BASE/modules/menu/domain.sh"
source "$NATHAYA_BASE/modules/menu/set_domain.sh"

# ---------- Informasi versi ----------
SCRIPT_VERSION="1.0.0"
# Status internal untuk meneruskan Keluar hingga loop dashboard.
DASHBOARD_EXIT=10
DASHBOARD_MONITOR_PID=

finish_dashboard() {
    # Abaikan SIGINT tambahan saat membereskan monitor dan tampilkan pesan sekali.
    trap '' INT
    if [[ -n "$DASHBOARD_MONITOR_PID" ]]; then
        kill -TERM "$DASHBOARD_MONITOR_PID" 2>/dev/null || true
        wait "$DASHBOARD_MONITOR_PID" 2>/dev/null || true
    fi
    if [[ -t 0 && -t 1 ]]; then
        printf '\n%bKetik "menu" untuk kembali ke menu%b\n' "$WHITE" "$RESET"
    fi
    exit 0
}

feature_not_ready() {
    clear_screen
    local width
    width=$(get_width)
    draw_nathaya_header "$width"
    draw_section_title "${1:-INFORMASI}" "$width"
    printf '  Modul belum tersedia\n'
    wait_submenu_navigation "$width"
}

dashboard_loop() {
    local choice status
    while true; do
        clear_screen
        draw_dashboard_info
        read -r -p "  Pilih menu [1-8 atau x]: " choice || return 0
        case "${choice,,}" in
            1) show_ssh_menu ;;
            2) feature_not_ready VMESS ;;
            3) feature_not_ready VLESS ;;
            4) feature_not_ready TROJAN ;;
            5) feature_not_ready "BOT AKSES VPS" ;;
            6) show_notification_bot ;;
            7) feature_not_ready "SET BANNER" ;;
            8) features_menu_loop ;;
            x|exit|keluar) return 0 ;;
            *) printf '\n  Pilihan tidak valid.\n'; sleep 1 ;;
        esac
        status=$?
        if (( status == DASHBOARD_EXIT )); then return 0; fi
    done
}

features_menu_loop() {
    local choice status
    while true; do
        show_features_menu
        read -r -p "  Pilih menu Features: " choice || return "$DASHBOARD_EXIT"
        case "${choice,,}" in
            1) show_live_traffic ;;
            2)
                clear_screen
                draw_service_status "$(get_width)"
                wait_submenu_navigation
                ;;
            3) domain_menu_loop ;;
            4) show_port_info ;;
            z) return 0 ;;
            x|exit|keluar) return "$DASHBOARD_EXIT" ;;
            *) printf '\n  Pilihan tidak valid.\n'; sleep 1 ;;
        esac
        status=$?
        if (( status == DASHBOARD_EXIT )); then return "$DASHBOARD_EXIT"; fi
    done
}

# ---------- Submenu Domain ----------
domain_menu_loop() {
    local choice status
    while true; do
        show_domain_menu
        read -r -p "  Pilih menu Domain: " choice || return "$DASHBOARD_EXIT"
        case "${choice,,}" in
            1) set_domain_vps ;;
            2) feature_not_ready ;;
            z) return 0 ;;
            x|exit|keluar) return "$DASHBOARD_EXIT" ;;
            *) printf '\n  Pilihan tidak valid.\n'; sleep 1 ;;
        esac
        status=$?
        if (( status == DASHBOARD_EXIT )); then return "$DASHBOARD_EXIT"; fi
    done
}

# ---------- Jalankan aplikasi ----------
# Monitor latar harus tetap di grup foreground agar bisa membaca TTY.
set +m
trap finish_dashboard INT
dashboard_loop
finish_dashboard
