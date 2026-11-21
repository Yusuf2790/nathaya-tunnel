#!/bin/bash

# NATHAYA_BASE diwarisi dari menu.sh.

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/common/functions.sh"

_service_row() {
    local name1="$1"
    local state1="$2"
    local name2="$3"
    local state2="$4"
    local visible_len

    printf '%b│%b %-8s : ' "$CYAN" "$RESET" "$name1"
    status_badge "$state1"

    if [[ "$state1" == "ON" ]]; then
        visible_len=4
    else
        visible_len=5
    fi

    printf '%*s│ ' "$((20 - 13 - visible_len))" ''
    printf '%-8s : ' "$name2"
    status_badge "$state2"
    printf '\n'
}

draw_service_status() {
    local width="$1"
    # SERVICE STATUS
    printf '\n'
    draw_section_title "SERVICE STATUS" "$width"

    _service_row "SSH" "$(get_service_status ssh)" "XRAY" "$(get_service_status xray)"
    _service_row "DROPBEAR" "$(get_service_status dropbear)" \
        "NGINX" "$(get_service_status nginx)"

    printf '%b│%b OPENVPN  : ' "$CYAN" "$RESET"
    status_badge "$(get_service_status openvpn)"
    printf '\n'

    draw_box_bottom "$width" "$CYAN"

}

draw_dashboard_info() {
    refresh_system_info

    local width
    width=$(get_width)

    # Header utama
    draw_nathaya_header "$width"

    # SYSTEM INFORMATION
    printf '\n'
    draw_section_title "SYSTEM INFORMATION" "$width"

    printf '%b│%b OS        : %s\n' "$CYAN" "$RESET" "$OS_NAME"
    printf '%b│%b CPU CORE  : %s Core\n' "$CYAN" "$RESET" "$CPU_CORES"

    local ram_used ram_total swap_used swap_total
    ram_used=$(free -h | awk '/^Mem:/ {print $3}')
    ram_total=$(free -h | awk '/^Mem:/ {print $2}')
    swap_used=$(free -h | awk '/^Swap:/ {print $3}')
    swap_total=$(free -h | awk '/^Swap:/ {print $2}')

    printf '%b│%b RAM       : %s / %s\n' \
        "$CYAN" "$RESET" "${ram_used:-?}" "${ram_total:-?}"
    printf '%b│%b SWAP      : %s / %s\n' \
        "$CYAN" "$RESET" "${swap_used:-?}" "${swap_total:-?}"
    printf '%b│%b CITY      : %s\n' "$CYAN" "$RESET" "$CITY"
    printf '%b│%b ISP       : %s\n' "$CYAN" "$RESET" "$ISP"
    printf '%b│%b IP PUBLIK : %s\n' "$CYAN" "$RESET" "$PUBLIC_IP"
    printf '%b│%b DOMAIN    : %s\n' "$CYAN" "$RESET" "${DOMAIN:-Belum disetting}"

    draw_box_bottom "$width" "$CYAN"

    printf '\n'
    draw_section_title "TELEGRAM STATUS" "$width"
    printf '  Bot Akses VPS  : '
    status_badge "${TELEGRAM_MANAGEMENT_STATUS:-OFF}"
    printf '\n  Bot Notifikasi : '
    status_badge "$(notification_bot_status)"
    printf '\n'
    draw_box_bottom "$width"

    draw_service_status "$width"

    printf '\n'
    draw_traffic_summary "$width"

    # ACCOUNT TOTAL
    printf '\n'
    draw_section_title "ACCOUNT TOTAL" "$width"

    printf '  SSH: %s   VMESS: 0   VLESS: 0   TROJAN: 0\n' "$SSH_TOTAL"
    draw_box_bottom "$width"

    printf '\n'
    show_main_menu

    # FOOTER
    printf '\n'
    draw_box_top "$width" "$CYAN"

    printf '%b│%b Script Version : %s\n' \
        "$CYAN" "$RESET" "${SCRIPT_VERSION:-1.0.0}"

    printf '%b│%b Client Name    : %s\n' "$CYAN" "$RESET" "${CLIENT_NAME:--}"
    printf '%b│%b Order by       : %s\n' "$CYAN" "$RESET" "${ORDER_BY:--}"

    printf '%b│%b Developer      : %b%s%b\n' \
        "$CYAN" "$RESET" "$ORANGE" \
        "${SCRIPT_DEVELOPER:-Nathaya Tunnel}" "$RESET"

    draw_box_bottom "$width" "$CYAN"

    printf '\n'
}

notification_bot_status() {
    if [[ "${TELEGRAM_STATUS:-OFF}" == ON && -n "${TELEGRAM_BOT_TOKEN:-}" &&
          "${TELEGRAM_ADMIN_ID:-}" =~ ^-?[0-9]+$ ]]; then
        printf ON
    else
        printf OFF
    fi
}

show_notification_bot() {
    clear_screen
    local width
    width=$(get_width)
    draw_nathaya_header "$width"
    draw_section_title "BOT NOTIFIKASI" "$width"
    printf '  Status konfigurasi: '
    status_badge "$(notification_bot_status)"
    printf '\n'
    wait_submenu_navigation "$width"
}
