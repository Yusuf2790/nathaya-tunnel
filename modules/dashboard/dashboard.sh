#!/bin/bash

# NATHAYA_BASE diwarisi dari menu.sh.

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/common/functions.sh"

draw_service_status() {
    local width="$1" index state badge_width bot_index
    local divider_column inline_bots=0
    local -a names=(SSH XRAY DROPBEAR NGINX OPENVPN)
    local -a units=(ssh xray dropbear nginx openvpn)
    local -a bots=("Bot Akses VPS" "Bot Notifikasi")
    local -a bot_states=("${TELEGRAM_MANAGEMENT_STATUS:-OFF}" "$(notification_bot_status)")

    # Sisakan ruang untuk nama dan lencana bot. Di panel sempit,
    # lencana bot tampil di bawah nama, tetap di kolom kanan.
    divider_column=$(dashboard_divider_column "$width")
    if (( width >= 40 )); then
        inline_bots=1
    fi

    printf '\n'
    draw_section_title "SERVICE & BOT STATUS" "$width"
    for index in "${!names[@]}"; do
        state=$(get_service_status "${units[index]}")
        badge_width=5
        [[ "$state" == ON ]] && badge_width=4
        printf ' %-8s ' "${names[index]}"
        status_badge "$state"
        printf '%*s │' "$((divider_column - 12 - badge_width))" ''

        if (( inline_bots )); then
            if (( index < ${#bots[@]} )); then
                printf ' %-14s : ' "${bots[index]}"
                status_badge "${bot_states[index]}"
            fi
        elif (( index < 2 * ${#bots[@]} )); then
            bot_index=$((index / 2))
            if (( index % 2 == 0 )); then
                printf ' %s' "${bots[bot_index]}"
            else
                printf ' '
                status_badge "${bot_states[bot_index]}"
            fi
        fi
        printf '\n'
    done
    draw_box_bottom "$width"
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
