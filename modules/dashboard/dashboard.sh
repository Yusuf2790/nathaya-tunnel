#!/bin/bash
# Nathaya dashboard; data comes only from the installed Alrescha services/databases.

draw_dashboard_info() {
    refresh_system_info
    local width
    width=$(get_width)
    draw_nathaya_header "$width"

    printf '\n'
    draw_section_title "SYSTEM INFORMATION" "$width"
    nathaya_field "$width" "OS" "$OS_NAME"
    nathaya_field "$width" "HOSTNAME" "$HOST_NAME"
    nathaya_field "$width" "CPU CORE" "$CPU_CORES Core"
    nathaya_field "$width" "RAM" "$RAM_INFO"
    nathaya_field "$width" "SWAP" "$SWAP_INFO"
    nathaya_field "$width" "CITY" "$CITY"
    nathaya_field "$width" "ISP" "$ISP"
    nathaya_field "$width" "IP PUBLIK" "$PUBLIC_IP"
    nathaya_field "$width" "DOMAIN" "${DOMAIN:-Belum disetting}"
    draw_box_bottom "$width"

    printf '\n'
    draw_section_title "TELEGRAM STATUS" "$width"
    nathaya_status_row "$width" "Notification Bot" "$TELEGRAM_NOTIFICATION_STATUS"
    nathaya_status_row "$width" "Management Bot" "$TELEGRAM_MANAGEMENT_STATUS"
    draw_box_bottom "$width"

    printf '\n'
    draw_section_title "SERVICE STATUS" "$width"
    nathaya_status_row "$width" "SSH" "$SSH_STATUS"
    nathaya_status_row "$width" "SSH NATHAYA" "$(get_service_status nathaya-ssh)"
    nathaya_status_row "$width" "XRAY" "$XRAY_STATUS"
    nathaya_status_row "$width" "DROPBEAR" "$(get_service_status nathaya-dropbear)"
    nathaya_status_row "$width" "NGINX" "$(get_service_status nginx)"
    nathaya_status_row "$width" "OPENVPN TCP" "$(get_service_status nathaya-openvpn-tcp)"
    nathaya_status_row "$width" "OPENVPN UDP" "$(get_service_status nathaya-openvpn-udp)"
    nathaya_status_row "$width" "HAPROXY" "$(get_service_status haproxy)"
    nathaya_status_row "$width" "WEBSOCKET" "$(get_service_status ws)"
    nathaya_status_row "$width" "VMESS" "$(get_service_status vmess@config)"
    nathaya_status_row "$width" "VLESS" "$(get_service_status vless@config)"
    nathaya_status_row "$width" "TROJAN" "$(get_service_status trojan@config)"
    nathaya_status_row "$width" "SHADOWSOCKS" "$(get_service_status shadowsocks@config)"
    draw_box_bottom "$width"

    printf '\n'
    draw_section_title "ACCOUNT TOTAL" "$width"
    nathaya_field "$width" "SSH" "$SSH_TOTAL"
    nathaya_field "$width" "VMESS" "$VMESS_TOTAL"
    nathaya_field "$width" "VLESS" "$VLESS_TOTAL"
    nathaya_field "$width" "TROJAN" "$TROJAN_TOTAL"
    nathaya_field "$width" "SSOCKS" "$SHADOWSOCKS_TOTAL"
    draw_box_bottom "$width"

    printf '\n'
    draw_box_top "$width"
    nathaya_field "$width" "Script Version" "${SCRIPT_VERSION:-1.0.0}"
    nathaya_field "$width" "Developer" "${SCRIPT_DEVELOPER:-Nathaya Tunnel}"
    draw_box_bottom "$width"
    printf '\nKetik "menu" untuk membuka panel, atau "x" untuk keluar: '
}
