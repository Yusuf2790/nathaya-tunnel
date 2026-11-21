#!/usr/bin/env bash

show_main_menu() {
    local width
    width=$(get_width)
    draw_section_title "MENU UTAMA" "$width"
    draw_menu_choices "$width" \
        1 SSH 2 VMESS 3 VLESS 4 TROJAN \
        5 "BOT AKSES VPS" 6 "BOT NOTIFIKASI" 7 "SET BANNER" 8 FEATURES
    draw_menu_item x "Keluar ke shell"
    draw_box_bottom "$width"
}

show_features_menu() {
    clear_screen
    local width
    width=$(get_width)
    draw_nathaya_header "$width"
    draw_section_title "FEATURES" "$width"
    draw_menu_item 1 "Monitoring Trafik"
    draw_menu_item 2 "Status Layanan"
    draw_menu_item 3 "Menu Domain"
    draw_submenu_navigation
    draw_box_bottom "$width"
}
