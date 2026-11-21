#!/usr/bin/env bash

show_domain_menu() {
    clear_screen
    local width
    width=$(get_width)
    draw_nathaya_header "$width"
    draw_section_title "MENU DOMAIN" "$width"
    draw_menu_item 1 "Set Domain VPS"
    draw_menu_item 2 "Hubungkan Cloudflare"
    draw_submenu_navigation
    draw_box_bottom "$width"
}
