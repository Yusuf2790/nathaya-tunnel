#!/bin/bash

# NATHAYA_BASE diwarisi dari menu.sh.

source "$NATHAYA_BASE/modules/common/ui.sh"

show_main_menu() {
    clear
    local width
    width=$(get_width)

    draw_nathaya_header
    draw_section_title "MAIN MENU" "$width"

    printf "  ${ORANGE}1.${RESET} ${WHITE}SSH${RESET}\n"
    printf "  ${ORANGE}2.${RESET} ${WHITE}VMESS${RESET}\n"
    printf "  ${ORANGE}3.${RESET} ${WHITE}VLESS${RESET}\n"
    printf "  ${ORANGE}4.${RESET} ${WHITE}TROJAN${RESET}\n"
    printf "  ${ORANGE}5.${RESET} ${WHITE}SETUP BOT${RESET}\n"
    printf "  ${ORANGE}6.${RESET} ${WHITE}FEATURES${RESET}\n"
    printf "  ${ORANGE}7.${RESET} ${WHITE}SET BANNER${RESET}\n"
    printf "  ${ORANGE}8.${RESET} ${WHITE}CHECK BANDWIDTH${RESET}\n"
    printf "  ${ORANGE}9.${RESET} ${WHITE}CHECK SERVICES${RESET}\n"
    printf "  ${ORANGE}10.${RESET} ${WHITE}MENU DOMAIN${RESET}\n"

    draw_box_bottom "$width" "$CYAN" "$RESET"

    printf "  ${ORANGE}z.${RESET} ${WHITE}KEMBALI KE DASHBOARD${RESET}\n"
    printf "  ${RED}x.${RESET} ${WHITE}EXIT${RESET}\n"
    printf "\n"
}

