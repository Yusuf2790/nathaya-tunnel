#!/bin/bash

# NATHAYA_BASE diwarisi dari menu.sh.

source "$NATHAYA_BASE/modules/common/ui.sh"

show_ssh_menu() {
    clear
    local width
    width=$(get_width)

    draw_nathaya_header
    draw_section_title "SSH MENU" "$width"

    printf "  ${ORANGE}1.${RESET} ${WHITE}Create${RESET}\n"
    printf "  ${ORANGE}2.${RESET} ${WHITE}Delete${RESET}\n"
    printf "  ${ORANGE}3.${RESET} ${WHITE}Renew${RESET}\n"
    printf "  ${ORANGE}4.${RESET} ${WHITE}Trial${RESET}\n"
    printf "  ${ORANGE}5.${RESET} ${WHITE}Check User Login${RESET}\n"
    printf "  ${ORANGE}6.${RESET} ${WHITE}List Member${RESET}\n"
    printf "  ${ORANGE}7.${RESET} ${WHITE}List User Expired${RESET}\n"
    printf "  ${ORANGE}8.${RESET} ${WHITE}Lock${RESET}\n"
    printf "  ${ORANGE}9.${RESET} ${WHITE}Unlock${RESET}\n"
    printf "  ${ORANGE}10.${RESET} ${WHITE}Limit IP${RESET}\n"

    draw_box_bottom "$width" "$CYAN" "$RESET"

    printf "  ${ORANGE}z.${RESET} ${WHITE}Kembali ke menu${RESET}\n"
    printf "  ${RED}x.${RESET} ${WHITE}Exit${RESET}\n"
    printf "\n"
}

