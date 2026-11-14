#!/bin/bash

source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../common" && pwd)/bootstrap.sh" || { return 1 2>/dev/null || exit 1; }

source "$NATHAYA_BASE/modules/common/ui.sh"

show_domain_menu() {
    clear
    local width
    width=$(get_width)

    draw_nathaya_header
    draw_section_title "DOMAIN MENU" "$width"

    printf "  ${ORANGE}01.${RESET} ${WHITE}Set Domain VPS${RESET}\n"
    printf "  ${ORANGE}02.${RESET} ${WHITE}Hubungkan Cloudflare${RESET}\n"

    draw_box_bottom "$width" "$CYAN" "$RESET"

    printf "  ${ORANGE}z.${RESET} ${WHITE}Kembali ke menu${RESET}\n"
    printf "  ${RED}x.${RESET} ${WHITE}Exit${RESET}\n"
    printf "\n"
}

