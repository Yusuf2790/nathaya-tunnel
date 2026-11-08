#!/usr/bin/env bash

# ==========================================
# NATHAYA TUNNEL - UI MODULE
# ==========================================

if [[ -t 1 ]]; then
    RESET=$'\033[0m'
    CYAN=$'\033[1;36m'
    ORANGE=$'\033[38;5;208m'
    WHITE=$'\033[1;37m'
    BLACK=$'\033[30m'
    BG_ORANGE=$'\033[48;5;208m'
    GREEN=$'\033[1;32m'
    RED=$'\033[1;31m'
else
    RESET=""
    CYAN=""
    ORANGE=""
    WHITE=""
    BLACK=""
    BG_ORANGE=""
    GREEN=""
    RED=""
fi

pause_return() {
    printf '\nTekan Enter untuk kembali...'
    read -r _ || true
}

# Lebar terminal, tanpa memaksakan minimum 40 kolom.
get_width() {
    local width
    width=$(tput cols 2>/dev/null || printf '50')
    [[ "$width" =~ ^[0-9]+$ ]] || width=50

    (( width > 64 )) && width=64
    (( width < 32 )) && width=32

    printf '%s' "$width"
}

repeat_char() {
    local char="$1"
    local count="$2"
    local i

    (( count < 0 )) && count=0

    for ((i=0; i<count; i++)); do
        printf '%s' "$char"
    done
}

center_text() {
    local text="$1"
    local width="$2"
    local padding

    padding=$(( (width - ${#text}) / 2 ))
    (( padding < 0 )) && padding=0

    printf '%*s%s' "$padding" '' "$text"
}

draw_box_top() {
    local width="$1"
    local color="${2:-$CYAN}"

    (( width < 2 )) && width=2

    printf '%b╭' "$color"
    repeat_char '━' "$((width - 2))"
    printf '╮%b\n' "$RESET"
}

draw_box_bottom() {
    local width="$1"
    local color="${2:-$CYAN}"

    (( width < 2 )) && width=2

    printf '%b╰' "$color"
    repeat_char '━' "$((width - 2))"
    printf '╯%b\n' "$RESET"
}

# Judul bagian dengan lebar total konsisten.
draw_section_title() {
    local title="$1"
    local width="$2"
    local color="${3:-$CYAN}"
    local title_len=${#title}
    local remaining left right

    # Format: ╭───┤ TITLE ├────╮
    remaining=$((width - title_len - 6))
    (( remaining < 2 )) && remaining=2

    left=$((remaining / 2))
    right=$((remaining - left))

    printf '%b╭' "$color"
    repeat_char '━' "$left"
    printf '┤'
    printf '%b %s %b' "$WHITE" "$title" "$color"
    printf '├'
    repeat_char '━' "$right"
    printf '╮%b\n' "$RESET"
}

status_badge() {
    local state="${1:-OFF}"

    if [[ "$state" == "ON" ]]; then
        printf '%b● ON%b' "$GREEN" "$RESET"
    else
        printf '%b● OFF%b' "$RED" "$RESET"
    fi
}

# Header Nathaya Tunnel.
# Mempertahankan PAD=18 selama lebar terminal memungkinkan.
draw_nathaya_header() {
    local width="${1:-$(get_width)}"
    local inner=$((width - 2))
    local title="NATHAYA TUNNEL"
    local pad=18
    local block_len left right

    block_len=$(( ${#title} + pad * 2 ))

    if (( block_len > inner )); then
        pad=$(( (inner - ${#title}) / 2 ))
        (( pad < 0 )) && pad=0
        block_len=$(( ${#title} + pad * 2 ))
    fi

    left=$(( (inner - block_len) / 2 ))
    right=$(( inner - block_len - left ))

    draw_box_top "$width" "$CYAN"

    printf '%b│%b' "$CYAN" "$RESET"
    repeat_char ' ' "$left"

    printf '%b' "$BG_ORANGE"
    repeat_char ' ' "$pad"
    printf '%b%s%b' "$WHITE" "$title" "$RESET"
    printf '%b' "$BG_ORANGE"
    repeat_char ' ' "$pad"
    printf '%b' "$RESET"

    repeat_char ' ' "$right"
    printf '%b│%b\n' "$CYAN" "$RESET"

    draw_box_bottom "$width" "$CYAN"
}

# Shared, bounded rows for dashboards and every protocol menu.
# Fold untrusted system text as data; never interpret embedded terminal escapes.
nathaya_plain_text() {
    printf '%s' "$1" | LC_ALL=C tr -d '\000-\010\013-\037\177' | tr '\t\n\r' '   '
}

nathaya_box_row() {
    local width="$1" text line
    text=$(nathaya_plain_text "$2")
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf '%b│%b %-*s %b│%b\n' "$CYAN" "$WHITE" "$((width - 4))" "$line" "$CYAN" "$RESET"
    done < <(printf '%s\n' "$text" | fold -s -w "$((width - 4))")
}

nathaya_field() {
    nathaya_box_row "$1" "$(printf '%-10s: %s' "$2" "$3")"
}

nathaya_status_row() {
    local width="$1" label="$2" state="$3" color="$RED" text
    [[ "$state" == ON ]] && color="$GREEN"
    text=$(printf '%-18s: ● %s' "$label" "$state")
    printf '%b│%b %-*s %b│%b\n' "$CYAN" "$color" "$((width - 4))" "$text" "$CYAN" "$RESET"
}

nathaya_menu_item() {
    local width="$1" number="$2" label="$3" line first=1
    while IFS= read -r line || [[ -n "$line" ]]; do
        if (( first )); then
            printf '%b│ %b%2s. %b%-*s %b│%b\n' "$CYAN" "$ORANGE" "$number" "$WHITE" "$((width - 8))" "$line" "$CYAN" "$RESET"
            first=0
        else
            printf '%b│     %b%-*s %b│%b\n' "$CYAN" "$WHITE" "$((width - 8))" "$line" "$CYAN" "$RESET"
        fi
    done < <(nathaya_plain_text "$label" | fold -s -w "$((width - 8))")
}

nathaya_show_menu() {
    local title="$1" width index=1 label
    shift
    width=$(get_width)
    [[ -t 1 ]] && clear
    draw_nathaya_header "$width"
    draw_section_title "$title" "$width"
    for label in "$@"; do
        nathaya_menu_item "$width" "$index" "$label"
        ((index++))
    done
    draw_box_bottom "$width"
    printf '  %bz.%b Kembali\n  %bx.%b Exit\n\n' "$ORANGE" "$RESET" "$ORANGE" "$RESET"
}
