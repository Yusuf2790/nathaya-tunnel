#!/usr/bin/env bash

draw_traffic_summary() {
    local width="$1"
    draw_section_title "TRAFIK VPS" "$width"
    if ! python3 "$NATHAYA_BASE/modules/dashboard/traffic.py" show 2>/dev/null; then
        printf '  Data trafik tidak tersedia.\n'
    fi
    draw_box_bottom "$width"
}

show_live_traffic() (
    if [[ ! -t 0 || ! -t 1 ]]; then
        draw_traffic_summary "$(get_width)"
        wait_submenu_navigation
        return
    fi
    # Tangani Ctrl+C di layar pemantauan agar proses dashboard tetap berjalan.
    trap ':' INT
    local status=0
    python3 "$NATHAYA_BASE/modules/dashboard/traffic.py" live || status=$?
    # traffic.py mengembalikan 10 jika pengguna memilih x atau stdin ditutup.
    case "$status" in
        10) return "$DASHBOARD_EXIT" ;;
        0|130) return 0 ;;
        *) wait_submenu_navigation ;;
    esac
)
