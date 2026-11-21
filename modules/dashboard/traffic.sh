#!/usr/bin/env bash

draw_traffic_summary() {
    local width="$1" divider_column
    divider_column=$(dashboard_divider_column "$width")
    draw_section_title "MONITORING TRAFIK" "$width"
    if ! python3 "$NATHAYA_BASE/modules/dashboard/traffic.py" show --width "$width" \
        --divider-column "$divider_column" 2>/dev/null; then
        printf '  Data trafik tidak tersedia.\n'
    fi
    draw_box_bottom "$width"
}

show_live_traffic() {
    if [[ ! -t 0 || ! -t 1 ]]; then
        draw_traffic_summary "$(get_width)"
        wait_submenu_navigation
        return
    fi

    # wait dapat diinterupsi oleh trap dashboard, sementara monitor tetap bisa
    # membaca tombol dari terminal. Tunda handler sampai PID siap dibersihkan.
    local status=0 interrupted=0
    trap 'interrupted=1' INT
    python3 "$NATHAYA_BASE/modules/dashboard/traffic.py" live <&0 2>/dev/null &
    DASHBOARD_MONITOR_PID=$!
    trap finish_dashboard INT
    if (( interrupted )); then finish_dashboard; fi
    wait "$DASHBOARD_MONITOR_PID" || status=$?
    DASHBOARD_MONITOR_PID=

    # 10 = keluar dari monitor, 130 = monitor diinterupsi, 0 = kembali (z).
    case "$status" in
        10|130) return "$DASHBOARD_EXIT" ;;
        0) return 0 ;;
        *)
            printf '  Data trafik tidak tersedia.\n'
            wait_submenu_navigation
            ;;
    esac
}
