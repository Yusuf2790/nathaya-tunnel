#!/usr/bin/env bash

# Service state and an owned socket are both required to mark a listener active.
port_state() {
    local unit="$1" protocol="$2" port="$3" flag=t pid group kind queues address rest owner path
    systemctl is-active --quiet "$unit" 2>/dev/null || { printf 'OFF'; return; }
    pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null) || { printf '?'; return; }
    group=$(systemctl show -p ControlGroup --value "$unit" 2>/dev/null) || { printf '?'; return; }
    [[ "$protocol" != UDP ]] || flag=u
    local lines
    lines=$(ss -H "-l${flag}np" 2>/dev/null) || { printf '?'; return; }
    while read -r kind _ queues address rest; do
        [[ "$address" == *":$port" ]] || continue
        while [[ "$rest" =~ pid=([0-9]+), ]]; do
            owner=${BASH_REMATCH[1]}
            if [[ "$owner" == "$pid" && "$pid" != 0 ]]; then printf 'ON'; return; fi
            if [[ -n "$group" && -r /proc/$owner/cgroup ]]; then
                while IFS=: read -r _ _ path; do
                    if [[ "$path" == "$group" ]]; then printf 'ON'; return; fi
                done < "/proc/$owner/cgroup"
            fi
            rest=${rest#*"pid=$owner,"}
        done
    done <<< "$lines"
    printf 'OFF'
}

port_info_row() {
    printf '  %-8s  %-3s  %-3s  %s\n' "$3" "$2" "$(port_state "$1" "$2" "$3")" "$4"
}

show_port_info() {
    local width port p
    width=$(get_width)
    clear_screen
    draw_nathaya_header "$width"
    draw_section_title 'INFORMASI PORT' "$width"
    printf '\n  PUBLIK (sesuai firewall VPS)\n'
    printf '  SSH admin: konfigurasi VPS\n'
    port_info_row nathaya-haproxy.service TCP 80 'SSH TCP, WS /, redirect'
    port_info_row nathaya-haproxy.service TCP 443 'SSH TLS, WSS /, Xray WSS/gRPC'
    port_info_row nathaya-haproxy.service TCP 8080 'HTTP redirect'
    port_info_row nathaya-dropbear.service TCP 109 'SSH Nathaya'
    port_info_row nathaya-dropbear.service TCP 143 'SSH Nathaya'
    port_info_row nathaya-openvpn-tcp.service TCP 1194 OpenVPN
    port_info_row nathaya-openvpn-udp.service UDP 2200 OpenVPN
    if systemctl is-active --quiet nathaya-connect.service 2>/dev/null && [[ -S /run/nathaya-connect/proxy.sock ]]; then
        port_info_row nathaya-haproxy.service TCP 8443 'HTTPS CONNECT'
    else
        printf '  %-8s  %-3s  %-3s  %s\n' 8443 TCP OFF 'HTTPS CONNECT'
    fi
    printf '\n  INTERNAL (loopback)\n'
    port_info_row nathaya-ws.service TCP 18080 'Gateway SSH WS'
    port_info_row nathaya-dropbear.service TCP 18091 'Relay SSH'
    port_info_row nathaya-nginx.service TCP 1010 'Nginx WS'
    port_info_row nathaya-nginx.service TCP 1013 'Nginx gRPC'
    for p in {10001..10008}; do port_info_row nathaya-xray.service TCP "$p" Xray; done
    for port in 7100 7200 7300; do port_info_row nathaya-badvpn.service TCP "$port" BadVPN; done
    printf '\n  Belum aktif: HTTPS 81, UDP Custom.\n'
    printf '  OpenVPN tidak dirutekan pada 443.\n\n'
    wait_submenu_navigation "$width"
}
