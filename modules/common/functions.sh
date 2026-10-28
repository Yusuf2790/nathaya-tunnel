#!/bin/bash

# ==========================================
# NATHAYA TUNNEL - COMMON FUNCTIONS
# ==========================================

NATHAYA_CONFIG="/etc/nathaya-tunnel"
NATHAYA_CACHE="/var/cache/nathaya-tunnel"

mkdir -p "$NATHAYA_CONFIG" "$NATHAYA_CACHE"

# ---------- Baca konfigurasi ----------
load_nathaya_config() {
    DOMAIN=""

    if [[ -f "$NATHAYA_CONFIG/config.conf" ]]; then
        # shellcheck source=/dev/null
        source "$NATHAYA_CONFIG/config.conf"
    fi

    DOMAIN="${DOMAIN:-}"
}

# ---------- Informasi sistem ----------
get_os_name() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        printf '%s' "${PRETTY_NAME:-Linux}"
    else
        printf 'Linux'
    fi
}

get_hostname() {
    hostname 2>/dev/null || printf 'Tidak diketahui'
}

get_cpu_cores() {
    nproc 2>/dev/null || printf 'Tidak diketahui'
}

get_ram_info() {
    free -h 2>/dev/null | awk '/^Mem:/ {print $2 " / " $3 " terpakai"}'
}

get_swap_info() {
    free -h 2>/dev/null | awk '/^Swap:/ {print $2 " / " $3 " terpakai"}'
}

# ---------- Public IP ----------
get_public_ip() {
    local ip=""

    if command -v curl >/dev/null 2>&1; then
        ip=$(curl -4 -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null)
    fi

    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    printf '%s' "${ip:-Tidak diketahui}"
}

# ---------- City dan ISP ----------
get_location_info() {
    local current_ip="$1"
    local cache_file="$NATHAYA_CACHE/location.cache"
    local cached_ip="" cached_time="" cached_city="" cached_isp=""
    local now
    now=$(date +%s)

    CITY="Tidak diketahui"
    ISP="Tidak diketahui"

    if [[ -f "$cache_file" ]]; then
        IFS='|' read -r cached_ip cached_time cached_city cached_isp < "$cache_file"

        if [[ "$cached_ip" == "$current_ip" ]] &&
           [[ "$cached_time" =~ ^[0-9]+$ ]] &&
           (( now - cached_time < 604800 )); then
            CITY="${cached_city:-Tidak diketahui}"
            ISP="${cached_isp:-Tidak diketahui}"
            return
        fi
    fi

    if command -v curl >/dev/null 2>&1 &&
       [[ "$current_ip" != "Tidak diketahui" ]]; then
        local response
        response=$(curl -4 -fsS --connect-timeout 3 --max-time 7 \
            "https://ipwho.is/${current_ip}" 2>/dev/null)

        if [[ -n "$response" ]] && command -v python3 >/dev/null 2>&1; then
            local result
            result=$(python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
    if d.get("success", True):
        city=str(d.get("city") or "Tidak diketahui").replace("|","/")
        isp=str((d.get("connection") or {}).get("isp") or "Tidak diketahui").replace("|","/")
        print(city+"|"+isp)
    else:
        print("Tidak diketahui|Tidak diketahui")
except Exception:
    print("Tidak diketahui|Tidak diketahui")
' <<< "$response" 2>/dev/null)

            IFS='|' read -r CITY ISP <<< "$result"
        fi
    fi

    CITY="${CITY:-Tidak diketahui}"
    ISP="${ISP:-Tidak diketahui}"

    printf '%s|%s|%s|%s\n' \
        "$current_ip" "$now" "$CITY" "$ISP" > "$cache_file"
}

# ---------- Status service ----------
get_service_status() {
    local service="$1"

    if systemctl is-active --quiet "$service" 2>/dev/null; then
        printf 'ON'
    else
        printf 'OFF'
    fi
}

# ---------- Jumlah akun SSH ----------
count_ssh_accounts() {
    local count=0

    if [[ -f /etc/passwd ]]; then
        count=$(awk -F: '
            $3 >= 1000 && $3 < 60000 &&
            $7 ~ /(bash|sh)$/ &&
            $6 ~ /^\/home\// {n++}
            END {print n+0}
        ' /etc/passwd)
    fi

    printf '%s' "${count:-0}"
}

# ---------- Inisialisasi data dashboard ----------
refresh_system_info() {
    load_nathaya_config

    OS_NAME=$(get_os_name)
    HOST_NAME=$(get_hostname)
    CPU_CORES=$(get_cpu_cores)
    RAM_INFO=$(get_ram_info)
    SWAP_INFO=$(get_swap_info)
    PUBLIC_IP=$(get_public_ip)

    get_location_info "$PUBLIC_IP"

    SSH_STATUS=$(get_service_status ssh)
    XRAY_STATUS=$(get_service_status xray)

    SSH_TOTAL=$(count_ssh_accounts)
}
