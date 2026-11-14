#!/bin/bash

# ==========================================
# NATHAYA TUNNEL - COMMON FUNCTIONS
# ==========================================

source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/bootstrap.sh" || { return 1 2>/dev/null || exit 1; }

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

    if mkdir -p -- "$NATHAYA_CACHE" 2>/dev/null; then
        printf '%s|%s|%s|%s\n' \
            "$current_ip" "$now" "$CITY" "$ISP" > "$cache_file" 2>/dev/null || true
    fi
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

# Runtime state, not menu availability. No probes run merely by sourcing this file.
get_ssh_status() {
    if systemctl is-active --quiet ssh.service 2>/dev/null ||
       systemctl is-active --quiet ssh.socket 2>/dev/null; then printf 'ON'; else printf 'OFF'; fi
}
get_xray_status() {
    local protocol
    for protocol in vmess vless trojan shadowsocks; do
        if ! systemctl is-active --quiet "$protocol@config.service" 2>/dev/null; then printf 'OFF'; return; fi
    done
    printf 'ON'
}
get_nathaya_version() {
    local identity='unknown'
    if [[ -r "$NATHAYA_BASE/VERSION" ]]; then IFS= read -r identity < "$NATHAYA_BASE/VERSION" || identity=unknown; fi
    [[ "$identity" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || identity=unknown
    printf '%s' "$identity"
}
count_ssh_accounts() {
    [[ -r "$NATHAYA_SSH_DB" ]] || { printf '0'; return; }
    awk -F '|' 'NF==7 && length($1)>=4 && length($1)<=32 && $1 ~ /^[a-z0-9]+$/ &&
        ($7=="regular" || $7=="trial") && $5 ~ /^(active|locked|expired)$/ {n++} END {print n+0}' "$NATHAYA_SSH_DB"
}
count_xray_accounts() {
    local protocol="$1"
    case "$protocol" in vmess|vless|trojan) ;; *) printf '?'; return ;; esac
    python3 -I -B -c '
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    if not p.exists(): print(0)
    else:
        config = json.loads(p.read_text())
        users = {item.get("id", item.get("password"))
                 for inbound in config["inbounds"] if inbound.get("protocol") == sys.argv[2]
                 for item in inbound.get("settings", {}).get("clients", [])}
        users.discard(None)
        print(len(users))
except (OSError, ValueError, KeyError, TypeError): print("?")
' "$NATHAYA_CONFIG/xray/$protocol/config.json" "$protocol" 2>/dev/null || printf '?'
}

# ---------- Inisialisasi data dashboard ----------
refresh_system_info() {
    load_nathaya_config || true

    OS_NAME=$(get_os_name)
    HOST_NAME=$(get_hostname)
    CPU_CORES=$(get_cpu_cores)
    RAM_INFO=$(get_ram_info)
    SWAP_INFO=$(get_swap_info)
    PUBLIC_IP=$(get_public_ip)

    get_location_info "$PUBLIC_IP"

    SSH_STATUS=$(get_ssh_status)
    XRAY_STATUS=$(get_xray_status)
    SCRIPT_VERSION=$(get_nathaya_version)
    SSH_TOTAL=$(count_ssh_accounts)
    VMESS_TOTAL=$(count_xray_accounts vmess)
    VLESS_TOTAL=$(count_xray_accounts vless)
    TROJAN_TOTAL=$(count_xray_accounts trojan)
}
