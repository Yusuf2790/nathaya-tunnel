#!/bin/bash

# ==========================================
# NATHAYA TUNNEL - COMMON FUNCTIONS
# ==========================================

NATHAYA_CONFIG="/etc/nathaya-tunnel"
NATHAYA_CACHE="/var/cache/nathaya-tunnel"

# Cache creation is deferred until a location lookup, not when sourcing the UI.

# Only optional menu cron jobs use this interface; share the installer's ledger.
nathaya_cron() (
    set +x
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    umask 077
    [[ $EUID -eq 0 && $# -eq 2 ]] || {
        echo 'nathaya_cron requires root and: set|remove PATH.' >&2; return 1;
    }
    local action="$1" target="$2"
    case "$action" in set|remove) ;; *) return 1 ;; esac
    case "$target" in
        /etc/cron.d/backup|/etc/cron.d/autokill|/etc/cron.d/daily_reboot) ;;
        *) echo 'Refusing a cron target outside the closed list.' >&2; return 1 ;;
    esac
    local state=/var/lib/nathaya-tunnel
    local ledger="$state/owned-files.tsv" lock="$state/owned-files.tsv.lock"
    local directory owner mode links old_hash digest cron_lock_fd
    local cron_stage='' ledger_stage=''
    trap '[[ -z "$cron_stage" ]] || rm -f -- "$cron_stage"; [[ -z "$ledger_stage" ]] || rm -f -- "$ledger_stage"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Check every ancestor, not just the two final directories.
    for directory in / /etc /etc/cron.d /var /var/lib "$state"; do
        [[ -d "$directory" && ! -L "$directory" ]] || {
            echo 'Refusing unsafe cron/ownership directory ancestry.' >&2; return 1;
        }
        read -r owner mode < <(stat -c '%u %a' -- "$directory") || return 1
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
            (( (8#$mode & 0022) == 0 )) || {
            echo 'Cron/ownership directories must be root-owned and not group/other-writable.' >&2; return 1;
        }
    done
    # Keep a stable lock inode while the ledger is atomically replaced.
    if [[ ! -e "$lock" && ! -L "$lock" ]]; then
        (set -o noclobber; : > "$lock") || return 1
    fi
    [[ -f "$lock" && ! -L "$lock" && $(stat -c '%u:%g:%a:%h' -- "$lock") == 0:0:600:1 ]] || {
        echo 'Ownership lock must be a root:root 0600 single-link regular file.' >&2; return 1;
    }
    exec {cron_lock_fd}>>"$lock" || return 1
    flock -x "$cron_lock_fd" || return 1
    [[ -f "$ledger" && ! -L "$ledger" && $(stat -c '%u:%g:%a:%h' -- "$ledger") == 0:0:600:1 ]] || {
        echo 'An existing root:root 0600 single-link ownership ledger is required.' >&2; return 1;
    }
    awk -F '\t' '
        NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/ ||
        $2 !~ /^\/[A-Za-z0-9_+.@:\/-]+$/ || $2 ~ /\/\// ||
        $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /\/$/ || seen[$2]++ { bad = 1; exit }
        END { exit bad }
    ' "$ledger" || { echo 'Invalid ownership ledger; no cron changes made.' >&2; return 1; }
    old_hash=$(awk -F '	' -v path="$target" '$2 == path {print tolower($1)}' "$ledger") || return 1
    if [[ -e "$target" || -L "$target" ]]; then
        [[ -n "$old_hash" && -f "$target" && ! -L "$target" ]] || {
            echo 'Refusing an unowned or unsafe existing cron target.' >&2; return 1;
        }
        read -r owner mode links < <(stat -c '%u %a %h' -- "$target") || return 1
        [[ "$owner" == 0 && "$links" == 1 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
            (( (8#$mode & 0022) == 0 )) || {
            echo 'Existing cron target is not a trusted root single-link regular file.' >&2; return 1;
        }
        digest=$(sha256sum -- "$target") || return 1
        [[ "${digest%% *}" == "$old_hash" ]] || {
            echo 'Owned cron target changed; manual review required.' >&2; return 1;
        }
    elif [[ "$action" == remove && -z "$old_hash" ]]; then
        return 0
    fi

    ledger_stage=$(mktemp "$state/.owned-files.XXXXXXXX") || return 1
    awk -F '	' -v path="$target" '$2 != path' "$ledger" > "$ledger_stage" || return 1
    if [[ "$action" == set ]]; then
        cron_stage=$(mktemp /etc/cron.d/.nathaya-cron.XXXXXXXX) || return 1
        cat > "$cron_stage" || return 1
        chown root:root "$cron_stage" && chmod 644 "$cron_stage" || return 1
        digest=$(sha256sum -- "$cron_stage") || return 1
        printf '%s\t%s\n' "${digest%% *}" "$target" >> "$ledger_stage" || return 1
    fi
    chown root:root "$ledger_stage" && chmod 600 "$ledger_stage" || return 1
    if [[ "$action" == set ]]; then
        # Publish ownership first, so interruption cannot create unrecorded cron.
        mv -fT -- "$ledger_stage" "$ledger" || return 1
        ledger_stage=''
        mv -fT -- "$cron_stage" "$target" || return 1
        cron_stage=''
    else
        # A missing owned target may clear its stale row; other rows stay intact.
        rm -f -- "$target" || return 1
        mv -fT -- "$ledger_stage" "$ledger" || return 1
        ledger_stage=''
    fi
)

# Read values as data, never source account databases or credential files.
nathaya_config_value() {
    local file="$1" key="$2"
    [[ -r "$file" ]] || return 0
    awk -v key="$key" '
        index($0, key "=") == 1 {
            value=substr($0, length(key)+2)
            sub(/^[\042\047]/, "", value)
            sub(/[\042\047]$/, "", value)
        }
        END {printf "%s", value}
    ' "$file"
}

load_nathaya_config() {
    DOMAIN=""
    [[ -r /etc/xray/domain ]] && IFS= read -r DOMAIN < /etc/xray/domain
    DOMAIN="$(nathaya_plain_text "$DOMAIN")"
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
    free -h 2>/dev/null | awk '/^Mem:/ {print $3 " / " $2}'
}

get_swap_info() {
    free -h 2>/dev/null | awk '/^Swap:/ {print $3 " / " $2}'
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

    if mkdir -p "$NATHAYA_CACHE" 2>/dev/null; then
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

# ---------- Upstream account database counts (read-only) ----------
count_accounts() {
    local protocol="$1" db
    case "$protocol" in
        ssh) db=/etc/ssh/.ssh.db ;;
        vmess|vless|trojan|shadowsocks) db="/etc/xray/$protocol/.$protocol.db" ;;
        *) printf '0'; return ;;
    esac
    if [[ -r "$db" ]]; then
        awk '$1 == "###" {n++} END {print n+0}' "$db"
    else
        printf '0'
    fi
}

count_ssh_accounts() { count_accounts ssh; }

get_xray_status() {
    local protocol
    # The installer creates one service instance per protocol, not xray.service.
    for protocol in vmess vless trojan shadowsocks; do
        if ! systemctl is-active --quiet "$protocol@config" 2>/dev/null; then
            printf 'OFF'
            return
        fi
    done
    printf 'ON'
}

refresh_telegram_status() {
    local token admin enabled
    TELEGRAM_NOTIFICATION_STATUS=OFF
    TELEGRAM_MANAGEMENT_STATUS=OFF
    token=$(nathaya_config_value "$NATHAYA_CONFIG/config.conf" TELEGRAM_BOT_TOKEN)
    admin=$(nathaya_config_value "$NATHAYA_CONFIG/config.conf" TELEGRAM_ADMIN_ID)
    enabled=$(nathaya_config_value "$NATHAYA_CONFIG/config.conf" TELEGRAM_STATUS)
    if [[ "$enabled" == ON && -n "$token" && -n "$admin" ]]; then
        TELEGRAM_NOTIFICATION_STATUS=ON
    elif [[ -z "$enabled" ]]; then
        token=$(nathaya_config_value /root/.vars bot_token)
        admin=$(nathaya_config_value /root/.vars telegram_id)
        [[ -n "$token" && -n "$admin" ]] && TELEGRAM_NOTIFICATION_STATUS=ON
    fi
    # Upstream does not ship a management bot. Never mark it active by default.
    if [[ -x /usr/bin/botserver ]] && systemctl is-active --quiet botserver 2>/dev/null; then
        TELEGRAM_MANAGEMENT_STATUS=ON
    fi
    return 0
}

# ---------- Dashboard data ----------
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
    XRAY_STATUS=$(get_xray_status)
    SSH_TOTAL=$(count_accounts ssh)
    VMESS_TOTAL=$(count_accounts vmess)
    VLESS_TOTAL=$(count_accounts vless)
    TROJAN_TOTAL=$(count_accounts trojan)
    SHADOWSOCKS_TOTAL=$(count_accounts shadowsocks)
    refresh_telegram_status
}
