#!/usr/bin/env bash

NATHAYA_TELEGRAM_CONFIG="/etc/nathaya-tunnel/config.conf"
NATHAYA_TELEGRAM_LOG="/opt/nathaya/logs/telegram.log"

telegram_send_message() {
    local message="${1:-}"
    local response_file http_code

    [[ -r "$NATHAYA_TELEGRAM_CONFIG" ]] || return 1
    [[ -n "$message" ]] || return 1

    source "$NATHAYA_TELEGRAM_CONFIG"

    [[ "${TELEGRAM_STATUS:-OFF}" == "ON" ]] || return 2
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] || return 3
    [[ "${TELEGRAM_ADMIN_ID:-}" =~ ^-?[0-9]+$ ]] || return 4
    command -v curl >/dev/null 2>&1 || return 5

    response_file="$(mktemp)" || return 6
    chmod 600 "$response_file"

    http_code="$(
        curl -sS \
            --connect-timeout 5 \
            --max-time 15 \
            -o "$response_file" \
            -w '%{http_code}' \
            -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            --data-urlencode "chat_id=${TELEGRAM_ADMIN_ID}" \
            --data-urlencode "text=${message}" \
            --data-urlencode "parse_mode=${parse_mode:-HTML}" \
            2>/dev/null
    )" || http_code="000"

    if [[ "$http_code" == "200" ]] &&
       grep -q '"ok":[[:space:]]*true' "$response_file"; then
        rm -f "$response_file"
        return 0
    fi

    {
        printf '%s Telegram send failed; HTTP=%s\n' \
            "$(date '+%F %T')" "${http_code:-unknown}"
    } >> "$NATHAYA_TELEGRAM_LOG"
    chmod 600 "$NATHAYA_TELEGRAM_LOG" 2>/dev/null || true

    rm -f "$response_file"
    return 7
}
