#!/usr/bin/env bash
# Optional shared transport. Credentials come only from trusted root-owned files.
# Telegram HTML: https://core.telegram.org/bots/api#html-style

if [[ -r /opt/nathaya/modules/common/ui.sh ]]; then
    source /opt/nathaya/modules/common/ui.sh
fi

if [[ -r "${BASH_SOURCE[0]%/*}/account-presentation.sh" ]]; then
    source "${BASH_SOURCE[0]%/*}/account-presentation.sh"
fi

nathaya_telegram_trusted_config() {
    local file="$1" check="$1" owner mode
    [[ -f "$file" && -r "$file" ]] || return 1
    # A non-root-writable parent must not allow replacement after validation.
    while :; do
        [[ ! -L "$check" ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$check" 2>/dev/null)
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
        [[ "$check" != / ]] || break
        check="${check%/*}"; [[ -n "$check" ]] || check=/
    done
    return 0
}

telegram_send_message() (
    # Subshell confines config variables, tracing, umask and cleanup traps.
    set +x
    local message="${1:-}" file request_dir response_file http_code
    local bot_token='' telegram_id='' TELEGRAM_BOT_TOKEN='' TELEGRAM_ADMIN_ID=''
    local TELEGRAM_STATUS='' token chat_id
    [[ -n "$message" ]] || return 0

    for file in /root/.vars /etc/nathaya-tunnel/config.conf; do
        if nathaya_telegram_trusted_config "$file"; then
            source "$file" >/dev/null 2>&1 || return 0
            set +x
        fi
    done
    case "${TELEGRAM_STATUS^^}" in OFF|DISABLED|0|FALSE) return 0 ;; esac
    token="${TELEGRAM_BOT_TOKEN:-$bot_token}"
    chat_id="${TELEGRAM_ADMIN_ID:-$telegram_id}"
    # Unconfigured or invalid configuration disables transport silently.
    [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || return 0
    [[ "$chat_id" =~ ^-?[0-9]+$ ]] || return 0
    command -v curl >/dev/null 2>&1 || return 1

    umask 077
    request_dir=$(mktemp -d) || return 1
    response_file="$request_dir/response"
    trap 'rm -f -- "$request_dir/chat" "$request_dir/text" "$response_file"; rmdir -- "$request_dir"' EXIT
    printf '%s' "$chat_id" >"$request_dir/chat" || return 1
    printf '%s' "$message" >"$request_dir/text" || return 1
    # The token is passed on stdin, not exposed in curl's process arguments.
    # Never print the API response, request URL, message, token or chat ID.
    http_code=$(
        printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$token" |
            curl --config - --silent --show-error \
                --connect-timeout 5 --max-time 15 \
                --output "$response_file" --write-out '%{http_code}' \
                --request POST \
                --data-urlencode "chat_id@$request_dir/chat" \
                --data-urlencode "text@$request_dir/text" \
                --data-urlencode 'parse_mode=HTML' \
                --data-urlencode 'disable_web_page_preview=true' 2>/dev/null
    ) || return 1
    [[ "$http_code" == 200 ]] &&
        grep -q '"ok":[[:space:]]*true' "$response_file"
)

# Compatibility for callers that already provide formatted HTML.
send_telegram_message() {
    telegram_send_message "${1:-}"
}

# Preserve upstream create/delete and trial signatures (trial's error is arg 4).
send_telegram_notification() {
    local error_message="${3:-}"
    [[ "${NATHAYA_ACCOUNT_ACTION:-}" != trial ]] || error_message="${4:-}"
    if declare -F nathaya_account_notify >/dev/null; then
        nathaya_account_notify "${1:-success}" "${2:-}" "$error_message"
    fi
    # Telegram must never change the result of an account operation.
    return 0
}
