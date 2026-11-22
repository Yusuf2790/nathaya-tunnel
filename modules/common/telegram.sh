#!/usr/bin/env bash

NATHAYA_TELEGRAM_CONFIG="/etc/nathaya-tunnel/config.conf"

# Existing config/chat, HTML <pre> for aligned details. Secrets travel via stdin.
telegram_send_message() (
    set +x
    local message="${1:-}"
    local TELEGRAM_STATUS=OFF TELEGRAM_BOT_TOKEN= TELEGRAM_ADMIN_ID=
    [[ -r "$NATHAYA_TELEGRAM_CONFIG" && -n "$message" ]] || return 2
    # shellcheck source=/dev/null
    source "$NATHAYA_TELEGRAM_CONFIG" >/dev/null 2>&1 || return 2
    [[ "$TELEGRAM_STATUS" == ON && "$TELEGRAM_BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ &&
       "$TELEGRAM_ADMIN_ID" =~ ^-?[0-9]+$ ]] || return 2
    printf '%s\n%s\n%s' "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_ADMIN_ID" "$message" |
        /usr/bin/python3 -I -c '
import html
import json
import sys
import urllib.parse
import urllib.request

try:
    token, chat, message = sys.stdin.read().split("\n", 2)
    data = urllib.parse.urlencode({"chat_id": chat, "parse_mode": "HTML",
                                  "text": "<pre>" + html.escape(message, quote=False) + "</pre>"}).encode()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open("https://api.telegram.org/bot" + token + "/sendMessage", data, timeout=15) as response:
        sys.exit(0 if json.loads(response.read(1048576)).get("ok") is True else 7)
except Exception:
    sys.exit(7)
' 2>/dev/null
)
