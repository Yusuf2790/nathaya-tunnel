#!/bin/bash

# Shared presentation and optional Telegram transport installed by Nathaya.
if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
    source /opt/nathaya/modules/common/telegram.sh
fi
if ! declare -F nathaya_account_render >/dev/null; then
    printf '%s\n' 'Nathaya account presentation module is not installed.' >&2
    exit 1
fi
NATHAYA_ACCOUNT_ACTION=create
NATHAYA_ACCOUNT_PROTOCOL=SSH

# Values below are the upstream connection/display data; formatting is shared.
nathaya_account_data() {
    nathaya_account_add 'SERVER INFORMATION' 'CITY' "${city:-Tidak diketahui}"
    nathaya_account_add 'SERVER INFORMATION' 'Host' "${domain:-}"
    nathaya_account_add 'SERVER INFORMATION' 'IP' "${IP:-}"
    nathaya_account_add 'ACCOUNT INFORMATION' 'User' "${Login:-}"
    nathaya_account_add 'ACCOUNT INFORMATION' 'Pass' "${Pass:-}"
    nathaya_account_add 'ACCOUNT INFORMATION' 'Expired' "${expi:-}"
    nathaya_account_add 'CONNECTION INFORMATION' 'OpenSSH' "2222, 2223 (SSH administrator tetap)"
    nathaya_account_add 'CONNECTION INFORMATION' 'Dropbear' "109, 143"
    nathaya_account_add 'CONNECTION INFORMATION' 'SSH WS TLS' "443"
    nathaya_account_add 'CONNECTION INFORMATION' 'Squid Proxy' "Tidak dipasang"
    nathaya_account_add 'CONNECTION INFORMATION' 'Websocket HTTP' "80, 8080"
    nathaya_account_add 'CONNECTION INFORMATION' 'Websocket HTTPS' "443"
    nathaya_account_add 'CONNECTION INFORMATION' 'badvpn' "Loopback 7100, 7200, 7300"
    nathaya_account_add 'ACCOUNT INFORMATION' 'Duration' "${Expired:-} days"
    nathaya_account_add 'PAYLOAD HTTP' 'Payload' "GET / HTTP/1.1[crlf]Host: ${domain:-}[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
    nathaya_account_add 'CONNECTION INFORMATION' 'SSH Host' "${domain:-}:2222"
}
red=$'\033[1;31m'
green=$'\033[1;32m'
NC=$'\033[0m'
IP=$(wget -qO- ifconfig.me/ip);
domain=$(cat /etc/xray/domain 2>/dev/null || hostname -f)

nathaya_account_header "CREATE SSH ACCOUNT"
read -r -p "Username : " Login
nathaya_account_require_username "$Login" || exit 1
read -r -p "Password : " Pass
read -r -p "Expired (days) : " Expired

if ! useradd -e `date -d "$Expired days" +"%Y-%m-%d"` -s /bin/false -M $Login; then
    send_telegram_notification "error" "$Login" "Failed to create user account"
    exit 1
fi
expi="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
if ! echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null; then
    send_telegram_notification "error" "$Login" "Failed to set user password"
    exit 1
fi
hariini=`date -d "0 days" +"%Y-%m-%d"`
expi=`date -d "$Expired days" +"%Y-%m-%d"`
clear
send_telegram_notification "success" "$Login"
nathaya_account_render terminal
