#!/bin/bash

# Shared presentation and optional Telegram transport installed by Nathaya.
if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
    source /opt/nathaya/modules/common/telegram.sh
fi
if ! declare -F nathaya_account_render >/dev/null; then
    printf '%s\n' 'Nathaya account presentation module is not installed.' >&2
    exit 1
fi
NATHAYA_ACCOUNT_ACTION=delete
NATHAYA_ACCOUNT_PROTOCOL=VMESS

# Valid Script
ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")


    
# colors
red=$'\033[1;31m'
green=$'\033[1;32m'
yellow=$'\033[38;5;208m'
blue=$'\033[1;36m'
purple=$'\033[1;36m'
cyan=$'\033[1;36m'
white=$'\033[1;37m'
reset=$'\033[0m'
# Function to print rainbow text

# variables
domain=$(cat /etc/xray/domain 2>/dev/null || hostname -f)
clear
read -r -p "User: " -e user
nathaya_account_require_username "$user" || exit 1

nathaya_account_header "DELETE VMESS"
echo -e "Remarks      : ${user}"
account_count=$(grep -c -E "^### " "/etc/xray/vmess/.vmess.db")
if [[ ${account_count} == '0' ]]; then
    echo ""
    echo "  Tidak ada akun yang tersedia untuk dihapus!"
    echo ""
    exit 0
fi


delete_choice="2"

if [[ $delete_choice == "1" ]]; then
clear
        nathaya_account_header "DELETE VMESS"
    echo " ╭────┬━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┬━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮"
    echo " │ no │ username           │     exp     │"
    echo " ├────┼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┤"
    grep -E "^### " "/etc/xray/vmess/.vmess.db" | awk '{
        cmd = "date -d \"" $3 "\" +%s"
        cmd | getline exp_timestamp
        close(cmd)
        current_timestamp = systime()
        days_left = int((exp_timestamp - current_timestamp) / 86400)
        if (days_left < 0) days_left = 0
        printf " │ %-2d │ %-18s │ %-11s │\n", NR, $2, days_left " days"
    }'
    echo " ╰────┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯"
    
fi

case $delete_choice in
    1)
        until [[ ${account_number} -ge 1 && ${account_number} -le ${account_count} ]]; do
            read -rp "Pilih nomor akun [1-${account_count}]: " account_number
        done
        user=$(grep -E "^### " "/etc/xray/vmess/.vmess.db" | cut -d ' ' -f 2 | sed -n "${account_number}p")
        nathaya_account_require_username "$user" || exit 1
        exp=$(grep -E "^### " "/etc/xray/vmess/.vmess.db" | cut -d ' ' -f 3 | sed -n "${account_number}p")
        echo ""
        nathaya_account_header "DELETE VMESS"
        echo -e "Username     : ${green}$user${reset}"
        echo -e "Expired      : ${yellow}$exp${reset}"
        echo ""
        sleep 2
        ;;
    2)
        # read -rp "enter username: " user
        if ! grep -qE "^### $user " "/etc/xray/vmess/.vmess.db"; then
            echo "Username tidak ditemukan"
            exit 1
        fi
        exp=$(grep -E "^### $user " "/etc/xray/vmess/.vmess.db" | cut -d ' ' -f 3)
        echo "Anda memilih: $user (Expired: $exp)"
        ;;
    *)
        echo "Pilihan tidak valid"
        exit 1
        ;;
esac

sed -i "/^### $user $exp/,/^},{/d" /etc/xray/vmess/config.json
sed -i "/^### $user $exp/d" /etc/xray/vmess/.vmess.db
if [ -f "/etc/xray/vmess/log-create-${user}.log" ]; then
    rm -f "/etc/xray/vmess/log-create-${user}.log"
    rm -f "/etc/xray/vmess/${user}-non.json"
    rm -f "/etc/xray/vmess/${user}-tls.json"
    rm -f "/etc/xray/vmess/${user}-grpc.json"
fi

if ! systemctl restart vmess@config >/dev/null 2>&1; then
    echo "Warning: Failed to restart vmess service. Please check system logs for more information."
    echo "However, the account has been successfully removed from the database."
fi

clear
send_telegram_notification "success" "$user"
nathaya_account_render terminal
