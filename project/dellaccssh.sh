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
NATHAYA_ACCOUNT_PROTOCOL=SSH

# Valid Script
ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")


    

# colors
green=$'\033[1;32m'
        red=$'\033[1;31m'
        neutral=$'\033[0m'
        blue=$'\033[1;36m'
        orange=$'\033[38;5;208m'
        yellow=$'\033[38;5;208m'
        purple=$'\033[1;36m'
        bold_white=$'\033[1;37m'
        normal=$'\033[0m'
        pink=$'\033[1;36m'
# variable
domain=$(cat /etc/xray/domain 2>/dev/null || hostname -f)
clear



account_count=$(grep -c -E "^### " "/etc/ssh/.ssh.db")
if [[ ${account_count} == '0' ]]; then
    echo ""
    echo "         Tidak ada akun yang tersedia untuk dihapus!"
    echo ""
    exit 0
fi

echo -e "${yellow}Pilih cara untuk menghapus akun:${reset}"
echo -e "${green}1) Berdasarkan nomor${reset}"
echo -e "${green}2) Ketik username secara manual${reset}"
# Auto-select option 2: enter username manually
delete_choice="2"
echo "Auto-selected: 2) Ketik username secara manual"

case $delete_choice in
    1)
        clear
        nathaya_account_header "DELETE SSH"
        echo " ╭────┬━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┬━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮"
        echo " │ No │ Username           │  Days Left  │"
        echo " ├────┼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┤"
        grep -E "^### " "/etc/ssh/.ssh.db" | awk '{
            cmd = "date -d \"" $3 "\" +%s"
            cmd | getline exp_timestamp
            close(cmd)
            current_timestamp = systime()
            days_left = int((exp_timestamp - current_timestamp) / 86400)
            if (days_left < 0) days_left = 0
            printf " │ %-2d │ %-18s │ %-11s │\n", NR, $2, days_left " days"
        }'
        echo " ╰────┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯"
        echo ""
        
        until [[ $client_number =~ ^[0-9]+$ && $client_number -ge 1 && $client_number -le $account_count ]]; do
            read -rp "Pilih nomor akun [1-${account_count}]: " client_number
        done
        
        user=$(grep -E "^### " "/etc/ssh/.ssh.db" | cut -d ' ' -f 2 | sed -n "${client_number}"p)
        nathaya_account_require_username "$user" || exit 1
        exp=$(grep -E "^### " "/etc/ssh/.ssh.db" | cut -d ' ' -f 3 | sed -n "${client_number}"p)
        ;;
    2)
        read -rp "Masukkan username: " user
        nathaya_account_require_username "$user" || exit 1
        if ! grep -qE "^### $user " "/etc/ssh/.ssh.db"; then
            echo "Username tidak ditemukan"
            exit 1
        fi
        exp=$(grep -E "^### $user " "/etc/ssh/.ssh.db" | cut -d ' ' -f 3)
        ;;
    *)
        echo "Pilihan tidak valid"
        exit 1
        ;;
esac



# Deletion process
if userdel -f $user 2>/dev/null; then
    sed -i "/^### $user /d" /etc/ssh/.ssh.db
    rm -f /etc/xray/log-createssh-$user.log
    
    clear
    send_telegram_notification "success" "$user"
    nathaya_account_render terminal
else
    echo "Gagal menghapus akun. Silakan periksa apakah username sudah benar."
    send_telegram_notification "error" "$user" "Gagal menghapus akun dari sistem."
fi


