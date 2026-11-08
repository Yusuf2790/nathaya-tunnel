#!/bin/bash

# Shared presentation and optional Telegram transport installed by Nathaya.
if [[ -r /opt/nathaya/modules/common/telegram.sh ]]; then
    source /opt/nathaya/modules/common/telegram.sh
fi
if ! declare -F nathaya_account_render >/dev/null; then
    printf '%s\n' 'Nathaya account presentation module is not installed.' >&2
    exit 1
fi
NATHAYA_ACCOUNT_ACTION=renew
NATHAYA_ACCOUNT_PROTOCOL=SSH

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
# variables
domain=$(cat /etc/xray/domain 2>/dev/null || hostname -f)
clear
nathaya_account_header "RENEW SSH"

account_count=$(grep -c -E "^### " "/etc/ssh/.ssh.db")
if [[ ${account_count} == '0' ]]; then
    echo ""
    echo "  Tidak ada data pengguna yang tersedia"
    echo ""
    exit 0
fi

# Prompt for username directly
read -rp "Masukkan nama pengguna: " user
nathaya_account_require_username "$user" || exit 1

# Check if user exists
if ! grep -qE "^### $user " "/etc/ssh/.ssh.db"; then
    echo ""
    echo "Nama pengguna tidak ditemukan"
    echo ""
    exit 1
fi

# Get current expiration date
exp=$(grep -E "^### $user " "/etc/ssh/.ssh.db" | cut -d ' ' -f 3)

clear
echo -e "${yellow}Memperbarui akun SSH $user${reset}"
echo ""

# Read expiration date from database
old_exp=$(grep -E "^### $user " "/etc/ssh/.ssh.db" | cut -d ' ' -f 3)

# Calculate remaining active days
days_left=$((($(date -d "$old_exp" +%s) - $(date +%s)) / 86400))

echo "Sisa masa aktif: $days_left hari"

while true; do
    read -r -p "Tambahkan masa aktif (hari): " active_days
    if [[ "$active_days" =~ ^[0-9]+$ ]]; then
        break
    else
        echo "Input harus berupa angka positif."
    fi
done

while true; do
    read -r -p "Batas perangkat (IP): " ip_limit
    if [[ "$ip_limit" =~ ^[1-9][0-9]*$ ]]; then
        break
    else
        echo "Input harus berupa angka positif lebih dari 0."
    fi
done

if [ ! -d /etc/ssh ]; then
    mkdir -p /etc/ssh
fi

# Remove old entries before updating to prevent duplicates
sed -i "/^### $user /d" /etc/ssh/.ssh.db

echo "${ip_limit}" >/etc/ssh/${user}

# Calculate new expiration date
new_exp=$(date -d "$old_exp +${active_days} days" +"%Y-%m-%d")

# Add updated entry
echo "### ${user} ${new_exp}" >>/etc/ssh/.ssh.db

# Update the user's expiration date
chage -E "$new_exp" "$user"

clear
send_telegram_notification "success" "$user"
nathaya_account_render terminal
