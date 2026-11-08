#!/bin/bash
# Extracted from the Alrescha vmess submenu; account formats and operations retained.
# Only palette/bootstrap, return navigation and the SSH selection capture are adapted.

convert_size() {
    local -i bytes=$1
    if [[ $bytes -lt 1024 ]]; then
        echo "${bytes}B"
    elif [[ $bytes -lt 1048576 ]]; then
        echo "$(((bytes + 1023) / 1024))KB"
    elif [[ $bytes -lt 1073741824 ]]; then
        echo "$(((bytes + 1048575) / 1048576))MB"
    else
        echo "$(((bytes + 1073741823) / 1073741824))GB"
    fi
}

vmess_members() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                      DAFTAR MEMBER vmess${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/vmess/.vmess.db" ]; then
        echo -e "   ${red}Tidak ada akun vmess yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
        echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    echo -e "Username         | Sisa      | Kuota     | IP    | Penggunaan | Status"
    echo -e "══════════════════════════════════════════════════════════════════════"

    grep -E "^### " "/etc/xray/vmess/.vmess.db" | while read -r line; do
        user=$(echo "$line" | awk '{print $2}')
        exp=$(echo "$line" | awk '{print $3}')
        current_timestamp=$(date +%s)
        exp_timestamp=$(date -d "$exp" +%s)
        days_left=$(((exp_timestamp - current_timestamp) / 86400))

        if [ $days_left -lt 0 ]; then
            status_text="KADALUARSA"
            status_color="${red}"
            exp_display="${days_left} hari"
        elif [ $days_left -le 3 ]; then
            status_text="SEGERA HABIS"
            status_color="${yellow}"
            exp_display="${days_left} hari"
        else
            status_text="AKTIF"
            status_color="${green}"
            exp_display="${days_left} hari"
        fi

        quota_file="/etc/xray/vmess/${user}"
        ip_limit_file="/etc/xray/vmess/${user}IP"
        usage_file="/etc/xray/vmess/usage/${user}"

        quota="Unlimited"
        if [ -f "$quota_file" ]; then
            quota_raw=$(cat "$quota_file")
            if [ -n "$quota_raw" ] && [ "$quota_raw" != "0" ]; then
                quota=$(convert_size "$quota_raw")
            fi
        fi

        ip_limit="Unlimited"
        if [ -f "$ip_limit_file" ]; then
            ip_limit_raw=$(cat "$ip_limit_file")
            if [ -n "$ip_limit_raw" ] && [ "$ip_limit_raw" != "0" ]; then
                ip_limit="$ip_limit_raw"
            fi
        fi

        usage="0B"
        if [ -f "$usage_file" ]; then
            usage_raw=$(cat "$usage_file")
            if [ -n "$usage_raw" ] && [ "$usage_raw" != "0" ]; then
                usage=$(convert_size "$usage_raw")
            fi
        fi

        printf "%-16s | %-9s | %-9s | %-5s | %-10s | " "$user" "$exp_display" "$quota" "$ip_limit" "$usage"
        echo -e "${status_color}${status_text}${neutral}"
    done

    total_count=$(grep -cE "^### " "/etc/xray/vmess/.vmess.db")
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${yellow}Total Akun vmess : ${green}${total_count}${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

change_vmess_limit() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                     UBAH LIMIT VMESS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/vmess/.vmess.db" ]; then
        echo -e "   ${red}Tidak ada akun VMESS yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e " Daftar Akun VMESS:"
    account_count=$(grep -cE "^### " "/etc/xray/vmess/.vmess.db")
    if [ $account_count -eq 0 ]; then
        echo -e "   ${red}Tidak ada akun VMESS yang aktif.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    echo -e "No  | Username           | Exp (hari)"
    echo -e "─────────────────────────────────────────────"
    grep -E "^### " "/etc/xray/vmess/.vmess.db" | awk '{
        cmd = "date -d \"" $3 "\" +%s"
        cmd | getline exp_timestamp
        close(cmd)
        current_timestamp = systime()
        days_left = int((exp_timestamp - current_timestamp) / 86400)
        if (days_left < 0) days_left = 0
        printf "%-3d | %-18s | %-10s\n", NR, $2, days_left " hari"
    }'
    echo -e "─────────────────────────────────────────────"
    echo -e ""
    read -p " Pilih nomor akun [ 1-$account_count ] atau [ x ] untuk batal: " account_number

    if [[ "$account_number" =~ ^[xX]$ ]]; then
        echo -e ""
        echo -e "${yellow}Batal mengubah limit. Kembali ke menu...${neutral}"
        echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    # Check if input is a number
    if ! [[ "$account_number" =~ ^[0-9]+$ ]]; then
        echo -e "   ${red}Error: Input harus berupa angka.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    # Check if account number is valid
    if [ "$account_number" -lt 1 ] || [ "$account_number" -gt "$account_count" ]; then
        echo -e "   ${red}Error: Nomor akun tidak valid.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    username=$(grep -E "^### " "/etc/xray/vmess/.vmess.db" | cut -d ' ' -f 2 | sed -n "${account_number}p")

    if [ -z "$username" ]; then
        echo -e "   ${red}Nomor akun tidak valid.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    echo -e ""
    echo -e "Mengubah limit untuk akun: ${green}$username${neutral}"
    echo -e ""
    read -p "Masukkan limit quota baru (dalam GB, 0 untuk unlimited): " new_quota
    read -p "Masukkan limit IP baru (0 untuk unlimited): " new_ip_limit

    # Validate input
    if ! [[ "$new_quota" =~ ^[0-9]+$ ]]; then
        echo -e "${red}Error: Limit quota harus berupa angka.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    if ! [[ "$new_ip_limit" =~ ^[0-9]+$ ]]; then
        echo -e "${red}Error: Limit IP harus berupa angka.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    # Convert quota to bytes
    new_quota_bytes=$((new_quota * 1024 * 1024 * 1024))

    # Update quota and IP limit files
    echo "${new_quota_bytes}" >"/etc/xray/vmess/${username}"
    echo "${new_ip_limit}" >"/etc/xray/vmess/${username}IP"

    # Check if update was successful
    echo -e ""
    if [ $? -eq 0 ]; then
        echo -e "${green}Limit untuk akun $username berhasil diubah.${neutral}"
        echo -e "Quota baru: ${new_quota} GB"
        echo -e "Limit IP baru: ${new_ip_limit}"
    else
        echo -e "${red}Gagal mengubah limit untuk akun $username.${neutral}"
        echo -e "Pastikan Anda memiliki izin yang cukup dan coba lagi."
    fi

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

vmess_details() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                      DETAIL AKUN VMESS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/vmess/.vmess.db" ]; then
        echo -e "   ${red}Tidak ada akun VMESS yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    account_counter=1
    while IFS= read -r line; do
    if [[ $line == \#\#\#* ]]; then
            user=$(echo $line | cut -d ' ' -f 2)
            exp=$(echo $line | cut -d ' ' -f 3)
            uuid=$(echo $line | cut -d ' ' -f 4)
            
            # Calculate days left
            current_timestamp=$(date +%s)
            exp_timestamp=$(date -d "$exp" +%s)
            days_left=$(( (exp_timestamp - current_timestamp) / 86400 ))
            
            if [ $days_left -lt 0 ]; then
                status="${red}KADALUARSA${neutral}"
                exp_display="$exp (${days_left} hari)"
            elif [ $days_left -le 3 ]; then
                status="${yellow}SEGERA HABIS${neutral}"
                exp_display="$exp (${days_left} hari)"
            else
                status="${green}AKTIF${neutral}"
                exp_display="$exp (${days_left} hari)"
            fi

            echo -e ""
            echo -e "${yellow}═══ AKUN #${account_counter} ═══${neutral}"
            echo -e "   Username      : ${green}$user${neutral}"
            echo -e "   Tanggal Exp   : ${green}$exp_display${neutral}"
            echo -e "   Status        : $status"
            echo -e "   UUID          : ${green}$uuid${neutral}"

            if [ -f "/etc/xray/vmess/${user}" ]; then
                quota=$(cat /etc/xray/vmess/${user})
                if [ -n "$quota" ] && [ "$quota" != "0" ]; then
                    quota_readable=$(convert_size $quota)
                    echo -e "   Quota         : ${green}$quota_readable${neutral}"
                else
                    echo -e "   Quota         : ${green}Unlimited${neutral}"
                fi
            else
                echo -e "   Quota         : ${green}Unlimited${neutral}"
            fi

            if [ -f "/etc/xray/vmess/${user}IP" ]; then
                ip_limit=$(cat /etc/xray/vmess/${user}IP)
                if [ -n "$ip_limit" ] && [ "$ip_limit" != "0" ]; then
                    echo -e "   Limit IP      : ${green}$ip_limit${neutral}"
                else
                    echo -e "   Limit IP      : ${green}Unlimited${neutral}"
                fi
            else
                echo -e "   Limit IP      : ${green}Unlimited${neutral}"
            fi
            
            # Show current usage
            if [ -f "/etc/xray/vmess/usage/${user}" ]; then
                usage_raw=$(cat /etc/xray/vmess/usage/${user})
                if [ -n "$usage_raw" ] && [ "$usage_raw" != "0" ]; then
                    usage_readable=$(convert_size $usage_raw)
                    echo -e "   Penggunaan    : ${green}$usage_readable${neutral}"
                else
                    echo -e "   Penggunaan    : ${green}0B${neutral}"
                fi
            else
                echo -e "   Penggunaan    : ${green}0B${neutral}"
            fi

            echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

            ((account_counter++))
        fi
    done <"/etc/xray/vmess/.vmess.db"

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}
custom_vmess_uuid() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                     CUSTOM UUID VMESS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/vmess/.vmess.db" ]; then
        echo -e "   ${red}Tidak ada akun VMESS yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    account_count=$(grep -cE "^### " "/etc/xray/vmess/.vmess.db")
    if [ $account_count -eq 0 ]; then
        echo -e "   ${red}Tidak ada akun VMESS yang aktif.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e "No  | Username           | Exp (hari)"
    echo -e "─────────────────────────────────────────────"
    grep -E "^### " "/etc/xray/vmess/.vmess.db" | awk '{
        cmd = "date -d \"" $3 "\" +%s"
        cmd | getline exp_timestamp
        close(cmd)
        current_timestamp = systime()
        days_left = int((exp_timestamp - current_timestamp) / 86400)
        if (days_left < 0) days_left = 0
        printf "%-3d | %-18s | %-10s\n", NR, $2, days_left " hari"
    }'
    echo -e "─────────────────────────────────────────────"
    echo -e ""
    read -p " Pilih nomor akun [ 1-$account_count ] atau [ x ] untuk batal: " account_number

    if [[ "$account_number" =~ ^[xX]$ ]]; then
        echo -e ""
        echo -e "${yellow}Batal mengubah UUID. Kembali ke menu...${neutral}"
        echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    # Check if input is a number
    if ! [[ "$account_number" =~ ^[0-9]+$ ]]; then
        echo -e "   ${red}Error: Input harus berupa angka.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    # Check if account number is valid
    if [ "$account_number" -lt 1 ] || [ "$account_number" -gt "$account_count" ]; then
        echo -e "   ${red}Error: Nomor akun tidak valid.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    user=$(grep -E "^### " "/etc/xray/vmess/.vmess.db" | cut -d ' ' -f 2 | sed -n "${account_number}p")

    if [ -z "$user" ]; then
        echo -e "   ${red}Nomor akun tidak valid.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e ""
    echo -e "Mengubah UUID untuk akun: ${green}$user${neutral}"
    echo -e ""
    while true; do
        read -p " UUID baru (minimal 6 karakter): " new_uuid
        if [[ ${#new_uuid} -ge 6 && "$new_uuid" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            break
        else
            echo -e "${red} UUID harus minimal 6 karakter dan hanya boleh berisi huruf, angka, _ atau -${neutral}"
        fi
    done

    if [ -z "$new_uuid" ]; then
        echo -e "${red}Error: UUID tidak boleh kosong.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    # Update UUID in config.json
    user_data=$(cat /etc/xray/vmess/.vmess.db | grep "^### $user")
    exp=$(echo "$user_data" | awk '{print $3}')
    config_file="/etc/xray/vmess/config.json"
    db_file="/etc/xray/vmess/.vmess.db"

    sed -i "/^### $user $exp/,/^},{/d" "$config_file"

    # Add configuration back to config_file
    sed -i '/#vmess$/a\### '"$user $exp"'\
},{"id": "'""$new_uuid""'","email": "'""$user""'"'  "$config_file"

    sed -i '/#vmessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$new_uuid""'","email": "'""$user""'"'  "$config_file"
  
    sed -i "/^### $user/d" "$db_file"
    echo "### $user $exp $new_uuid" >> "$db_file"
    systemctl restart vmess@config

    echo -e ""
    if [ $? -eq 0 ]; then
        echo -e "${green}UUID untuk akun $user berhasil diubah.${neutral}"
        echo -e "UUID baru: ${green}$new_uuid${neutral}"
    else
        echo -e "${red}Gagal mengubah UUID untuk akun $user.${neutral}"
        echo -e "Pastikan Anda memiliki izin yang cukup dan coba lagi."
    fi

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}
# Function to display VMESS menu
