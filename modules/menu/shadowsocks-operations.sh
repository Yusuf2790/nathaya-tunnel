#!/bin/bash
# Extracted from the Alrescha shadowsocks submenu; account formats and operations retained.
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

# Function to print rainbow text
shadowsocks_members() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                 DAFTAR MEMBER SHADOWSOCKS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/shadowsocks/.shadowsocks.db" ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    echo -e "Username         | Sisa      | Kuota     | IP    | Penggunaan | Status"
    echo -e "══════════════════════════════════════════════════════════════════════"

    total_accounts=0
    grep -E "^### " "/etc/xray/shadowsocks/.shadowsocks.db" | while read -r line; do
        ((total_accounts++))
        user=$(echo "$line" | awk '{print $2}')
        exp=$(echo "$line" | awk '{print $3}')
        current_timestamp=$(date +%s)
        exp_timestamp=$(date -d "$exp" +%s)
        days_left=$(( (exp_timestamp - current_timestamp) / 86400 ))
        
        if [ $days_left -lt 0 ]; then
            status_text="KADALUARSA"
            status_color="${red}"
            exp_display="${days_left}d"
        elif [ $days_left -le 3 ]; then
            status_text="SEGERA HABIS"
            status_color="${yellow}"
            exp_display="${days_left}d"
        else
            status_text="AKTIF"
            status_color="${green}"
            exp_display="${days_left}d"
        fi

        quota_file="/etc/xray/shadowsocks/${user}"
        ip_limit_file="/etc/xray/shadowsocks/${user}IP"
        usage_file="/etc/xray/shadowsocks/usage/${user}"

        quota="Unlimited"
        if [ -f "$quota_file" ]; then
            quota_raw=$(cat "$quota_file")
            if [ "$quota_raw" != "" ] && [ "$quota_raw" != "0" ]; then
                quota=$(convert_size "$quota_raw")
            else
                quota="Unlimited"
            fi
        fi

        ip_limit="Unlimited"
        if [ -f "$ip_limit_file" ]; then
            ip_limit_raw=$(cat "$ip_limit_file")
            if [ "$ip_limit_raw" != "" ] && [ "$ip_limit_raw" != "0" ]; then
                ip_limit="$ip_limit_raw"
            else
                ip_limit="Unlimited"
            fi
        fi

        usage="0B"
        if [ -f "$usage_file" ]; then
            usage_raw=$(cat "$usage_file")
            if [ "$usage_raw" != "" ] && [ "$usage_raw" != "0" ]; then
                usage=$(convert_size "$usage_raw")
            else
                usage="0B"
            fi
        fi

        printf "%-16s | %-9s | %-9s | %-5s | %-10s | " "$user" "$exp_display" "$quota" "$ip_limit" "$usage"
        echo -e "${status_color}${status_text}${neutral}"
    done
    
    total_count=$(grep -cE "^### " "/etc/xray/shadowsocks/.shadowsocks.db")
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${yellow}Total Akun Shadowsocks : ${green}${total_count}${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

change_shadowsocks_limit() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                  UBAH LIMIT SHADOWSOCKS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/shadowsocks/.shadowsocks.db" ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e " Daftar Akun Shadowsocks:"
    account_count=$(grep -cE "^### " "/etc/xray/shadowsocks/.shadowsocks.db")
    if [ $account_count -eq 0 ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang aktif.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    echo -e "No  | Username           | Exp (hari)"
    echo -e "─────────────────────────────────────────────"
    grep -E "^### " "/etc/xray/shadowsocks/.shadowsocks.db" | awk '{
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
    read -p " Pilih nomor akun [ 1-$account_count ] atau [ x ] untuk batal: " account_number || return 1

    # Check if input is 'x'
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

    username=$(grep -E "^### " "/etc/xray/shadowsocks/.shadowsocks.db" | cut -d ' ' -f 2 | sed -n "${account_number}p")

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
    read -p "Masukkan limit quota baru (dalam GB, 0 untuk unlimited): " new_quota || return 1
    read -p "Masukkan limit IP baru (0 untuk unlimited): " new_ip_limit || return 1

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

    # Each sidecar can fail independently; quota=0 removes the quota file.
    local limit_status=0
    if [[ "$new_quota" == "0" ]]; then
        rm -f "/etc/xray/shadowsocks/${username}" || limit_status=1
    else
        printf '%s\n' "$new_quota_bytes" >"/etc/xray/shadowsocks/${username}" || limit_status=1
    fi
    printf '%s\n' "$new_ip_limit" >"/etc/xray/shadowsocks/${username}IP" || limit_status=1

    echo -e ""
    if (( limit_status == 0 )); then
        echo -e "${green}Limit untuk akun $username berhasil diubah.${neutral}"
        echo -e "Quota baru: ${new_quota} GB"
        echo -e "Limit IP baru: ${new_ip_limit}"
    else
        echo -e "${red}Gagal mengubah limit untuk akun $username.${neutral}"
        printf '%s\n' 'Perubahan sebelumnya mungkin sudah tersimpan; periksa quota dan limit IP sebelum mencoba lagi.' >&2
        return 1
    fi

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

shadowsocks_details() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                   DETAIL AKUN SHADOWSOCKS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/shadowsocks/.shadowsocks.db" ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang terdaftar.${neutral}"
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
            password=$(echo $line | cut -d ' ' -f 4)
            
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
            echo -e "${yellow}══════ AKUN #${account_counter} ══════${neutral}"
            echo -e "   Username      : ${green}$user${neutral}"
            echo -e "   Tanggal Exp   : ${green}$exp_display${neutral}"
            echo -e "   Status        : $status"
            echo -e "   Password      : ${green}$password${neutral}"

            if [ -f "/etc/xray/shadowsocks/${user}" ]; then
                quota=$(cat /etc/xray/shadowsocks/${user})
                if [ -n "$quota" ] && [ "$quota" != "0" ]; then
                    quota_readable=$(convert_size $quota)
                    echo -e "   Quota         : ${green}$quota_readable${neutral}"
                else
                    echo -e "   Quota         : ${green}Unlimited${neutral}"
                fi
            else
                echo -e "   Quota         : ${green}Unlimited${neutral}"
            fi

            if [ -f "/etc/xray/shadowsocks/${user}IP" ]; then
                ip_limit=$(cat /etc/xray/shadowsocks/${user}IP)
                if [ -n "$ip_limit" ] && [ "$ip_limit" != "0" ]; then
                    echo -e "   Limit IP      : ${green}$ip_limit${neutral}"
                else
                    echo -e "   Limit IP      : ${green}Unlimited${neutral}"
                fi
            else
                echo -e "   Limit IP      : ${green}Unlimited${neutral}"
            fi
            
            # Show current usage
            if [ -f "/etc/xray/shadowsocks/usage/${user}" ]; then
                usage_raw=$(cat /etc/xray/shadowsocks/usage/${user})
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
    done <"/etc/xray/shadowsocks/.shadowsocks.db"

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

custom_shadowsocks_password() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                CUSTOM PASSWORD SHADOWSOCKS${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    if [ ! -e "/etc/xray/shadowsocks/.shadowsocks.db" ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang terdaftar.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    account_count=$(grep -cE "^### " "/etc/xray/shadowsocks/.shadowsocks.db")
    if [ $account_count -eq 0 ]; then
        echo -e "   ${red}Tidak ada akun Shadowsocks yang aktif.${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e " Daftar Akun Shadowsocks:"
    echo -e "No  | Username           | Exp (hari)"
    echo -e "─────────────────────────────────────────────"
    grep -E "^### " "/etc/xray/shadowsocks/.shadowsocks.db" | awk '{
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
    read -p " Pilih nomor akun [ 1-$account_count ] atau [ x ] untuk batal: " account_number || return 1

    # Check if input is 'x'
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

    user=$(grep -E "^### " "/etc/xray/shadowsocks/.shadowsocks.db" | cut -d ' ' -f 2 | sed -n "${account_number}p")

    if [ -z "$user" ]; then
        echo -e "   ${red}Nomor akun tidak valid.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi
    
    echo -e ""
    echo -e "Mengubah password untuk akun: ${green}$user${neutral}"
    echo -e ""
    while true; do
        read -p " Password baru (minimal 6 karakter): " new_password || return 1
        if [[ ${#new_password} -ge 6 && "$new_password" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            break
        else
            echo -e "${red} Password harus minimal 6 karakter dan hanya boleh berisi huruf, angka, _ atau -${neutral}"
        fi
    done

    if [ -z "$new_password" ]; then
        echo -e "${red}Error: Password tidak boleh kosong.${neutral}"
        echo -e " Tekan Enter untuk kembali ke menu..."
        read
    : # Return to the shared, non-recursive Nathaya menu loop.
        return
    fi

    # Refuse missing/wrong transport anchors before touching either file.
    local config_file="/etc/xray/shadowsocks/config.json"
    local db_file="/etc/xray/shadowsocks/.shadowsocks.db" user_data
    if [[ ! "$user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]*$ ]] ||
        ! grep -qx '#ssws' "$config_file" ||
        ! grep -qx '#ssgrpc' "$config_file"; then
        printf '%s\n' 'Konfigurasi atau marker Shadowsocks tidak valid; password tidak diubah.' >&2
        return 1
    fi
    # Match the username field, never a prefix (e.g. anna must not match annabel).
    user_data=$(awk -v user="$user" '$1 == "###" && $2 == user {
        count++; row=$0
        if (NF != 4 && !(NF == 5 && $4 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/)) bad=1
    } END { if (count == 1 && !bad) print row; else exit 1 }' "$db_file") || {
        printf '%s\n' 'Database akun tidak valid; password tidak diubah.' >&2
        return 1
    }
    # Require exactly one existing client inside each bounded marker section.
    # Edit only the password: retain each transport's method and schema verbatim.
    if ! awk -v user="$user" '
    /^#[^#]/ {
        section=""
        if ($0 == "#ssws") { ws_markers++; section="ws" }
        if ($0 == "#ssgrpc") { grpc_markers++; section="grpc" }
        next
    }
    /^[[:space:]]*\]/ { section="" }
    $1 == "###" && $2 == user {
        count++
        if (section == "ws") ws_count++
        else if (section == "grpc") grpc_count++
        else bad=1
        if ($0 !~ ("^### " user " ") ||
            (NF != 3 && !(NF == 4 && $4 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/))) bad=1
        if ((getline) <= 0) { bad=1; next }
        if ($0 !~ /"password"[[:space:]]*:[[:space:]]*"[^"]+"/ ||
            $0 !~ /"method"[[:space:]]*:[[:space:]]*"[^"]+"/ ||
            $0 !~ ("\"email\"[[:space:]]*:[[:space:]]*\"" user "\"")) bad=1
    }
    END { exit (bad || count != 2 || ws_count != 1 || grpc_count != 1 ||
                ws_markers != 1 || grpc_markers != 1) }' "$config_file"; then
        printf '%s\n' 'Client WS/gRPC tidak valid; password tidak diubah.' >&2
        return 1
    fi

    if ! sed -i -E "/^### $user /{n;s/(\"password\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")/\\1$new_password\\2/;}" "$config_file" ||
        ! sed -i -E "/^### $user /s/[^[:space:]]+([[:space:]]*)$/$new_password\\1/" "$db_file"; then
        printf '%s\n' 'Gagal menulis password. Perubahan sebelumnya mungkin sudah tersimpan; periksa akun sebelum mencoba lagi.' >&2
        return 1
    fi
    if ! systemctl restart shadowsocks@config; then
        printf '%s\n' 'Gagal memulai ulang Shadowsocks. Password baru mungkin sudah tersimpan; layanan belum berhasil dimulai ulang.' >&2
        return 1
    fi

    echo -e ""
    echo -e "${green}Password untuk akun $user berhasil diubah.${neutral}"
    echo -e "Password baru: ${green}$new_password${neutral}"

    echo -e ""
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    read -n 1 -s -r -p "Tekan [ Enter ] untuk kembali ke menu..."
    echo -e ""
    : # Return to the shared, non-recursive Nathaya menu loop.
}

# Function to display Shadowsocks menu
