#!/bin/bash
# Extracted from the Alrescha ssh submenu; account formats and operations retained.
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

prompt_back_to_menu() {
    pause_return
}

select_ssh_user() {
    local db_file="/etc/ssh/.ssh.db"
    if [ ! -f "$db_file" ]; then
        echo -e "${red}Database akun SSH tidak ditemukan.${neutral}"
        return 1
    fi

    mapfile -t accounts < <(grep -E "^### " "$db_file")
    local total=${#accounts[@]}
    if [ "$total" -eq 0 ]; then
        echo -e "${red}Belum ada akun SSH/OpenVPN yang terdaftar.${neutral}"
        return 1
    fi

    echo -e "No  | Username           | Kadaluarsa"
    echo -e "─────────────────────────────────────────────"
    local idx=1
    for line in "${accounts[@]}"; do
        user=$(echo "$line" | awk '{print $2}')
        exp=$(echo "$line" | awk '{print $3}')
        cmd=$(date -d "$exp" +%s 2>/dev/null)
        if [ -n "$cmd" ]; then
            days_left=$(( (cmd - $(date +%s)) / 86400 ))
            [ $days_left -lt 0 ] && days_left=0
        else
            days_left="-"
        fi
        printf "%-3s | %-18s | %-10s\n" "$idx" "$user" "$exp (${days_left} hari)"
        ((idx++))
    done
    echo -e "─────────────────────────────────────────────"
    echo -e ""
    read -p " Pilih nomor akun (atau x untuk batal): " choice

    if [[ "$choice" =~ ^[xX]$ ]]; then
        return 2
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${red}Input harus berupa angka.${neutral}"
        return 1
    fi

    if [ "$choice" -lt 1 ] || [ "$choice" -gt "$total" ]; then
        echo -e "${red}Nomor akun tidak valid.${neutral}"
        return 1
    fi

    selected_user=$(echo "${accounts[$((10#$choice-1))]}" | awk '{print $2}')
    selected_exp=$(echo "${accounts[$((10#$choice-1))]}" | awk '{print $3}')
    echo "$selected_user $selected_exp"
    return 0
}

autokill_ssh() {
    local cron_file="/etc/cron.d/autokill"
    local status
    if [ -f "$cron_file" ] && grep -q "autokill" "$cron_file"; then
        status="${green}AKTIF${neutral}"
    else
        status="${red}NONAKTIF${neutral}"
    fi

    while true; do
        clear
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e "${green}${bold_white}                   PENGELOLA AUTOKILL SSH/OPENVPN${neutral}"
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        echo -e ""
        echo -e " Status Autokill : $status"
        echo -e ""
        echo -e "   ${green}[1]${neutral} Aktifkan Autokill (5 menit)"
        echo -e "   ${green}[2]${neutral} Aktifkan Autokill (10 menit)"
        echo -e "   ${green}[3]${neutral} Aktifkan Autokill (15 menit)"
        echo -e "   ${green}[4]${neutral} Nonaktifkan Autokill"
        echo -e "   ${red}[x]${neutral}  Kembali ke Menu SSH"
        echo -e ""
        echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
        read -p " Pilih opsi [1-4/x]: " choice

        case "$choice" in
        1)
            nathaya_cron set "$cron_file" <<EOF || return 1
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/5 * * * * root /usr/bin/autokill
EOF
            service cron restart >/dev/null 2>&1 || return 1
            status="${green}AKTIF${neutral}"
            echo -e ""
            echo -e "${green}Autokill diaktifkan setiap 5 menit.${neutral}"
            prompt_back_to_menu
            return
            ;;
        2)
            nathaya_cron set "$cron_file" <<EOF || return 1
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/bin/autokill
EOF
            service cron restart >/dev/null 2>&1 || return 1
            status="${green}AKTIF${neutral}"
            echo -e ""
            echo -e "${green}Autokill diaktifkan setiap 10 menit.${neutral}"
            prompt_back_to_menu
            return
            ;;
        3)
            nathaya_cron set "$cron_file" <<EOF || return 1
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/bin/autokill
EOF
            service cron restart >/dev/null 2>&1 || return 1
            status="${green}AKTIF${neutral}"
            echo -e ""
            echo -e "${green}Autokill diaktifkan setiap 15 menit.${neutral}"
            prompt_back_to_menu
            return
            ;;
        4)
            nathaya_cron remove "$cron_file" || return 1
            service cron restart >/dev/null 2>&1 || return 1
            status="${red}NONAKTIF${neutral}"
            echo -e ""
            echo -e "${yellow}Autokill dinonaktifkan.${neutral}"
            prompt_back_to_menu
            return
            ;;
        x | X)
    : # Return to the shared, non-recursive Nathaya menu loop.
            return
            ;;
        *)
            echo -e "${red}Pilihan tidak valid. Coba lagi.${neutral}"
            sleep 1
            ;;
        esac
    done
}

lock_ssh() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                       KUNCI AKUN SSH/OPENVPN${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    select_ssh_user || {
        prompt_back_to_menu
        return
    }

    local user="$selected_user"

    if [[ "$user" == "root" || "$user" == "admin" ]]; then
        echo -e "${red}Akun sistem tidak boleh dikunci.${neutral}"
        prompt_back_to_menu
        return
    fi

    if ! grep -q "^$user:" /etc/passwd; then
        echo -e "${red}Akun $user tidak ditemukan di sistem.${neutral}"
        prompt_back_to_menu
        return
    fi

    if passwd -S "$user" | grep -q " L "; then
        echo -e "${yellow}Akun ${green}$user${yellow} sudah dalam keadaan terkunci.${neutral}"
        prompt_back_to_menu
        return
    fi

    if passwd -l "$user" >/dev/null 2>&1; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") LOCKED $user" >>/var/log/ssh_account_actions.log
        echo -e "${green}Akun ${user} berhasil dikunci.${neutral}"
    else
        echo -e "${red}Gagal mengunci akun ${user}.${neutral}"
    fi

    prompt_back_to_menu
}

unlock_ssh() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                     BUKA KUNCI AKUN SSH/OPENVPN${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    select_ssh_user || {
        prompt_back_to_menu
        return
    }

    local user="$selected_user"

    if ! grep -q "^$user:" /etc/passwd; then
        echo -e "${red}Akun $user tidak ditemukan di sistem.${neutral}"
        prompt_back_to_menu
        return
    fi

    if ! passwd -S "$user" | grep -q " L "; then
        echo -e "${yellow}Akun ${green}$user${yellow} sudah terbuka.${neutral}"
        prompt_back_to_menu
        return
    fi

    if passwd -u "$user" >/dev/null 2>&1; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") UNLOCKED $user" >>/var/log/ssh_account_actions.log
        echo -e "${green}Akun ${user} berhasil dibuka kuncinya.${neutral}"
    else
        echo -e "${red}Gagal membuka kunci akun ${user}.${neutral}"
    fi

    prompt_back_to_menu
}

detail_ssh() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                      DETAIL AKUN SSH/OPENVPN${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    select_ssh_user || {
        prompt_back_to_menu
        return
    }

    local user="$selected_user"

    clear
    echo -e "${yellow}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${yellow}║                     DETAIL AKUN : ${green}$user${yellow}                     ║${neutral}"
    echo -e "${yellow}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    local log_file="/etc/xray/log-createssh-${user}.log"
    if [ -f "$log_file" ]; then
        cat "$log_file"
    else
        echo -e "${yellow}Catatan akun tidak ditemukan. Kemungkinan akun dibuat manual.${neutral}"
    fi

    prompt_back_to_menu
}

change_ssh_limit() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                       UBAH LIMIT AKUN SSH${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    select_ssh_user || {
        prompt_back_to_menu
        return
    }

    local user="$selected_user"

    while true; do
        read -p " Masukkan limit IP baru (minimal 1, x untuk batal): " new_limit
        if [[ "$new_limit" =~ ^[xX]$ ]]; then
            prompt_back_to_menu
            return
        fi
        if [[ "$new_limit" =~ ^[1-9][0-9]*$ ]]; then
            break
        fi
        echo -e "${red}Input tidak valid. Masukkan angka lebih besar dari 0 atau 'x' untuk batal.${neutral}"
    done

    echo "$new_limit" >"/etc/ssh/${user}" || true
    echo -e "${green}Limit IP untuk akun ${user} diperbarui menjadi ${new_limit} perangkat.${neutral}"

    prompt_back_to_menu
}

member_ssh() {
    clear
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "${green}${bold_white}                        DAFTAR MEMBER SSH${neutral}"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e ""

    local db_file="/etc/ssh/.ssh.db"
    if [ ! -f "$db_file" ]; then
        echo -e "${red}Database akun SSH tidak ditemukan.${neutral}"
        prompt_back_to_menu
        return
    fi

    mapfile -t accounts < <(grep -E "^### " "$db_file")
    local total=${#accounts[@]}

    if [ "$total" -eq 0 ]; then
        echo -e "${yellow}Belum ada akun SSH/OpenVPN yang terdaftar.${neutral}"
        prompt_back_to_menu
        return
    fi

    printf "%-3s %-18s %-15s %-15s %-7s\n" "No" "Username" "Kadaluarsa" "Status" "Limit IP"
    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"

    local idx=1
    local now_ts=$(date +%s)
    for line in "${accounts[@]}"; do
        user=$(echo "$line" | awk '{print $2}')
        exp=$(echo "$line" | awk '{print $3}')

        exp_ts=$(date -d "$exp" +%s 2>/dev/null)
        if [ -n "$exp_ts" ]; then
            days_left=$(((exp_ts - now_ts) / 86400))
        else
            days_left=-999
        fi

        if [ "$days_left" -lt 0 ]; then
            status_text="KADALUARSA"
            status_color="${red}"
        elif [ "$days_left" -le 3 ]; then
            status_text="SEGERA HABIS"
            status_color="${yellow}"
        else
            status_text="AKTIF"
            status_color="${green}"
        fi

        if passwd -S "$user" 2>/dev/null | grep -q " L "; then
            status_text="TERKUNCI"
            status_color="${red}"
        fi

        ip_limit=$(cat /etc/ssh/${user} 2>/dev/null || echo "Unlimited")

        printf "%-3s %-18s %-15s " "$idx" "$user" "$exp"
        echo -ne "${status_color}${status_text}${neutral}"
        printf " %-10s\n" "$ip_limit"
        ((idx++))
    done

    echo -e "${orange}══════════════════════════════════════════════════════════════════════${neutral}"
    echo -e "Total akun : ${green}${total}${neutral}"

    prompt_back_to_menu
}

# ===============================
# TAMPILKAN MENU SSH/OPENVPN
# ===============================

# Nathaya choice 7, using the upstream SSH database (never the old accounts.db).
list_expired_ssh() {
    local width marker user exp rest exp_ts today count=0
    width=$(get_width)
    [[ -t 1 ]] && clear
    draw_nathaya_header "$width"
    draw_section_title "EXPIRED SSH USERS" "$width"
    today=$(date -d "$(date +%F)" +%s)
    if [[ -r /etc/ssh/.ssh.db ]]; then
        while read -r marker user exp rest; do
            [[ "$marker" == '###' ]] || continue
            exp_ts=$(date -d "$exp" +%s 2>/dev/null) || continue
            if (( exp_ts <= today )); then
                nathaya_box_row "$width" "$user : $exp"
                ((count++))
            fi
        done < /etc/ssh/.ssh.db
    fi
    nathaya_field "$width" "Total" "$count"
    draw_box_bottom "$width"
    pause_return
}
