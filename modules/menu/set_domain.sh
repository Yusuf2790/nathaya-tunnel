#!/bin/bash

# NATHAYA_BASE diwarisi dari menu.sh.
CONFIG_FILE="/etc/nathaya-tunnel/config.conf"

source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/common/functions.sh"

get_vps_ipv4() {
    local ip

    ip=$(curl -4 -fsS --connect-timeout 3 --max-time 6 \
        https://api.ipify.org 2>/dev/null) || return 1

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    printf '%s' "$ip"
}

get_domain_a_records() {
    local domain="$1"
    local resolver="$2"

    dig @"$resolver" "$domain" A \
        +time=3 +tries=1 +short 2>/dev/null |
        awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}$/'
}

set_domain_vps() {
    clear

    local width domain confirm vps_ip
    local dns_cf dns_google
    local valid_cf=0 valid_google=0

    width=$(get_width)

    draw_nathaya_header "$width"
    draw_section_title "SET DOMAIN VPS" "$width"

    source "$CONFIG_FILE" 2>/dev/null || true

    printf "  Domain saat ini : %s\n\n" "${DOMAIN:-Belum disetting}"
    printf "  Masukkan domain VPS.\n"
    printf "  Contoh: id1.nathaya.web.id\n\n"

    read -r -p "  Domain baru: " domain

    domain="${domain,,}"
    domain="${domain%.}"

    if [[ -z "$domain" ]] ||
       (( ${#domain} > 253 )) ||
       [[ "$domain" != *.* ]] ||
       [[ ! "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] ||
       [[ "$domain" == *..* ]] ||
       [[ "$domain" =~ (^|[.])-|-(\.|$) ]]; then
        printf "\n  Domain tidak valid. Periksa kembali.\n"
        pause_return
        return 1
    fi

    printf "\n  Memeriksa domain...\n"

    if ! vps_ip=$(get_vps_ipv4); then
        printf "\n  Tidak dapat memeriksa koneksi VPS.\n"
        printf "  Silakan coba lagi nanti.\n"
        pause_return
        return 1
    fi

    dns_cf=$(get_domain_a_records "$domain" "1.1.1.1")
    dns_google=$(get_domain_a_records "$domain" "8.8.8.8")

    if printf '%s\n' "$dns_cf" | grep -Fxq "$vps_ip"; then
        valid_cf=1
    fi

    if printf '%s\n' "$dns_google" | grep -Fxq "$vps_ip"; then
        valid_google=1
    fi

    if (( valid_cf != 1 || valid_google != 1 )); then
        printf "\n  Domain belum terhubung ke VPS.\n"
        printf "  Periksa pengaturan DNS domain, lalu coba lagi.\n"
        pause_return
        return 1
    fi

    printf "\n  Domain berhasil diverifikasi!\n"
    read -r -p "  Simpan domain ini? [y/N]: " confirm

    case "${confirm,,}" in
        y|ya) ;;
        *)
            printf "\n  Perubahan dibatalkan.\n"
            pause_return
            return 0
            ;;
    esac

    mkdir -p "$(dirname "$CONFIG_FILE")"
    touch "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"

    local tmp
    tmp=$(mktemp "${CONFIG_FILE}.XXXXXX") || {
        printf "\n  Gagal menyimpan konfigurasi.\n"
        pause_return
        return 1
    }

    if [[ -f "$CONFIG_FILE" ]]; then
        grep -v '^DOMAIN=' "$CONFIG_FILE" > "$tmp" || true
    fi

    printf 'DOMAIN="%s"\n' "$domain" >> "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$CONFIG_FILE"

    printf "\n  Domain berhasil disimpan!\n"
    pause_return
}
