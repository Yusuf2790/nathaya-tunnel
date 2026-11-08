#!/bin/bash
# One renderer/dispatcher for SSH, VMess, VLESS, Trojan and Shadowsocks.
# Definitions populate dynamically-scoped arrays in the caller.
nathaya_protocol_definition() {
    local protocol="$1"
    if [[ "$protocol" == ssh ]]; then
        NATHAYA_MENU_LABELS=("Create" "Delete" "Renew" "Trial" "Check User Login" "List Member" "List User Expired" "Lock" "Unlock" "Limit IP" "Detail Akun" "Autokill SSH/OpenVPN")
        NATHAYA_MENU_ACTIONS=("command:addssh" "command:dellssh" "command:renewssh" "command:trialssh" "command:checkssh" "function:member_ssh" "function:list_expired_ssh" "function:lock_ssh" "function:unlock_ssh" "function:change_ssh_limit" "function:detail_ssh" "function:autokill_ssh")
    else
        case "$protocol" in vmess|vless|trojan|shadowsocks) ;; *) return 1 ;; esac
        local custom="custom_${protocol}_uuid" credential="Custom UUID"
        [[ "$protocol" == trojan ]] && custom=custom_uuid_trojan
        if [[ "$protocol" == shadowsocks ]]; then
            custom=custom_shadowsocks_password
            credential="Custom Password"
        fi
        NATHAYA_MENU_LABELS=("Create" "Delete" "Renew" "Check User Login" "List Member" "Quota / Limit IP" "Detail Akun" "Trial" "$credential")
        NATHAYA_MENU_ACTIONS=("command:add$protocol" "command:dell$protocol" "command:renew$protocol" "command:check$protocol" "function:${protocol}_members" "function:change_${protocol}_limit" "function:${protocol}_details" "command:trial$protocol" "function:$custom")
    fi
}

nathaya_show_protocol_menu() {
    local protocol="$1"
    local -a NATHAYA_MENU_LABELS NATHAYA_MENU_ACTIONS
    nathaya_protocol_definition "$protocol" || return 1
    nathaya_show_menu "${protocol^^} MENU" "${NATHAYA_MENU_LABELS[@]}"
}

nathaya_protocol_loop() {
    local protocol="$1" choice action type operation index
    local -a NATHAYA_MENU_LABELS NATHAYA_MENU_ACTIONS
    nathaya_protocol_definition "$protocol" || return 1
    # Explicit protocol whitelist above; never source modules/ssh (the retired DB).
    if [[ ! -r "$NATHAYA_BASE/modules/menu/$protocol-operations.sh" ]]; then
        printf 'Operasi %s belum terpasang. Perbarui modul Nathaya.\n' "$protocol" >&2
        return 1
    fi
    source "$NATHAYA_BASE/modules/menu/$protocol-operations.sh" || return 1
    while true; do
        nathaya_show_menu "${protocol^^} MENU" "${NATHAYA_MENU_LABELS[@]}"
        read -r -p "  Pilih menu: " choice || return 0
        choice=$(nathaya_normalize_choice "$choice")
        case "$choice" in
            z|0) return 0 ;;
            x|exit|keluar) return 100 ;;
        esac
        # Length bound also prevents arithmetic overflow on hostile input.
        if [[ ! "$choice" =~ ^[1-9][0-9]?$ ]] || (( choice > ${#NATHAYA_MENU_ACTIONS[@]} )); then
            printf '\n  Pilihan tidak valid.\n'
            pause_return
            continue
        fi
        index=$((choice - 1))
        action="${NATHAYA_MENU_ACTIONS[$index]}"
        type="${action%%:*}"
        operation="${action#*:}"
        case "$type" in
            command)
                nathaya_run_action "$operation"
                pause_return
                ;;
            function)
                if declare -F "$operation" >/dev/null; then
                    # Upstream functions use globals; isolate each invocation.
                    ( "$operation" )
                else
                    printf 'Operasi %s tidak ditemukan.\n' "$operation" >&2
                    pause_return
                fi
                ;;
        esac
    done
}
