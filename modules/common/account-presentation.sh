#!/usr/bin/env bash
# Presentation only: retain Alrescha's account database, services and links.
# Titles, section order, separators and footer follow original Nathaya SSH UI.

nathaya_account_html_escape() {
    local value="${1:-}" character escaped=''
    while [[ -n "$value" ]]; do
        character="${value:0:1}"; value="${value:1}"
        case "$character" in
            '&') escaped+='&amp;' ;;
            '<') escaped+='&lt;' ;;
            '>') escaped+='&gt;' ;;
            '"') escaped+='&quot;' ;;
            "'") escaped+='&#39;' ;;
            $'\n') escaped+='&#10;' ;;
            $'\r') escaped+='&#13;' ;;
            *) escaped+="$character" ;;
        esac
    done
    printf '%s' "$escaped"
}

nathaya_account_require_username() {
    # Safe in upstream grep/sed expressions, paths and Linux command arguments.
    [[ "${1:-}" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]*$ ]] && return 0
    printf '%s\n' 'Username hanya boleh huruf, angka, garis bawah dan tanda hubung; tidak boleh diawali tanda hubung.' >&2
    return 1
}

nathaya_account_db_secret() {
    # Both historic ### user DATE TIME UUID and upstream ### user DATE UUID.
    # Never mistake the timestamp for the credential or rewrite an existing row.
    awk -v user="$2" '$1 == "###" && $2 == user {
        if ($4 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) print $5
        else print $4
        exit
    }' "$1"
}

nathaya_account_rule() {
    if [[ -t 1 ]]; then printf '\033[1;36m'; fi
    printf '%s' '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
    if [[ -t 1 ]]; then printf '\033[0m'; fi
    printf '\n'
}

nathaya_account_header() {
    local title="${1:-NATHAYA TUNNEL}" width=50
    if declare -F draw_nathaya_header >/dev/null && declare -F draw_section_title >/dev/null; then
        if declare -F get_width >/dev/null; then width=$(get_width); fi
        draw_nathaya_header "$width"
        draw_section_title "$title" "$width"
    else
        nathaya_account_rule
        if [[ -t 1 ]]; then printf '\033[48;5;208m\033[1;37m'; fi
        printf '%s' '             NATHAYA TUNNEL              '
        if [[ -t 1 ]]; then printf '\033[0m'; fi
        printf '\n'
        nathaya_account_rule
        printf '╭━━┤ %s ├━━╮\n' "$title"
    fi
}

nathaya_account_footer() {
    nathaya_account_rule
    printf '%s\n' 'Nathaya Tunnel | Version 1.0.0'
    nathaya_account_rule
}

# These arrays are local to render(); Bash's dynamic scope keeps calls isolated.
nathaya_account_add() {
    local index
    for ((index=0; index<${#_n_labels[@]}; index++)); do
        if [[ "${_n_sections[index]}" == "$1" && "${_n_labels[index]}" == "$2" ]]; then
            _n_values[index]="${3:-}"
            return 0
        fi
    done
    index=${#_n_labels[@]}
    _n_sections[index]="$1"
    _n_labels[index]="$2"
    _n_values[index]="${3:-}"
}

nathaya_account_html_field() {
    local label="$1" value="${2:-}" piece
    # Split BEFORE escaping; never cut an HTML entity or tag. Also bounds each
    # line so notifications can be safely paged below Telegram's 4096 limit.
    while :; do
        piece="${value:0:400}"
        value="${value:400}"
        printf '<code>%-8s:</code> <code>%s</code>\n' \
            "$(nathaya_account_html_escape "$label")" \
            "$(nathaya_account_html_escape "$piece")"
        [[ -n "$value" ]] || break
        label='...'
    done
}

nathaya_account_render() (
    local mode="${1:-terminal}" status="${2:-success}" error_message="${3:-}"
    local selected_user="${4:-${user:-${Login:-}}}"
    local action="${NATHAYA_ACCOUNT_ACTION:-create}" protocol="${NATHAYA_ACCOUNT_PROTOCOL:-SSH}"
    local title emoji note section index found value label
    local -a _n_sections=() _n_labels=() _n_values=()
    case "$action" in
        trial) title="TRIAL $protocol CREATED"; emoji='&#128994;'; note='Akun trial berhasil dibuat.' ;;
        renew) title="$protocol ACCOUNT RENEWED"; emoji='&#9989;'; note='Masa aktif berhasil diperpanjang.' ;;
        delete) title="$protocol ACCOUNT DELETED"; emoji='&#128308;'; note='Akun dan database berhasil dihapus.' ;;
        *) title="$protocol ACCOUNT CREATED"; emoji='&#128994;'; note='Akun berhasil dibuat.' ;;
    esac
    if [[ "$status" != success ]]; then
        title="$protocol ACCOUNT ${action^^} FAILED"
        emoji='&#10060;'
        note='Operasi belum selesai. Periksa status akun sebelum mencoba lagi.'
    fi

    if [[ "$action" == delete ]]; then
        nathaya_account_add 'DELETE INFORMATION' 'User' "$selected_user"
        nathaya_account_add 'DELETE INFORMATION' 'Type' "$protocol"
        nathaya_account_add 'DELETE INFORMATION' 'Expiry' "${exp:-Tidak diketahui}"
        nathaya_account_add 'DELETE INFORMATION' 'Time' "$(date '+%Y-%m-%d %H:%M:%S')"
        value=Deleted; [[ "$status" == success ]] || value=Failed
        nathaya_account_add 'DELETE INFORMATION' 'Status' "$value"
        nathaya_account_add 'DELETE INFORMATION' 'Host' "${domain:-Tidak diketahui}"
    else
        if [[ "$action" == renew ]]; then
            nathaya_account_add 'SERVER INFORMATION' 'Host' "${domain:-Tidak diketahui}"
            nathaya_account_add 'SERVER INFORMATION' 'IP' "${ip:-${IP:-Tidak diketahui}}"
            nathaya_account_add 'RENEW INFORMATION' 'User' "$selected_user"
            nathaya_account_add 'RENEW INFORMATION' 'Old Expiry' "${old_exp:-${exp:-}}"
            nathaya_account_add 'RENEW INFORMATION' 'Duration' "${active_days:-${active_period:-}} hari"
            nathaya_account_add 'RENEW INFORMATION' 'New Expiry' "${new_exp:-}"
            [[ -z "${quota:-}" ]] || nathaya_account_add 'RENEW INFORMATION' 'Quota' "$quota GB"
            [[ -z "${ip_limit:-}" ]] || nathaya_account_add 'RENEW INFORMATION' 'Limit IP' "$ip_limit"
        else
            nathaya_account_add 'SERVER INFORMATION' 'ISP' "${isp:-Tidak diketahui}"
            # Per-command data comes from upstream display expressions, including
            # every upstream port, payload and generated URL (never guessed here).
            if declare -F nathaya_account_data >/dev/null; then nathaya_account_data; fi
            nathaya_account_add 'ACCOUNT INFORMATION' 'User' "$selected_user"
            [[ -z "${iplim:-${ip_limit:-}}" ]] || nathaya_account_add 'ACCOUNT INFORMATION' 'Limit IP' "${iplim:-${ip_limit:-}}"
            [[ -z "${quota:-}" ]] || nathaya_account_add 'ACCOUNT INFORMATION' 'Quota' "$quota GB"
            if [[ "$action" == trial ]]; then
                nathaya_account_add 'ACCOUNT INFORMATION' 'Duration' "${duration:-} menit"
                nathaya_account_add 'ACCOUNT INFORMATION' 'Type' 'TRIAL ACCOUNT'
            fi
        fi
    fi
    if [[ "$status" != success ]]; then
        nathaya_account_add 'CATATAN' 'Error' "$error_message"
    fi
    case "$action" in create|trial) nathaya_account_add 'CATATAN' '' "$note" ;; esac

    if [[ "$mode" == telegram ]]; then
        printf '&#128640; <b>NATHAYA TUNNEL</b>\n%s <b>%s</b>\n' "$emoji" "$(nathaya_account_html_escape "$title")"
    else
        nathaya_account_header "$title"
    fi
    for section in 'SERVER INFORMATION' 'ACCOUNT INFORMATION' 'RENEW INFORMATION' \
        'DELETE INFORMATION' 'CONNECTION INFORMATION' 'PAYLOAD HTTP' 'CONNECTION LINKS' 'CATATAN'; do
        found=0
        for ((index=0; index<${#_n_labels[@]}; index++)); do
            [[ "${_n_sections[index]}" == "$section" ]] || continue
            # Do not publish connection links/passwords for a failed operation.
            label="${_n_labels[index]}"
            if [[ "$status" != success ]]; then
                case "$section:$label" in
                    'CONNECTION INFORMATION:'*|'CONNECTION LINKS:'*|'PAYLOAD HTTP:'*|*':Pass'|*':Password'|*':User ID') continue ;;
                esac
            fi
            if (( found == 0 )); then
                if [[ "$mode" == telegram ]]; then
                    value="$section"; [[ "$section" != 'CONNECTION INFORMATION' ]] || value=CONNECTION
                    if [[ "$section" == CATATAN && "$action" == create ]]; then
                        printf '\n&#9888;&#65039; <b>CATATAN</b>\n'
                    else
                        printf '\n━━━━━━━━━━━━━━━━━━━━\n<b>%s</b>\n━━━━━━━━━━━━━━━━━━━━\n' "$value"
                    fi
                else
                    printf '\n'
                    if [[ -t 1 ]]; then printf '\033[1;36m'; fi
                    printf '%s' "$section"
                    if [[ -t 1 ]]; then printf '\033[0m'; fi
                    printf '\n'; nathaya_account_rule
                fi
                found=1
            fi
            value="${_n_values[index]}"
            if [[ "$mode" == telegram ]]; then
                if [[ -n "$label" ]]; then
                    nathaya_account_html_field "$label" "$value"
                else
                    printf '%s\n' "$(nathaya_account_html_escape "$value")"
                fi
            else
                # %s, not echo -e: passwords, payloads and links stay literal.
                if [[ -n "$label" ]]; then
                    printf '%-18s: %s\n' "$label" "$value"
                else
                    printf '%s\n' "$value"
                fi
            fi
        done
    done
    if [[ "$mode" == telegram ]]; then
        printf '\n━━━━━━━━━━━━━━━━━━━━\n'
        case "$action" in
            renew) printf '&#9989; %s\n' "$note" ;;
            delete) printf '%s\n' "$note" ;;
        esac
        printf '<i>Nathaya Tunnel | Version 1.0.0</i>\n'
    else
        case "$action" in renew|delete) printf '\n%s\n' "$note" ;; esac
        nathaya_account_footer
    fi
)

nathaya_account_send_html() {
    local content="${1:-}" line chunk='' result=0
    # Split at complete HTML lines, retaining all fields, links and event details.
    while IFS= read -r line || [[ -n "$line" ]]; do
        if (( ${#chunk} + ${#line} > 3500 )) && [[ -n "$chunk" ]]; then
            telegram_send_message "$chunk" || result=1
            chunk='&#128640; <b>NATHAYA TUNNEL</b> (lanjutan)'
            chunk+=$'\n'
        fi
        chunk+="$line"$'\n'
    done <<< "$content"
    [[ -z "$chunk" ]] || telegram_send_message "$chunk" || result=1
    return "$result"
}

nathaya_account_notify() {
    local formatted
    formatted=$(nathaya_account_render telegram "${1:-success}" "${3:-}" "${2:-}") || return 0
    nathaya_account_send_html "$formatted" || true
}

nathaya_account_warning() {
    local days="$1" users="$2" total="$3" today="$4" message
    message="&#128640; <b>NATHAYA TUNNEL</b>
&#9888;&#65039; <b>ACCOUNT EXPIRY WARNING</b>

━━━━━━━━━━━━━━━━━━━━
<b>ACCOUNT INFORMATION</b>
━━━━━━━━━━━━━━━━━━━━
$(nathaya_account_html_field 'Checked' "$today")
$(nathaya_account_html_field 'Remaining' "$days hari")
$(nathaya_account_html_field 'Accounts' "$total")
$(nathaya_account_html_field 'Details' "$users")

━━━━━━━━━━━━━━━━━━━━
Segera perpanjang sebelum dihapus otomatis!
<i>Nathaya Tunnel | Version 1.0.0</i>"
    nathaya_account_send_html "$message" || true
}
