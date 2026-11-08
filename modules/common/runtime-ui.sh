#!/bin/bash
# Shared bootstrap for /usr/bin/menu and the installed protocol entry points.
NATHAYA_BASE="${NATHAYA_BASE:-/opt/nathaya}"
if [[ ! -r "$NATHAYA_BASE/modules/common/ui.sh" || ! -r "$NATHAYA_BASE/modules/common/functions.sh" ]]; then
    printf 'Modul Nathaya tidak ditemukan di %s/modules. Jalankan pembaruan installer.\n' "$NATHAYA_BASE" >&2
    return 1
fi
source "$NATHAYA_BASE/modules/common/ui.sh" || return 1
source "$NATHAYA_BASE/modules/common/functions.sh" || return 1

# Palette aliases for extracted upstream operations; their backend is unchanged.
green="$CYAN"; red="$ORANGE"; neutral="$RESET"; blue="$CYAN"
orange="$ORANGE"; yellow="$ORANGE"; purple="$CYAN"; bold_white="$WHITE"
reset="$RESET"; pink="$CYAN"; magenta="$CYAN"; cyan="$CYAN"; bold="$WHITE"

nathaya_normalize_choice() {
    local value="${1,,}"
    # Strip leading zeros textually: 08/09 must not be interpreted as octal.
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        while [[ ${#value} -gt 1 && "$value" == 0* ]]; do
            value="${value#0}"
        done
    fi
    printf '%s' "$value"
}

nathaya_run_command() {
    local name="$1" status
    shift
    case "$name" in
        menu|menussh|menuvmess|menuvless|menutrojan|menushadowsocks|features|addssh|dellssh|renewssh|trialssh|checkssh|addvmess|dellvmess|renewvmess|trialvmess|checkvmess|addvless|dellvless|renewvless|trialvless|checkvless|addtrojan|delltrojan|renewtrojan|trialtrojan|checktrojan|addshadowsocks|dellshadowsocks|renewshadowsocks|trialshadowsocks|checkshadowsocks) ;;
        *) printf 'Perintah tidak diizinkan: %s\n' "$name" >&2; return 127 ;;
    esac
    if [[ ! -x "/usr/bin/$name" ]]; then
        printf 'Perintah %s belum terpasang di /usr/bin. Perbarui instalasi.\n' "$name" >&2
        return 127
    fi
    "/usr/bin/$name" "$@"
    status=$?
    if (( status != 0 && status != 100 )); then
        printf '\nPerintah %s gagal (status %s).\n' "$name" "$status" >&2
    fi
    return "$status"
}

nathaya_run_action() (
    # Legacy action scripts sometimes launch menu/menussh before returning.
    # Suppress that re-entry only in the action child, never in the parent UI.
    export NATHAYA_UI_ACTION=1
    nathaya_run_command "$@"
)

nathaya_features_section() {
    # Integration contract: features --section banner|bandwidth|services|domain|telegram
    nathaya_run_action features --section "$1"
}
