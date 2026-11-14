#!/bin/sh
# Nathaya Tunnel managed dashboard hook v1
# Sourced only by a login shell. Never exec/replace the parent shell.
_nathaya_login() {
    [ "$(/usr/bin/id -u)" = 0 ] || return 0
    case "$-" in *i*) ;; *) return 0 ;; esac
    [ -r /opt/nathaya/services/login-policy.sh ] || return 0
    . /opt/nathaya/services/login-policy.sh || return 0
    _nt_tty=no
    if [ -t 0 ] && [ -t 1 ]; then _nt_tty=yes; fi
    if nathaya_login_policy 0 "$-" "${SSH_CONNECTION:-}" "$_nt_tty" "$0" "${NATHAYA_DASHBOARD_SHOWN:-}" "${SSH_ORIGINAL_COMMAND:-}"; then
        NATHAYA_DASHBOARD_SHOWN=1
        export NATHAYA_DASHBOARD_SHOWN
        /usr/local/bin/menu --login || printf 'Dashboard gagal; login shell tetap tersedia.\n' >&2
    fi
    unset _nt_tty
    unset -f nathaya_login_policy
    return 0
}
_nathaya_login || :
unset -f _nathaya_login
