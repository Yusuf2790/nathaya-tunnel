#!/usr/bin/env bash
# Source defines functions only. No initialization, scanning or account operations.
# Expiry only: IP enforcement is excluded until a trustworthy real-peer collector
# exists across SSH/WebSocket/Dropbear/OpenVPN. No password unlock or user deletion.

ssh_expire_valid_record() {
    local record="${1:-}" separators username created expiry limit_ip status lock_until account_type
    [[ -n "$record" && "$record" != *$'\n'* && "$record" != *$'\r'* ]] || return 1
    separators="${record//[^|]/}"
    [[ ${#separators} -eq 6 ]] || return 1
    IFS='|' read -r username created expiry limit_ip status lock_until account_type <<< "$record"
    ssh_valid_username "$username" && [[ "$username" != root ]] || return 1
    ssh_valid_date "$created" || return 1
    ssh_valid_expiry_for_type "$account_type" "$expiry" || return 1
    case "$status" in active|locked|expired) ;; *) return 1 ;; esac
    [[ "$limit_ip" =~ ^[1-9][0-9]{0,2}$ ]] && (( limit_ip <= 100 )) || return 1
    [[ "$lock_until" =~ ^[0-9]+$ ]] || return 1
    [[ "$created" > "${expiry%% *}" ]] && return 1
    return 0
}

# A DB username alone is insufficient authority to touch a Linux identity.
ssh_expire_managed_identity() {
    local username="${1:-}" identity separators linux_user marker uid gid gecos home shell id_uid
    ssh_valid_username "$username" && [[ "$username" != root ]] || return 1
    identity="$(getent passwd "$username")" || return 1
    [[ "$identity" != *$'\n'* ]] || return 1
    separators="${identity//[^:]/}"
    [[ ${#separators} -eq 6 ]] || return 1
    IFS=: read -r linux_user marker uid gid gecos home shell <<< "$identity"
    [[ "$linux_user" == "$username" && "$uid" =~ ^[1-9][0-9]{3,9}$ &&
       "$home" == "/home/$username" && "$shell" == /bin/bash ]] || return 1
    (( uid >= 1000 && uid != 65534 )) || return 1
    id_uid="$(id -u "$username" 2>/dev/null)" || return 1
    [[ "$id_uid" == "$uid" ]] || return 1
    printf '%s\n' "$uid"
}

# Caller holds operations.lock (FD 8) throughout. DB helpers take FD 9 separately.
# Always re-read: duplicate, legacy, changed or invalid records fail closed.
ssh_expire_one_locked() {
    local username="$1" expected="$2" current created expiry limit_ip status lock_until account_type
    local kill_rc=0 db_rc=0 uid
    current="$(ssh_db_get_account "$username")" || return 0
    [[ "$current" == "$expected" ]] || return 0
    ssh_expire_valid_record "$current" || return 0
    IFS='|' read -r username created expiry limit_ip status lock_until account_type <<< "$current"
    ssh_account_expiry_reached "$account_type" "$expiry" || return 0
    ssh_expire_managed_identity "$username" >/dev/null || return 0

    # Recheck the managed record and Linux identity while still holding the lock.
    [[ "$(ssh_db_get_account "$username")" == "$current" ]] || return 0
    uid="$(ssh_expire_managed_identity "$username")" || return 0
    # Account expiry (not passwd -l) also denies public-key login when PAM account
    # checks are enabled. Do not rewrite password/key state or admin password locks.
    if ! chage -E 0 "$username"; then
        printf 'ERROR: SSH expiry Linux gagal: %s\n' "$username" >&2
        return 1
    fi
    # Kill existing trial/regular sessions as well as denying subsequent logins.
    # Never target a daemon globally; all identity safeguards precede this call.
    # Use the verified UID: an all-numeric username must NOT be parsed by pkill
    # as a different UID (in particular a numeric name resembling UID 0).
    pkill -KILL -u "$uid" 2>/dev/null || kill_rc=$?
    # Preserve lock metadata for Renew; never auto-unlock an administrator lock.
    ssh_db_update_status "$username" expired "$lock_until" || db_rc=$?
    if (( db_rc != 0 || kill_rc > 1 )); then
        printf 'ERROR: SSH expiry perlu rekonsiliasi: %s\n' "$username" >&2
        return 1
    fi
}

ssh_expire_once() (
    [[ $EUID -eq 0 ]] || { echo 'ERROR: Jalankan sebagai root.' >&2; return 1; }
    # No source-time filesystem changes. Runtime initialization uses the one DB.
    ssh_db_init || return 1
    # Same ordering as Create/Delete/Lock/Unlock/Renew/Trial: operations, then DB.
    # Subshell owns FD 8, so errors/signals cannot leave a lock in the caller.
    exec 8>>"$NATHAYA_SSH_OPERATIONS_LOCK" || return 1
    flock -x 8 || return 1
    ssh_expire_scan_locked
)

# Internal worker: operations.lock must already be held by the caller.
ssh_expire_scan_locked() {
    local row username rc=0
    while IFS= read -r row || [[ -n "$row" ]]; do
        ssh_expire_valid_record "$row" || continue
        username="${row%%|*}"
        ssh_expire_one_locked "$username" "$row" || rc=1
    done < "$NATHAYA_SSH_DB" || rc=1
    return "$rc"
}

ssh_expire_main() {
    [[ $EUID -eq 0 ]] || { echo 'ERROR: Jalankan sebagai root.' >&2; return 1; }
    if (( $# > 1 )) || [[ "${1:---once}" != --once ]]; then
        echo 'Usage: ssh-expire.sh [--once]' >&2
        return 2
    fi
    source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../common" && pwd)/bootstrap.sh" || return 1
    source "$NATHAYA_BASE/modules/ssh/account-db.sh" || return 1
    ssh_expire_once
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    ssh_expire_main "$@"
fi
