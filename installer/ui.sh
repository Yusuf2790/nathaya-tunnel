#!/usr/bin/env bash
nt_setup_stage() { NT_STAGE="$1"; printf '\n\033[1;36m[NATHAYA TUNNEL] %s\033[0m\n' "$NT_STAGE"; }
nt_state() {
    local state="$1"
    printf '%s | %s | %s\n' "$(date -u +%FT%TZ)" "$NT_STAGE" "$state" | tee -a "$NT_RUN/stages.tsv"
}
nt_run_stage() {
    NT_STAGE="$1"; shift
    nt_setup_stage "$NT_STAGE"
    nt_state BERJALAN
    "$@"
    nt_state SELESAI
}
nt_can_reboot() { [[ "$1" == full && "$2" == FULL_SUCCESS && "$3" == 0 ]]; }
nt_reboot_countdown() {
    nt_can_reboot "$NT_PROFILE" "$NT_RESULT" "${NT_GATES_RC:-1}" || return 0
    printf 'Full gates sukses. Reboot dalam 30 detik. Batalkan: touch /run/nathaya-cancel-reboot\n'
    local remaining
    for ((remaining=30; remaining>0; remaining--)); do
        if [[ -e /run/nathaya-cancel-reboot ]]; then
            nt_safe_path /run/nathaya-cancel-reboot file
            [[ "$(stat -c %u /run/nathaya-cancel-reboot)" == 0 ]] || return 1
            printf 'Reboot dibatalkan; full result/log dipertahankan.\n'
            return 0
        fi
        printf 'Reboot: %s detik\n' "$remaining"
        sleep 1
    done
    # Commit mandatory cleanup, exit status and permanent logs before requesting reboot.
    nt_finalize_success
    NT_REBOOT_REQUESTED=1
    systemctl reboot
}
