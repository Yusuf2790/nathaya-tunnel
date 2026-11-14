#!/usr/bin/env bash
# Source-only service-action guard. OS maintenance intentionally does not hold it.
nt_policy_owner() { chown "0:$2" -- "$1"; }
nt_publish_policy() {
    local input="$1" mode="$2" group="$3" destination="$4"
    nt_safe_path "$destination" file || return 1
    NT_POLICY_TMP="$(mktemp "$(dirname -- "$destination")/.nathaya-policy.XXXXXXXX")" || return 1
    if ! { cat -- "$input" > "$NT_POLICY_TMP" && nt_policy_owner "$NT_POLICY_TMP" "$group" && chmod "$mode" -- "$NT_POLICY_TMP" && mv -fT -- "$NT_POLICY_TMP" "$destination"; }; then
        rm -f -- "$NT_POLICY_TMP"
        NT_POLICY_TMP=''
        return 1
    fi
    NT_POLICY_TMP=''
}

nt_restore_policy() {
    local destination="$NT_POLICY_PATH"
    if [[ "$NT_POLICY_EXISTED" == 0 && ! -e "$destination" && ! -L "$destination" ]]; then
        NT_POLICY_ACTIVE=0
        return 0
    fi
    # Restore our guard OR the untouched original after failed publication;
    # do not overwrite a policy with unrelated content installed by someone else.
    [[ -f "$destination" && ! -L "$destination" ]] &&
        { cmp -s -- "$destination" "$NT_RUN/policy-deny" ||
          { [[ "$NT_POLICY_EXISTED" == 1 ]] && cmp -s -- "$destination" "$NT_RUN/policy-original"; }; } || {
            printf 'ERROR: policy-rc.d berubah; pemulihan manual dari %s diperlukan.\n' "$NT_RUN" >&2
            return 1
        }
    if [[ "$NT_POLICY_EXISTED" == 1 ]]; then
        nt_publish_policy "$NT_RUN/policy-original" "$NT_POLICY_MODE" "$NT_POLICY_GROUP" "$destination" || return 1
        touch -r "$NT_RUN/policy-original" -- "$destination" || return 1
    else
        rm -- "$destination" || return 1
    fi
    NT_POLICY_ACTIVE=0
}

nt_hold_services() {
    NT_POLICY_PATH="$1"
    NT_POLICY_EXISTED=0
    nt_safe_path "$NT_RUN/policy-original" file || return 1
    nt_safe_path "$NT_RUN/policy-deny" file || return 1
    nt_safe_path "$NT_POLICY_PATH" file || return 1
    if [[ -e "$NT_POLICY_PATH" ]]; then
        NT_POLICY_MODE="$(stat -c %a "$NT_POLICY_PATH")" || return 1
        NT_POLICY_GROUP="$(stat -c %g "$NT_POLICY_PATH")" || return 1
        cp -p -- "$NT_POLICY_PATH" "$NT_RUN/policy-original" || return 1
        chmod 600 -- "$NT_RUN/policy-original" || return 1
        NT_POLICY_EXISTED=1
    fi
    printf '#!/bin/sh\n# Nathaya temporary service-action guard\nexit 101\n' > "$NT_RUN/policy-deny" || return 1
    chmod 600 -- "$NT_RUN/policy-deny" || return 1
    NT_POLICY_ACTIVE=1
    nt_publish_policy "$NT_RUN/policy-deny" 755 0 "$NT_POLICY_PATH"
}

