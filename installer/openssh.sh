#!/usr/bin/env bash
# Source-only adapters, no operations on load.
nt_package_installed() {
    [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" == 'install ok installed' ]]
}
nt_unit_active() { systemctl is-active "$1" 2>/dev/null || true; }
nt_unit_enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }

# Query failures are not equivalent to inactive/empty properties. The sentinel
# preserves every trailing newline of Listen through Bash command substitution.
nt_ssh_property_to() {
    [[ "${3:-}" =~ ^NT_[A-Z0-9_]+$ ]] || return 1
    local _nt_value _nt_rc=0
    if _nt_value="$(systemctl show "${1}" -p "${2}" --value 2>/dev/null; _nt_rc=$?; printf '\001'; exit "$_nt_rc")"; then
        _nt_rc=0
    else
        _nt_rc=$?
    fi
    printf -v "${3}" '%s' "${_nt_value%$'\001'}"
    if (( _nt_rc != 0 )); then
        nt_error "Gagal membaca systemctl ${1} property ${2}; preservasi SSH tidak dapat dibuktikan."
        return 1
    fi
}
nt_ssh_scalar_to() {
    nt_ssh_property_to "$@" || return 1
    local _nt_scalar="${!3}"
    [[ "$_nt_scalar" =~ ^[[:space:]]*([^[:space:]]*)[[:space:]]*$ ]] || {
        nt_error 'Property SSH bukan nilai tunggal yang valid.'; return 1;
    }
    printf -v "${3}" '%s' "${BASH_REMATCH[1]}"
}
nt_ssh_listener_tool() {
    python3 -I -B "${NT_SOURCE:-${_NT_SOURCE}}/installer/checks.py" "$@"
}
nt_ssh_artifact() {
    [[ -n "${NT_RUN:-}" && -d "$NT_RUN" && "${1}" =~ ^ssh-[a-z0-9.-]+$ ]] || return 1
    nt_private_file "$NT_RUN/${1}" || return 1
    printf '%s' "${2}" > "$NT_RUN/${1}"
}
nt_ssh_read_states() {
    nt_ssh_scalar_to ssh.service ActiveState NT_SERVICE_CURRENT || return 1
    nt_ssh_scalar_to ssh.socket ActiveState NT_SOCKET_CURRENT || return 1
    nt_ssh_scalar_to ssh.service UnitFileState NT_SERVICE_ENABLE_CURRENT || return 1
    nt_ssh_scalar_to ssh.socket UnitFileState NT_SOCKET_ENABLE_CURRENT || return 1
    local _nt_state
    for _nt_state in "$NT_SERVICE_CURRENT" "$NT_SOCKET_CURRENT"; do
        case "$_nt_state" in active|inactive|failed|activating|deactivating|reloading|maintenance|refreshing) ;;
            *) nt_error 'Status unit SSH kosong/tidak dikenal.'; return 1 ;;
        esac
    done
    for _nt_state in "$NT_SERVICE_ENABLE_CURRENT" "$NT_SOCKET_ENABLE_CURRENT"; do
        case "$_nt_state" in enabled|enabled-runtime|linked|linked-runtime|alias|masked|masked-runtime|static|disabled|indirect|generated|transient) ;;
            '') [[ "$NT_SSH_EXISTED" == 0 ]] || { nt_error 'Enablement SSH tidak terbaca.'; return 1; } ;;
            *) nt_error 'Enablement SSH tidak dikenal.'; return 1 ;;
        esac
    done
}
nt_ssh_read_identity() {
    nt_ssh_scalar_to ssh.service ExecMainStartTimestampMonotonic NT_SSH_START_CURRENT || return 1
    nt_ssh_scalar_to ssh.socket ActiveEnterTimestampMonotonic NT_SOCKET_TIMESTAMP_CURRENT || return 1
    nt_ssh_scalar_to ssh.socket InvocationID NT_SOCKET_INVOCATION_CURRENT || return 1
    local _nt_stamp _nt_state _nt_kind
    for _nt_kind in service socket; do
        if [[ "$_nt_kind" == service ]]; then
            _nt_stamp="$NT_SSH_START_CURRENT"; _nt_state="$NT_SERVICE_CURRENT"
        else
            _nt_stamp="$NT_SOCKET_TIMESTAMP_CURRENT"; _nt_state="$NT_SOCKET_CURRENT"
        fi
        [[ -z "$_nt_stamp" || "$_nt_stamp" =~ ^[0-9]+$ ]] || { nt_error 'Timestamp SSH invalid.'; return 1; }
        if [[ "$_nt_state" == active && ( -z "$_nt_stamp" || "$_nt_stamp" =~ ^0+$ ) ]]; then
            nt_error 'Identitas unit SSH aktif kosong.'; return 1
        fi
    done
    # Listen is deliberately NOT process identity. Empty InvocationID is allowed
    # for units without one; the nonzero active timestamp remains mandatory.
    NT_SOCKET_IDENTITY_CURRENT="$(python3 -I -B -c 'import json,sys; print(json.dumps(dict(zip(("ActiveEnterTimestampMonotonic","InvocationID"),sys.argv[1:])),sort_keys=True,separators=(",",":")))' "$NT_SOCKET_TIMESTAMP_CURRENT" "$NT_SOCKET_INVOCATION_CURRENT")" || return 1
}
nt_ssh_snapshot() {
    NT_SSH_BASELINE_READY=0 NT_SSH_VERIFY_SEQ=0 NT_SSH_EXISTED=0
    nt_package_installed openssh-server && NT_SSH_EXISTED=1
    nt_ssh_read_states || return 1
    NT_SERVICE_BEFORE="$NT_SERVICE_CURRENT" NT_SOCKET_BEFORE="$NT_SOCKET_CURRENT"
    NT_SERVICE_ENABLE_BEFORE="$NT_SERVICE_ENABLE_CURRENT" NT_SOCKET_ENABLE_BEFORE="$NT_SOCKET_ENABLE_CURRENT"
    if [[ "$NT_SSH_EXISTED" == 1 ]]; then
        if [[ "$NT_SERVICE_BEFORE" != active && "$NT_SOCKET_BEFORE" != active ]]; then
            nt_error 'OpenSSH sudah terpasang tetapi tidak aktif. Periksa/aktifkan sendiri melalui konsol VPS; installer tidak mengubah keputusan admin.'
            return 1
        fi
    elif [[ -e /etc/ssh/sshd_config || "$NT_SERVICE_BEFORE" == active || "$NT_SOCKET_BEFORE" == active ]]; then
        nt_error 'SSH/config terdeteksi tanpa paket openssh-server terkelola. Rekonsiliasi manual diperlukan.'
        return 1
    fi
    nt_ssh_property_to ssh.socket Listen NT_SOCKET_LISTEN_BEFORE || return 1
    local -a _nt_allow=()
    [[ "$NT_SOCKET_BEFORE" == active ]] || _nt_allow=(--allow-empty)
    NT_SOCKET_CANON_BEFORE="$(printf '%s' "$NT_SOCKET_LISTEN_BEFORE" | nt_ssh_listener_tool canonical-ssh-listeners "${_nt_allow[@]}")" || return 1
    nt_ssh_read_identity || return 1
    NT_SSH_START_BEFORE="$NT_SSH_START_CURRENT" NT_SOCKET_IDENTITY_BEFORE="$NT_SOCKET_IDENTITY_CURRENT"
    NT_SSH_START_EXPECTED="$NT_SSH_START_BEFORE" NT_SOCKET_IDENTITY_EXPECTED="$NT_SOCKET_IDENTITY_BEFORE"
    NT_SSH_BASELINE_READY=1
}
nt_ssh_baseline_document() {
    python3 -I -B -c 'import json,sys; print(json.dumps(dict(zip(("existed","service","socket","service_enabled","socket_enabled","service_start","socket_identity","listen_raw","listen_canonical"),sys.argv[1:])),sort_keys=True,separators=(",",":")))' \
        "${NT_SSH_EXISTED:-}" "${NT_SERVICE_BEFORE:-}" "${NT_SOCKET_BEFORE:-}" \
        "${NT_SERVICE_ENABLE_BEFORE:-}" "${NT_SOCKET_ENABLE_BEFORE:-}" \
        "${NT_SSH_START_BEFORE:-}" "${NT_SOCKET_IDENTITY_BEFORE:-}" \
        "${NT_SOCKET_LISTEN_BEFORE:-}" "${NT_SOCKET_CANON_BEFORE:-}"
}
nt_ssh_persist_baseline() {
    [[ "${NT_SSH_BASELINE_READY:-0}" == 1 ]] || { nt_error 'Baseline SSH preflight belum valid.'; return 1; }
    local _nt_document
    _nt_document="$(nt_ssh_baseline_document)" || return 1
    # Persist the preflight values, NEVER recollect/rebase listeners at this point.
    nt_ssh_artifact ssh-listen-before.raw "$NT_SOCKET_LISTEN_BEFORE" || return 1
    nt_ssh_artifact ssh-listen-before.canonical.json "$NT_SOCKET_CANON_BEFORE" || return 1
    nt_ssh_artifact ssh-baseline.json "$_nt_document"
}
nt_ssh_assert_baseline() {
    [[ "${NT_SSH_BASELINE_READY:-0}" == 1 ]] || { nt_error 'Baseline SSH preflight hilang pada batas worker.'; return 1; }
    local _nt_document _nt_canonical
    local -a _nt_allow=()
    [[ "${NT_SOCKET_BEFORE:-}" == active ]] || _nt_allow=(--allow-empty)
    _nt_canonical="$(printf '%s' "${NT_SOCKET_LISTEN_BEFORE:-}" | nt_ssh_listener_tool canonical-ssh-listeners "${_nt_allow[@]}")" || return 1
    [[ "$_nt_canonical" == "${NT_SOCKET_CANON_BEFORE:-}" ]] || { nt_error 'Baseline canonical SSH hilang/invalid.'; return 1; }
    _nt_document="$(nt_ssh_baseline_document)" || return 1
    nt_ssh_artifact ssh-baseline-inherited.json "$_nt_document" || return 1
    cmp -s -- "$NT_RUN/ssh-baseline.json" "$NT_RUN/ssh-baseline-inherited.json" || {
        nt_error 'Baseline worker tidak sama dengan snapshot preflight; tidak diambil ulang.'; return 1;
    }
    # Keep both evidence files bound to the same immutable preflight snapshot.
    nt_ssh_artifact ssh-baseline-raw-check.raw "${NT_SOCKET_LISTEN_BEFORE:-}" || return 1
    cmp -s -- "$NT_RUN/ssh-listen-before.raw" "$NT_RUN/ssh-baseline-raw-check.raw" || return 1
    nt_ssh_artifact ssh-baseline-canonical-check.json "$_nt_canonical" || return 1
    cmp -s -- "$NT_RUN/ssh-listen-before.canonical.json" "$NT_RUN/ssh-baseline-canonical-check.json" || return 1
}

nt_ssh_config_fingerprint() {
    # Only hashes of public server configuration; never read/copy private host keys.
    if [[ -f /etc/ssh/sshd_config ]]; then
        sha256sum -- /etc/ssh/sshd_config || return 1
        /usr/sbin/sshd -T | awk '$1 ~ /^(port|listenaddress|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|authenticationmethods|usepam|authorizedkeysfile|allowusers|denyusers|allowgroups|denygroups)$/ {print}' | sort | sha256sum || return 1
    fi
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        find /etc/ssh/sshd_config.d -type f -name '*.conf' -exec sha256sum -- {} + | sort || return 1
    fi
}

nt_verify_preserved_ssh() {
    nt_ssh_assert_baseline || return 1
    NT_SSH_VERIFY_SEQ=$((NT_SSH_VERIFY_SEQ + 1))
    local _nt_prefix="ssh-listen-after-$NT_SSH_VERIFY_SEQ" _nt_rc=0
    local -a _nt_allow=()
    nt_ssh_artifact "$_nt_prefix.context" "${NT_STAGE:-unknown}" || return 1
    nt_ssh_artifact "$_nt_prefix.status" 'FAILED: read not completed' || return 1
    nt_ssh_read_states || return 1
    if ! nt_ssh_property_to ssh.socket Listen NT_SOCKET_LISTEN_CURRENT; then
        nt_ssh_artifact "$_nt_prefix.raw" "${NT_SOCKET_LISTEN_CURRENT:-}" || return 1
        return 1
    fi
    nt_ssh_artifact "$_nt_prefix.raw" "$NT_SOCKET_LISTEN_CURRENT" || return 1
    [[ "$NT_SOCKET_CURRENT" == active ]] || _nt_allow=(--allow-empty)
    NT_SOCKET_CANON_CURRENT="$(printf '%s' "$NT_SOCKET_LISTEN_CURRENT" | nt_ssh_listener_tool canonical-ssh-listeners "${_nt_allow[@]}")" || {
        nt_ssh_artifact "$_nt_prefix.status" 'FAILED: invalid/empty listener value' || return 1
        return 1
    }
    nt_ssh_artifact "$_nt_prefix.canonical.json" "$NT_SOCKET_CANON_CURRENT" || return 1
    nt_ssh_artifact "$_nt_prefix.status" 'CAPTURED: Listen read/canonicalized; not yet preservation-verified' || return 1
    nt_ssh_read_identity || return 1
    nt_ssh_artifact "$_nt_prefix.identity.json" "$NT_SOCKET_IDENTITY_CURRENT" || return 1
    nt_ssh_artifact "$_nt_prefix.service-start" "$NT_SSH_START_CURRENT" || return 1
    if [[ "$NT_SSH_EXISTED" == 1 ]]; then
        if [[ "$NT_SOCKET_BEFORE" == active ]]; then
            nt_private_file "$NT_RUN/$_nt_prefix.diff.json" || return 1
            nt_ssh_listener_tool compare-ssh-listeners "$NT_RUN/ssh-listen-before.canonical.json" \
                "$NT_RUN/$_nt_prefix.canonical.json" > "$NT_RUN/$_nt_prefix.diff.json" || _nt_rc=$?
            if (( _nt_rc != 0 )); then
                if (( _nt_rc == 1 )); then
                    # Emit the structured difference BEFORE nt_error (returns 1),
                    # including when the real worker runs with errexit enabled.
                    nt_ssh_artifact "$_nt_prefix.status" 'FAILED: listener sets differ' || return 1
                    cat -- "$NT_RUN/$_nt_prefix.diff.json" >&2 || return 1
                    nt_error "Kumpulan listener socket admin berubah (removed=hilang, added=baru); IPv4/IPv6 tidak disamakan. Snapshot raw/canonical/diff: $NT_RUN/$_nt_prefix.*"
                else
                    nt_ssh_artifact "$_nt_prefix.status" 'FAILED: snapshot comparison unreadable/invalid' || return 1
                    nt_error "Gagal membaca/membandingkan snapshot SSH: $NT_RUN/$_nt_prefix.*"
                fi
                return 1
            fi
        fi
        [[ "$NT_SERVICE_ENABLE_CURRENT" == "$NT_SERVICE_ENABLE_BEFORE" &&
           "$NT_SOCKET_ENABLE_CURRENT" == "$NT_SOCKET_ENABLE_BEFORE" ]] || {
            nt_error 'Enablement SSH berubah selama pemasangan paket; periksa manual.'; return 1;
        }
        if [[ "$NT_SERVICE_BEFORE" == active ]]; then
            [[ "$NT_SERVICE_CURRENT" == active ]] || { nt_error 'Service SSH admin awal tidak aktif.'; return 1; }
            if [[ "${NT_OS_MAINTENANCE:-0}" != 1 ]]; then
                [[ "$NT_SSH_START_CURRENT" == "${NT_SSH_START_EXPECTED:-}" ]] || {
                    nt_error 'Proses SSH awal berubah; hentikan dan periksa akses admin.'; return 1;
                }
            fi
        fi
        [[ "$NT_SOCKET_CURRENT" == "$NT_SOCKET_BEFORE" ]] || { nt_error 'Status socket SSH berubah.'; return 1; }
        if [[ "$NT_SOCKET_BEFORE" == active && "${NT_OS_MAINTENANCE:-0}" != 1 ]]; then
            [[ "$NT_SOCKET_IDENTITY_CURRENT" == "${NT_SOCKET_IDENTITY_EXPECTED:-}" ]] || {
                nt_error 'Identitas socket SSH berubah; periksa manual.'; return 1;
            }
        fi
    fi
    [[ "$NT_SERVICE_CURRENT" == active || "$NT_SOCKET_CURRENT" == active ]] || {
        nt_error 'SSH tidak memiliki service/socket aktif setelah maintenance.'; return 1;
    }
    if [[ "$NT_SSH_EXISTED" != 1 ]]; then
        nt_ssh_artifact "$_nt_prefix.status" 'VERIFIED: new SSH active' || return 1
        return 0
    fi
    nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-after" || return 1
    cmp -s -- "$NT_RUN/ssh-config-before" "$NT_RUN/ssh-config-after" || {
        nt_error 'Konfigurasi SSH berubah selama pemasangan paket; tidak ada rollback otomatis.'; return 1;
    }
    nt_ssh_artifact "$_nt_prefix.status" 'VERIFIED: SSH preserved'
}

nt_ssh_accept_post_os_identity() {
    [[ "${NT_OS_MAINTENANCE:-0}" == 1 ]] || return 1
    [[ "$NT_SSH_EXISTED" == 1 ]] || return 0
    # Reverify listeners/config/auth/enablement/access BEFORE accepting OS restarts.
    nt_verify_preserved_ssh || return 1
    NT_SSH_START_EXPECTED="$NT_SSH_START_CURRENT" NT_SOCKET_IDENTITY_EXPECTED="$NT_SOCKET_IDENTITY_CURRENT"
    nt_ssh_artifact ssh-post-os-identity.json "$NT_SOCKET_IDENTITY_EXPECTED" || return 1
    nt_ssh_artifact ssh-post-os-service-start "$NT_SSH_START_EXPECTED"
}


nt_openssh_keys() {
    local key
    nt_directory /run/sshd 755
    for key in /etc/ssh/ssh_host_*_key; do
        [[ -e "$key" || -L "$key" ]] || continue
        nt_safe_path "$key" file
        ssh-keygen -y -P '' -f "$key" >/dev/null 2>&1 || { nt_error 'Host key existing invalid; tidak diregenerasi otomatis.'; return 1; }
        chown root:root "$key"; chmod 600 "$key"
    done
    ssh-keygen -A >/dev/null 2>&1
    /usr/sbin/sshd -t
    nt_ssh_read_states || return 1
    if [[ "$NT_SERVICE_CURRENT" != active && "$NT_SOCKET_CURRENT" != active ]]; then
        [[ "$NT_SSH_EXISTED" == 0 ]] || return 1
        systemctl start ssh.service
    fi
    nt_verify_preserved_ssh
}
