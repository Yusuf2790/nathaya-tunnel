#!/usr/bin/env bash
# Source-only installer helpers. Explicit roots are for isolated unit tests;
# setup.sh always supplies / and never accepts destination/environment overrides.

nt_error() { printf 'ERROR: %s\n' "$*" >&2; return 1; }

nt_program_files() {
    printf '%s\n' \
        menu.sh \
        VERSION \
        NOTICE \
        licenses/Alrescha79-MIT.txt \
        config/config.conf.example \
        config/ports.json \
        modules/common/bootstrap.sh \
        modules/common/functions.sh \
        modules/common/telegram.sh \
        modules/common/ui.sh \
        modules/dashboard/dashboard.sh \
        modules/menu/domain.sh \
        modules/menu/main.sh \
        modules/menu/set_domain.sh \
        modules/menu/ssh.sh \
        modules/ssh/account-db.sh \
        modules/ssh/create.sh \
        modules/ssh/delete.sh \
        modules/ssh/list-expired.sh \
        modules/ssh/list-member.sh \
        modules/ssh/lock.sh \
        modules/ssh/login.sh \
        modules/ssh/renew.sh \
        modules/ssh/trial.sh \
        modules/ssh/unlock.sh \
        modules/maintenance/ssh-expire.sh \
        installer/lib.sh \
        installer/policy.sh \
        installer/openssh.sh \
        installer/domain.sh \
        installer/dependencies.sh \
        installer/firewall.sh \
        installer/dropbear.sh \
        installer/websocket.sh \
        installer/udp.sh \
        installer/openvpn.sh \
        installer/ui.sh \
        installer/runtime.sh \
        installer/tls.sh \
        installer/tls-renew.sh \
        installer/xray.sh \
        installer/proxies.sh \
        installer/maintenance.sh \
        installer/verify.sh \
        installer/preflight.sh \
        installer/menu-wrapper.sh \
        installer/external-lock.json \
        installer/artifacts.py \
        installer/render.py \
        installer/checks.py \
        installer/state.py \
        services/login-policy.sh \
        services/nathaya-dashboard.sh \
        services/ws_proxy.py \
        services/nathaya-ssh-expire.service \
        services/nathaya-ssh-expire.timer \
        services/nathaya-cert-renew.service \
        services/nathaya-cert-renew.timer \
        updater/main.py \
        updater/release.py \
        updater/release-policy.json \
        updater/update.sh \
        updater/nathaya-update.service \
        updater/nathaya-update.timer
}

nt_source_files() {
    nt_program_files
    printf '%s\n' setup.sh
}

# Reject symlinks in ANY component, wrong types, and multiply-linked files.
# Does not create anything, including when the leaf/ancestors do not exist.
nt_safe_path() {
    local path="$1" kind="$2" part cursor="" i
    local -a parts
    [[ "$path" == /* && "$path" != *$'\n'* ]] || { nt_error 'Path harus absolut.'; return 1; }
    IFS='/' read -r -a parts <<< "$path"
    for ((i=1; i<${#parts[@]}; i++)); do
        part="${parts[i]}"
        [[ -n "$part" ]] || continue
        [[ "$part" != . && "$part" != .. ]] || { nt_error "Komponen path tidak aman: $path"; return 1; }
        cursor+="/$part"
        [[ ! -L "$cursor" ]] || { nt_error "Symlink ditolak: $cursor"; return 1; }
        if [[ -e "$cursor" ]]; then
            if (( i < ${#parts[@]} - 1 )) || [[ "$kind" == dir ]]; then
                [[ -d "$cursor" ]] || { nt_error "Bukan direktori: $cursor"; return 1; }
            else
                [[ -f "$cursor" && "$(stat -c %h -- "$cursor")" == 1 ]] || {
                    nt_error "Bukan file reguler tunggal: $cursor"; return 1;
                }
            fi
        fi
    done
}

nt_check_wrapper() {
    local path="$1" first="" marker=""
    nt_safe_path "$path" file || return 1
    [[ -e "$path" ]] || return 0
    { IFS= read -r first; IFS= read -r marker; } < "$path" || true
    [[ "$first" == '#!/bin/sh' && "$marker" == '# Nathaya Tunnel managed menu wrapper v1' ]] || {
        nt_error "Konflik $path: bukan wrapper milik Nathaya; pindahkan/selesaikan konflik secara manual."; return 1;
    }
}

nt_validate_source() {
    local source="$1" relative
    nt_safe_path "$source" dir || return 1
    while IFS= read -r relative; do
        nt_safe_path "$source/$relative" file || return 1
        [[ -f "$source/$relative" && -r "$source/$relative" ]] || {
            nt_error "Source tidak lengkap: $relative"; return 1;
        }
        if [[ "$relative" == *.sh ]]; then
            bash -n "$source/$relative" 2>/dev/null || { nt_error "Sintaks Bash source gagal: $relative"; return 1; }
        elif [[ "$relative" == *.py ]]; then
            python3 -I -B -c 'import ast,sys; ast.parse(open(sys.argv[1],"rb").read(),filename=sys.argv[1])' "$source/$relative" 2>/dev/null || { nt_error "Sintaks Python source gagal: $relative"; return 1; }
        elif [[ "$relative" == *.json ]]; then
            python3 -I -B -c 'import json,sys; json.load(open(sys.argv[1],encoding="utf-8"))' "$source/$relative" 2>/dev/null || { nt_error "Sintaks JSON source gagal: $relative"; return 1; }
        fi
    done < <(nt_source_files)
}

nt_validate_config() {
    local config="$1" bootstrap="$2" require_defaults="${3:-no}"
    # Separate shell, no inherited bootstrap guard, functions, path overrides or secrets.
    env -i PATH="$PATH" "$BASH" --noprofile --norc -c '
        source "$1" || exit 1
        CONFIG_FILE="$2"
        load_nathaya_config || exit 1
        if [[ "$3" == yes ]]; then
            [[ -z "$DOMAIN" && "$TELEGRAM_STATUS" == OFF &&
               -z "$TELEGRAM_BOT_TOKEN" && -z "$TELEGRAM_ADMIN_ID" ]] || exit 1
        fi
    ' bash "$bootstrap" "$config" "$require_defaults" || {
        nt_error 'Konfigurasi tidak valid/default example tidak aman (nilai tidak ditampilkan).'; return 1;
    }
}

nt_check_apt_plan() {
    local plan="$1" mode="${2:-app}" action package rest
    while read -r action package rest || [[ -n "$action$package$rest" ]]; do
        case "$action" in
            Remv)
                if [[ "$mode" != os ]] || nt_is_critical_package "$package"; then
                    nt_error "Rencana apt menghapus komponen terlarang: $package"; return 1
                fi
                ;;
            Inst)
                if [[ "$mode" != os ]] && nt_package_installed "$package"; then
                    nt_error "Rencana apt mengganti paket terpasang: $package; lakukan pemeliharaan terpisah."
                    return 1
                fi
                ;;
        esac
    done < "$plan"
}

nt_check_targets() {
    local root="${1%/}" relative path
    nt_check_wrapper "$root/usr/local/bin/menu" || return 1
    for path in opt/nathaya etc/nathaya-tunnel opt/nathaya/data opt/nathaya/data/ssh \
        opt/nathaya/logs var/cache/nathaya-tunnel var/backups/nathaya-tunnel; do
        nt_safe_path "$root/$path" dir || return 1
    done
    while IFS= read -r relative; do
        nt_safe_path "$root/opt/nathaya/$relative" file || return 1
    done < <(nt_program_files)
    for path in etc/nathaya-tunnel/config.conf opt/nathaya/data/ssh/accounts.db \
        opt/nathaya/data/ssh/accounts.lock opt/nathaya/data/ssh/operations.lock \
        opt/nathaya/logs/telegram.log opt/nathaya/logs/ssh-reconcile.log var/cache/nathaya-tunnel/location.cache; do
        nt_safe_path "$root/$path" file || return 1
    done
}

# Production-only ownership check. Every existing destination directory must be
# root-owned and not group/world writable; files may be tightened during install.
nt_secure_parents() {
    local path="$1" cursor="" part uid mode
    local -a parts
    IFS='/' read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [[ -n "$part" ]] || continue
        cursor+="/$part"
        [[ -d "$cursor" ]] || continue
        uid="$(stat -c %u -- "$cursor")" || return 1
        mode="$(stat -c %a -- "$cursor")" || return 1
        [[ "$uid" == 0 ]] && (( (8#$mode & 0022) == 0 )) || {
            nt_error "Direktori tujuan tidak tepercaya (owner/mode): $cursor"; return 1;
        }
    done
}

nt_set_owner() { chown root:root -- "$1"; }
nt_directory() {
    local path="$1" mode="$2"
    nt_safe_path "$path" dir || return 1
    mkdir -p -- "$path" || return 1
    nt_set_owner "$path" && chmod "$mode" -- "$path"
}

nt_backup_file() {
    local target="$1" backup="$2" relative="$3"
    [[ -e "$target" ]] || return 0
    nt_safe_path "$target" file || return 1
    nt_directory "$(dirname -- "$backup/replaced/$relative")" 700 || return 1
    nt_safe_path "$backup/replaced/$relative" file || return 1
    [[ ! -e "$backup/replaced/$relative" ]] || { nt_error 'Backup sudah ada; gunakan run directory baru.'; return 1; }
    cp -p -- "$target" "$backup/replaced/$relative" || return 1
    nt_set_owner "$backup/replaced/$relative" || return 1
    chmod 600 -- "$backup/replaced/$relative" || return 1
    printf '%s\n' "$relative" >> "$backup/replaced-files" || return 1
}

nt_replace_file() {
    local source="$1" target="$2" mode="$3" backup="$4" relative="$5" tmp
    nt_safe_path "$target" file || return 1
    nt_backup_file "$target" "$backup" "$relative" || return 1
    if [[ ! -e "$target" ]]; then
        printf '%s\n' "$relative" >> "$backup/new-files" || return 1
    fi
    tmp="$(mktemp "$(dirname -- "$target")/.nathaya.XXXXXX")" || return 1
    if ! { cat -- "$source" > "$tmp" && nt_set_owner "$tmp" && chmod "$mode" -- "$tmp" && mv -fT -- "$tmp" "$target"; }; then
        rm -f -- "$tmp"
        return 1
    fi
}

nt_private_file() {
    local path="$1" template="${2:-}"
    nt_safe_path "$path" file || return 1
    if [[ ! -e "$path" ]]; then
        # noclobber prevents truncating a file created between the check and open.
        if [[ -n "$template" ]]; then
            (set -o noclobber; cat -- "$template" > "$path") || return 1
        else
            (set -o noclobber; : > "$path") || return 1
        fi
    fi
    nt_set_owner "$path" && chmod 600 -- "$path"
}

# Copies only the manifest, never repository runtime config/data/logs/.git/tests.
# No package/service operations here: shared by production and temporary-root tests.
nt_deploy() {
    local source="$1" root="${2%/}" backup="$3" relative mode target
    nt_validate_source "$source" || return 1
    [[ "$source" != "$root/opt/nathaya" && "$source" != "$root/opt/nathaya/"* ]] || {
        nt_error 'Gunakan salinan source terpisah di luar /opt/nathaya.'; return 1;
    }
    nt_check_targets "$root" || return 1
    nt_directory "$backup" 700 || return 1
    for relative in replaced-files new-files; do
        nt_safe_path "$backup/$relative" file || return 1
        [[ ! -e "$backup/$relative" ]] || { nt_error 'Jurnal backup sudah ada; gunakan run directory baru.'; return 1; }
    done
    (set -o noclobber; : > "$backup/replaced-files") || return 1
    (set -o noclobber; : > "$backup/new-files") || return 1
    chmod 600 -- "$backup/replaced-files" "$backup/new-files" || return 1
    nt_directory "$root/opt/nathaya" 755 || return 1
    nt_directory "$root/opt/nathaya/modules" 755 || return 1
    for relative in common dashboard menu ssh; do
        nt_directory "$root/opt/nathaya/modules/$relative" 755 || return 1
    done
    nt_directory "$root/opt/nathaya/config" 755 || return 1
    while IFS= read -r relative; do
        mode=644
        [[ "$relative" == menu.sh ]] && mode=755
        [[ "$relative" == updater/update.sh ]] && mode=755
        nt_directory "$(dirname -- "$root/opt/nathaya/$relative")" 755 || return 1
        nt_replace_file "$source/$relative" "$root/opt/nathaya/$relative" "$mode" "$backup" "opt/nathaya/$relative" || return 1
    done < <(nt_program_files)

    for relative in etc/nathaya-tunnel opt/nathaya/data opt/nathaya/data/ssh opt/nathaya/logs var/cache/nathaya-tunnel; do
        nt_directory "$root/$relative" 700 || return 1
    done
    NT_CONFIG_RESULT=preserved
    NT_DB_RESULT=preserved
    [[ -e "$root/etc/nathaya-tunnel/config.conf" ]] || NT_CONFIG_RESULT=created
    [[ -e "$root/opt/nathaya/data/ssh/accounts.db" ]] || NT_DB_RESULT=created
    nt_private_file "$root/etc/nathaya-tunnel/config.conf" "$source/config/config.conf.example" || return 1
    for relative in accounts.db accounts.lock operations.lock; do
        nt_private_file "$root/opt/nathaya/data/ssh/$relative" || return 1
    done
    for relative in opt/nathaya/logs/telegram.log opt/nathaya/logs/ssh-reconcile.log var/cache/nathaya-tunnel/location.cache; do
        if [[ -e "$root/$relative" ]]; then
            nt_set_owner "$root/$relative" && chmod 600 -- "$root/$relative" || return 1
        fi
    done
    # Publish launcher last, after code and private runtime files are ready.
    if [[ ! -d "$root/usr/local/bin" ]]; then
        nt_directory "$root/usr/local/bin" 755 || return 1
    fi
    nt_replace_file "$source/installer/menu-wrapper.sh" "$root/usr/local/bin/menu" 755 "$backup" usr/local/bin/menu || return 1
}
