#!/usr/bin/env bash
nt_is_critical_package() {
    local name="${1%%:*}" flags
    case "$name" in
        openssh-*|sudo|systemd*|libpam*|libnss*|netplan.io|iproute2|ifupdown|network-manager|dbus*|linux-image*|ubuntu-minimal|passwd|login|bash|coreutils|apt|dpkg|libc6|ca-certificates) return 0 ;;
    esac
    flags="$(dpkg-query -W -f='${Essential} ${Protected}' "$name" 2>/dev/null || true)"
    [[ "$flags" == *yes* ]]
}
nt_dns_package_needed() { ! command -v dig >/dev/null 2>&1; }
nt_apt() {
    local deadline=$((SECONDS + 300)) output rc
    output="$(mktemp "$NT_RUN/apt-output.XXXXXXXX")"
    while true; do
        rc=0
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get \
            -o DPkg::Lock::Timeout=5 -o Acquire::Retries=3 \
            -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" > "$output" 2>&1 || rc=$?
        cat -- "$output"
        if (( rc == 0 )); then rm -f -- "$output"; return 0; fi
        if grep -Eq 'Could not get lock|Unable to acquire.*lock|Unable to lock' "$output" &&
           ! grep -Eq '^(Unpacking|Setting up|Processing triggers)' "$output" && (( SECONDS < deadline )); then
            printf 'APT lock busy; retry within 300s deadline (no locks deleted/processes killed).\n'
            sleep 3
            continue
        fi
        rm -f -- "$output"
        printf 'APT transaction failed/lock timeout; state may be partial (exit %s).\n' "$rc" >&2
        return "$rc"
    done
}
nt_os_maintenance() {
    local action
    nt_apt -o APT::Update::Error-Mode=any update > "$NT_RUN/apt-update.log" 2>&1
    for action in upgrade dist-upgrade; do
        nt_apt -s "$action" > "$NT_RUN/apt-$action.plan" 2>&1
        nt_check_apt_plan "$NT_RUN/apt-$action.plan" os
        nt_apt -y "$action" > "$NT_RUN/apt-$action.result" 2>&1
        if [[ "$NT_SSH_EXISTED" == 1 ]]; then /usr/sbin/sshd -t; nt_verify_preserved_ssh; fi
    done
    nt_ssh_accept_post_os_identity || return 1
    NT_OS_MAINTENANCE=0
}
nt_dependencies() {
    local package
    local -a packages=()
    for package in openssh-server ca-certificates curl python3 util-linux procps iproute2         bash coreutils passwd libc-bin hostname mawk grep ncurses-bin findutils sed         openssl dropbear nginx haproxy certbot nftables; do
        nt_package_installed "$package" || packages+=("$package")
    done
    # Noble dig is provided by bind9-dnsutils; never request dnsutils when dig exists.
    nt_dns_package_needed && packages+=(bind9-dnsutils)
    if (( ${#packages[@]} )); then
        nt_hold_services /usr/sbin/policy-rc.d
        nt_apt -s --no-remove --no-install-recommends install "${packages[@]}" > "$NT_RUN/app-packages.plan" 2>&1
        nt_check_apt_plan "$NT_RUN/app-packages.plan" os
        nt_apt -y --no-remove --no-install-recommends install "${packages[@]}" > "$NT_RUN/app-packages.result" 2>&1
        nt_restore_policy
    fi
    command -v dig >/dev/null || { nt_error 'Paket bind9-dnsutils tidak menyediakan executable dig.'; return 1; }
    dig +time=3 +tries=1 +short "$NT_DOMAIN" A | grep -Fxq "$NT_PUBLIC_IP" || { nt_error 'DNS verification dig gagal.'; return 1; }
    if [[ "$NT_SSH_EXISTED" == 1 ]]; then /usr/sbin/sshd -t; fi
}
