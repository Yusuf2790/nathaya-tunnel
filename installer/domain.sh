#!/usr/bin/env bash
nt_domain_valid() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$1" == *.* && "$1" != *..* &&        ! "$1" =~ (^|[.])-|-(\.|$) &&        ! "$1" =~ ^[0-9.]+$ && ${#1} -le 253 ]]
}
nt_domain_check() {
    nt_domain_valid "$NT_DOMAIN" || { nt_error 'Domain FQDN tidak valid.'; return 1; }
    NT_PUBLIC_IP="$(python3 -I -B -c 'import urllib.request,ipaddress; print(ipaddress.IPv4Address(urllib.request.urlopen("https://api.ipify.org",timeout=10).read(64).decode()))')"
    python3 -I -B -c 'import socket,sys; assert sys.argv[2] in {r[4][0] for r in socket.getaddrinfo(sys.argv[1],80,socket.AF_INET)}' "$NT_DOMAIN" "$NT_PUBLIC_IP" || { nt_error 'A record domain tidak menuju IPv4 VPS.'; return 1; }
}
nt_domain_save() {
    [[ "${NT_CONFIG_DOMAIN:-}" != "$NT_DOMAIN" ]] || return 0
    nt_backup_file /etc/nathaya-tunnel/config.conf "$NT_RUN" etc/nathaya-tunnel/config.conf
    local temp
    temp="$(mktemp /etc/nathaya-tunnel/.config.XXXXXXXX)"
    grep -Ev '^[[:space:]]*DOMAIN[[:space:]]*=' /etc/nathaya-tunnel/config.conf > "$temp" || [[ $? == 1 ]]
    printf 'DOMAIN="%s"\n' "$NT_DOMAIN" >> "$temp"
    chown root:root "$temp"; chmod 600 "$temp"
    mv -fT -- "$temp" /etc/nathaya-tunnel/config.conf
}
