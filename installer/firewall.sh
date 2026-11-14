#!/usr/bin/env bash
nt_firewall_remove() {
    local package
    local -a remove=()
    for package in ufw firewalld; do
        nt_package_installed "$package" || continue
        remove+=("$package")
        if [[ -d "/etc/$package" ]]; then
            nt_safe_path "/etc/$package" dir
            tar --create --file="$NT_RUN/$package-config.tar" --directory=/etc -- "$package"
            chmod 600 "$NT_RUN/$package-config.tar"
        fi
    done
    command -v iptables-save >/dev/null && iptables-save > "$NT_RUN/firewall-before.iptables" || true
    command -v nft >/dev/null && nft list ruleset > "$NT_RUN/firewall-before.nft" || true
    if (( ${#remove[@]} )); then
        nt_apt -s purge "${remove[@]}" > "$NT_RUN/firewall-removal.plan" 2>&1
        nt_check_apt_plan "$NT_RUN/firewall-removal.plan" os
        for package in "${remove[@]}"; do
            if [[ "$package" == ufw ]]; then ufw --force disable; fi
            if [[ "$package" == firewalld ]]; then systemctl disable --now firewalld.service; fi
        done
        nt_apt -y purge "${remove[@]}" > "$NT_RUN/firewall-removal.result" 2>&1
    fi
    # No global flush. Provider/foreign rules are not edited. No NAT is needed for
    # core WS/SSH/Xray. OpenVPN and UDP full gates prevent installing unreviewed NAT.
    printf 'UFW/firewalld inventory/removal done; unrelated/provider rules not flushed.\n'
}
