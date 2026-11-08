#!/bin/bash
# Alrescha OpenVPN forwarding only. No network-manager, address, route or DNS edits.
# Managed by nathaya-openvpn-forward.service; invoked only during installation/service use.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
fail() { printf 'NATHAYA OpenVPN forwarding: %s\n' "$1" >&2; exit 1; }
[[ $EUID -eq 0 && $# -eq 1 ]] || fail 'Use up or down as root.'
case "$1" in up|down) action=$1 ;; *) fail 'Only up/down are supported.' ;; esac
config=/etc/nathaya-tunnel/install.conf
for directory in / /etc /etc/nathaya-tunnel; do
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || fail 'Unsafe configuration ancestor.'
    mode=$(stat -c %a "$directory")
    (( (8#$mode & 0022) == 0 )) || fail 'Writable configuration ancestor.'
done
[[ -f $config && ! -L $config && $(stat -c '%u:%g:%a:%h' "$config") == 0:0:600:1 ]] || fail 'Private installer configuration required.'
# Parse one literal value; never source/eval operator configuration.
uplink=$(awk -F= '$1=="UPLINK" {count++; value=$2} END {if(count!=1) exit 1; print value}' "$config") || fail 'Missing or ambiguous uplink.'
[[ $uplink =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ && $uplink != lo && $uplink != tun* ]] || fail 'Invalid uplink.'
[[ -x /usr/sbin/iptables && -x /usr/sbin/sysctl ]] || fail 'Packaged iptables/sysctl are required.'
exec 9>>/run/nathaya-openvpn-forward.lock
chmod 0600 /run/nathaya-openvpn-forward.lock
flock -x 9
rule() {
    local table=$1 chain=$2; shift 2
    if [[ $action == up ]]; then
        if ! /usr/sbin/iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
            /usr/sbin/iptables -w 5 -t "$table" -A "$chain" "$@"
        fi
    else
        # Delete only this exact, labelled rule; never flush or change policies.
        while /usr/sbin/iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; do
            /usr/sbin/iptables -w 5 -t "$table" -D "$chain" "$@"
        done
    fi
}
if [[ $action == up ]]; then
    actual=$(ip -4 route show default | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}')
    [[ $actual == "$uplink" ]] || fail 'The default uplink changed; no route was modified.'
    ip link show dev "$uplink" >/dev/null
    # Required for VPN transit. No other sysctl, IPv6 or global firewall policy is changed.
    /usr/sbin/sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi
for transport in tcp udp; do
    if [[ $transport == tcp ]]; then pool=10.8.0.0/24; else pool=20.8.0.0/24; fi
    tun=tun-nathaya-$transport
    rule nat POSTROUTING -s "$pool" -o "$uplink" -m comment --comment nathaya-openvpn -j MASQUERADE
    rule filter FORWARD -i "$tun" -o "$uplink" -s "$pool" -m comment --comment nathaya-openvpn -j ACCEPT
    rule filter FORWARD -i "$uplink" -o "$tun" -d "$pool" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment nathaya-openvpn -j ACCEPT
done
# down deliberately does not reset ip_forward: other host services may use it.
