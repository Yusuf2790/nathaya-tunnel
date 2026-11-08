#!/usr/bin/env bash
# NATHAYA TUNNEL — fresh Ubuntu installer, adapted from Alrescha79 (MIT).
# Original backend/configuration sources and attribution are retained in LICENSE.
# Run from the complete, root-owned Nathaya repository. Never source upstream setup.
set +x
set +v
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH

msg() { printf 'NATHAYA TUNNEL: %s\n' "$*"; }
fail() { printf 'NATHAYA TUNNEL: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: bash setup.sh [--install] [--domain FQDN] [--email EMAIL]
       bash setup.sh --help

Fresh Ubuntu 24.04 amd64, systemd, root and an interactive terminal are required.
Domain/email may be entered at prompts. EasyRSA asks directly for a CA passphrase.
Existing VPN configuration, accounts or installer state are never overwritten.
No force, unattended installation, automatic menu launch or reboot is provided.

Use the complete repository, not a downloaded setup.sh alone:
  git clone https://github.com/Yusuf2790/nathaya-tunnel.git
  cd nathaya-tunnel
  bash setup.sh
HELP
}
for argument in "$@"; do
    case $argument in --help|-h) usage; exit 0 ;; esac
done
DOMAIN='' EMAIL=''
while (( $# )); do
    case $1 in
        --install) shift ;;
        --domain)
            (( $# >= 2 )) && [[ -z $DOMAIN && -n $2 ]] || fail '--domain requires one FQDN.'
            DOMAIN=$2; shift 2 ;;
        --email)
            (( $# >= 2 )) && [[ -z $EMAIL && -n $2 ]] || fail '--email requires one email address.'
            EMAIL=$2; shift 2 ;;
        *) fail "Unknown argument: $1. Use --help." ;;
    esac
done
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
STATE=/var/lib/nathaya-tunnel
LEDGER=$STATE/owned-files.tsv
LEDGER_LOCK=$STATE/owned-files.tsv.lock
WORK='' POLICY_ID='' POLICY_TEXT='' PHASE=preparation
XRAY_VERSION=${XRAY_VERSION:-v25.3.6}
[[ $XRAY_VERSION =~ ^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || fail 'XRAY_VERSION must be a bounded vN.N.N release tag.'

trusted_directory() {
    local path=$1 mode
    while :; do
        [[ -d $path && ! -L $path && $(stat -c %u -- "$path") == 0 ]] || fail "Untrusted directory: $path"
        mode=$(stat -c %a -- "$path")
        (( (8#$mode & 0022) == 0 )) || fail "Directory is writable by others: $path"
        [[ $path != / ]] || break
        path=${path%/*}; [[ -n $path ]] || path=/
    done
}
trusted_file() {
    local path=$1 mode
    trusted_directory "${path%/*}"
    [[ -f $path && ! -L $path && $(stat -c '%u:%h' -- "$path") == 0:1 ]] || fail "Untrusted regular file: $path"
    mode=$(stat -c %a -- "$path")
    (( (8#$mode & 0022) == 0 )) || fail "File is writable by others: $path"
}
ensure_directory() {
    local path=$1 mode=${2:-755}
    if [[ ! -e $path && ! -L $path ]]; then
        ensure_directory "${path%/*}"
        install -d -o root -g root -m "$mode" -- "$path"
    fi
    trusted_directory "$path"
}
safe_target() {
    [[ $1 =~ ^/[A-Za-z0-9_+.@:/-]+$ && $1 != *//* && $1 != */ &&
       ! $1 =~ (^|/)\.\.?(/|$) ]] || fail 'Unsafe destination path.'
}
ledger_valid() {
    trusted_file "$LEDGER"
    [[ $(stat -c '%g:%a' -- "$LEDGER") == 0:600 ]] || fail 'Ownership ledger must be private.'
    awk -F '\t' 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ ||
        $2 !~ /^\/[A-Za-z0-9_+.@:\/-]+$/ || $2 ~ /\/\// ||
        $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /\/$/ || seen[$2]++ {bad=1}
        END {exit bad}' "$LEDGER" || fail 'Invalid ownership ledger; it was preserved.'
    if [[ -s $LEDGER ]]; then
        [[ $(tail -c 1 -- "$LEDGER" | od -An -tu1) =~ ^[[:space:]]*10[[:space:]]*$ ]] || fail 'Incomplete ownership ledger.'
    fi
}
# API used by the ordinary configuration helpers. Stable sibling lock, not the
# replaceable inventory inode. Every update keeps exactly one row per pathname.
record_owned() (
    local path=$1 digest temporary=''
    safe_target "$path"; trusted_file "$path"
    trusted_file "$LEDGER_LOCK"
    [[ $(stat -c '%g:%a' -- "$LEDGER_LOCK") == 0:600 ]] || fail 'Unsafe ownership lock.'
    exec {inventory_fd}>>"$LEDGER_LOCK"
    flock -x "$inventory_fd"
    ledger_valid
    digest=$(sha256sum -- "$path"); digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || fail 'Cannot hash an installed file.'
    temporary=$(mktemp "$STATE/.owned-files.XXXXXXXX")
    trap '[[ -z $temporary ]] || rm -f -- "$temporary"' EXIT
    awk -F '\t' -v path="$path" '$2 != path' "$LEDGER" >"$temporary"
    printf '%s\t%s\n' "$digest" "$path" >>"$temporary"
    chown root:root "$temporary"; chmod 0600 "$temporary"
    mv -fT -- "$temporary" "$LEDGER"
    temporary=''
)
owned_unchanged() {
    local path=$1 expected actual
    ledger_valid
    expected=$(awk -F '\t' -v path="$path" '$2==path {print $1}' "$LEDGER")
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
    actual=$(sha256sum -- "$path")
    [[ ${actual%% *} == "$expected" ]]
}
packaged_original() {
    local path=$1 package expected actual
    case $path in
        /etc/nginx/nginx.conf) package=nginx-common ;;
        /etc/haproxy/haproxy.cfg) package=haproxy ;;
        /etc/default/openvpn) package=openvpn ;;
        *) return 1 ;;
    esac
    expected=$(dpkg-query -W -f='${Conffiles}\n' "$package" | awk -v path="$path" '$1==path {print $2}') || return 1
    [[ $expected =~ ^[0-9a-f]{32}$ ]] || return 1
    actual=$(md5sum -- "$path")
    [[ ${actual%% *} == "$expected" ]]
}
backup_existing() {
    local path=$1 backup
    safe_target "$path"
    trusted_directory "${path%/*}"
    [[ -e $path || -L $path ]] || return 0
    trusted_file "$path"
    # This API cannot authorize arbitrary administrator-file replacement.
    if [[ $path != /etc/shells ]]; then
        owned_unchanged "$path" || packaged_original "$path" || fail "Existing non-owned configuration preserved: $path"
    fi
    backup=$STATE/originals$path
    ensure_directory "${backup%/*}" 700
    if [[ -e $backup || -L $backup ]]; then
        trusted_file "$backup"
        [[ $(stat -c '%g:%a' -- "$backup") == 0:600 ]] || fail 'Unsafe original-file backup.'
        return 0
    fi
    (set -C; cat -- "$path" >"$backup")
    chown root:root "$backup"; chmod 0600 "$backup"
}
install_owned() (
    local source=$1 target=$2 mode=$3 temporary=''
    [[ $mode =~ ^0?[0-7]{3}$ ]] || fail 'Invalid installation mode.'
    trusted_file "$source"; safe_target "$target"
    ensure_directory "${target%/*}"
    backup_existing "$target"
    temporary=$(mktemp "${target%/*}/.nathaya-install.XXXXXXXX")
    trap '[[ -z $temporary ]] || rm -f -- "$temporary"' EXIT
    install -o root -g root -m "$mode" -- "$source" "$temporary"
    mv -fT -- "$temporary" "$target"
    temporary=''
    record_owned "$target"
)
remove_policy() {
    [[ -n $POLICY_ID ]] || return 0
    if [[ -f /usr/sbin/policy-rc.d && ! -L /usr/sbin/policy-rc.d &&
          $(stat -c '%d:%i:%u:%g:%a:%h' /usr/sbin/policy-rc.d) == "$POLICY_ID" &&
          $(cat /usr/sbin/policy-rc.d) == "$POLICY_TEXT" ]]; then
        rm -- /usr/sbin/policy-rc.d
        POLICY_ID=''
    else
        msg 'Temporary package policy changed; preserved for administrator review.' >&2
        return 1
    fi
}
cleanup() {
    local rc=$?
    trap - EXIT ERR HUP INT TERM
    remove_policy || rc=1
    [[ -z $WORK ]] || rm -rf -- "$WORK"
    # No service restart, rollback, state deletion or key regeneration on failure.
    if (( rc != 0 )); then
        msg "Installation stopped during $PHASE. Installed state, backups and keys are preserved; do not rerun over them." >&2
    fi
    exit "$rc"
}
valid_domain() {
    local value=$1 label; local -a labels=()
    [[ ${#value} -le 253 && $value == *.* && $value != *. && $value =~ ^[a-z0-9.-]+$ ]] || return 1
    IFS=. read -r -a labels <<<"$value"
    for label in "${labels[@]}"; do
        [[ $label =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
    done
    [[ ${labels[-1]} =~ [a-z] ]]
}
valid_email() {
    local value=$1 localpart=${1%@*} host=${1##*@}
    [[ ${#value} -le 254 && ${#localpart} -le 64 &&
       $value =~ ^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+$ &&
       $localpart != *. && $localpart != *..* ]] && valid_domain "${host,,}"
}
require_source() {
    local relative mode kind target extra
    trusted_directory "$ROOT"
    for relative in lib/configure-openvpn.sh lib/configure-proxies.sh lib/install-runtime.sh \
        lib/openvpn-forward.sh install-manifest.tsv uninstall.sh menu.sh LICENSE nathaya.txt \
        fodder/websocket/ws.py fodder/nginx/nginx.conf fodder/nginx/xray.conf \
        fodder/Haproxy/haproxy.cfg fodder/udp/udp-custom-linux-amd64 BadVPN-UDPWG/badvpn gotop; do
        [[ -s $ROOT/$relative && ! -L $ROOT/$relative ]] || fail "Complete local source is required ($relative missing). Clone the full Nathaya repository; no upstream-menu fallback is used."
        trusted_file "$ROOT/$relative"
    done
    for relative in vmess vless trojan shadowsocks; do
        trusted_file "$ROOT/VMess-VLESS-Trojan+Websocket+gRPC/$relative/config.json"
    done
    while IFS=$'\t' read -r mode kind relative target extra; do
        [[ -n $mode && $mode != \#* ]] || continue
        [[ -z ${extra:-} && $relative =~ ^[A-Za-z0-9_+./-]+$ && $relative != /* && $relative != *..* ]] || fail 'Invalid runtime manifest source.'
        trusted_file "$ROOT/$relative"
        safe_target "$target"
        [[ ! -e $target && ! -L $target ]] || fail "Fresh installation only; existing runtime preserved: $target"
    done <"$ROOT/install-manifest.tsv"
}
require_fresh_openvpn() {
    local path mode; local -a entries=() children=()
    [[ -e /etc/openvpn || -L /etc/openvpn ]] || return 0
    trusted_directory /etc/openvpn
    shopt -s nullglob dotglob
    entries=(/etc/openvpn/*)
    for path in "${entries[@]}"; do
        case $path in
            /etc/openvpn/client|/etc/openvpn/server)
                trusted_directory "$path"; children=("$path"/*)
                (( ${#children[@]} == 0 )) || fail 'Existing OpenVPN configuration/PKI was preserved; fresh installation only.' ;;
            /etc/openvpn/update-resolv-conf)
                trusted_file "$path"
                [[ $(dpkg-query -S "$path") == "openvpn: $path" ]] || fail 'Existing OpenVPN files were preserved.' ;;
            *) fail 'Existing OpenVPN configuration/PKI was preserved; fresh installation only.' ;;
        esac
    done
    shopt -u nullglob dotglob
}
require_fresh_host() {
    local path service listeners
    for path in "$STATE/install.state" /etc/xray /etc/vmess /etc/vless /etc/trojan \
        /etc/shadowsocks /etc/ssh/.ssh.db /etc/slowdns /root/nathaya-clients \
        /etc/nathaya-tunnel/install.conf /etc/ssh/sshd_config.nathaya \
        /etc/dropbear/nathaya_rsa_host_key /usr/local/bin/xray /usr/bin/xray \
        /usr/bin/ws.py /usr/bin/udp /usr/bin/config.json /usr/bin/badvpn /usr/bin/gotop \
        /usr/bin/nathaya-uninstall /etc/gerhanatunnel.txt /etc/sysctl.d/90-nathaya-openvpn.conf \
        /usr/local/lib/nathaya/openvpn-forward.sh /usr/local/sbin/nathaya-domain \
        /usr/local/sbin/nathaya-acme-pre /usr/local/sbin/nathaya-acme-post /usr/local/sbin/nathaya-acme-deploy \
        /usr/local/share/xray/geoip.dat /usr/local/share/xray/geosite.dat \
        /etc/nginx/conf.d/xray.conf /etc/haproxy/yha.pem /var/log/nathaya-openvpn \
        /etc/cron.d/xp_all /etc/cron.d/exp_warning /etc/cron.d/logclear; do
        [[ ! -e $path && ! -L $path ]] || fail "Fresh installation only; existing path preserved: $path"
    done
    if [[ -e $STATE || -L $STATE ]]; then
        trusted_directory "$STATE"
        [[ $(stat -c '%g:%a' "$STATE") == 0:700 && -z $(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit) ]] || fail 'Existing installer state was preserved; fresh installation only.'
    fi
    require_fresh_openvpn
    for service in nginx haproxy dropbear openvpn xray; do
        if systemctl is-active --quiet "$service.service"; then
            fail "Existing $service service is active; it will not be stopped."
        fi
    done
    for service in nathaya-ssh nathaya-dropbear ws udp limitip limitquota badvpn badvpn@ \
        vmess@config vless@config trojan@config shadowsocks@config \
        nathaya-openvpn-forward nathaya-openvpn-tcp nathaya-openvpn-udp; do
        for path in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system; do
            [[ ! -e $path/$service.service && ! -L $path/$service.service &&
               ! -e $path/$service.service.d && ! -L $path/$service.service.d ]] || fail 'Existing VPN service definitions were preserved.'
        done
    done
    [[ ! -e /usr/sbin/policy-rc.d && ! -L /usr/sbin/policy-rc.d ]] || fail 'Administrator policy-rc.d exists; it will not be replaced.'
    # Both transports, including internal listeners, must be free. No service is stopped.
    listeners=$(ss -H -lntu) || fail 'Cannot inspect reserved TCP/UDP ports.'
    if awk '{port=$5; sub(/^.*:/,"",port); if (port ~ /^(80|81|109|143|443|8080|1010|1013|1194|2200|2100|2222|2223|7100|7200|7300|1000[1-8]|10015|2000[1-4])$/) busy=1} END {exit !busy}' <<<"$listeners"; then
        fail 'A reserved VPN/proxy port is occupied; administrator services were left untouched.'
    fi
}
require_routes() {
    # Read-only route inspection precedes all credential generation. Keep the two
    # original pools, but refuse overlap with ANY existing non-default IPv4 route.
    UPLINK=$(python3 -I - <<'PY'
import ipaddress, json, re, subprocess, sys
routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
pools = [ipaddress.ip_network('10.8.0.0/24'), ipaddress.ip_network('20.8.0.0/24')]
for route in routes:
    dst = route.get('dst', 'default')
    if dst in ('default', '0.0.0.0/0'):
        continue
    network = ipaddress.ip_network(dst, strict=False)
    if any(network.overlaps(pool) for pool in pools):
        sys.exit('NATHAYA TUNNEL: Existing route overlaps an OpenVPN pool; no routes were changed.')
defaults = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'default']))
if len(defaults) != 1 or 'nexthops' in defaults[0]:
    sys.exit('NATHAYA TUNNEL: Exactly one ordinary IPv4 default uplink is required.')
uplink = defaults[0].get('dev', '')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', uplink):
    sys.exit('NATHAYA TUNNEL: Invalid default uplink.')
print(uplink)
PY
    ) || fail 'Cannot select a safe IPv4 uplink and non-overlapping OpenVPN pools.'
}
write_private_data() {
    local source=$1 target=$2 mode=${3:-600}
    ensure_directory "${target%/*}" 700
    [[ ! -e $target && ! -L $target ]] || fail "Private data already exists: $target"
    install -o root -g root -m "$mode" -- "$source" "$target"
}
write_state() {
    printf '%s\n' "$1" >"$WORK/install.state"
    install -o root -g root -m 0600 "$WORK/install.state" "$STATE/.install.state.next"
    mv -fT "$STATE/.install.state.next" "$STATE/install.state"
}
install_packages() {
    PHASE='Ubuntu packages'
    POLICY_TEXT=$(printf '#!/bin/sh\n# Nathaya temporary package policy %s\nexit 101' "${WORK##*/}")
    (set -C; printf '%s\n' "$POLICY_TEXT" >/usr/sbin/policy-rc.d)
    POLICY_ID=$(stat -c '%d:%i:%u:%g:%a:%h' /usr/sbin/policy-rc.d)
    chmod 0755 /usr/sbin/policy-rc.d
    POLICY_ID=$(stat -c '%d:%i:%u:%g:%a:%h' /usr/sbin/policy-rc.d)
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
    apt-get update
    apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confold install \
        curl wget git ca-certificates gnupg unzip zip openssl openssh-server \
        dropbear openvpn easy-rsa libpam-modules python3 jq nodejs nginx haproxy \
        certbot iproute2 iptables cron at rsyslog vnstat bc gawk coreutils \
        util-linux socat lsof file procps passwd tar net-tools
    # Do not execute any NodeSource, npm, PPA or upstream root installer.
}
install_xray() {
    local base expected actual name description
    PHASE='Xray release and native configuration'
    # Official pinned release and its digest asset:
    # https://github.com/XTLS/Xray-core/releases/expanded_assets/v25.3.6
    base=https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 300 --max-filesize 134217728 \
        "$base/Xray-linux-64.zip" -o "$WORK/Xray-linux-64.zip"
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 60 --max-filesize 16384 \
        "$base/Xray-linux-64.zip.dgst" -o "$WORK/Xray-linux-64.zip.dgst"
    expected=$(python3 -I - "$WORK/Xray-linux-64.zip.dgst" <<'PY'
import re, sys
with open(sys.argv[1], encoding='ascii') as stream:
    lines = stream.read().splitlines()
label = re.compile(r'^\s*SHA(?:2-256|256|-256)\b', re.I)
pattern = re.compile(r'\s*SHA(?:2-256|256|-256)\s*=\s*([0-9a-f]{64})\s*', re.I)
candidates = [line for line in lines if label.match(line)]
if len(candidates) != 1:
    sys.exit('Expected exactly one published SHA256 record.')
match = pattern.fullmatch(candidates[0])
if match is None:
    sys.exit('Malformed published SHA256 record.')
print(match.group(1).lower())
PY
    ) || fail 'The official SHA256 digest could not be parsed.'
    if [[ $XRAY_VERSION == v25.3.6 ]]; then
        [[ $expected == 82d4be3a5ed8bd2621df9c9913c3a2761b86a42ae8485da836f7447ff2ec3d4d ]] || fail 'Pinned release digest differs from its published value.'
    fi
    actual=$(sha256sum "$WORK/Xray-linux-64.zip")
    [[ ${actual%% *} == "$expected" ]] || fail 'Xray download SHA256 mismatch.'
    # Extract fixed members only; no archive pathname is ever used as a target.
    for name in xray geoip.dat geosite.dat; do
        unzip -p "$WORK/Xray-linux-64.zip" "$name" >"$WORK/$name"
        [[ -s $WORK/$name ]] || fail "The release lacks $name."
    done
    install_owned "$WORK/xray" /usr/local/bin/xray 0755
    ensure_directory /usr/local/share/xray
    install_owned "$WORK/geoip.dat" /usr/local/share/xray/geoip.dat 0644
    install_owned "$WORK/geosite.dat" /usr/local/share/xray/geosite.dat 0644
    ensure_directory /etc/xray
    ensure_directory /var/log/xray
    for name in access.log error.log; do
        [[ ! -e /var/log/xray/$name && ! -L /var/log/xray/$name ]] || fail 'Existing Xray log data was preserved.'
        install -o www-data -g www-data -m 0640 /dev/null "/var/log/xray/$name"
    done
    local protocol uuid
    for protocol in vmess vless trojan shadowsocks; do
        ensure_directory "/etc/xray/$protocol"
        ensure_directory "/etc/$protocol" 700
        uuid=$(cat /proc/sys/kernel/random/uuid)
        [[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail 'UUID generation failed.'
        # Preserve the source JSONC layout and all account insertion markers.
        sed -e "s/__NATHAYA_CREDENTIAL__/$uuid/g" \
            -e 's/"loglevel"[[:space:]]*:[[:space:]]*"debug"/"loglevel": "warning"/g' \
            "$ROOT/VMess-VLESS-Trojan+Websocket+gRPC/$protocol/config.json" >"$WORK/$protocol.json"
        install_owned "$WORK/$protocol.json" "/etc/xray/$protocol/config.json" 0640
        chown root:www-data "/etc/xray/$protocol/config.json"
        write_private_data /dev/null "/etc/xray/$protocol/.$protocol.db"
    done
    ensure_directory /etc/xray/ssh
    write_private_data /dev/null /etc/xray/ssh/.ssh.db
    write_private_data /dev/null /etc/ssh/.ssh.db
    printf '%s\n' "$DOMAIN" >"$WORK/domain"
    write_private_data "$WORK/domain" /etc/xray/domain
    printf '%s\n' 'Location not configured' >"$WORK/location"
    write_private_data "$WORK/location" /etc/xray/city
    write_private_data "$WORK/location" /etc/xray/isp
    ensure_directory /var/www/html
}
install_ssh_and_udp() {
    PHASE='secondary SSH, WebSocket and UDP backends'
    ensure_directory /run/sshd
    # -A creates only missing host keys; existing administrator keys are untouched.
    ssh-keygen -A
    cat >"$WORK/sshd_config.nathaya" <<'SSH'
# Nathaya secondary daemon; the administrator's sshd_config is not included.
Port 2222
Port 2223
AddressFamily inet
ListenAddress 0.0.0.0
PidFile /run/nathaya-sshd.pid
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
AllowTcpForwarding yes
GatewayPorts no
PermitTTY no
X11Forwarding no
# No SFTP subsystem: this secondary daemon is for VPN account forwarding only.
Banner /etc/gerhanatunnel.txt
SSH
    install_owned "$WORK/sshd_config.nathaya" /etc/ssh/sshd_config.nathaya 0600
    install_owned "$ROOT/nathaya.txt" /etc/gerhanatunnel.txt 0644
    ensure_directory /etc/dropbear 700
    [[ ! -e /etc/dropbear/nathaya_rsa_host_key && ! -L /etc/dropbear/nathaya_rsa_host_key ]] || fail 'Existing Dropbear key was preserved.'
    dropbearkey -t rsa -s 3072 -f /etc/dropbear/nathaya_rsa_host_key >"$WORK/dropbear-public.log" 2>&1
    chown root:root /etc/dropbear/nathaya_rsa_host_key
    chmod 0600 /etc/dropbear/nathaya_rsa_host_key
    # Never import a shared DSS key or remove the packaged Dropbear service.
    trusted_file /etc/shells
    if ! grep -qxF /bin/false /etc/shells; then
        backup_existing /etc/shells
        # Append only, preserving every administrator entry (including no final LF).
        printf '\n/bin/false\n' >>/etc/shells
    fi
    # Older local copies bind wildcard; the installed copy is loopback-only.
    sed "s/^LISTENING_ADDR = '0.0.0.0'$/LISTENING_ADDR = '127.0.0.1'/" \
        "$ROOT/fodder/websocket/ws.py" >"$WORK/ws.py"
    grep -qxF "LISTENING_ADDR = '127.0.0.1'" "$WORK/ws.py" || fail 'WebSocket source needs an explicit loopback bind.'
    install_owned "$WORK/ws.py" /usr/bin/ws.py 0755
    local binary description
    for binary in BadVPN-UDPWG/badvpn fodder/udp/udp-custom-linux-amd64; do
        description=$(file -b -- "$ROOT/$binary")
        [[ $description == ELF\ 64-bit\ LSB* && $description == *x86-64* ]] || fail 'A local UDP binary is not Linux ELF x86-64.'
        python3 -I - "$ROOT/$binary" <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as stream:
    header = stream.read(20)
if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', header[18:20])[0] != 62:
    sys.exit('Refusing a non-amd64 ELF binary.')
PY
    done
    install_owned "$ROOT/BadVPN-UDPWG/badvpn" /usr/bin/badvpn 0755
    install_owned "$ROOT/fodder/udp/udp-custom-linux-amd64" /usr/bin/udp 0755
    install_owned "$ROOT/gotop" /usr/bin/gotop 0755
    # Exact nested authentication structure from the original setup.sh.
    cat >"$WORK/udp.json" <<'UDP'
{
    "listen": ":2100",
    "stream_buffer": 16777216,
    "receive_buffer": 16777216,
    "auth": {
        "mode": "passwords"
    }
}
UDP
    write_private_data "$WORK/udp.json" /usr/bin/config.json
}
install_networking() {
    PHASE='owned OpenVPN forwarding configuration'
    ensure_directory /usr/local/lib/nathaya
    install_owned "$ROOT/lib/openvpn-forward.sh" /usr/local/lib/nathaya/openvpn-forward.sh 0755
    printf 'net.ipv4.ip_forward=1\n' >"$WORK/90-nathaya-openvpn.conf"
    install_owned "$WORK/90-nathaya-openvpn.conf" /etc/sysctl.d/90-nathaya-openvpn.conf 0644
    # The forwarding helper applies only this IPv4 setting and its tagged rules.
    # No host addresses, default routes, DNS, IPv6, INPUT policy or rule flushes.
    # Avoid duplicate packaged instances after reboot: only our two units own
    # these top-level .conf files. Never start/restart the OpenVPN umbrella unit.
    # https://ubuntu.com/server/docs/how-to/security/install-openvpn/
    if [[ -e /etc/default/openvpn || -L /etc/default/openvpn ]]; then
        trusted_file /etc/default/openvpn
        packaged_original /etc/default/openvpn || fail 'Administrator OpenVPN defaults were preserved.'
        sed '/^[[:space:]]*AUTOSTART=/d' /etc/default/openvpn >"$WORK/openvpn-defaults"
    else
        : >"$WORK/openvpn-defaults"
    fi
    printf '\nAUTOSTART="none"\n' >>"$WORK/openvpn-defaults"
    install_owned "$WORK/openvpn-defaults" /etc/default/openvpn 0644
}
add_openvpn_demux() {
    # Classify the initial OpenVPN TCP reset before the source HTTPS recirculator.
    # Only a TCP destination is selected here; OpenVPN/PAM still authenticates.
    # https://docs.haproxy.org/2.8/configuration.html#7.3.5-req.payload
    python3 -I - /etc/haproxy/haproxy.cfg "$WORK/haproxy-demux.cfg" <<'PY'
import sys
with open(sys.argv[1], encoding='utf-8') as stream:
    data = stream.read()
old = '''    tcp-request inspect-delay 10ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http_backend if HTTP'''
new = '''    tcp-request inspect-delay 5s
    acl nathaya_openvpn req.payload(2,1) -m bin 38
    tcp-request content accept if nathaya_openvpn
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend nathaya_openvpn_tcp if nathaya_openvpn
    use_backend recir_http_backend if HTTP'''
if data.count(old) != 1:
    sys.exit('The local HAProxy TCP 443 frontend does not match its source contract.')
data = data.replace(old, new, 1)
data += '\nbackend nathaya_openvpn_tcp\n    mode tcp\n    server nathaya_openvpn 127.0.0.1:1194\n'
with open(sys.argv[2], 'x', encoding='utf-8') as stream:
    stream.write(data)
PY
    install_owned "$WORK/haproxy-demux.cfg" /etc/haproxy/haproxy.cfg 0644
}
install_units_and_cron() {
    local protocol
    PHASE='native service units and cron'
    for protocol in vmess vless trojan shadowsocks; do
        cat >"$WORK/unit" <<UNIT
[Unit]
Description=Nathaya $protocol Xray instance
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=www-data
Group=www-data
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/bin/xray run -config /etc/xray/$protocol/config.json
NoNewPrivileges=yes
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
UNIT
        install_owned "$WORK/unit" "/etc/systemd/system/$protocol@config.service" 0644
    done
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya secondary OpenSSH (administrator SSH remains untouched)
After=network.target
[Service]
Type=simple
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStartPre=/usr/sbin/sshd -t -f /etc/ssh/sshd_config.nathaya
ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config.nathaya
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/nathaya-ssh.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya secondary Dropbear
After=network.target
[Service]
Type=simple
UMask=0077
ExecStart=/usr/sbin/dropbear -F -E -p 143 -p 109 -r /etc/dropbear/nathaya_rsa_host_key -b /etc/gerhanatunnel.txt -w
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/nathaya-dropbear.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya loopback SSH/OpenVPN WebSocket proxy
After=network.target nathaya-ssh.service nathaya-dropbear.service
[Service]
Type=simple
User=root
NoNewPrivileges=yes
ExecStart=/usr/bin/python3 -O /usr/bin/ws.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/ws.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya UDP custom server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/udp server -exclude 2200,7300,7200,7100,323,10008,10004 /usr/bin/config.json
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
LimitNPROC=10000
LimitNOFILE=1000000
Restart=on-failure
RestartPreventExitStatus=23
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/udp.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya BadVPN loopback endpoint %i
After=network.target
[Service]
Type=simple
User=root
NoNewPrivileges=yes
ExecStart=/usr/bin/badvpn --listen-addr 127.0.0.1:%i --max-clients 500
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/badvpn@.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya OpenVPN IPv4 forwarding and owned NAT rules
After=network.target
Before=nathaya-openvpn-tcp.service nathaya-openvpn-udp.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/nathaya/openvpn-forward.sh up
ExecStop=/usr/local/lib/nathaya/openvpn-forward.sh down
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/nathaya-openvpn-forward.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya native account IP limits
After=network-online.target rsyslog.service
[Service]
Type=simple
User=root
NoNewPrivileges=yes
ExecStart=/bin/bash -c '/usr/bin/limitipssh 15 & /usr/bin/limitip 15 & wait'
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/limitip.service 0644
    cat >"$WORK/unit" <<'UNIT'
[Unit]
Description=Nathaya native account quota limits
After=network-online.target rsyslog.service
[Service]
Type=simple
User=root
NoNewPrivileges=yes
ExecStart=/usr/bin/quota
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
    install_owned "$WORK/unit" /etc/systemd/system/limitquota.service 0644
    cat >"$WORK/cron" <<'CRON'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/exp
CRON
    install_owned "$WORK/cron" /etc/cron.d/xp_all 0644
    cat >"$WORK/cron" <<'CRON'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 9,18 * * * root /usr/bin/exp-warning
CRON
    install_owned "$WORK/cron" /etc/cron.d/exp_warning 0644
    cat >"$WORK/cron" <<'CRON'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */6 * * * root /usr/bin/logclear
CRON
    install_owned "$WORK/cron" /etc/cron.d/logclear 0644
}

# Native host requirements: no Android, container-only session or remote execution.
(( EUID == 0 )) || fail 'Run as root on a fresh Ubuntu 24.04 amd64 host.'
[[ -t 0 && -t 1 ]] || fail 'An interactive controlling terminal is required.'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && -z ${ANDROID_ROOT:-} && ! -e /system/build.prop ]] || fail 'Linux amd64 is required; Android is unsupported.'
[[ -r /etc/os-release && -d /run/systemd/system && $(cat /proc/1/comm) == systemd ]] || fail 'A systemd Ubuntu host is required.'
[[ $(awk -F= '$1=="ID" {gsub(/"/,"",$2); print $2}' /etc/os-release) == ubuntu &&
   $(awk -F= '$1=="VERSION_ID" {gsub(/"/,"",$2); print $2}' /etc/os-release) == 24.04 ]] || fail 'Only Ubuntu 24.04 is supported.'
for dependency in stat install mktemp flock sha256sum md5sum awk grep sed find ip ss python3 dpkg-query systemctl; do
    command -v "$dependency" >/dev/null || fail "Base Ubuntu utility missing: $dependency"
done
trusted_directory /root
trusted_directory /run
if [[ -e /run/nathaya-install.lock || -L /run/nathaya-install.lock ]]; then
    trusted_file /run/nathaya-install.lock
    [[ $(stat -c '%g:%a' /run/nathaya-install.lock) == 0:600 ]] || fail 'Unsafe installer lock.'
fi
exec {installer_fd}>>/run/nathaya-install.lock
flock -n "$installer_fd" || fail 'Another Nathaya installation is running.'
require_source
require_fresh_host
require_routes
[[ -n $DOMAIN ]] || read -r -p 'Domain VPS (FQDN): ' DOMAIN
DOMAIN=${DOMAIN,,}
[[ -n $EMAIL ]] || read -r -p "Email for Let's Encrypt: " EMAIL
valid_domain "$DOMAIN" || fail 'Enter a valid fully qualified DNS hostname.'
valid_email "$EMAIL" || fail 'Enter a valid literal email address.'
cat <<NOTICE
NATHAYA TUNNEL — FRESH INSTALLATION
This installs the local Alrescha backend with Nathaya presentation and runtime.
Public DNS A must point to this VPS; ACME HTTP-01 requires public inbound TCP 80.
A published AAAA record must also reach this host; this installer does not change DNS.
Ubuntu packages and an official Xray $XRAY_VERSION release will be downloaded.

IPv4 forwarding will be enabled and exact tagged NAT/FORWARD rules added on $UPLINK.
OpenVPN retains 10.8.0.0/24 and 20.8.0.0/24. WARNING: 20.8.0.0/24 is PUBLIC
address space; VPN clients cannot reach that real public subnet while using it.
Public services: TCP 80,81,109,143,443,8080,1194,2222,2223; UDP 2100,2200.
Reserved local endpoints: 1010,1013,10001-10008,10015,20001-20004,7100/7200/7300.
UDP-custom may also use client-selected UDP ports; upstream firewall policy remains yours.
Host/provider inbound firewall openings remain the administrator's responsibility.
No existing service is stopped. Primary SSH, its keys/config/custom ports, host
addresses, default routes, resolver and IPv6 remain unchanged. No firewall purge,
OS upgrade, global tuning, swap, automatic reboot or shell-login menu is installed.
SlowDNS is NOT installed: no implementation exists in the local source; no DNS redirect.
OpenVPN CA passphrase prompts require this terminal. Failed state/keys are kept.
NOTICE
read -r -p 'Type INSTALL NATHAYA to authorize provisioning: ' confirmation
[[ $confirmation == 'INSTALL NATHAYA' ]] || { msg 'Cancelled; no provisioning performed.'; exit 0; }
# Reinspect freshness immediately before the first provisioning operation.
require_fresh_host
ensure_directory "$STATE" 700
[[ $(stat -c '%g:%a' "$STATE") == 0:700 ]] || fail 'Installer state directory must be root-private.'
WORK=$(mktemp -d "$STATE/.setup.XXXXXXXX")
trap cleanup EXIT
trap 'fail "A native operation failed during $PHASE."' ERR
trap 'exit 130' INT
trap 'exit 143' HUP TERM
install -o root -g root -m 0600 /dev/null "$LEDGER"
install -o root -g root -m 0600 /dev/null "$LEDGER_LOCK"
ensure_directory "$STATE/originals" 700
write_state installing
# Literal data, never shell-sourced. Must exist before proxy/domain helper calls.
ensure_directory /etc/nathaya-tunnel 700
[[ $(stat -c '%g:%a' /etc/nathaya-tunnel) == 0:700 ]] || fail 'Private Nathaya configuration directory must have mode 0700.'
printf 'DOMAIN=%s\nEMAIL=%s\nUPLINK=%s\n' "$DOMAIN" "$EMAIL" "$UPLINK" >"$WORK/install.conf"
write_private_data "$WORK/install.conf" /etc/nathaya-tunnel/install.conf
install_packages
# Ordinary source-only function definitions; no former installer framework.
source "$ROOT/lib/configure-openvpn.sh"
source "$ROOT/lib/configure-proxies.sh"
install_xray
install_ssh_and_udp
PHASE='complete Nathaya runtime'
# The runtime merger takes the same stable ownership lock as parent writes.
# Do not hold a second open-description lock across the child invocation.
bash "$ROOT/lib/install-runtime.sh" --source "$ROOT"
install_owned "$ROOT/uninstall.sh" /usr/bin/nathaya-uninstall 0755
install_networking
PHASE='OpenVPN CA, PAM servers and private profiles'
configure_openvpn "$ROOT" "$DOMAIN"
PHASE='source proxy routing and ACME certificates'
configure_proxies "$ROOT" "$DOMAIN" "$EMAIL"
add_openvpn_demux
# Source helpers own private data; protocol configuration directories stay 0755.
chown root:root /etc/xray
chmod 0755 /etc/xray
install_units_and_cron
PHASE='native configuration validation'
nginx -t
haproxy -c -f /etc/haproxy/haproxy.cfg
/usr/sbin/sshd -t -f /etc/ssh/sshd_config.nathaya
for protocol in vmess vless trojan shadowsocks; do
    XRAY_LOCATION_ASSET=/usr/local/share/xray /usr/local/bin/xray run -test -config "/etc/xray/$protocol/config.json" >"$WORK/xray-validation.log" 2>&1 || fail "Xray rejected the $protocol configuration; no services were activated."
done
# No daemon is activated until all files, code and native configuration are ready.
PHASE='native service activation'
remove_policy
systemctl daemon-reload
systemctl enable --now nathaya-ssh.service nathaya-dropbear.service ws.service \
    vmess@config.service vless@config.service trojan@config.service shadowsocks@config.service \
    nathaya-openvpn-forward.service nathaya-openvpn-tcp.service nathaya-openvpn-udp.service \
    badvpn@7100.service badvpn@7200.service badvpn@7300.service udp.service \
    nginx.service haproxy.service cron.service atd.service rsyslog.service vnstat.service certbot.timer
systemctl enable --now limitip.service limitquota.service
write_state complete
PHASE=complete
# Optional shared transport; it reads only trusted operator configuration. There
# are no embedded bot credentials, account details or key material in this notice.
(
    source /opt/nathaya/modules/common/telegram.sh
    telegram_send_message "<b>NATHAYA TUNNEL</b> installation completed for <code>$DOMAIN</code>. Open the menu on the server; no reboot was requested."
) >/dev/null 2>&1 || msg 'Optional Telegram delivery was unavailable.'
msg 'Installation completed. Run menu as root when you are ready; no reboot is required.'
msg 'Private CA-only OpenVPN profiles: /root/nathaya-clients (not served publicly).'
msg 'Public export/profile HTTP links are intentionally unavailable (403); deliver profiles privately.'
msg 'Keep the encrypted CA, its passphrase and private installer state safe. SlowDNS was not installed.'
