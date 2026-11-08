#!/usr/bin/env bash
# Sourced by the fresh installer; defining this function has no side effects.
# Uses native Ubuntu packages. The parent owns networking and service activation.

configure_openvpn() (
    # A subshell keeps options, traps, descriptors and private helpers local.
    set +x
    set +v
    set -Eeuo pipefail
    umask 077
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export LC_ALL=C
    trap - EXIT ERR DEBUG RETURN

    if ! declare -F fail >/dev/null || ! declare -F msg >/dev/null; then
        printf '%s\n' 'configure_openvpn requires parent functions fail and msg.' >&2
        exit 1
    fi
    _ovpn_die() { fail "OpenVPN: $1" || true; exit 1; }

    [[ $# == 2 && -d $1 ]] || _ovpn_die 'Expected configure_openvpn ROOT DOMAIN.'
    (( EUID == 0 )) || _ovpn_die 'Root is required.'
    local domain="${2,,}" label
    local -a labels
    [[ ${#domain} -le 253 && $domain =~ ^[a-z0-9.-]+$ && $domain == *.* && $domain != *. ]] ||
        _ovpn_die 'A DNS hostname is required.'
    IFS=. read -r -a labels <<<"$domain" || _ovpn_die 'Cannot parse the DNS hostname.'
    for label in "${labels[@]}"; do
        [[ $label =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] ||
            _ovpn_die 'Invalid DNS hostname.'
    done
    [[ ${labels[-1]} =~ [a-z] ]] || _ovpn_die 'A DNS hostname, not an IP address, is required.'

    local state=/var/lib/nathaya-tunnel
    local inventory=$state/owned-files.tsv lock=$state/owned-files.tsv.lock
    local easy=/etc/openvpn/easy-rsa pki=/etc/openvpn/easy-rsa/pki
    local stage='' inventory_tmp='' tty_fd inventory_fd command path mode
    trap 'rc=$?; trap - EXIT; [[ -z $inventory_tmp ]] || rm -f -- "$inventory_tmp"; [[ -z $stage ]] || rm -rf -- "$stage"; exit "$rc"' EXIT
    trap '_ovpn_die "Installation failed; generated keys and installed files are preserved. Do not rerun over them."' ERR
    trap '_ovpn_die "Installation interrupted; generated keys and installed files are preserved."' HUP INT TERM

    for command in install stat mktemp flock sha256sum mv cat chmod chown find grep sed awk env dpkg-query dpkg tail od rm; do
        command -v "$command" >/dev/null || _ovpn_die 'A required system utility is missing.'
    done
    [[ -x /usr/bin/openssl && -x /usr/sbin/openvpn && -x /usr/share/easy-rsa/easyrsa ]] ||
        _ovpn_die 'Install packaged openvpn, easy-rsa, openssl and libpam-modules first.'
    local version
    version=$(dpkg-query -W -f='${Version}' openvpn) || _ovpn_die 'The OpenVPN package is missing.'
    dpkg --compare-versions "$version" ge 2.6 || _ovpn_die 'OpenVPN 2.6 or newer is required.'
    [[ $(dpkg-query -W -f='${db:Status-Status}' libpam-modules) == installed ]] ||
        _ovpn_die 'The packaged Unix PAM modules are required.'
    exec {tty_fd}<>/dev/tty || _ovpn_die 'An operator controlling TTY is required for passphrases.'
    [[ -t $tty_fd ]] || _ovpn_die 'Passphrases must be entered on a TTY.'

    _ovpn_trusted_directory() {
        local directory="$1" permissions
        while :; do
            [[ -d $directory && ! -L $directory && $(stat -c %u -- "$directory") == 0 ]] ||
                _ovpn_die 'A destination ancestor is not a root-owned real directory.'
            permissions=$(stat -c %a -- "$directory") || _ovpn_die 'Cannot inspect a destination.'
            (( (8#$permissions & 0022) == 0 )) || _ovpn_die 'A destination ancestor is writable by others.'
            [[ $directory != / ]] || break
            directory=${directory%/*}
            [[ -n $directory ]] || directory=/
        done
    }
    for path in "$state" /etc /etc/systemd/system /root /var/log; do
        _ovpn_trusted_directory "$path"
    done

    # Resolve the actual packaged PAM plugin, without assuming an architecture.
    local package_files plugin
    local -a plugins=()
    package_files=$(dpkg-query -L openvpn) || _ovpn_die 'Cannot locate packaged OpenVPN files.'
    while IFS= read -r path; do
        if [[ $path == /*/openvpn-plugin-auth-pam.so && -f $path && ! -L $path ]]; then
            plugins+=("$path")
        fi
    done <<<"$package_files"
    [[ ${#plugins[@]} == 1 ]] || _ovpn_die 'Expected one packaged OpenVPN PAM plugin.'
    plugin=${plugins[0]}
    _ovpn_trusted_directory "${plugin%/*}"
    [[ $(stat -c %u -- "$plugin") == 0 ]] || _ovpn_die 'The PAM plugin is not root-owned.'
    mode=$(stat -c %a -- "$plugin") || _ovpn_die 'Cannot inspect the PAM plugin.'
    (( (8#$mode & 0022) == 0 )) || _ovpn_die 'The PAM plugin is writable by others.'

    # Accept only the package's empty layout, not an existing CA/configuration.
    shopt -s nullglob dotglob
    local -a entries=() children=()
    if [[ -e /etc/openvpn || -L /etc/openvpn ]]; then
        _ovpn_trusted_directory /etc/openvpn
        entries=(/etc/openvpn/*)
        for path in "${entries[@]}"; do
            case $path in
                /etc/openvpn/server|/etc/openvpn/client)
                    _ovpn_trusted_directory "$path"
                    children=("$path"/*)
                    [[ ${#children[@]} == 0 ]] || _ovpn_die 'Existing OpenVPN configuration or credentials: preserved; fresh installation only.'
                    ;;
                /etc/openvpn/update-resolv-conf)
                    [[ -f $path && ! -L $path && $(stat -c '%u:%h' -- "$path") == 0:1 ]] ||
                        _ovpn_die 'Unexpected existing OpenVPN file.'
                    [[ $(dpkg-query -S "$path") == "openvpn: $path" ]] ||
                        _ovpn_die 'Unexpected existing OpenVPN file.'
                    mode=$(stat -c %a -- "$path") || _ovpn_die 'Cannot inspect the packaged resolver helper.'
                    (( (8#$mode & 0022) == 0 )) || _ovpn_die 'Unsafe packaged resolver helper.'
                    ;;
                *) _ovpn_die 'Existing OpenVPN tree: preserved; no reuse, deletion or key rotation.' ;;
            esac
        done
    fi
    for path in /root/nathaya-clients /var/log/nathaya-openvpn \
        /etc/systemd/system/nathaya-openvpn-{tcp,udp}.service \
        /etc/systemd/system/nathaya-openvpn-{tcp,udp}.service.d \
        /run/systemd/system/nathaya-openvpn-{tcp,udp}.service \
        /run/systemd/system/nathaya-openvpn-{tcp,udp}.service.d; do
        [[ ! -e $path && ! -L $path ]] || _ovpn_die 'An OpenVPN output already exists; it was preserved.'
    done

    # The parent holds its installer lock. This stable sibling lock serializes
    # inventory replacements; locking the replaced inventory inode would not.
    for path in "$inventory" "$lock"; do
        if [[ -e $path || -L $path ]]; then
            [[ -f $path && ! -L $path && $(stat -c '%u:%g:%a:%h' -- "$path") == 0:0:600:1 ]] ||
                _ovpn_die 'Unsafe ownership inventory or inventory lock.'
        fi
    done
    if [[ ! -e $lock ]]; then
        install -o root -g root -m 0600 /dev/null "$lock" || _ovpn_die 'Cannot create the inventory lock.'
    fi
    exec {inventory_fd}>>"$lock" || _ovpn_die 'Cannot open the inventory lock.'
    flock -x "$inventory_fd" || _ovpn_die 'Cannot lock the ownership inventory.'
    if [[ -e $inventory ]]; then
        # Require complete SHA256<TAB>absolute-path records; never repair state.
        awk -F '\t' 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || $2 !~ /^\// || $2 ~ /[[:cntrl:]]/ {exit 1}' \
            "$inventory" || _ovpn_die 'Invalid parent ownership inventory.'
        # awk accepts a missing final newline; prevent merging two records.
        if [[ -s $inventory ]]; then
            [[ $(tail -c 1 -- "$inventory" | od -An -tu1) =~ ^[[:space:]]*10[[:space:]]*$ ]] ||
                _ovpn_die 'Incomplete parent ownership inventory.'
        fi
    fi

    _ovpn_record() {
        local target="$1" digest
        digest=$(sha256sum -- "$target") || _ovpn_die 'Cannot hash an installed file.'
        digest=${digest%% *}
        inventory_tmp=$(mktemp "$state/.owned-files.XXXXXXXX") || _ovpn_die 'Cannot stage ownership records.'
        if [[ -e $inventory ]]; then
            cat -- "$inventory" >"$inventory_tmp" || _ovpn_die 'Cannot preserve ownership records.'
        fi
        printf '%s\t%s\n' "$digest" "$target" >>"$inventory_tmp" || _ovpn_die 'Cannot append an ownership record.'
        chown root:root -- "$inventory_tmp" && chmod 0600 -- "$inventory_tmp" ||
            _ovpn_die 'Cannot protect ownership records.'
        mv -fT -- "$inventory_tmp" "$inventory" || _ovpn_die 'Cannot publish ownership records.'
        inventory_tmp=''
    }
    _ovpn_install() {
        local source="$1" target="$2" permissions="$3"
        [[ ! -e $target && ! -L $target ]] || _ovpn_die 'Refusing to overwrite an output.'
        install -o root -g root -m "$permissions" -- "$source" "$target" || _ovpn_die 'Cannot install an OpenVPN file.'
        _ovpn_record "$target"
    }

    stage=$(mktemp -d "$state/.openvpn-install.XXXXXXXX") || _ovpn_die 'Cannot create private staging.'
    install -d -o root -g root -m 0700 /etc/openvpn /etc/openvpn/client \
        "$easy" /root/nathaya-clients /var/log/nathaya-openvpn || _ovpn_die 'Cannot create private directories.'
    local install_id ca_cn server_cn
    install_id=$(/usr/bin/openssl rand -hex 16) || _ovpn_die 'Cannot generate an installation identity.'
    [[ $install_id =~ ^[0-9a-f]{32}$ ]] || _ovpn_die 'Invalid generated installation identity.'
    ca_cn=Nathaya-CA-$install_id
    server_cn=Nathaya-server-$install_id

    cat >"$stage/vars" <<'VARS' || _ovpn_die 'Cannot stage EasyRSA settings.'
set_var EASYRSA_ALGO rsa
set_var EASYRSA_KEY_SIZE 3072
set_var EASYRSA_DN cn_only
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 825
set_var EASYRSA_CRL_DAYS 365
VARS
    _ovpn_install "$stage/vars" "$easy/vars" 0600
    _ovpn_easyrsa() {
        # No inherited batch/nopass/password variables or auto-discovered vars.
        # Neither Bash nor the parent reads, stores or supplies a passphrase.
        env -i PATH="$PATH" HOME=/root LANG=C TERM=dumb EASYRSA_PKI="$pki" \
            /usr/share/easy-rsa/easyrsa --vars="$easy/vars" "$@" \
            <&"$tty_fd" >&"$tty_fd" 2>&1 || _ovpn_die 'EasyRSA stopped; preserve the incomplete PKI and investigate.'
    }
    msg 'OpenVPN: enter a strong CA passphrase directly at the EasyRSA TTY prompts; no client key or client-key passphrase is needed. Do not record the terminal.' ||
        _ovpn_die 'Cannot display the operator instructions.'
    msg "OpenVPN: at the CA Common Name prompt enter exactly $ca_cn (replace any other default); confirm signing when prompted." ||
        _ovpn_die 'Cannot display the operator instructions.'
    _ovpn_easyrsa init-pki
    # Older packaged EasyRSA releases ignore --req-cn as an interactive default;
    # the operator enters this public name, never a scripted passphrase.
    _ovpn_easyrsa --req-cn="$ca_cn" build-ca
    [[ $(/usr/bin/openssl x509 -in "$pki/ca.crt" -noout -subject -nameopt RFC2253) == "subject=CN=$ca_cn" ]] ||
        _ovpn_die 'The CA common name must match the displayed installation identity; existing material was preserved.'
    _ovpn_easyrsa build-server-full "$server_cn" nopass
    _ovpn_easyrsa gen-crl

    local server_crt=$pki/issued/$server_cn.crt server_key=$pki/private/$server_cn.key
    # Accept OpenSSL PKCS#8 or traditional encrypted RSA PEM, never cleartext.
    grep -qFx -- '-----BEGIN ENCRYPTED PRIVATE KEY-----' "$pki/private/ca.key" ||
        grep -qFx -- 'Proc-Type: 4,ENCRYPTED' "$pki/private/ca.key" || _ovpn_die 'The CA private key must be encrypted.'
    /usr/bin/openssl pkey -in "$server_key" -passin file:/dev/null -noout -check >/dev/null 2>&1 ||
        _ovpn_die 'The unattended server key is invalid or encrypted.'
    /usr/bin/openssl verify -CAfile "$pki/ca.crt" -purpose sslserver "$server_crt" >/dev/null 2>&1 ||
        _ovpn_die 'The generated server certificate is invalid.'
    [[ $(/usr/bin/openssl x509 -in "$server_crt" -noout -subject -nameopt RFC2253) == "subject=CN=$server_cn" ]] ||
        _ovpn_die 'The generated server certificate has an unexpected common name.'
    /usr/bin/openssl crl -in "$pki/crl.pem" -noout -verify -CAfile "$pki/ca.crt" >/dev/null 2>&1 ||
        _ovpn_die 'The generated CRL is invalid.'
    chown -R root:root -- "$easy" || _ovpn_die 'Cannot set PKI ownership.'
    find "$easy" -type d -exec chmod 0700 -- {} + || _ovpn_die 'Cannot protect PKI directories.'
    find "$easy" -type f -exec chmod 0600 -- {} + || _ovpn_die 'Cannot protect PKI files.'
    find "$pki" -type f -print0 >"$stage/pki-files" || _ovpn_die 'Cannot enumerate generated PKI files.'
    while IFS= read -r -d '' path; do _ovpn_record "$path"; done <"$stage/pki-files"

    local transport port subnet protocol
    for transport in tcp udp; do
        if [[ $transport == tcp ]]; then
            port=1194; subnet=10.8.0.0; protocol=tcp4-server
        else
            port=2200; subnet=20.8.0.0; protocol=udp4
        fi
        cat >"$stage/server.conf" <<SERVER || _ovpn_die 'Cannot stage an OpenVPN server configuration.'
port $port
proto $protocol
local 0.0.0.0
dev tun-nathaya-$transport
dev-type tun
topology subnet
server $subnet 255.255.255.0
ca $pki/ca.crt
cert $server_crt
key $server_key
crl-verify $pki/crl.pem
dh none
verify-client-cert none
username-as-common-name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
allow-compression no
plugin $plugin login
duplicate-cn
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
persist-key
persist-tun
keepalive 10 120
reneg-sec 3600
umask 0077
status server-$transport.log 10
log-append /var/log/nathaya-openvpn/$transport.log
verb 3
SERVER
        _ovpn_install "$stage/server.conf" "/etc/openvpn/server-$transport.conf" 0600
        cat >"$stage/service" <<UNIT || _ovpn_die 'Cannot stage an OpenVPN service.'
[Unit]
Description=Nathaya OpenVPN $transport
Wants=network-online.target
After=network-online.target nathaya-openvpn-forward.service
Requires=nathaya-openvpn-forward.service

[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=/etc/openvpn
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server-$transport.conf
Restart=on-failure
RestartSec=5s
LimitCORE=0

[Install]
WantedBy=multi-user.target
UNIT
        _ovpn_install "$stage/service" "/etc/systemd/system/nathaya-openvpn-$transport.service" 0644
    done

    local profile
    for profile in tcp udp ssl; do
        case $profile in
            tcp) port=1194; protocol=tcp4-client ;;
            udp) port=2200; protocol=udp4 ;;
            ssl) port=443; protocol=tcp4-client ;;
        esac
        cat >"$stage/client.ovpn" <<CLIENT || _ovpn_die 'Cannot stage a private client profile.'
# CA-only per-VPS profile: authenticate with an existing Unix account.
# The ssl-named profile needs parent transparent TCP 443 -> TCP 1194 forwarding.
client
dev tun
proto $protocol
remote $domain $port
nobind
resolv-retry infinite
persist-key
persist-tun
auth-user-pass
auth-nocache
remote-cert-tls server
verify-x509-name $server_cn name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
allow-compression no
verb 3
CLIENT
        {
            printf '<ca>\n' || _ovpn_die 'Cannot write the private profile.'
            sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' "$pki/ca.crt" ||
                _ovpn_die 'Cannot embed the CA certificate.'
            printf '</ca>\n' || _ovpn_die 'Cannot write the CA-only profile.'
        } >>"$stage/client.ovpn" || _ovpn_die 'Cannot assemble the private client profile.'
        _ovpn_install "$stage/client.ovpn" "/etc/openvpn/client/client-$profile.ovpn" 0600
        _ovpn_install "/etc/openvpn/client/client-$profile.ovpn" "/root/nathaya-clients/client-$profile.ovpn" 0600
    done
    msg 'OpenVPN: installed TCP/UDP units and CA-only profiles in /root/nathaya-clients. Parent must activate the units after networking is ready.' ||
        _ovpn_die 'Cannot report installation completion.'
)
