#!/usr/bin/env bash
# Source-only API: configure_proxies ROOT DOMAIN EMAIL, after APT, before services.
# Parent provides fail(message), msg(message), install_owned(source,target,mode).
# install_owned MUST back up existing targets and SHA256-record installed code in
# /var/lib/nathaya-tunnel/owned-files.tsv (SHA256<TAB>absolute-path, no header).
# No direct record_owned/backup_existing dependency; those belong to that helper.
# Parent checks fresh-host port conflicts, suppresses package autostarts, and
# enables nginx.service, haproxy.service and the packaged certbot.timer afterwards.
# Certificate/domain/profile data is deliberately NOT placed in the code ledger.
# Certbot hook semantics: https://eff-certbot.readthedocs.io/en/stable/using.html

configure_proxies() (
    set +x
    set +v
    set -Eeuo pipefail
    umask 077
    export PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    trap - EXIT ERR DEBUG RETURN
    local root=${1:-} domain=${2:-} email=${3:-} stage='' target command
    _proxy_die() { fail "Proxy/TLS: $1" || true; exit 1; }
    for command in fail msg install_owned; do
        declare -F "$command" >/dev/null || {
            printf 'configure_proxies requires parent function %s.\n' "$command" >&2; exit 1;
        }
    done
    [[ $# == 3 && -d $root && $EUID == 0 ]] || _proxy_die 'Expected configure_proxies ROOT DOMAIN EMAIL as root.'
    for command in certbot nginx haproxy openssl python3 flock sha256sum readlink stat install mktemp; do
        command -v "$command" >/dev/null || _proxy_die 'Install the required Ubuntu packages before configuring proxies.'
    done
    # Never stop an existing administrator service in the fresh installer.
    for target in nginx haproxy; do
        if systemctl is-active --quiet "$target"; then
            _proxy_die 'An existing proxy is active; fresh-host preflight/autostart suppression is required.'
        fi
    done
    [[ -r $root/fodder/nginx/nginx.conf && -r $root/fodder/nginx/xray.conf &&
       -r $root/fodder/Haproxy/haproxy.cfg ]] || _proxy_die 'The local fodder proxy sources are required.'
    stage=$(mktemp -d /root/.nathaya-proxies.XXXXXXXX) || _proxy_die 'Cannot create private staging.'
    trap 'rc=$?; trap - EXIT; rm -rf -- "$stage"; exit "$rc"' EXIT
    trap '_proxy_die "Configuration failed; parent backups and private certificate data are preserved."' ERR

    cat >"$stage/nathaya-domain" <<'DOMAIN_SCRIPT' || _proxy_die 'Cannot stage the domain backend.'
#!/usr/bin/env bash
# Nathaya domain/certbot backend. No repository, acme.sh or shell-sourced data.
set +x
set +v
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset BASH_ENV ENV CDPATH
(( EUID == 0 )) || { printf 'NATHAYA TUNNEL: Administrator privileges required.\n' >&2; exit 1; }
state=/run/nathaya-acme.services
ledger=/var/lib/nathaya-tunnel/owned-files.tsv
backup_root=/var/lib/nathaya-tunnel/acme-backups
owner=${NATHAYA_ACME_OWNER:-timer}
[[ $owner =~ ^(timer|domain-[0-9]+)$ ]] || exit 1
work='' temporary='' committed=0 initial=0 wrapper=0
# Array entries refer only to fixed, explicitly managed paths, never user paths.
declare -a paths=() existed=() dirty=()
error() { printf 'NATHAYA TUNNEL: %s\n' "$1" >&2; }
die() { error "$1"; exit 1; }
trusted_dir() {
    local p=$1 mode
    while :; do
        [[ -d $p && ! -L $p && $(stat -c %u -- "$p") == 0 ]] || return 1
        mode=$(stat -c %a -- "$p") || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
        [[ $p != / ]] || break
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
trusted_file() {
    local p=$1 mode
    trusted_dir "${p%/*}" || return 1
    [[ -f $p && ! -L $p && $(stat -c '%u:%h' -- "$p") == 0:1 ]] || return 1
    mode=$(stat -c %a -- "$p") || return 1
    (( (8#$mode & 0022) == 0 ))
}
ensure_dir() {
    local p=$1 mode=${2:-700}
    trusted_dir "${p%/*}" || return 1
    if [[ ! -e $p && ! -L $p ]]; then install -d -o root -g root -m "$mode" -- "$p" || return 1; fi
    trusted_dir "$p"
}
valid_domain() {
    local d=$1 label; local -a labels
    [[ ${#d} -le 253 && $d == *.* && $d != *. && $d =~ ^[a-z0-9.-]+$ ]] || return 1
    IFS=. read -r -a labels <<<"$d"
    for label in "${labels[@]}"; do
        [[ $label =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
    done
    [[ ${labels[-1]} =~ [a-z] ]]
}
valid_email() {
    local e=$1 localpart=${1%@*} host=${1##*@}
    # A conservative literal mailbox alphabet; NEVER eval/source even valid email.
    [[ ${#e} -le 254 && ${#localpart} -le 64 && $e =~ ^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+$ &&
       $localpart != *. && $localpart != *..* ]] && valid_domain "${host,,}"
}
private_file() { trusted_file "$1" && [[ $(stat -c '%g:%a' -- "$1") == 0:600 ]]; }
read_domain() {
    private_file /etc/xray/domain || return 1
    local value
    value=$(cat /etc/xray/domain) || return 1
    valid_domain "$value" || return 1
    printf '%s' "$value"
}
owned_proxy() {
    local service=$1 config hash actual
    case $service in
        nginx.service) config=/etc/nginx/nginx.conf ;;
        haproxy.service) config=/etc/haproxy/haproxy.cfg ;;
        *) return 1 ;;
    esac
    private_file "$ledger" && trusted_file "$config" || return 1
    hash=$(awk -F '\t' -v p="$config" '$2==p {h=$1; n++} END {if(n==1) print h}' "$ledger") || return 1
    [[ $hash =~ ^[a-f0-9]{64}$ ]] || return 1
    actual=$(sha256sum -- "$config") || return 1
    [[ ${actual%% *} == "$hash" ]] || return 1
    if [[ $service == nginx.service ]]; then
        config=/etc/nginx/conf.d/xray.conf
        trusted_file "$config" || return 1
        hash=$(awk -F '\t' -v p="$config" '$2==p {h=$1; n++} END {if(n==1) print h}' "$ledger") || return 1
        actual=$(sha256sum -- "$config") || return 1
        [[ $hash =~ ^[a-f0-9]{64}$ && ${actual%% *} == "$hash" ]] || return 1
    fi
}
owned_proxies() { owned_proxy nginx.service && owned_proxy haproxy.service; }
validate_proxies() {
    owned_proxies && nginx -t >/dev/null 2>&1 && haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1
}
reload_active() {
    local service failed=0
    for service in nginx.service haproxy.service; do
        if systemctl is-active --quiet "$service"; then
            owned_proxy "$service" && systemctl reload "$service" || failed=1
        fi
    done
    return "$failed"
}
hook_lock() {
    trusted_dir /run || return 1
    if [[ -e /run/nathaya-acme.lock || -L /run/nathaya-acme.lock ]]; then
        private_file /run/nathaya-acme.lock || return 1
    else
        (set -C; : >/run/nathaya-acme.lock) || return 1
    fi
    exec {hook_fd}>>/run/nathaya-acme.lock || return 1
    flock -x "$hook_fd"
}
post_locked() {
    [[ -e $state || -L $state ]] || return 0
    private_file "$state" || return 1
    local token service failed=0; local -a services=()
    mapfile -t services <"$state" || return 1
    ((${#services[@]} >= 1 && ${#services[@]} <= 3)) || return 1
    token=${services[0]}
    [[ $token == "$owner" ]] || return 1
    for service in "${services[@]:1}"; do
        case $service in nginx.service|haproxy.service) ;; *) return 1 ;; esac
        # Never start a service whose configuration ownership changed meanwhile.
        owned_proxy "$service" && systemctl start "$service" || failed=1
    done
    (( failed == 0 )) || { error 'Proxy restoration failed; private /run/nathaya-acme.services retained.'; return 1; }
    rm -f -- "$state"
}
pre_services() (
    # Keep this short-lived lock scope independent of the caller's EXIT trap.
    trap - EXIT ERR HUP INT TERM
    hook_lock || return 1
    if [[ -e $state || -L $state ]]; then post_locked || return 1; fi
    local service; local -a services=()
    # Inspect everything before stopping anything, including a partially owned pair.
    for service in nginx.service haproxy.service; do
        if systemctl is-active --quiet "$service"; then
            owned_proxy "$service" || { error 'Active proxy is not unchanged Nathaya-owned code; not stopped.'; return 1; }
            services+=("$service")
        fi
    done
    (set -C; { printf '%s\n' "$owner";
        for service in "${services[@]}"; do printf '%s\n' "$service"; done;
    } >"$state") || return 1
    chown root:root "$state" && chmod 600 "$state" || return 1
    trap 'post_locked || true; exit 1' HUP INT TERM
    for service in "${services[@]}"; do
        if ! systemctl stop "$service"; then post_locked || true; return 1; fi
    done
)
post_services() ( trap - EXIT ERR HUP INT TERM; hook_lock && post_locked; )
begin_transaction() {
    ensure_dir /var/lib/nathaya-tunnel || return 1
    ensure_dir "$backup_root" || return 1
    [[ $(stat -c '%g:%a' -- "$backup_root") == 0:700 ]] || return 1
    work=$(mktemp -d "$backup_root/transaction.XXXXXXXX") || return 1
    chmod 700 "$work" || return 1
}
snapshot() {
    local p=$1 i=${#paths[@]}
    trusted_dir "${p%/*}" || return 1
    paths+=("$p"); dirty+=(0)
    if [[ -e $p || -L $p ]]; then
        trusted_file "$p" || return 1
        cp -p -- "$p" "$work/$i.old" || return 1
        existed+=(1)
    else
        existed+=(0)
    fi
    printf '%s\n' "$p" >>"$work/paths" || return 1
}
put() {
    local source=$1 dest=$2 mode=$3 group=$4 i found=0
    for i in "${!paths[@]}"; do
        if [[ ${paths[i]} == "$dest" ]]; then dirty[i]=1; found=1; break; fi
    done
    (( found == 1 )) || return 1
    trusted_dir "${dest%/*}" || return 1
    [[ ! -e $dest && ! -L $dest ]] || trusted_file "$dest" || return 1
    temporary=$(mktemp "${dest%/*}/.nathaya-acme.XXXXXXXX") || return 1
    install -o root -g "$group" -m "$mode" -- "$source" "$temporary" && mv -fT -- "$temporary" "$dest" || return 1
    temporary=''
}
rollback() {
    local i p failed=0 changed=0
    for ((i=${#paths[@]}-1; i>=0; i--)); do
        [[ ${dirty[i]:-0} == 1 ]] || continue
        changed=1
        p=${paths[i]}
        trusted_dir "${p%/*}" || { failed=1; continue; }
        if [[ ${existed[i]:-0} == 1 ]]; then
            temporary=$(mktemp "${p%/*}/.nathaya-acme.XXXXXXXX") || { failed=1; continue; }
            cp -p -- "$work/$i.old" "$temporary" && mv -fT -- "$temporary" "$p" || failed=1
        else
            [[ ! -L $p ]] && rm -f -- "$p" || failed=1
        fi
    done
    if (( changed == 1 )); then validate_proxies && reload_active || failed=1; fi
    return "$failed"
}
cleanup() {
    local rc=$?
    trap - EXIT ERR HUP INT TERM
    if [[ -n $work && $committed == 0 ]]; then
        rollback || error 'Rollback incomplete; inspect the private acme-backups directory.'
        error 'Operation failed; previous data restored best-effort. Private backup retained in /var/lib/nathaya-tunnel/acme-backups.'
        rc=1
    fi
    [[ -z $temporary ]] || rm -f -- "$temporary" || error 'Private temporary-file cleanup needs attention.'
    if (( wrapper == 1 && committed == 0 )); then
        post_services || { error 'Proxy restoration needs attention; private service state retained.'; rc=1; }
    fi
    if [[ -n $work && $committed == 1 ]]; then
        rm -rf -- "$work" || error 'Deployment completed; private backup cleanup needs attention.'
    fi
    exit "$rc"
}
# Accept Certbot's expected live symlinks only after checking resolved archive
# targets AND every ancestor. No arbitrary RENEWED_LINEAGE input is copied.
stage_certificate() {
    local domain=$1 output=$2 name resolved file key_hash cert_hash leaf_hash chain_leaf_hash
    local lineage=/etc/letsencrypt/live/$domain
    trusted_dir "$lineage" && trusted_dir "/etc/letsencrypt/archive/$domain" || return 1
    for name in cert chain fullchain privkey; do
        file=$lineage/$name.pem
        [[ -L $file ]] || return 1
        resolved=$(readlink -f -- "$file") || return 1
        [[ ${resolved%/*} == "/etc/letsencrypt/archive/$domain" && ${resolved##*/} =~ ^${name}[0-9]+\.pem$ ]] || return 1
        trusted_file "$resolved" || return 1
        if [[ $name == privkey ]]; then
            [[ $(stat -c '%g:%a' -- "$resolved") == 0:600 ]] || return 1
        fi
        install -o root -g root -m 600 -- "$resolved" "$output/$name.pem" || return 1
    done
    openssl x509 -in "$output/cert.pem" -noout -checkhost "$domain" >/dev/null 2>&1 &&
        openssl x509 -in "$output/cert.pem" -noout -checkend 0 >/dev/null 2>&1 &&
        openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$output/chain.pem" "$output/cert.pem" >/dev/null 2>&1 || return 1
    key_hash=$(openssl pkey -in "$output/privkey.pem" -pubout 2>/dev/null | sha256sum) || return 1
    cert_hash=$(openssl x509 -in "$output/cert.pem" -pubkey -noout 2>/dev/null | sha256sum) || return 1
    [[ $key_hash == "$cert_hash" ]] || return 1
    leaf_hash=$(openssl x509 -in "$output/cert.pem" -outform DER 2>/dev/null | sha256sum) || return 1
    chain_leaf_hash=$(openssl x509 -in "$output/fullchain.pem" -outform DER 2>/dev/null | sha256sum) || return 1
    [[ $leaf_hash == "$chain_leaf_hash" ]] || return 1
    cat "$output/fullchain.pem" "$output/privkey.pem" >"$output/haproxy.pem" || return 1
    chmod 600 "$output/haproxy.pem"
}
snapshot_certificates() {
    snapshot /etc/xray/xray.crt && snapshot /etc/xray/xray.key && snapshot /etc/haproxy/yha.pem
}
apply_certificates() {
    put "$work/fullchain.pem" /etc/xray/xray.crt 644 root &&
        put "$work/privkey.pem" /etc/xray/xray.key 640 www-data &&
        put "$work/haproxy.pem" /etc/haproxy/yha.pem 600 root
}
deploy_certificate() {
    [[ ${NATHAYA_ACME_DEFER_DEPLOY:-0} == 1 ]] && return 0
    local domain lineage=${RENEWED_LINEAGE:-}
    domain=$(read_domain) || return 1
    # Old/other Certbot lineages remain intact but cannot change this server.
    [[ $lineage == "/etc/letsencrypt/live/$domain" ]] || return 0
    owned_proxies || return 1
    begin_transaction && snapshot_certificates && stage_certificate "$domain" "$work" &&
        apply_certificates && validate_proxies && reload_active || return 1
    committed=1
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
case ${1:-} in
    --validate) [[ $# == 3 ]] && valid_domain "${2,,}" && valid_email "$3"; exit $? ;;
    --acme-pre) [[ $# == 1 ]] || exit 1; pre_services; exit $? ;;
    --acme-post) [[ $# == 1 ]] || exit 1; post_services; exit $? ;;
    --acme-deploy) [[ $# == 1 ]] || exit 1; deploy_certificate; exit $? ;;
esac

# The ordinary domain UI and the installer share issuance, validation and atomic
# deployment. Certificate hooks defer UI deployment until Certbot has succeeded.
if [[ ${1:-} == --initial ]]; then
    [[ $# == 3 ]] || die 'Invalid initial certificate arguments.'
    initial=1; new_domain=${2,,}; email=$3; old_domain=''
else
    [[ $# -le 1 && ${1:-} != -* ]] || die 'Usage: nathaya-domain [DOMAIN]'
    old_domain=$(read_domain) || die 'Current private domain data is missing or unsafe.'
    new_domain=${1:-}
    if [[ -z $new_domain ]]; then
        printf 'Domain saat ini: %s\n' "$old_domain"
        read -r -p 'Masukkan domain baru (kosong = perbarui sertifikat): ' new_domain || exit 1
        new_domain=${new_domain:-$old_domain}
    fi
    new_domain=${new_domain,,}; email=''
    if [[ -e /etc/nathaya-tunnel/install.conf || -L /etc/nathaya-tunnel/install.conf ]]; then
        private_file /etc/nathaya-tunnel/install.conf || die 'Unsafe private install.conf; preserved.'
        # Parent writes literal DOMAIN=... and EMAIL=... lines. Never source it.
        count=0
        while IFS= read -r line || [[ -n $line ]]; do
            case $line in EMAIL=*) email=${line#EMAIL=}; count=$((count+1)) ;; esac
        done </etc/nathaya-tunnel/install.conf
        (( count <= 1 )) || die 'Ambiguous email configuration; preserved.'
    fi
    if [[ -z $email ]]; then read -r -p "Email untuk Let's Encrypt: " email || exit 1; fi
fi
valid_domain "$new_domain" && valid_email "$email" || die 'Invalid FQDN or literal email address.'
owned_proxies || die 'Proxy configurations are not unchanged Nathaya-owned files.'
ensure_dir /etc/nathaya-tunnel || die 'Unsafe configuration directory.'
if [[ -e /etc/nathaya-tunnel/install.conf || -L /etc/nathaya-tunnel/install.conf ]]; then
    private_file /etc/nathaya-tunnel/install.conf || die 'Unsafe install.conf; preserved.'
fi
if (( initial == 1 )); then
    for p in /etc/xray/xray.key /etc/xray/xray.crt /etc/haproxy/yha.pem "/etc/letsencrypt/live/$new_domain" "/etc/letsencrypt/archive/$new_domain" "/etc/letsencrypt/renewal/$new_domain.conf"; do
        [[ ! -e $p && ! -L $p ]] || die 'Existing certificate data was preserved; initial issuance requires a fresh host.'
    done
fi
# Serialize UI invocations. Certbot itself serializes issuance against its timer.
if [[ -e /run/nathaya-domain.lock || -L /run/nathaya-domain.lock ]]; then
    private_file /run/nathaya-domain.lock || die 'Unsafe domain lock.'
else
    trusted_dir /run && (set -C; : >/run/nathaya-domain.lock) || die 'Cannot create domain lock.'
fi
exec {domain_fd}>>/run/nathaya-domain.lock
flock -n "$domain_fd" || die 'Another domain operation is running.'
export NATHAYA_ACME_OWNER=domain-$$ NATHAYA_ACME_DEFER_DEPLOY=1
owner=$NATHAYA_ACME_OWNER
wrapper=1
printf 'NATHAYA TUNNEL: HTTP-01 memerlukan port 80 publik.\n'
printf 'Maintenance singkat: hanya nginx/HAProxy milik Nathaya yang aktif akan dihentikan sementara dan dipulihkan, termasuk bila penerbitan gagal.\n'
begin_transaction && snapshot_certificates && snapshot /etc/xray/domain && snapshot /etc/nathaya-tunnel/install.conf || die 'Cannot create a private rollback snapshot.'
# Proxy configs contain no domain interpolation and are NEVER rewritten here.
# Keep copies for diagnosis; rollback only replaces data we actually changed.
cp -p /etc/nginx/nginx.conf "$work/nginx.conf.old" &&
    cp -p /etc/nginx/conf.d/xray.conf "$work/xray.conf.old" &&
    cp -p /etc/haproxy/haproxy.cfg "$work/haproxy.cfg.old" || die 'Cannot back up owned proxy configurations.'
declare -a profiles=()
for p in /etc/openvpn/client/client-{tcp,udp,ssl}.ovpn /root/nathaya-clients/client-{tcp,udp,ssl}.ovpn; do
    if [[ -e $p || -L $p ]]; then
        private_file "$p" && snapshot "$p" || die 'Unsafe private OpenVPN profile; preserved.'
        profiles+=("$p")
    fi
done
args=(certonly --standalone --preferred-challenges http --http-01-port 80
    --non-interactive --agree-tos --email "$email" --cert-name "$new_domain" -d "$new_domain"
    --key-type ecdsa --elliptic-curve secp256r1 --new-key
    --pre-hook /usr/local/sbin/nathaya-acme-pre
    --post-hook /usr/local/sbin/nathaya-acme-post
    --deploy-hook /usr/local/sbin/nathaya-acme-deploy)
if [[ $new_domain == "$old_domain" ]]; then args+=(--force-renewal); else args+=(--keep-until-expiring); fi
# Certbot's standard logs stay in its private package-managed directory. Never
# print key material or tee certificate/private-key concatenation to a terminal.
certbot "${args[@]}" >"$work/certbot.log" 2>&1 || die 'Certificate issuance failed. Previous domain/certificates remain in place.'
post_services || die 'Certificate obtained, but proxy restoration failed.'
owned_proxies && stage_certificate "$new_domain" "$work" || die 'Issued certificate or proxy ownership validation failed.'
# Stage profile substitutions before modifying any live data. Only the remote
# host token is changed; embedded CA/client keys and all other bytes are retained.
for i in "${!profiles[@]}"; do
    python3 -I - "${profiles[i]}" "$work/profile.$i" "$old_domain" "$new_domain" <<'PY'
import os, re, sys
source, target, old, new = sys.argv[1:]
with open(source, 'rb') as f:
    data = f.read()
pattern = re.compile(rb'(?m)^([ \t]*remote[ \t]+)([^ \t\r\n]+)(?=[ \t])')
matches = list(pattern.finditer(data))
if len(matches) != 1 or matches[0].group(2) not in (old.encode('ascii'), new.encode('ascii')):
    sys.exit('Private profile remote host does not match the managed domain.')
data = pattern.sub(lambda m: m.group(1) + new.encode('ascii'), data)
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as f:
    f.write(data)
PY
done
printf '%s\n' "$new_domain" >"$work/domain"
if [[ -f /etc/nathaya-tunnel/install.conf ]]; then
    awk '!/^DOMAIN=/ && !/^EMAIL=/' /etc/nathaya-tunnel/install.conf >"$work/install.conf"
else
    : >"$work/install.conf"
fi
printf 'DOMAIN=%s\nEMAIL=%s\n' "$new_domain" "$email" >>"$work/install.conf"
apply_certificates && put "$work/domain" /etc/xray/domain 600 root &&
    put "$work/install.conf" /etc/nathaya-tunnel/install.conf 600 root || die 'Certificate/domain deployment failed.'
for i in "${!profiles[@]}"; do
    put "$work/profile.$i" "${profiles[i]}" 600 root || die 'Private profile deployment failed.'
done
validate_proxies && reload_active || die 'Proxy validation/reload failed; restoring previous certificate and domain.'
committed=1
printf 'NATHAYA TUNNEL: Domain dan sertifikat berhasil diterapkan: %s\n' "$new_domain"
DOMAIN_SCRIPT

    bash "$stage/nathaya-domain" --validate "$domain" "$email" || _proxy_die 'Invalid FQDN or literal email address.'
    for target in pre post deploy; do
        printf '#!/usr/bin/env bash\nset +x\nset +v\nexec /usr/local/sbin/nathaya-domain --acme-%s\n' "$target" >"$stage/nathaya-acme-$target" || _proxy_die 'Cannot stage a certificate hook.'
    done
    # Keep source routing, WS/gRPC paths, frontend ports and the public 403.
    { printf '# Nathaya-owned proxy configuration.\n'; cat "$root/fodder/nginx/nginx.conf"; } >"$stage/nginx.conf" || _proxy_die 'Cannot stage nginx configuration.'
    { printf '# Nathaya-owned proxy configuration.\n';
      sed -e 's/ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;/ssl_protocols TLSv1.2 TLSv1.3;/' \
          -e 's/listen 1010 /listen 127.0.0.1:1010 /' \
          -e 's/listen 1013 /listen 127.0.0.1:1013 /' "$root/fodder/nginx/xray.conf";
    } >"$stage/xray.conf" || _proxy_die 'Cannot stage nginx routes.'
    { printf '# Nathaya-owned proxy configuration.\n'; cat "$root/fodder/Haproxy/haproxy.cfg"; } >"$stage/haproxy.cfg" || _proxy_die 'Cannot stage HAProxy configuration.'
    # Package directories already exist after APT. Refuse symlink/writable roots.
    for target in /etc /etc/nginx /etc/nginx/conf.d /etc/haproxy /usr/local/sbin /var/lib/nathaya-tunnel; do
        [[ -d $target && ! -L $target && $(stat -c %u -- "$target") == 0 ]] || _proxy_die 'Unsafe proxy destination directory.'
        local mode
        mode=$(stat -c %a -- "$target") || _proxy_die 'Cannot inspect a proxy destination.'
        (( (8#$mode & 0022) == 0 )) || _proxy_die 'Writable proxy destination directory.'
    done
    if [[ ! -e /etc/xray && ! -L /etc/xray ]]; then
        install -d -o root -g www-data -m 750 /etc/xray || _proxy_die 'Cannot create the private Xray directory.'
    fi
    [[ -d /etc/xray && ! -L /etc/xray && $(stat -c %u /etc/xray) == 0 ]] || _proxy_die 'Unsafe Xray directory.'
    # This is the parent's fresh tree, not a migrated administrator service tree.
    chown root:www-data /etc/xray && chmod 750 /etc/xray || _proxy_die 'Cannot protect the Xray directory.'
    install_owned "$stage/nathaya-domain" /usr/local/sbin/nathaya-domain 0755 || _proxy_die 'Cannot install the domain backend.'
    for target in pre post deploy; do
        install_owned "$stage/nathaya-acme-$target" "/usr/local/sbin/nathaya-acme-$target" 0755 || _proxy_die 'Cannot install a certificate hook.'
    done
    install_owned "$stage/nginx.conf" /etc/nginx/nginx.conf 0644 || _proxy_die 'Cannot install nginx configuration.'
    install_owned "$stage/xray.conf" /etc/nginx/conf.d/xray.conf 0644 || _proxy_die 'Cannot install nginx routes.'
    install_owned "$stage/haproxy.cfg" /etc/haproxy/haproxy.cfg 0644 || _proxy_die 'Cannot install HAProxy configuration.'
    /usr/local/sbin/nathaya-domain --initial "$domain" "$email" || _proxy_die 'Initial HTTP-01 issuance/deployment failed; services were not activated.'
    msg 'Proxy/TLS: configured local nginx/HAProxy routes and certificate hooks. Parent must activate nginx, HAProxy and the packaged certbot.timer.' || _proxy_die 'Cannot report configuration completion.'
)
