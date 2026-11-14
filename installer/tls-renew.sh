#!/usr/bin/env bash
# Systemd invokes this with a clean environment; no CLI destination overrides.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset NATHAYA_BASE NATHAYA_CONFIG NATHAYA_CONFIG_FILE CONFIG_FILE _NATHAYA_BOOTSTRAP_LOADED
source /opt/nathaya/modules/common/bootstrap.sh
load_nathaya_config
NT_DOMAIN="$DOMAIN"
for helper in lib domain tls; do source "/opt/nathaya/installer/$helper.sh"; done
nt_domain_valid "$NT_DOMAIN"
nt_safe_path /run/nathaya-tunnel-setup.lock dir
mkdir -m 700 /run/nathaya-tunnel-setup.lock || exit 75
was_active=0
renew_cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    if (( was_active )); then systemctl start nathaya-haproxy.service || rc=1; fi
    rmdir /run/nathaya-tunnel-setup.lock || rc=1
    exit "$rc"
}
trap renew_cleanup EXIT
NT_RUN="$(mktemp -d /var/backups/nathaya-tunnel/renew.XXXXXXXX)"
: > "$NT_RUN/replaced-files"; : > "$NT_RUN/new-files"
if systemctl is-active --quiet nathaya-haproxy.service; then was_active=1; fi
# certbot calls pre/post only when an actual renewal is due. Post restores service
# even on a failed challenge; the EXIT trap is an additional safety net.
if (( was_active )); then
    certbot renew --cert-name "$NT_DOMAIN" --standalone --non-interactive \
        --pre-hook 'systemctl stop nathaya-haproxy.service' \
        --post-hook 'systemctl start nathaya-haproxy.service'
else
    certbot renew --cert-name "$NT_DOMAIN" --standalone --non-interactive
fi
nt_tls_sync
nt_reload_active_proxies
