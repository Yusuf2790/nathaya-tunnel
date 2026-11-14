#!/usr/bin/env bash
nt_tls_validate_lineage() {
    local file resolved
    for file in fullchain.pem privkey.pem; do
        resolved="$(readlink -f -- "/etc/letsencrypt/live/$NT_DOMAIN/$file")" || return 1
        [[ "$resolved" == "/etc/letsencrypt/archive/$NT_DOMAIN/"* ]] || return 1
        nt_safe_path "$resolved" file || return 1
        nt_secure_parents "$resolved" || return 1
        [[ "$(stat -c %u "$resolved")" == 0 ]] || return 1
    done
    openssl verify -purpose sslserver -verify_hostname "$NT_DOMAIN" \
        -CAfile /etc/ssl/certs/ca-certificates.crt \
        -untrusted "/etc/letsencrypt/live/$NT_DOMAIN/fullchain.pem" \
        "/etc/letsencrypt/live/$NT_DOMAIN/fullchain.pem" >/dev/null 2>&1 || return 1
    local cert_pub key_pub
    cert_pub="$(openssl x509 -in "/etc/letsencrypt/live/$NT_DOMAIN/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" || return 1
    key_pub="$(openssl pkey -in "/etc/letsencrypt/live/$NT_DOMAIN/privkey.pem" -pubout -outform DER | sha256sum)" || return 1
    [[ "$cert_pub" == "$key_pub" ]]
}
nt_tls_sync() {
    nt_tls_validate_lineage || { nt_error 'Certificate lineage/key/domain tidak valid.'; return 1; }
    nt_directory /etc/nathaya-tunnel/tls 700
    local file
    for file in fullchain.pem privkey.pem; do
        nt_replace_file "/etc/letsencrypt/live/$NT_DOMAIN/$file" "/etc/nathaya-tunnel/tls/$file" 600 "$NT_RUN" "etc/nathaya-tunnel/tls/$file"
    done
    cat "/etc/letsencrypt/live/$NT_DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$NT_DOMAIN/privkey.pem" > "$NT_RUN/haproxy.pem"
    chmod 600 "$NT_RUN/haproxy.pem"
    nt_replace_file "$NT_RUN/haproxy.pem" /etc/nathaya-tunnel/tls/haproxy.pem 600 "$NT_RUN" etc/nathaya-tunnel/tls/haproxy.pem
}
nt_reload_active_proxies() {
    local rc=0
    # Inactive nginx may legitimately lack its ephemeral RuntimeDirectory.
    # Validate/reload each active service independently; never activate stopped ones.
    if systemctl is-active --quiet nathaya-nginx.service; then
        if nginx -t -c /etc/nathaya-tunnel/services/nginx.conf && systemctl reload nathaya-nginx.service; then :; else rc=1; fi
    fi
    if systemctl is-active --quiet nathaya-haproxy.service; then
        if haproxy -c -f /etc/nathaya-tunnel/services/haproxy.cfg && systemctl reload nathaya-haproxy.service; then :; else rc=1; fi
    fi
    return "$rc"
}
nt_tls_issue() {
    if nt_tls_validate_lineage; then
        printf 'Sertifikat valid dipertahankan.\n'
    else
        # Initial issuance only: foreign port 80 conflicts were rejected by preflight.
        local was_active=0 rc=0
        if systemctl is-active --quiet nathaya-haproxy.service; then was_active=1; systemctl stop nathaya-haproxy.service; fi
        certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email             --keep-until-expiring --cert-name "$NT_DOMAIN" -d "$NT_DOMAIN" || rc=$?
        if (( was_active )); then systemctl start nathaya-haproxy.service; fi
        (( rc == 0 )) || return "$rc"
    fi
    nt_tls_sync
}
