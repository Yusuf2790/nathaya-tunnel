#!/usr/bin/env bash
nt_track_unit_change() {
    local unit="$1" enable="${2:-yes}"
    if ! systemctl is-active --quiet "$unit"; then NT_STARTED_UNITS="${NT_STARTED_UNITS:-} $unit"; fi
    if [[ "$enable" == yes ]] && ! systemctl is-enabled --quiet "$unit"; then NT_NEW_ENABLED_UNITS="${NT_NEW_ENABLED_UNITS:-} $unit"; fi
}
nt_core_units() {
    printf '%s\n' nathaya-sshd nathaya-dropbear nathaya-ws vmess@config vless@config trojan@config shadowsocks@config nathaya-nginx nathaya-haproxy
}
nt_proxies_install() {
    local protocol unit
    python3 -I -B "$NT_SOURCE/installer/render.py" --domain "$NT_DOMAIN" --output-directory "$NT_RUN/rendered"
    nt_directory /etc/nathaya-tunnel/services 700
    nt_directory /etc/nathaya-tunnel/xray 700
    for protocol in vmess vless trojan shadowsocks; do
        nt_directory "/etc/nathaya-tunnel/xray/$protocol" 700
        # Keep existing clients/keys/ports rather than replacing them with defaults.
        if [[ ! -e "/etc/nathaya-tunnel/xray/$protocol/config.json" ]]; then
            nt_private_file "/etc/nathaya-tunnel/xray/$protocol/config.json" "$NT_RUN/rendered/$protocol.json"
        fi
        /opt/nathaya/bin/xray run -test -config "/etc/nathaya-tunnel/xray/$protocol/config.json" > "$NT_RUN/$protocol-test.log" 2>&1
    done
    for protocol in nginx.conf haproxy.cfg; do
        if [[ ! -e "/etc/nathaya-tunnel/services/$protocol" ]]; then
            nt_private_file "/etc/nathaya-tunnel/services/$protocol" "$NT_RUN/rendered/$protocol"
        fi
    done
    nt_directory /run/nathaya-nginx 750
    chown root:www-data /run/nathaya-nginx
    local tempdir
    for tempdir in body proxy fastcgi uwsgi scgi; do
        nt_safe_path "/run/nathaya-nginx/$tempdir" dir
        install -d -o www-data -g www-data -m 700 "/run/nathaya-nginx/$tempdir"
    done
    # Reject additive admin ListenAddress settings BEFORE starting the extra daemon.
    /usr/sbin/sshd -T -f /etc/ssh/sshd_config -p 2222 -p 2223 -oListenAddress=127.0.0.1 -oPidFile=/run/nathaya-sshd.pid |
        awk '$1=="listenaddress" {n++; if ($2 !~ /^127[.]0[.]0[.]1:222[23]$/) bad=1} END {exit (n!=2 || bad)}'
    nginx -t -c /etc/nathaya-tunnel/services/nginx.conf
    haproxy -c -f /etc/nathaya-tunnel/services/haproxy.cfg
    systemd-analyze verify "$NT_RUN/rendered/"*.service > "$NT_RUN/systemd-verify.log" 2>&1
    while IFS= read -r unit; do
        nt_replace_file "$NT_RUN/rendered/$unit.service" "/etc/systemd/system/$unit.service" 644 "$NT_RUN" "etc/systemd/system/$unit.service"
    done < <(nt_core_units)
    if [[ "$NT_NGINX_NEW" == 1 ]]; then systemctl disable --now nginx.service; fi
    if [[ "$NT_HAPROXY_NEW" == 1 ]]; then systemctl disable --now haproxy.service; fi
    systemctl daemon-reload
    python3 -I -B "$NT_SOURCE/installer/state.py" record-services
    while IFS= read -r unit; do
        nt_track_unit_change "$unit.service" yes
        systemctl enable "$unit.service"
        systemctl restart "$unit.service"
    done < <(nt_core_units)
}
