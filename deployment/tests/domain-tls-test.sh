#!/usr/bin/env bash
# Local configuration and OpenSSL fixture; does not run installer main or systemd.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo/install-dashboard.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
set_paths "$work"
local_uid=$EUID
mkdir -p "$work"/{etc/nathaya-tunnel/tls,stage/ws}
stage="$work/stage"
ws_domain=sg1.example.test
requested_domain=$ws_domain
use_certbot=0
tls_source_cert= tls_source_key=
inputs=(); outputs=()

printf 'DOMAIN="old.example.test"\nKEEP="fixture untouched"\n' > "$ws_config"
[[ $(configured_domain) == old.example.test ]]
for bad in 'https://bad.test' 'bad.test:443' '-bad.test' '10.0.0.1' 'a..test'; do
    if valid_domain "$bad"; then printf 'Hostname tidak valid diterima: %s\n' "$bad" >&2; exit 1; fi
done
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj "/CN=$ws_domain" \
    -addext "subjectAltName=DNS:$ws_domain" -keyout "$stage/ws/privkey.pem" -out "$stage/ws/fullchain.pem" 2>/dev/null
valid_tls_pair "$stage/ws/fullchain.pem" "$stage/ws/privkey.pem"
if (ws_domain=wrong.example.test; valid_tls_pair "$stage/ws/fullchain.pem" "$stage/ws/privkey.pem"); then
    printf 'Sertifikat hostname salah diterima\n' >&2; exit 1
fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$stage/other.pem" 2>/dev/null
if valid_tls_pair "$stage/ws/fullchain.pem" "$stage/other.pem"; then
    printf 'Pasangan private key salah diterima\n' >&2; exit 1
fi
stage_domain_outputs
grep -Fxq 'DOMAIN="sg1.example.test"' "$stage/ws/config.conf"
grep -Fxq 'KEEP="fixture untouched"' "$stage/ws/config.conf"
grep -Fxq 'DOMAIN="old.example.test"' "$ws_config"
[[ ${#outputs[@]} == 3 ]]
read_ssh_ports
[[ $ssh_ports_display == '109 143' && $fresh_ports == 1 ]]
printf '109\n' > "$ssh_ports_file"
read_ssh_ports
[[ $ssh_ports_display == 109 && $fresh_ports == 0 ]]
printf 'OK: hostname, TLS domain/key, konfigurasi staged, serta default/override port.\n'
