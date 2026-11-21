#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
    printf 'Jalankan installer sebagai root.\n' >&2
    exit 1
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/opt/nathaya
menu_command=/usr/local/bin/menu

for command in python3 ip systemctl; do
    if ! command -v "$command" >/dev/null; then
        printf 'Perintah %s diperlukan.\n' "$command" >&2
        exit 1
    fi
done
if [[ ! -d /run/systemd/system ]]; then
    printf 'Installer memerlukan VPS dengan systemd aktif.\n' >&2
    exit 1
fi

if [[ -e "$menu_command" || -L "$menu_command" ]] &&
   [[ "$(readlink -f "$menu_command")" != "$target/menu.sh" ]] &&
   ! grep -Eq '(/opt/nathaya/|NATHAYA_BASE=.{0,2}/opt/nathaya)' "$menu_command"; then
    printf '%s sudah digunakan oleh program lain.\n' "$menu_command" >&2
    exit 1
fi

install -d -m 0755 "$target" /etc/nathaya-tunnel
if [[ ! -e /etc/nathaya-tunnel/config.conf && ! -L /etc/nathaya-tunnel/config.conf ]]; then
    install -m 0600 /dev/null /etc/nathaya-tunnel/config.conf
fi
if [[ ! -d "$target/logs" ]]; then
    install -d -m 0750 "$target/logs"
fi
while IFS= read -r -d '' file; do
    relative=${file#"$source_dir/"}
    install -d -m 0755 "$target/${relative%/*}"
    if [[ "$file" != "$target/$relative" ]]; then
        install -m 0644 "$file" "$target/$relative"
    fi
done < <(find "$source_dir/modules" -type f \( -name '*.sh' -o -name 'traffic.py' \) -print0)

if [[ "$source_dir" != "$target" ]]; then
    install -m 0755 "$source_dir/menu.sh" "$target/menu.sh"
else
    chmod 0755 "$target/menu.sh"
fi

install -m 0644 "$source_dir/deployment/nathaya-traffic.service" /etc/systemd/system/
install -m 0644 "$source_dir/deployment/nathaya-traffic.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nathaya-traffic.timer

install -m 0755 "$source_dir/deployment/menu" "$menu_command"
install -m 0644 "$source_dir/deployment/nathaya-login.sh" /etc/profile.d/
printf 'Dashboard terpasang. Ketik menu atau login ulang via SSH.\n'
