#!/bin/sh
# Nathaya Tunnel managed menu wrapper v1
# Installed by setup.sh; no inherited development path overrides.
if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf 'ERROR: Jalankan menu sebagai root (sudo menu).\n' >&2
    exit 1
fi
exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root USER=root LOGNAME=root LANG=C.UTF-8 TERM="${TERM:-dumb}" \
    /bin/bash --noprofile --norc /opt/nathaya/menu.sh "$@"
