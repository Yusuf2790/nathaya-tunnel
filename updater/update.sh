#!/bin/sh
# Nathaya fixed-path updater launcher. No caller environment enters Python.
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
    /usr/bin/python3 -I -B /opt/nathaya/updater/main.py "$@"
