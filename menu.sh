#!/bin/bash
# Interactive Nathaya menu only. Install runtime code with:
# bash lib/install-runtime.sh --source /opt/nathaya/source
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -f "$here/project/menu" && ! -L "$here/project/menu" ]]; then
    export NATHAYA_BASE="$here"
    exec bash "$here/project/menu" "$@"
fi
if [[ -f /usr/bin/menu && ! -L /usr/bin/menu && -x /usr/bin/menu ]]; then
    exec /usr/bin/menu "$@"
fi
printf '%s\n' 'Nathaya interactive menu is unavailable; install the complete runtime first.' >&2
exit 1
