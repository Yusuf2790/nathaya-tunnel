#!/usr/bin/env bash
nt_websocket_verify_source() {
    python3 -I -B -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$NT_SOURCE/services/ws_proxy.py"
}
