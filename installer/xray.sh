#!/usr/bin/env bash
nt_xray_install() {
    nt_directory /opt/nathaya/bin 755
    nt_directory "$NT_RUN/xray-stage" 700
    python3 -I -B "$NT_SOURCE/installer/artifacts.py" --lock "$NT_SOURCE/installer/external-lock.json" --stage "$NT_RUN/xray-stage"
    chmod 700 "$NT_RUN/xray-stage/xray"
    "$NT_RUN/xray-stage/xray" version > "$NT_RUN/xray-version.txt"
    nt_replace_file "$NT_RUN/xray-stage/xray" /opt/nathaya/bin/xray 755 "$NT_RUN" opt/nathaya/bin/xray
    nt_replace_file "$NT_RUN/xray-stage/LICENSE" /opt/nathaya/licenses/Xray-core.txt 644 "$NT_RUN" opt/nathaya/licenses/Xray-core.txt
    nt_replace_file "$NT_RUN/xray-stage/xray-binary.json" /etc/nathaya-tunnel/xray-binary.json 600 "$NT_RUN" etc/nathaya-tunnel/xray-binary.json
}
