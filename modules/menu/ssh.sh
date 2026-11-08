#!/bin/bash
# The SSH UI never loads the retired modules/ssh backend.
source "$NATHAYA_BASE/modules/menu/protocol.sh" || return 1
show_ssh_menu() { nathaya_show_protocol_menu ssh; }
ssh_menu_loop() { nathaya_protocol_loop ssh; }
