#!/usr/bin/env bash
# The reference server ZIP has not been inspectable in this development runtime.
# No private server identity or guessed replacement configuration is deployed.
nt_openvpn_require() {
    nt_error 'BLOCKED OpenVPN: reference server archive not audited, PKI/auth/server contract and 2.6 exact-client interoperability unverified. Run tools/audit-openvpn.py and review docs/alrescha-parity.md.'
    return 78
}
