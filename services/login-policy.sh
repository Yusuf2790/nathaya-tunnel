#!/bin/sh
# Pure predicate; no commands or state changes.
nathaya_login_policy() {
    [ "$1" = 0 ] || return 1
    case "$2" in *i*) ;; *) return 1 ;; esac
    [ -n "$3" ] && [ "$4" = yes ] || return 1
    case "$5" in -*) ;; *) return 1 ;; esac
    [ -z "$6" ] && [ -z "$7" ]
}
