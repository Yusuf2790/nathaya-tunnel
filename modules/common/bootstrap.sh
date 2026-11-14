#!/usr/bin/env bash

# Source-only foundation: no filesystem writes, network, services or account operations.
if [[ "${_NATHAYA_BOOTSTRAP_LOADED:-}" == "1" ]]; then
    return 0
fi

# Code discovery is independent of the working directory and runtime data.
# NATHAYA_BASE is a trusted caller/environment override, never a config key.
NATHAYA_BASE="$(CDPATH= cd -- "${NATHAYA_BASE:-$(dirname -- "${BASH_SOURCE[0]}")/../..}" && pwd -P)" || {
    printf 'ERROR: Lokasi kode Nathaya tidak tersedia.\n' >&2
    return 1
}

NATHAYA_CONFIG="${NATHAYA_CONFIG:-/etc/nathaya-tunnel}"
CONFIG_FILE="${NATHAYA_CONFIG_FILE:-$NATHAYA_CONFIG/config.conf}"
NATHAYA_CACHE="${NATHAYA_CACHE:-/var/cache/nathaya-tunnel}"
NATHAYA_LOG_DIR="${NATHAYA_LOG_DIR:-/opt/nathaya/logs}"
NATHAYA_SSH_DIR="${NATHAYA_SSH_DIR:-/opt/nathaya/data/ssh}"
NATHAYA_SSH_DB="${NATHAYA_SSH_DB:-$NATHAYA_SSH_DIR/accounts.db}"
NATHAYA_SSH_LOCK="${NATHAYA_SSH_LOCK:-$NATHAYA_SSH_DIR/accounts.lock}"
NATHAYA_SSH_OPERATIONS_LOCK="${NATHAYA_SSH_OPERATIONS_LOCK:-$NATHAYA_SSH_DIR/operations.lock}"
NATHAYA_SSH_RECONCILE_LOG="$NATHAYA_LOG_DIR/ssh-reconcile.log"
NATHAYA_TELEGRAM_LOG="$NATHAYA_LOG_DIR/telegram.log"

_nathaya_config_unavailable() {
    local state="$1"
    if [[ "${NATHAYA_CONFIG_STATE:-}" != "$state" ]]; then
        printf 'PERINGATAN: Konfigurasi Nathaya %s; domain kosong dan Telegram OFF.\n' "$state" >&2
    fi
    NATHAYA_CONFIG_STATE="$state"
}

# Literal KEY=value reader. No source/eval, expansion, escapes or inline comments.
# Unknown assignment keys are ignored, including all code/runtime path overrides.
load_nathaya_config() {
    local line key value
    local config_domain="" config_status="OFF" config_token="" config_admin=""
    local assignment='^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$'
    local double_quoted='^"([^"]*)"$'
    local single_quoted="^'([^']*)'$"
    local bare='^[a-zA-Z0-9_./:@+-]*$'

    DOMAIN=""
    TELEGRAM_STATUS="OFF"
    TELEGRAM_BOT_TOKEN=""
    TELEGRAM_ADMIN_ID=""

    if [[ ! -f "$CONFIG_FILE" ]]; then
        _nathaya_config_unavailable "belum tersedia"
        return 1
    fi
    if [[ ! -r "$CONFIG_FILE" ]]; then
        _nathaya_config_unavailable "tidak dapat dibaca"
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! "$line" =~ $assignment ]]; then
            _nathaya_config_unavailable "tidak valid"
            return 2
        fi
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        case "$key" in
            DOMAIN|TELEGRAM_STATUS|TELEGRAM_BOT_TOKEN|TELEGRAM_ADMIN_ID) ;;
            *) continue ;;
        esac
        value="${value%"${value##*[![:space:]]}"}"
        if [[ "$value" =~ $double_quoted || "$value" =~ $single_quoted ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ ! "$value" =~ $bare ]]; then
            _nathaya_config_unavailable "tidak valid"
            return 2
        fi
        case "$key" in
            DOMAIN) config_domain="$value" ;;
            TELEGRAM_STATUS) config_status="$value" ;;
            TELEGRAM_BOT_TOKEN) config_token="$value" ;;
            TELEGRAM_ADMIN_ID) config_admin="$value" ;;
        esac
    done < "$CONFIG_FILE"

    if [[ "$config_status" != "ON" && "$config_status" != "OFF" ]] ||
       [[ -n "$config_admin" && ! "$config_admin" =~ ^-?[0-9]+$ ]]; then
        _nathaya_config_unavailable "tidak valid"
        return 2
    fi

    # Publish only after the entire file has been parsed successfully.
    DOMAIN="$config_domain"
    TELEGRAM_STATUS="$config_status"
    TELEGRAM_BOT_TOKEN="$config_token"
    TELEGRAM_ADMIN_ID="$config_admin"
    NATHAYA_CONFIG_STATE="loaded"
    return 0
}

_NATHAYA_BOOTSTRAP_LOADED=1
