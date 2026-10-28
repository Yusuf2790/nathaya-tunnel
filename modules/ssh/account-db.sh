#!/usr/bin/env bash

NATHAYA_SSH_DIR="${NATHAYA_SSH_DIR:-/opt/nathaya/data/ssh}"
NATHAYA_SSH_DB="${NATHAYA_SSH_DB:-$NATHAYA_SSH_DIR/accounts.db}"
NATHAYA_SSH_LOCK="${NATHAYA_SSH_LOCK:-$NATHAYA_SSH_DIR/accounts.lock}"

ssh_db_init() {
    install -d -o root -g root -m 700 "$NATHAYA_SSH_DIR" || return 1
    touch "$NATHAYA_SSH_DB" "$NATHAYA_SSH_LOCK" || return 1
    chown root:root "$NATHAYA_SSH_DB" "$NATHAYA_SSH_LOCK" || return 1
    chmod 600 "$NATHAYA_SSH_DB" "$NATHAYA_SSH_LOCK" || return 1
}

ssh_valid_username() {
    [[ "${1:-}" =~ ^[a-z0-9]{4,32}$ ]]
}

# Validasi tanggal ISO sekaligus tanggal kalender yang nyata.
ssh_valid_date() {
    local value="${1:-}"
    [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    [[ "$(date -d "$value" +%F 2>/dev/null)" == "$value" ]]
}

# Validasi timestamp lokal dalam format YYYY-MM-DD HH:MM:SS.
ssh_valid_datetime() {
    local value="${1:-}"
    [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || return 1
    [[ "$(date -d "$value" '+%F %T' 2>/dev/null)" == "$value" ]]
}

# Validasi expiry sesuai tipe akun. Regular tetap memakai tanggal; trial memakai timestamp.
ssh_valid_expiry_for_type() {
    local account_type="${1:-}"
    local expiry="${2:-}"

    case "$account_type" in
        regular) ssh_valid_date "$expiry" ;;
        trial)   ssh_valid_datetime "$expiry" ;;
        *)       return 1 ;;
    esac
}

# Return 0 jika sudah expired, 1 jika masih aktif, 2 jika data tidak valid.
# Akun regular berlaku sampai akhir tanggal expiry; trial expired tepat pada timestamp.
ssh_account_expiry_reached() {
    local account_type="${1:-}"
    local expiry="${2:-}"
    local now_epoch expiry_epoch today

    case "$account_type" in
        regular)
            ssh_valid_date "$expiry" || return 2
            today="$(date +%F)" || return 2
            [[ "$expiry" < "$today" ]]
            return $?
            ;;
        trial)
            ssh_valid_datetime "$expiry" || return 2
            expiry_epoch="$(date -d "$expiry" +%s 2>/dev/null)" || return 2
            now_epoch="$(date +%s)" || return 2
            (( now_epoch >= expiry_epoch ))
            return $?
            ;;
        *)
            return 2
            ;;
    esac
}

ssh_username_exists() {
    id "$1" >/dev/null 2>&1
}

ssh_db_has_username() {
    local username="$1"

    awk -F '|' -v u="$username" '
        $1 == u { found=1 }
        END { exit !found }
    ' "$NATHAYA_SSH_DB"
}

# Membuat akun reguler. account_type selalu ditulis eksplisit sebagai "regular".
ssh_db_add_account() {
    local username="${1:-}"
    local created="${2:-}"
    local expiry="${3:-}"
    local limit_ip="${4:-}"

    ssh_valid_username "$username" || {
        echo "ERROR: Username tidak valid." >&2
        return 1
    }
    ssh_valid_date "$created" || {
        echo "ERROR: Tanggal pembuatan tidak valid." >&2
        return 1
    }
    ssh_valid_date "$expiry" || {
        echo "ERROR: Tanggal expiry akun reguler tidak valid." >&2
        return 1
    }
    [[ "$limit_ip" =~ ^[1-9][0-9]*$ ]] &&
        (( limit_ip <= 100 )) || {
        echo "ERROR: Limit IP harus 1-100." >&2
        return 1
    }

    (
        flock -x 9 || exit 1

        if ssh_db_has_username "$username"; then
            echo "ERROR: Username sudah tercatat di database Nathaya." >&2
            exit 1
        fi

        printf '%s|%s|%s|%s|active|0|regular\n' \
            "$username" "$created" "$expiry" "$limit_ip" \
            >> "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"
}

# Membuat akun trial. expiry wajib berupa YYYY-MM-DD HH:MM:SS.
ssh_db_add_trial_account() {
    local username="${1:-}"
    local created="${2:-}"
    local expiry="${3:-}"
    local limit_ip="${4:-}"

    ssh_valid_username "$username" || {
        echo "ERROR: Username tidak valid." >&2
        return 1
    }
    ssh_valid_date "$created" || {
        echo "ERROR: Tanggal pembuatan tidak valid." >&2
        return 1
    }
    ssh_valid_datetime "$expiry" || {
        echo "ERROR: Timestamp expiry trial tidak valid." >&2
        return 1
    }
    [[ "$limit_ip" =~ ^[1-9][0-9]*$ ]] &&
        (( limit_ip <= 100 )) || {
        echo "ERROR: Limit IP harus 1-100." >&2
        return 1
    }

    (
        flock -x 9 || exit 1

        if ssh_db_has_username "$username"; then
            echo "ERROR: Username sudah tercatat di database Nathaya." >&2
            exit 1
        fi

        printf '%s|%s|%s|%s|active|0|trial\n' \
            "$username" "$created" "$expiry" "$limit_ip" \
            >> "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"
}

ssh_db_get_account() {
    local username="${1:-}"

    awk -F '|' -v u="$username" '
        $1 == u { print; found=1 }
        END { if (!found) exit 1 }
    ' "$NATHAYA_SSH_DB"
}

ssh_db_remove_account() {
    local username="${1:-}"
    local tmp
    local rc

    ssh_valid_username "$username" || return 1
    tmp="$(mktemp "${NATHAYA_SSH_DIR}/accounts.XXXXXX")" || return 1

    (
        flock -x 9 || exit 1

        # Jangan melaporkan sukses jika username tidak ditemukan.
        if ! awk -F '|' -v u="$username" '
            $1 == u { found=1 }
            END { exit !found }
        ' "$NATHAYA_SSH_DB"; then
            echo "ERROR: Username tidak ditemukan di database." >&2
            exit 1
        fi

        if ! awk -F '|' -v u="$username" '$1 != u' \
            "$NATHAYA_SSH_DB" > "$tmp"; then
            exit 1
        fi

        chmod 600 "$tmp" &&
        chown root:root "$tmp" &&
        mv -f "$tmp" "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"

    rc=$?
    rm -f "$tmp"
    return "$rc"
}

ssh_db_update_status() {
    local username="${1:-}"
    local status="${2:-}"
    local lock_until="${3:-0}"
    local tmp rc

    ssh_valid_username "$username" || return 1
    case "$status" in
        active|locked|expired) ;;
        *)
            echo "ERROR: Status tidak valid." >&2
            return 1
            ;;
    esac
    [[ "$lock_until" =~ ^[0-9]+$ ]] || return 1

    tmp="$(mktemp "${NATHAYA_SSH_DIR}/accounts.XXXXXX")" || return 1

    (
        flock -x 9 || exit 1

        # Hanya ubah record skema 7 kolom dengan tipe yang dikenal.
        if ! awk -F '|' -v u="$username" \
            -v s="$status" -v l="$lock_until" '
            BEGIN { OFS="|" }
            $1 == u {
                if (NF != 7 || ($7 != "regular" && $7 != "trial")) {
                    invalid=1
                    next
                }
                $5=s
                $6=l
                found=1
            }
            { print }
            END {
                if (invalid || !found) exit 1
            }
        ' "$NATHAYA_SSH_DB" > "$tmp"; then
            exit 1
        fi

        chmod 600 "$tmp" &&
        chown root:root "$tmp" &&
        mv -f "$tmp" "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"

    rc=$?
    rm -f "$tmp"
    return "$rc"
}

# Update expiry reguler saja; trial tidak boleh diperpanjang lewat fungsi ini.
ssh_db_update_expiry() {
    local username="${1:-}"
    local new_expiry="${2:-}"
    local tmp rc

    ssh_valid_username "$username" || return 1
    ssh_valid_date "$new_expiry" || {
        echo "ERROR: Tanggal expiry akun reguler tidak valid." >&2
        return 1
    }

    tmp="$(mktemp "${NATHAYA_SSH_DIR}/accounts.XXXXXX")" || return 1

    (
        flock -x 9 || exit 1

        if ! awk -F '|' -v u="$username" -v e="$new_expiry" '
            BEGIN { OFS="|" }
            $1 == u {
                # Kolom ke-7 harus regular. Baris lama 6 kolom tidak diubah
                # menjadi regular secara diam-diam; migrasi dilakukan terpisah.
                if (NF != 7 || $7 != "regular") {
                    invalid=1
                    next
                }
                $3=e
                found=1
            }
            { print }
            END {
                if (invalid || !found) exit 1
            }
        ' "$NATHAYA_SSH_DB" > "$tmp"; then
            exit 1
        fi

        chmod 600 "$tmp" &&
        chown root:root "$tmp" &&
        mv -f "$tmp" "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"

    rc=$?
    rm -f "$tmp"
    return "$rc"
}

# Mengunci akun hanya jika statusnya masih active.
# Fungsi ini menerima akun regular saja sampai modul lock/unlock ikut diperbarui.
ssh_db_lock_if_active() {
    local username="${1:-}"
    local lock_until="${2:-}"
    local tmp rc

    ssh_valid_username "$username" || return 1
    [[ "$lock_until" =~ ^[0-9]+$ ]] || return 1

    tmp="$(mktemp "${NATHAYA_SSH_DIR}/accounts.XXXXXX")" || return 1

    (
        flock -x 9 || exit 1

        if ! awk -F '|' -v u="$username" -v l="$lock_until" '
            BEGIN { OFS="|" }
            $1 == u && NF == 7 && $7 == "regular" && $5 == "active" {
                $5="locked"
                $6=l
                changed=1
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$NATHAYA_SSH_DB" > "$tmp"; then
            exit 1
        fi

        chmod 600 "$tmp" &&
        chown root:root "$tmp" &&
        mv -f "$tmp" "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"

    rc=$?
    rm -f "$tmp"
    return "$rc"
}

# Membuka lock otomatis hanya jika waktu lock sudah habis.
ssh_db_unlock_if_expired() {
    local username="${1:-}"
    local expected_until="${2:-}"
    local now="${3:-}"
    local tmp rc

    ssh_valid_username "$username" || return 1
    [[ "$expected_until" =~ ^[0-9]+$ ]] || return 1
    [[ "$now" =~ ^[0-9]+$ ]] || return 1
    (( expected_until > 0 && expected_until <= now )) || return 1

    tmp="$(mktemp "${NATHAYA_SSH_DIR}/accounts.XXXXXX")" || return 1

    (
        flock -x 9 || exit 1

        if ! awk -F '|' -v u="$username" -v expected="$expected_until" '
            BEGIN { OFS="|" }
            $1 == u && NF == 7 && $7 == "regular" &&
            $5 == "locked" && $6 == expected {
                $5="active"
                $6=0
                changed=1
            }
            { print }
            END { if (!changed) exit 1 }
        ' "$NATHAYA_SSH_DB" > "$tmp"; then
            exit 1
        fi

        chmod 600 "$tmp" &&
        chown root:root "$tmp" &&
        mv -f "$tmp" "$NATHAYA_SSH_DB"
    ) 9>"$NATHAYA_SSH_LOCK"

    rc=$?
    rm -f "$tmp"
    return "$rc"
}
