# Dipanggil oleh /etc/profile saat login SSH interaktif root.
# Jalankan sebagai proses anak agar keluar dashboard kembali ke shell.
if [ -n "${BASH_VERSION:-}" ] &&
   [ "${EUID:-1}" -eq 0 ] &&
   [ -n "${SSH_CONNECTION:-}" ] &&
   [ -n "${SSH_TTY:-}" ] &&
   [ -t 0 ] && [ -t 1 ] &&
   [ -x /usr/local/bin/menu ]; then
    case "$-" in
        *i*)
            if [ -z "${NATHAYA_LOGIN_SHOWN:-}" ]; then
                export NATHAYA_LOGIN_SHOWN=1
                /usr/local/bin/menu
            fi
            ;;
    esac
fi
