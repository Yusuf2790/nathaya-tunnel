# Penghapusan NATHAYA TUNNEL — data tetap disimpan

Gunakan uninstaller milik instalasi yang sama, bukan script upstream internet.

```sh
nathaya-uninstall
# Atau dari source lengkap yang sesuai:
bash /root/nathaya-tunnel/uninstall.sh
```

Root, Ubuntu24.04 dan terminal interaktif diperlukan. Ketik `UNINSTALL NATHAYA KEEP DATA` setelah membaca daftar dampaknya. Tidak ada opsi force/unattended/data purge.

Uninstaller membaca `/var/lib/nathaya-tunnel/owned-files.tsv`, lalu hanya menghentikan dan menghapus code/unit/cron/proxy configuration dalam daftar tertutup yang hash SHA256-nya masih sesuai. Missing/unsafe/modified files berarti berhenti untuk review, bukan menghapus berdasarkan nama/path saja. Cron backup/autokill/reboot harian yang dipilih lewat menu memakai ledger/lock yang sama dan ikut dihapus jika tetap dimiliki; cron administrator tidak diambil alih.

Yang tetap disimpan:

- Seluruh Unix accounts dan database/limit/quota Alrescha.
- Konfigurasi akun Xray, OpenVPN, CA/server/client data dan private profiles.
- Sertifikat TLS/Let’s Encrypt, host keys SSH/Dropbear dan credentials Telegram.
- Backup, logs, ownership metadata dan `/var/lib/nathaya-tunnel/originals`.
- Paket sistem dan konfigurasi administratif primary SSH/Netplan/DNS/IPv6/firewall.

Rule NAT/FORWARD dibersihkan hanya melalui helper forwarding yang tercatat/hash cocok dan hanya rule exact berlabel `nathaya-openvpn`. Tidak ada flush/policy reset; runtime ip_forward tidak dipaksa nol. File setting forwarding milik installer dapat dihapus bila tetap cocok, tanpa menulis ulang sysctl global yang sedang berjalan.

Jika konfigurasi proxy milik installer dihapus, nginx/HAProxy dihentikan. Paket dan originals tetap tersedia; uninstaller tidak otomatis memulihkan shared proxy configuration atau menjalankan service administrator. Primary SSH tidak dihentikan/restart. Setelah removal, nilai AUTOSTART OpenVPN tetap dipertahankan agar private server configuration yang disimpan tidak otomatis diaktifkan paket umbrella.

Operasi tidak transactional. Jika berhenti, pertahankan sesi SSH/console dan review metadata/backup secara privat sebelum tindakan lanjutan. Tidak ada reset VPS, user deletion, apt autoremove atau reboot otomatis. Pelaksanaan native belum dilakukan oleh sesi pengembangan ini.
