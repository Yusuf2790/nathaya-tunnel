# Aturan kerja Nathaya Tunnel — installer modular penuh

- Baca aturan, kode/buffer aktual dan status Git sebelum edit. Bila Bash/Git tidak tersedia, laporkan; jangan menganggap tree bersih. Pertahankan perubahan pengguna dan penghapusan nathaya.txt.
- ../alrescha-source hanya referensi baca. Pertahankan atribusi/lisensi adaptasi (NOTICE, licenses/). Jangan salin token, password, private key atau identitas bawaan.
- Acode/Termux hanya pengembangan: JANGAN menjalankan installer nyata, apt, mutasi firewall/systemctl, operasi akun atau reboot. Tes fixture/mocks saja. Jangan commit/push/publish release.
- Pengguna mengizinkan source installer penuh Ubuntu 24.04 amd64 systemd PID1: upgrade/dist-upgrade OS, removal UFW/firewalld terinventarisasi, tunnel/TLS/maintenance/updater dan reboot akhir. Ini bukan izin menjalankannya di pengembangan.
- chmod 777 hanya direktori nonrahasia eksplisit public/drop, tidak rekursif; bukan kode executable/config/DB/token/key atau parent yang memungkinkan penggantiannya. Private data root:root 600, direktori 700.
- Pertahankan path runtime tahap 1, config data allowlist (bukan source shell), satu DB SSH tujuh kolom. Jangan migrasi diam-diam atau pasang monitor DB Alrescha.
- Validasi source, konflik target/port/hook, lock bersama, staging, backup privat dan preservasi data/key. Helper source hanya definisi/path, tanpa jaringan/mkdir/chown/operasi akun/menu.
- Pisahkan pemeliharaan OS dan deployment aplikasi. Upgrade boleh mengganti binary/proses, tetapi port dan autentikasi admin harus dipertahankan; tolak removal komponen kritis. Jangan hapus lock apt/kill unattended-upgrades.
- Host key unik dibuat di VPS; valid key/PKI/sertifikat dipertahankan pada reinstall/update, tidak dicetak ke log atau diunduh dari referensi.
- OpenVPN directive referensi termasuk cipher none/auth none/comp-lzo tidak diganti diam-diam. Artefak/lisensi/kompatibilitas belum terbukti harus BLOCKED; jangan mengaktifkan substitusi seolah parity.
- Backend internal loopback, routing deterministik, PROXY protocol cocok. Tidak ada arbitrary-target relay dari header klien.
- Pertahankan UI Nathaya dan format HTML Telegram. Bedakan implemented/BLOCKED/panel unavailable/belum diuji VPS; badge membaca unit aktual.
- Reboot hanya sesudah full profile dan seluruh gate wajib sukses; tidak pada core subset/failure/tests/help/update. Tidak ada reboot harian.
- Updater dari stable GitHub remote aktual, validator lokal tepercaya, satu versi tervalidasi, backup+rollback kode. Tidak upgrade OS/setup/migrasi data/reboot. Auto-update default disabled sampai verifikasi manual berhasil.
- Laporan sukses installer dasar dari pengguna bukan bukti layanan penuh lolos VPS. Tes baru belum boleh dianggap PASS tanpa dijalankan.
