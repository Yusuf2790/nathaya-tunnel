# Nathaya Tunnel Dashboard

## Instalasi dashboard

Target pengujian: VPS amd64 dengan systemd pada Ubuntu 22.04/24.04 dan Debian
12/13. Daftar ini adalah target installer, bukan klaim sudah lulus uji pada semua OS.

```bash
cd nathaya-tunnel
bash install-dashboard.sh --help
bash install-dashboard.sh --check
sudo bash install-dashboard.sh
```

Jika sudah root, hilangkan `sudo`. `--check` melaporkan penyebab preflight gagal
atau daftar dependensi yang belum ada. Mode ini tidak menulis file, mengambil
lock, menjalankan APT, atau mengubah status unit. Instalasi memakai `apt-get
update` dan memasang hanya dependensi yang diperlukan dan belum tersedia,
termasuk Python 3, `ip`, dan alat untuk fitur Set Domain. Installer tidak
melakukan upgrade sistem atau mengganti sumber APT.

Pada **instalasi baru**, menu otomatis saat login tidak aktif secara bawaan.
Untuk memilihnya saat instalasi pertama:

```bash
sudo bash install-dashboard.sh --enable-login-menu
```

Instal ulang mempertahankan pilihan yang sudah terpasang, termasuk hook dari
installer lama. Hook hanya membuka dashboard pada sesi **SSH root interaktif
(Bash dengan TTY)**, bukan saat menjalankan perintah SSH noninteraktif. Dari shell
root, ketik `menu` untuk membuka dashboard. Pilih `x` atau tekan **Ctrl+C** untuk
kembali ke shell tanpa menutup sesi SSH; pilih `z` untuk kembali satu tingkat.

### Instal ulang, konflik, dan rollback

Jalankan ulang `bash install-dashboard.sh` setelah memperbarui checkout repo.
Installer mengganti file aplikasi yang dikelolanya di `/opt/nathaya`, wrapper
`/usr/local/bin/menu`, unit trafik, dan hook login jika sebelumnya aktif. File
lain tidak dibersihkan. Installer tidak menulis `/etc/nathaya-tunnel/config.conf`,
`/etc/nathaya-tunnel/traffic-interface`, atau `/var/lib/nathaya-tunnel/traffic.json`;
data akun sistem di `/etc/passwd`, file akun lama lain, konfigurasi SSH admin,
firewall, dan port VPS juga tidak diubah. Timer yang berjalan tetap mencatat trafik
secara normal. Salinan file aplikasi lama yang diganti tersimpan di backup.

Jika ada benturan, installer berhenti **sebelum APT** dan menyebut path-nya.
Wrapper Nathaya lama (termasuk symlink ke `/opt/nathaya/menu.sh`), unit, dan hook
standar yang sudah terpasang dikenali. File yang diubah manual, unit dari lokasi
lain, atau drop-in yang tidak dikenali tidak ditimpa. Periksa siapa yang mengelola
path tersebut dan selesaikan benturan secara manual; jangan menghapusnya tanpa
memeriksa isinya dan menyiapkan backup. Jika status awal unit tidak bisa
snapshot dengan aman (misalnya `failed`), periksa unit sebelum mencoba ulang.

Installer mengunci sesi instalasi, memvalidasi file yang dipersiapkan, dan
mencatat status unit serta file lama/baru sebelum deployment. Ringkasan mencetak
lokasi backup/log terbatas untuk root di `/var/backups/nathaya-install.*`. Jika
penyalinan atau aktivasi gagal, installer mencoba memulihkan file dan keadaan
unit Nathaya serta menghapus hanya file deployment baru. Jika rollback tidak
lengkap, periksa log dan backup yang ditunjukkan sebelum mencoba lagi. Rollback
tidak mencopot paket yang sudah dipasang APT, tidak mengembalikan cache APT,
dan tidak memundurkan sampel trafik yang mungkin sudah dicatat. Pemadaman paksa
atau `SIGKILL` tidak dapat ditangani oleh rollback otomatis.

### Verifikasi timer

```bash
systemctl is-enabled nathaya-traffic.timer
systemctl is-active nathaya-traffic.timer
systemctl list-timers --all nathaya-traffic.timer
systemctl show nathaya-traffic.service -p Result
```

Timer yang sehat saat instalasi seharusnya `enabled` dan `active`. Periksa juga
hasil kolektor (`Result=success` setelah timer berjalan); timer aktif tidak
menjamin pengambilan sampel berhasil. Rujukan: [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)
dan [systemd-analyze verify](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html).

## Konfigurasi dashboard

Konfigurasi opsional. Jika perlu, buat `/etc/nathaya-tunnel` sebagai root dan
simpan `/etc/nathaya-tunnel/config.conf` dengan izin `0600`, milik root. Dashboard
membaca file ini sebagai skrip Bash, jadi jangan gunakan file dari sumber yang
tidak tepercaya. Contoh konfigurasi:

```bash
CLIENT_NAME="Nama Client"
ORDER_BY="Nama Pemesan"
SCRIPT_DEVELOPER="Nathaya Tunnel"
```

Dashboard mengukur RX/TX uplink VPS dengan sampel satu detik saat dibuka
atau saat kembali ke dashboard. Untuk pembaruan per detik, pilih
**Features → Monitoring Trafik**. Pilih `z` untuk kembali ke Features, atau
pilih `x` atau tekan **Ctrl+C** untuk keluar ke shell.

Timer mencatat trafik setiap 15 detik ke
`/var/lib/nathaya-tunnel/traffic.json`. Periode harian dan bulanan mengikuti
zona waktu VPS. Akumulasi dimulai dari sampel pertama. Trafik di antara dua
sampel yang melintasi pergantian hari atau bulan dibagi secara proporsional
menurut waktu. Statistik mencakup seluruh trafik pada satu interface uplink.
Interface dipilih dari default route IPv4, dengan IPv6 sebagai cadangan.
Untuk memilih interface sendiri, tulis namanya pada satu baris di
`/etc/nathaya-tunnel/traffic-interface`.

## Modul SSH tahap pertama (opsional)

Aktifkan hanya pada **VPS uji** sampai uji koneksi nyata di bawah lulus:

```bash
sudo bash install-dashboard.sh --check --enable-ssh
sudo bash install-dashboard.sh --enable-ssh
systemctl status nathaya-dropbear.service
ss -ltnp
```

Installer memasang `dropbear-bin` (bukan layanan Dropbear bawaan distro),
Bubblewrap, OpenSSL, dan Python Cryptography jika diperlukan. Unit khusus
`nathaya-dropbear.service` memakai TCP 109. Untuk menambah TCP 143, buat
`/etc/nathaya-tunnel/ssh-ports.conf` milik root dengan isi `109 143`, lalu
jalankan preflight dan installer lagi. Installer menolak listener asing pada
port yang dipilih; tidak mengubah firewall, port, atau konfigurasi SSH admin.
Instal ulang mempertahankan modul yang terpasang, akun, dan host key. Restart
layanan saat instal ulang dapat memutus tunnel pelanggan yang sedang aktif.

Menu SSH menyediakan Create, Trial, List Member/detail, Lock, dan Unlock.
Delete, Renew, Check User Login, List User Expired, dan Limit IP masih bertanda
**Belum tersedia**. Validasi saat ini membatasi username ke 4–32 karakter,
password ke 1–64 karakter. Create menerima angka hari 1–3650 (contoh `30`,
bukan `30d`). Trial menerima menit berakhiran `m` atau jam berakhiran `h`,
misalnya `30m` atau `1h`, hingga 720 jam (43.200 menit). Pemanggilan backend
lama dengan angka tanpa satuan tetap dihitung dalam jam.

Password Create terlihat saat diketik; `x` dan `z` dapat dimasukkan langsung.
Di formulir dan konfirmasi, Ctrl+C membatalkan dan kembali ke menu SSH. Pada
konfirmasi, `n` kembali ke formulir atau daftar dan hanya `y` menjalankan aksi.
Pada daftar, `z` kembali ke menu SSH dan `x` keluar. Pilih akun dengan nomor
atau username; `@1234` memilih username numerik tanpa memakai nomor baris.
`NATHAYA_TZ` (contoh `Asia/Jakarta`) pada konfigurasi dashboard memilih zona
waktu detail; jika tidak diatur, gunakan zona VPS.

Pelanggan hanya dibuat dalam SQLite Nathaya, bukan pada akun Linux host.
Worker Dropbear memakai namespace terpisah dengan passwd/shadow sintetis,
password, dan local TCP forwarding (`ssh -N -L` atau `-D`). Remote forwarding
(`-R`) dimatikan. Tidak tersedia home, kunci publik pelanggan, shell yang dapat
dieksekusi, atau perangkat PTY. Beberapa klien mungkin menerima respons awal
atas permintaan sesi/subsystem, tetapi tidak boleh mendapat shell, eksekusi
perintah, atau transfer file. Verifikasi dengan paket distro dan VPS uji
sebelum mengandalkan pembatasan ini. [Manual Dropbear](https://manpages.debian.org/trixie/dropbear-bin/dropbear.8.en.html).

Lock/Unlock hanya mengubah akun Nathaya. Supervisor memeriksa akun aktif dan
memutus worker milik akun yang dikunci atau kedaluwarsa; koneksi yang belum
terautentikasi juga dapat diminta menyambung ulang jika snapshot akun berubah.
Unlock tidak mengaktifkan akun expired atau masih terkunci otomatis. Limit IP
dan batas dua sesi disimpan sebagai metadata, **belum ditegakkan**. `0` berarti
IP unik tidak dibatasi; tahap berikutnya tetap harus membedakan IP unik dan
sesi serta menerapkan penguncian 15 menit.

Telegram menggunakan bot dan chat admin yang sama, mengirim username dan
password ke chat tersebut setelah commit akun. Gunakan hanya chat admin yang
dikendalikan sendiri; kredensial yang dikirim tersimpan di Telegram. Pengiriman
yang gagal tidak membatalkan akun. Ulangi dari List Member bila diperlukan.

### Backup / pemulihan SSH

Direktori `/var/lib/nathaya-ssh` (root, `0700`) berisi `accounts.sqlite3`,
`password.key` (AES-256-GCM, terpisah dari DB), dan `dropbear_ed25519_host_key`.
Backup ketiganya bersama konfigurasi port; simpan salinan kunci secara terpisah
dan aman. Gunakan backup SQLite yang konsisten, atau hentikan layanan **dan
jangan jalankan operasi akun** selama backup/restore. Pulihkan ke lokasi yang
sama dengan pemilik root dan izin file `0600`, lalu aktifkan layanan lagi.
Tanpa `password.key` yang cocok, password lama tak dapat dibuka. Baris lama yang
ada di penyimpanan Nathaya tanpa salinan terenkripsi tetap tampil tetapi
password ditandai tidak tersedia. Akun Linux lama tidak dimigrasikan otomatis.

### Uji modul SSH

```bash
bash -n install-dashboard.sh && bash -n deployment/ssh-installer.sh
bash -n modules/menu/ssh.sh && bash -n modules/common/telegram.sh
bash -n deployment/tests/ssh-menu-smoke.sh
git diff --check
bash deployment/tests/installer-smoke.sh
bash deployment/tests/ssh-menu-smoke.sh
python3 -B deployment/tests/ssh-menu-pty-test.py  # memerlukan PTY
python3 -B deployment/tests/ssh-backend-test.py  # memerlukan cryptography
```

Di Ubuntu 22.04 **disposabel**, buat akun member dan trial, lalu dari klien uji:

1. Gunakan `ssh -p 109 -N -L 8088:127.0.0.1:8080 AKUN@VPS_UJI` ke server HTTP
   uji pada VPS. Buktikan akses lewat `curl http://127.0.0.1:8088` berhasil dan
   koneksi bertahan lebih dari 20 detik. Jangan masukkan password di argv.
2. Pastikan `ssh -tt -p 109 AKUN@VPS_UJI`, `ssh -p 109 AKUN@VPS_UJI id`,
   `sftp -P 109 AKUN@VPS_UJI` dan `scp -O -P 109 ...` gagal mendapatkan terminal,
   mengeksekusi perintah, atau menyalin file. Cek bahwa autentikasi public-key
   pelanggan dan remote forwarding tidak berfungsi.
3. Buat tunnel dari dua akun. Lock satu akun; pastikan tunnel akun itu terputus,
   login baru ditolak, dan akun lain tetap tersambung. Unlock dan uji lagi sebelum
   kedaluwarsa. Verifikasi akun pelanggan ditolak di port admin, lalu uji login
   admin yang biasa dari koneksi kedua sebelum menutup shell admin pertama.
4. Uji Telegram gagal (chat admin uji, bukan produksi), ulangi pengiriman, dan
   instal ulang. Bandingkan fingerprint host key serta keberadaan akun dan
   password sebelum/sesudah. Uji konflik port 143 sebelum aktivasi jika dipilih.

VMESS, VLESS, TROJAN, Bot Akses VPS, dan Set Banner masih belum tersedia.

## Pengujian installer

Dari checkout Git di lingkungan yang bisa menjalankan Bash, jalankan validasi
lokal berikut tanpa menjalankan installer terhadap host:

```bash
bash -n install-dashboard.sh
bash -n deployment/tests/installer-smoke.sh
git diff --check
if command -v shellcheck >/dev/null; then
    shellcheck -x install-dashboard.sh deployment/tests/installer-smoke.sh
fi
bash deployment/tests/installer-smoke.sh
```

Smoke test memakai direktori sementara dan mock APT/systemd, bukan akses root.
Skenarionya mencakup bantuan, `--check` tanpa penulisan, benturan, lock, validasi
unit, instalasi fresh dan instal ulang, rollback fresh/upgrade, serta hook
noninteraktif tanpa output. Hasil ini tidak menggantikan uji VPS sungguhan.

Pada **VM uji yang boleh di-reset** untuk tiap distro target:

1. Uji `--check`, benturan `menu` dengan file uji, lalu hapus file uji itu dan
   uji instalasi fresh. Pastikan `menu` membuka dashboard dan timer serta kolektor
   sehat. Ulangi pada VM fresh lain dengan `--enable-login-menu`.
2. Isi konfigurasi dan `traffic-interface` dengan nilai uji yang valid. Catat
   checksum konfigurasi dan pastikan data akun serta riwayat trafik tetap ada
   setelah instal ulang. File trafik dapat berubah karena sampel baru, tetapi
   installer tidak semestinya membuat ulang atau mengosongkannya.
3. Reboot VM, lalu cek timer `enabled` dan `active` serta kolektor menerima sampel.
   Uji login SSH root interaktif dengan hook aktif dan `x`/Ctrl+C kembali ke shell.
   Dari mesin lain, `ssh root@VPS_UJI 'printf "%s\n" UJI_NONINTERAKTIF'` harus
   menampilkan hanya `UJI_NONINTERAKTIF` di stdout.
4. Untuk menguji rollback dengan systemd nyata, buat snapshot VM dan catat
   checksum aplikasi, target symlink timer, serta status unit. Jalankan installer
   sebagai root di VM dengan shim `systemctl` sementara di awal `PATH`: teruskan
   semua panggilan ke `/usr/bin/systemctl` kecuali panggilan pertama `--system
   start nathaya-traffic.timer`, yang harus keluar nonzero. Pastikan instalasi
   gagal, lalu bandingkan file, symlink, dan status unit dengan kondisi awal.
   Hapus shim setelah uji; jangan gunakan injeksi ini pada VPS produksi.
