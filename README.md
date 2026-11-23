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

Footer dan Telegram opsional. Buat `/etc/nathaya-tunnel` sebagai root dan
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

## SSH, WebSocket, dan TLS

Instalasi standar memasang dan mengaktifkan `nathaya-dropbear.service`,
`nathaya-ws.service` (aiohttp), dan `nathaya-haproxy.service`. Tidak perlu flag.
`--enable-ssh` masih diterima untuk kompatibilitas dan tidak mengubah hasil.

| Jalur NetMod | Port | Pengaturan |
|---|---:|---|
| SSH langsung | 109 | Host domain VPS, SSH tanpa WS |
| WS (NoSSL) | 80 | WebSocket standar, host domain VPS, path `/ssh`, TLS mati |
| WSS | 443 | WebSocket standar, host/SNI domain VPS, path `/ssh`, TLS dan verifikasi sertifikat aktif |

Gunakan akun Nathaya yang sama di ketiga jalur. Port tambahan SSH langsung 143
tetap bisa dipilih melalui `/etc/nathaya-tunnel/ssh-ports.conf` berisi `109 143`.
HTTP biasa di port 80 untuk domain yang valid diarahkan ke HTTPS. Host lain
atau WebSocket dengan endpoint salah ditolak.

### Siapkan domain dan sertifikat sebelum instalasi

1. Atur DNS domain ke VPS dan isi `DOMAIN="tunnel.example.com"` di
   `/etc/nathaya-tunnel/config.conf`, milik root. Pertahankan pengaturan lain.
2. Sediakan fullchain PEM dan private key PEM tanpa passphrase yang sesuai di
   `/etc/nathaya-tunnel/tls/fullchain.pem` dan `/etc/nathaya-tunnel/tls/privkey.pem`.
   File harus milik root; private key harus berizin `0600` atau `0400`.
   Symlink boleh dipakai jika tujuan dan direktori aman. Klien harus mempercayai CA.
3. Jalankan `sudo bash install-dashboard.sh --check`, lalu
   `sudo bash install-dashboard.sh` jika preflight lulus. Port 80, 443, 109,
   dan listener loopback 18080/18091 tidak boleh berbenturan. Installer tidak
   mengambil alih `haproxy.service` distro yang aktif/enabled. Saat memasang
   paket HAProxy baru, unit distro dicegah berjalan otomatis.

Installer tidak membuka firewall atau mengubah SSH admin. Izinkan port publik
sesuai kebijakan VPS; **jangan** membuka 18080/18091. HAProxy mengambil IP peer
TCP dan menimpa header relay. Gateway dan supervisor memvalidasi metadata
melalui loopback dengan kunci internal; ketiga jalur memakai inventaris sama.

Setelah memperbarui sertifikat atau DOMAIN, jalankan installer lagi. ACME
otomatis belum tersedia. Instal ulang mempertahankan akun, host key, dan kunci
relay. Gateway dan HAProxy dinyalakan sebelum supervisor SSH disentuh. Jika
supervisor dan konfigurasi relainya tidak berubah, TCP 109 tidak di-restart.
Cutover supervisor yang diperlukan dapat memutus tunnel lama. Rollback
memulihkan file dan listener, bukan sesi yang terputus.
Rujukan konfigurasi: [HAProxy 2.4](https://docs.haproxy.org/2.4/configuration.html).

Menu SSH menyediakan Create, Delete, Renew, Trial, Check User Login, List
Member/detail, List User Expired, Lock, dan Unlock. Limit IP masih bertanda
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

- **Delete** mencantumkan semua akun Nathaya, termasuk Trial, locked, dan
  expired. Setelah konfirmasi, backend memeriksa identitas akun lagi sebelum
  menghapusnya. Penghapusan tidak dapat dibatalkan lewat menu. Supervisor
  mencabut akses pada pemeriksaan sesi berikutnya, tanpa menghentikan layanan
  atau memutus sesi akun lain yang sudah terautentikasi.
- **Renew** mencantumkan akun reguler dan Trial, termasuk locked. Nomor
  berlanjut dari bagian aktif ke expired. Masukkan tambahan `1–3650` hari.
  Backend menambah hari dari kedaluwarsa lama atau, untuk akun expired, dari
  waktu penyimpanan. Pratinjau akun expired bersifat perkiraan; layar hasil
  menunjukkan tanggal yang benar-benar disimpan. Jika data akun berubah
  selama konfirmasi, konfirmasi dimuat ulang atau kamu diminta memilih ulang
  bila akun telah diganti. Renew tidak mengubah password, jenis akun, limit,
  atau status lock.
- **List User Expired** mencakup akun reguler dan Trial yang sudah kedaluwarsa,
  termasuk yang terkunci. Pilih `d` untuk menghapus satu akun atau `a` untuk
  menghapus semua akun pada daftar. Untuk satu akun gunakan nomor, username,
  atau `@username`. Pilih `y` untuk menghapus, `n` untuk kembali ke daftar, atau
  Ctrl+C untuk membatalkan dan kembali ke menu SSH.
- Jika akun tunggal diperpanjang atau diganti sebelum penghapusan, atau jika
  daftar berubah sebelum penghapusan massal, aksi dibatalkan dan daftar dimuat
  ulang. Hapus massal berjalan dalam satu transaksi; kegagalan tidak menyisakan
  penghapusan sebagian. Tidak ada restart layanan Dropbear.
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

### Check User Login

Buka menu SSH → **[5] Check User Login**. Tekan `r` untuk memuat ulang,
`z` untuk kembali, atau `x` untuk keluar ke shell. Satu sesi berarti satu
koneksi SSH terautentikasi yang masih tersambung, termasuk tunnel tanpa
terminal. Beberapa channel dalam satu koneksi tetap dihitung satu. Tabel
mengelompokkan koneksi per username dan IP peer yang diamati Dropbear, bukan
per perangkat. Total user menghitung username unik; total sesi menjumlahkan
seluruh koneksi. IPv4 dan IPv6 didukung. NAT dapat membuat beberapa perangkat
terlihat berasal dari IP yang sama.

Inventaris hidup hanya di memori supervisor. Menu membacanya melalui
socket Unix khusus admin (`/run/nathaya-ssh/inventory.sock`); tidak ada
kredensial atau riwayat login yang disimpan di inventaris. Socket yang tidak
tersedia menghasilkan pesan error, bukan daftar kosong. Restart layanan
menghapus sesi lama dan memutus tunnel yang sedang berjalan; lakukan restart
pada VPS uji untuk memuat versi supervisor ini. Tidak ada penegakan Limit IP
atau batas sesi dari layar ini.

Di VPS uji, hubungkan NetMod dengan akun Nathaya lewat **109**, **WS 80**, dan
**WSS 443** sesuai tabel di atas. Bandingkan IP Wi-Fi dan data seluler:

1. Coba sebelum autentikasi dan dengan password salah. Muat ulang daftar:
   kedua percobaan itu tidak boleh terlihat. Setelah autentikasi berhasil,
   satu sesi harus muncul, termasuk saat NetMod hanya menjalankan tunnel.
2. Buka dua koneksi dari IP yang sama: satu baris harus berjumlah dua sesi.
   Sambungkan akun yang sama dari IP berbeda (uji juga IPv6): harus muncul
   baris kedua tetapi total user tidak bertambah. Putus koneksi dan tekan
   `r`; jumlah sesi harus berkurang.
3. Dengan dua akun tersambung, Lock atau Delete satu akun. Muat ulang: hanya
   sesi akun sasaran yang hilang. Restart layanan: sesi lama tidak tampil.
   Hentikan layanan di VPS uji dan pastikan menu menampilkan error, bukan
   “Tidak ada user SSH yang online”.

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
bash -n deployment/ws-installer.sh && bash -n deployment/tests/installer-smoke.sh
bash -n modules/menu/ssh.sh && bash -n modules/common/telegram.sh
bash -n deployment/tests/ssh-menu-smoke.sh
git diff --check
bash deployment/tests/installer-smoke.sh
bash deployment/tests/ssh-menu-smoke.sh
python3 -B deployment/tests/ws-proxy-test.py  # haproxy, openssl, aiohttp; port lokal sementara
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
5. Dengan minimal dua tunnel aktif, Delete satu akun. Pastikan hanya tunnel
   akun sasaran putus, kredensialnya tidak bisa login kembali, dan akun sasaran
   hilang dari daftar. Uji juga pembuatan ulang username yang sama saat layanan
   berjalan. Verifikasi Renew pada akun reguler dan Trial, termasuk expired dan
   locked: tanggal tersimpan sesuai hasil, password tetap, dan akun locked
   tetap ditolak. Uji `n` dan Ctrl+C tanpa perubahan data.

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
