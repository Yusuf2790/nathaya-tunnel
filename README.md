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

Bot Notifikasi menampilkan status konfigurasi pengiriman Telegram yang
sudah dipakai modul SSH. Menu SSH, VMESS, VLESS, TROJAN, Bot Akses VPS, dan
Set Banner menampilkan “Modul belum tersedia”. File modul SSH dan data akun
yang sudah ada tetap disimpan.

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
