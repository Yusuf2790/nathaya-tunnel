# Nathaya Tunnel Dashboard

Jalankan sebagai root pada VPS Ubuntu/Debian yang menggunakan systemd,
dengan `python3` dan `iproute2` terpasang.

```bash
cd nathaya-tunnel
bash install-dashboard.sh
menu
```

Installer menyalin modul ke `/opt/nathaya` dan mempertahankan konfigurasi dan
data akun yang sudah ada. Login SSH interaktif sebagai root langsung membuka
dashboard. Pilih `x` atau tekan **Ctrl+C** dari Menu Utama atau submenu untuk
keluar ke shell tanpa menutup sesi SSH. Dashboard menampilkan petunjuk untuk
mengetik `menu` agar terbuka lagi. Pilih `z` di submenu untuk kembali satu tingkat.

Tambahkan atau sesuaikan nilai berikut di `/etc/nathaya-tunnel/config.conf`.

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
