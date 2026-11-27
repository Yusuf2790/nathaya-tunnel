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

| Mode klien | Port | Pengaturan |
|---|---:|---|
| SSH langsung (NetMod) | 109 dan 143 | Host domain VPS, SSH tanpa WebSocket. |
| WS (NoSSL) | 80 | Klien SSH-over-WebSocket standar, host domain VPS, path `/`, TLS mati. |
| WSS | 443 | Klien SSH-over-WebSocket standar, host dan SNI domain VPS, path `/`, verifikasi TLS aktif. |
| HTTPS CONNECT (opsional) | 8443 | Proksi TLS domain VPS, autentikasi Basic, tujuan tetap `DOMAIN:109`. Dukungan NetMod belum diuji. |

Instalasi baru tanpa konfigurasi port menyimpan `109 143` di
`/etc/nathaya-tunnel/ssh-ports.conf`. Instal ulang mempertahankan pilihan admin;
instalasi lama tanpa file itu tetap memakai 109. HTTP biasa di port 80 untuk
host yang valid diarahkan ke HTTPS; host asing dan endpoint WS yang salah ditolak.

### NetMod tanpa proksi atau payload

| Profil | Host dan port | Proksi | Payload | Keamanan |
|---|---|---|---|---|
| SSH TCP | Domain VPS, TCP 80 | `none` | kosong | `none` |
| SSH melalui TLS | SNI SSH khusus, TCP 443 | `none` | kosong | SSL/TLS; verifikasi sertifikat aktif |

Kedua profil memakai username/password akun Dropbear Nathaya. Tidak perlu
WebSocket, header HTTP, atau HTTPS CONNECT untuk profil ini. Di TCP 80, HAProxy
mengenali awalan SSH maupun HTTP. Klien SSH yang menunggu banner dilayani
setelah paling lama jendela inspeksi **5 detik**. HTTP yang sudah mengirim
metode dalam jendela itu tetap dirutekan sebagai HTTP, meski header menyusul
lebih lambat. HTTP yang diam selama seluruh jendela tidak bisa dibedakan dari
SSH server-first dan dapat menerima banner SSH. Gunakan 109/143 jika klien
SSH tidak bisa menunggu; gunakan HTTPS untuk klien web yang lambat memulai.

**TCP 443 memerlukan SNI khusus** agar SSH server-first tidak berbenturan dengan
HTTPS/WSS/gRPC. Buat satu nama DNS berbeda, misalnya `ssh.tunnel.example.com`,
yang mengarah ke VPS yang sama. Simpan nama itu (satu baris, milik root) di
`/etc/nathaya-tunnel/ssh-tls-sni.conf`. Sediakan satu sertifikat TLS yang valid
untuk **domain web dan nama SSH** (SAN), jalankan `sudo bash install-dashboard.sh --check`,
lalu installer. Saat menerbitkan sertifikat baru, installer meminta kedua nama
ke Certbot bila SNI SSH dikonfigurasi. Pada NetMod gunakan nama khusus sebagai
Host dan SNI bila ada kolom SNI. Tanpa file SNI atau jika NetMod tidak mengirim
SNI itu, jalur 443 tetap HTTPS biasa; jangan menonaktifkan validasi TLS untuk
memaksa koneksi. Input SSH biasa tanpa TLS juga bukan profil 443 ini.

HAProxy hanya meneruskan raw SSH dari port 80 atau TLS dengan SNI khusus ke
socket Unix internal. Alamat peer diteruskan melalui PROXY v2 dari proses
HAProxy yang terverifikasi, lalu melalui relay Nathaya. Check User Login tetap
mencatat IP asal setelah autentikasi SSH, bukan header pilihan klien.
Rujukan multiplex: [manual HAProxy](https://docs.haproxy.org/2.4/configuration.html).

Untuk verifikasi di VPS uji, pisahkan **banner/handshake**, **login**, dan
**trafik yang diteruskan**. Uji kedua profil NetMod sampai autentikasi dan
trafik, muat ulang Check User Login sebelum dan sesudah disconnect, lalu
regresikan SSH 109/143, WS/WSS di `/`, HTTP biasa dan Xray. Tes lokal memakai
backend SSH tiruan untuk banner dan byte, bukan autentikasi Dropbear/NetMod.

### Stack tambahan: Nginx, Xray, OpenVPN, BadVPN

Sebelum preflight, sediakan **Xray-core Linux amd64 dari rilis resmi** di
`/etc/nathaya-tunnel/bin/xray` dan digest SHA-256 terverifikasi pada
`/etc/nathaya-tunnel/bin/xray.sha256` (64 digit heksadesimal saja). Cocokkan
rilis dengan kanal resmi XTLS; checksum yang dibuat dari unduhan tidak
tepercaya bukan bukti asal. File dan direktori harus milik root. Installer
tidak mengunduh atau menjalankan skrip pemasangan pihak ketiga. Nginx dan
OpenVPN memakai paket distro melalui APT. OpenVPN memerlukan `/dev/net/tun`.

| Listener | Cakupan | Fungsi |
|---|---|---|
| TCP 80 | Publik / HAProxy | SSH TCP, SSH WS path `/`; HTTP biasa diarahkan ke HTTPS |
| TCP 443 | Publik / HAProxy | SSH TLS (SNI khusus), SSH WSS path `/`, Xray WSS dan gRPC; tidak ada rute OpenVPN |
| TCP 8080 | Publik / HAProxy | HTTP redirect; tidak menerima upgrade WebSocket |
| TCP 109/143 | Publik / Dropbear | SSH langsung; instal ulang mempertahankan port admin Nathaya |
| TCP 1194, UDP 2200 | Publik / OpenVPN | Listener terpisah dengan autentikasi sertifikat |
| TCP 8443 | Publik bila diaktifkan | HTTPS CONNECT terautentikasi dengan tujuan tetap |
| TCP 1010/1013 | Loopback / Nginx | Backend Xray WS / gRPC h2c |
| TCP 10001–10008 | Loopback / Xray | Inbound sesuai tabel rute di bawah |
| TCP 18080/18091 | Loopback | Gateway dan relay SSH |
| TCP 7100/7200/7300 | Loopback bila dipasang | BadVPN `udpgw` |
| HTTPS 81, UDP Custom | Belum aktif | Tidak ada listener atau profil klien |

**Features → Informasi Port** memeriksa unit dan socket, bukan sekadar daftar
port. Status ON bukan bukti autentikasi atau trafik berhasil. SSH admin tetap
menggunakan konfigurasi VPS yang sudah ada. Rute dipetakan dari spesifikasi
port; tidak ada file konfigurasi Alrescha79 yang ditemukan di repo ini.

| Protokol | Path WSS (443) | Backend WS | serviceName gRPC (443) | Backend gRPC |
|---|---|---:|---|---:|
| VLESS | `/vless` | 10001 | `vless-grpc` | 10005 |
| VMess | `/vmess` | 10002 | `vmess-grpc` | 10006 |
| Trojan | `/trojan-ws` | 10003 | `trojan-grpc` | 10007 |
| Shadowsocks | `/ss-ws` | 10004 | `ss-grpc` | 10008 |

Aktifkan TLS, verifikasi sertifikat, dan gunakan domain Nathaya sebagai
host/SNI pada klien Xray. Upgrade WS Xray melalui HTTP tanpa TLS ditolak.
VLESS memakai enkripsi transport TLS; Shadowsocks memakai `aes-256-gcm`.
Kredensial awal ada di `/etc/nathaya-tunnel/managed-stack/xray-credentials.json`
(akses root). Simpan dan distribusikan secara aman; installer tidak merotasi
kredensial tersebut saat upgrade atau membuat akun SSH baru untuknya.

Profil OpenVPN `client-tcp.ovpn` dan `client-udp.ovpn` tersedia di direktori
`managed-stack` yang sama. Profil memeriksa CA serta nama sertifikat server.
Profil awal mengandung private key klien; jangan distribusikan sebagai profil
umum. Installer tidak mengubah firewall, IP forwarding, atau NAT; untuk akses
keluar VPS admin perlu menyiapkan routing dan kebijakan jaringan. Tidak ada
sambungan OpenVPN melalui port 443.

BadVPN bersifat opsional. Sediakan binari `badvpn-udpgw` amd64 dari sumber
terverifikasi dan `badvpn-udpgw.sha256` di direktori binari yang sama. Gunakan
klien yang mendukung protokol BadVPN udpgw melalui SSH port-forward yang
sudah terautentikasi; tidak ada autentikasi BadVPN terpisah atau port UDP
publik BadVPN. UDP yang tersedia untuk koneksi VPN adalah OpenVPN UDP 2200
(paket distro, autentikasi sertifikat, klien OpenVPN). UDP Custom belum
tersedia; jangan menyamakan dengan OpenVPN atau BadVPN.

Rujukan: [Xray-core](https://github.com/XTLS/Xray-core/releases),
[Nginx gRPC](https://nginx.org/en/docs/http/ngx_http_grpc_module.html), dan
[manual OpenVPN](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/).

### Setup domain dan sertifikat

1. Arahkan DNS domain ke VPS. Pada instalasi interaktif tanpa DOMAIN, isi
   formulir **SETUP DOMAIN**, lihat hasil resolusi dan ringkasan port, lalu
   konfirmasi. Untuk mengganti domain pada instalasi lama gunakan
   `sudo bash install-dashboard.sh --set-domain`. `n` atau Ctrl+C sebelum
   deployment membatalkan setup tanpa menulis konfigurasi. Mode noninteraktif
   membaca `DOMAIN="tunnel.example.com"` dari `/etc/nathaya-tunnel/config.conf`;
   pengaturan lain di file itu tetap dipertahankan.
2. Installer memprioritaskan pasangan PEM admin di
   `/etc/nathaya-tunnel/tls/{fullchain,privkey}.pem`, lalu mencari lineage Certbot
   yang cocok. Sertifikat harus berlaku untuk domain dan cocok dengan private
   key PEM tanpa passphrase. File yang dipasang milik root; private key `0600`.
3. Jika belum ada sertifikat valid, installer interaktif pada pemasangan baru
   dapat meminta izin untuk Certbot standalone dan email ACME. TCP 80 harus
   bebas dan dapat dijangkau publik; DNS yang berhasil di VPS saja tidak
   membuktikan akses publik. Jika port sudah dipakai, sediakan PEM admin atau
   terbitkan sertifikat dengan DNS-01 lewat plugin/kredensial yang dikelola
   admin. Installer tidak menghentikan layanan asing; bebaskan port 80/443
   secara terencana sebelum deployment.
4. `sudo bash install-dashboard.sh --check` hanya memeriksa, tidak meminta input,
   menerbitkan sertifikat, atau mengubah layanan. Jalankan
   `sudo bash install-dashboard.sh` untuk pemasangan setelah persiapan. Installer
   memvalidasi HAProxy sebelum aktivasi dan tidak membuka firewall atau mengubah
   akses SSH admin. Jangan membuka listener internal 18080/18091 ke publik.

**Pembaruan TLS.** Untuk PEM admin, sediakan pasangan baru dan jalankan ulang
installer. Untuk Certbot, perbarui lineage dengan metode yang sesuai, lalu
jalankan `sudo bash install-dashboard.sh --use-certbot` agar sertifikat lineage
baru dipilih meski salinan lokal belum expired. Standalone memerlukan port 80
bebas; untuk pembaruan tanpa menghentikan HAProxy, siapkan DNS-01 melalui plugin
admin atau gunakan sertifikat eksternal. Installer memuat PEM baru dengan
mengaktifkan ulang frontend setelah validasi; lakukan pada jendela pemeliharaan.
Rollback memulihkan konfigurasi/PEM dan listener sebelumnya, bukan sesi yang
sudah putus atau state eksternal Certbot. Lihat [panduan Certbot](https://eff-certbot.readthedocs.io/en/stable/using.html).

### HTTPS CONNECT terbatas

Tidak aktif secara default. Untuk mengaktifkan, buat
`/etc/nathaya-tunnel/connect.key` (milik root, `0600`) berisi satu baris acak,
misalnya dibuat dengan `openssl rand -hex 32` dan disimpan langsung ke file
berizin ketat. Jalankan preflight dan installer. Untuk menonaktifkan, hapus
file kunci dan jalankan installer lagi. Jangan membagikan kunci lewat log.

Gunakan proksi HTTPS domain VPS port 8443, username proksi `nathaya`, dan
password dari file tadi. Target CONNECT harus `DOMAIN:109`. Target ini hanya
allowlist; gateway selalu meneruskan ke relay Nathaya, bukan ke alamat dari
klien. Setelah CONNECT, login memakai akun SSH Nathaya biasa. Untuk uji NetMod,
coba profil proksi **TLS ke proksi**, aktifkan autentikasi proksi, dan kosongkan
Payload. Jika versi NetMod tidak mendukungnya, jangan kirim Basic auth melalui
HTTP tanpa TLS. Lihat [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

Supervisor mencatat IP peer listener, bukan header IP dari klien. Semua jalur
memakai akun, host key, aturan akses, dan inventaris Check User Login yang sama.

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
bash -n deployment/ws-installer.sh && bash -n deployment/domain-installer.sh
bash -n deployment/stack-installer.sh && bash -n modules/dashboard/ports.sh
bash -n deployment/tests/installer-smoke.sh
bash -n modules/menu/ssh.sh && bash -n modules/common/telegram.sh
bash -n deployment/tests/ssh-menu-smoke.sh
git diff --check
bash deployment/tests/installer-smoke.sh
bash deployment/tests/ssh-menu-smoke.sh
bash deployment/tests/domain-tls-test.sh  # fixture OpenSSL, tanpa systemd
python3 -B deployment/tests/stack-render-test.py
python3 -B deployment/tests/connect-gateway-test.py
python3 -B deployment/tests/ws-proxy-test.py  # haproxy, openssl, aiohttp, h2; port lokal sementara
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

Menu manajemen akun VMESS/VLESS/TROJAN, Bot Akses VPS, dan Set Banner masih belum tersedia.

## Pengujian installer

Dari checkout Git di lingkungan yang bisa menjalankan Bash, jalankan validasi
lokal berikut tanpa menjalankan installer terhadap host:

```bash
bash -n install-dashboard.sh
bash -n deployment/tests/installer-smoke.sh && bash -n deployment/tests/domain-tls-test.sh
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
