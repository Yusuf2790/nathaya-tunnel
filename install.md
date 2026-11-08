# Instalasi NATHAYA TUNNEL

## Target dan sumber

Ubuntu24.04 amd64 baru, root, systemd dan terminal interaktif. `setup.sh` memakai alur provisioning Alrescha dengan aset lokal, command backend/database Alrescha dan UI/Telegram Nathaya. Script belum dijalankan atau dipasang oleh sesi ini; tidak ada hasil instalasi nyata yang diklaim. Jangan jalankan dari Android.

Source lengkap wajib: `setup.sh`, `lib/`, `project/`, `modules/`, `fodder/`, `BadVPN-UDPWG/`, konfigurasi empat protokol, manifest dan LICENSE. Menyalin setup.sh saja bukan instalasi lengkap; tidak ada fallback yang mengunduh menu Alrescha.

## Sebelum menjalankan nanti

- Gunakan VPS baru, bukan server yang menyimpan akun/config/CA instalasi lain. File yang sudah ada tidak dihapus untuk memaksa pemasangan.
- Pertahankan terminal SSH kedua/console provider. Tidak boleh ada installer/updater/account writer lain yang berjalan bersamaan.
- Siapkan FQDN dan email ACME. DNS A/AAAA harus benar; port80 publik wajib tersedia saat HTTP-01. Jangan menaruh password/token dalam URL atau command-line.
- Pastikan port pada tabel README tidak dipakai daemon lain. Installer berhenti pada konflik, tidak menghentikan service administrator untuk mengambil port.
- UFW/security group tidak dihapus/direset. Administrator harus mengizinkan ingress yang diperlukan. NAT VPN hanya menambah rule berlabel; host IP/uplink/default route/DNS/IPv6 tidak diubah.
- Paket Ubuntu diambil lewat APT native tanpa dist-upgrade, purge firewall, NodeSource atau PPA. Existing policy-rc.d memerlukan review operator; tidak ditimpa. Paket autostart ditahan sementara saat provisioning.

## Perintah setelah publish

Sebagai root, gunakan source Nathaya yang sudah diunggah dan direview:

```sh
apt-get update
apt-get install -y git ca-certificates
git clone https://github.com/Yusuf2790/nathaya-tunnel.git
cd nathaya-tunnel
bash setup.sh
```

`bash setup.sh --install` adalah alias pemasangan yang sama. Domain/email dapat diberikan dengan `--domain` dan `--email`; `--help` hanya menampilkan bantuan. Tidak ada instalasi unattended atau force-overwrite.

Ketik `INSTALL NATHAYA` hanya setelah membaca dampak yang ditampilkan. EasyRSA meminta passphrase CA langsung di controlling terminal. Buat passphrase kuat dan simpan offline; jangan kirim ke chat/Telegram atau merekam terminal. Nama CA unik ditampilkan; ikuti instruksi Common Name yang diberikan helper. Server key unattended disimpan root-private.

## Yang dikerjakan installer

1. Memastikan platform, sumber lengkap, fresh host, port dan pool VPN tidak konflik.
2. Memasang dependency distro dan Xray resmi yang dipin, dengan checksum rilis.
3. Memasang seluruh backend command, alias API/CLI, UI dashboard/menu dan satu Telegram adapter dari manifest Nathaya.
4. Membuat credential awal unik untuk empat template Xray tanpa menghilangkan marker account writer. Menggunakan `/etc/ssh/.ssh.db`, `/etc/xray/<protocol>/.<protocol>.db` dan sidecar limit/quota Alrescha; bukan database UI kedua.
5. Menyediakan SSH tambahan2222/2223 dan Dropbear109/143 dengan host key lokal unik; daemon/config SSH administrator tidak diubah.
6. Memasang ws.py, tiga instance BadVPN, UDP Custom serta limiter/quota dan cron expiry/warning/logclear Alrescha.
7. Membuat CA/server OpenVPN lokal dan dua instance native TCP1194/UDP2200. Auth menggunakan packaged PAM `login`, `verify-client-cert none` dan `username-as-common-name` sesuai konfigurasi Alrescha. Tidak menyalin ZIP/private key contoh, tidak membuat registry akun/certificate authority aplikasi baru.
8. Memasang konfigurasi nginx/HAProxy lokal dan memperoleh sertifikat Let’s Encrypt via Certbot distro. Hook renewal menyalin cert/key privat, membangun PEM HAProxy dan memulihkan proxy yang dihentikan.
9. Menambahkan rule NAT/FORWARD khusus dua pool dan setting IPv4 forwarding yang dinyatakan saat konfirmasi; bukan network-manager atau global firewall replacement.
10. Menjalankan validasi konfigurasi native saat pemasangan dan baru mengaktifkan unit setelah seluruh file tersedia. Tidak ada reboot otomatis.

Validasi konfigurasi bawaan nginx/HAProxy/sshd/Xray bukan hasil yang sudah dijalankan sesi ini. Kegagalan native menghentikan instalasi; status/data/key dipertahankan untuk penanganan manual, bukan dibersihkan/diulang otomatis.

## Setelah pemasangan

```sh
menu
```

Menu interaktif memuat `/opt/nathaya/modules` dan memanggil backend `/usr/bin`. Root `menu.sh` hanya launcher; setup memanggil installer runtime langsung agar menu tidak tertimpa.

Notifikasi opsional menggunakan konfigurasi operator root-private `/root/.vars` atau `/etc/nathaya-tunnel/config.conf`. Pengaturan dilakukan lewat menu Telegram. Tidak ada bot token/chat ID bawaan atau pengirim kedua. Jangan menambah kredensial pada repository.

Profil CA-only: `/root/nathaya-clients/client-{tcp,udp,ssl}.ovpn`, juga `/etc/openvpn/client/`. Profil tidak mengandung password/client private key dan meminta username/password Unix. Distribusikan secara privat. Port443 memakai pengenal OpenVPN TCP pada HAProxy; interoperabilitas client/multiplexer belum dijalankan dalam sesi ini. Tidak ada DNS/IPv6 host yang dinonaktifkan; profil IPv4 bukan jaminan tunneling IPv6.

CA terenkripsi di `/etc/openvpn/easy-rsa/pki`; simpan CA/key/database dan passphrase. CRL berumur terbatas. Operator harus memperbaruinya memakai EasyRSA lokal ketika diperlukan, lalu merestart dua service OpenVPN pada maintenance window; tidak ada passphrase CA tersimpan untuk cron.

## Pemeliharaan

```sh
nathaya-update
# Sumber lokal lengkap tanpa unduhan:
bash update.sh --source /root/nathaya-tunnel
# Unduhan snapshot secara eksplisit:
bash update.sh --yes
```

Updater mengambil satu snapshot Nathaya, hanya mengganti allowlisted code/UI, membuat backup kode privat dan mempertahankan akun/config/CA/SSL/service state. Tidak menjalankan setup. Backups account/server tetap privat melalui `backuprestore`; layanan web backup hanya loopback dengan autentikasi operator. Restore tidak mengaktifkan service otomatis.

`features`/menu domain menggunakan `/usr/local/sbin/nathaya-domain` dan Certbot. Pergantian domain/renewal dapat memutus koneksi proxy singkat; tidak memerlukan reboot dan tidak menghentikan SSH utama. Aksi restart menu menargetkan `nathaya-ssh`, `nathaya-dropbear`, dua `nathaya-openvpn-*`, ws/proxy dan empat protocol instance; bukan daemon SSH administrator.

Cron opsional backup, autokill dan reboot harian dibuat hanya setelah pilihan operator. Path `/etc/cron.d/{backup,autokill,daily_reboot}` dicatat ke ownership installer; file administrator yang tidak dimiliki/telah berubah tidak ditimpa atau dihapus. Tidak ada reboot terjadwal bawaan. Menu perawatan Dropbear hanya memberi panduan APT manual; tidak mengunduh/kompilasi binary versi lama.

State pemasangan/ownership berada di `/var/lib/nathaya-tunnel`, originals di subdirectory `originals`; runtime-code backups di `/opt/nathaya/runtime-backup.*`. Perubahan per file bersifat atomic, bukan transaksi seluruh VPS. Jangan hapus state/key atau mengulang setup di atas kegagalan parsial; gunakan console/backup dan review manual. Uninstaller mempertahankan data: lihat uninstall.md.

## Kompatibilitas yang masih perlu pemasangan nyata

- SlowDNS hanya dirujuk upstream, tanpa source receiver/unit lengkap; sengaja tidak dipasang dan tidak ada UDP53 redirect ke receiver fiktif. Tampilan SSH/trial menunjukkan status ini, port aktual dan pengiriman profil privat, bukan URL HTTP/ZIP yang tidak disediakan.
- Pool UDP20.8.0.0/24 berasal dari Alrescha tetapi public address space. Konflik lokal ditolak; client tidak dapat mengakses subnet publik itu melalui rute biasa selama VPN aktif.
- Xray v25.3.6 dipilih agar template WS/gRPC tetap cocok, bukan versi terbaru. Pembaruan versi harus mempertimbangkan schema/protokol template; `XRAY_VERSION` hanya menerima tag numerik vN.N.N resmi.
- Binary BadVPN/UDP Custom dan helper limit/trial upstream belum dijalankan di sini. Format/arsitektur diperiksa saat pemasangan, bukan bukti perilaku native. Satu NUL akhir pada enam Bash helpers upstream dinormalisasi hanya di staging runtime.
- Root daemon OpenVPN digunakan agar plugin PAM dan key/CRL privat tetap dapat dibaca; backend autentikasi Unix tetap sama. TLS1.2+/AES-GCM mengganti cipher/auth none dan kompresi lawas yang tidak aman/tidak cocok OpenVPN2.6.
- Jalur download/account export HTTP lama tidak dibuka. `gotop` tidak meng-upgrade OS; memakai binary gotop lokal bila ada, atau htop/top.

Atribusi MIT upstream tetap di LICENSE. Referensi implementasi: https://github.com/alrescha79-cmd/sc-vpn ; https://github.com/XTLS/Xray-core/releases/tag/v25.3.6 ; https://eff-certbot.readthedocs.io/en/stable/using.html ; https://build.openvpn.net/man/openvpn-2.6/openvpn.8.html .
