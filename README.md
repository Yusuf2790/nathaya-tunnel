# NATHAYA TUNNEL

Installer VPS **Ubuntu 24.04 amd64** dengan backend [Alrescha79/sc-vpn](https://github.com/alrescha79-cmd/sc-vpn), UI terminal dan format notifikasi Telegram Nathaya.

**Source installer telah ditulis, tetapi belum dipasang/dijalankan pada VPS oleh sesi ini.** Tidak ada klaim koneksi atau kompatibilitas native yang sudah berhasil. Gunakan VPS baru; bukan migrasi otomatis server yang sudah berisi akun/VPN.

## Instalasi setelah source ini diunggah

Jalankan sebagai root melalui terminal SSH interaktif pada VPS baru, bukan Android:

```sh
apt-get update
apt-get install -y git ca-certificates
git clone https://github.com/Yusuf2790/nathaya-tunnel.git
cd nathaya-tunnel
bash setup.sh
```

Atau berikan domain/email secara eksplisit:

```sh
bash setup.sh --domain vpn.example.com --email admin@example.com
```

Ganti contoh domain/email. DNS A harus menuju VPS; AAAA, bila dipublikasikan, juga harus benar. Buka HTTP80 untuk ACME dan port layanan melalui firewall/provider sesuai kebijakan administrator. Installer meminta konfirmasi `INSTALL NATHAYA` dan passphrase CA langsung di terminal; tidak ada password atau token bawaan. Jangan merekam terminal berisi rahasia.

Sesudah instalasi berhasil, buka **`menu`**. Tidak ada reboot otomatis. Panduan lengkap: [install.md](install.md).

## Pembagian komponen

- **Alrescha:** konfigurasi WS/gRPC Xray, VMess/VLESS/Trojan/Shadowsocks, Unix SSH/Dropbear, OpenVPN PAM, UDP Custom/BadVPN, database/limit/quota/trial/expiry, backend fitur dan scheduler. Marker konfigurasi dan path akun dipertahankan.
- **Nathaya:** branding/menu/dashboard terminal, presentasi akun dan format/transport Telegram tunggal. UI memanggil perintah backend, bukan database akun lain.
- Sumber lokal di `project/`, `fodder/`, `BadVPN-UDPWG/` dan `VMess-VLESS-Trojan+Websocket+gRPC/` digunakan installer. Runtime menu tidak diambil dari repository Alrescha.
- `menu.sh` adalah launcher UI. `package-gohide.sh` memasang runtime kode; `update.sh` memperbarui snapshot Nathaya tanpa provisioning ulang.

## Layanan dan port

| Komponen | Port |
|---|---|
| SSH administrator | Konfigurasi lama tetap |
| SSH tambahan Nathaya | TCP2222,2223 |
| Dropbear | TCP109,143 |
| HAProxy | TCP80,443,8080 |
| nginx | TLS81; backend loopback1010,1013 |
| OpenVPN | TCP1194, UDP2200; TCP443 melalui demux HAProxy |
| UDP Custom | UDP2100, kemampuan port lain mengikuti binary upstream |
| BadVPN UDPGW | Loopback7100,7200,7300 |
| Xray WS / gRPC / Stats API | Loopback10001–10008 /20001–20004 |
| SSH WebSocket | Loopback10015 |

## Update dan penghapusan

```sh
nathaya-update
# Dari source lokal lengkap:
bash update.sh --source /root/nathaya-tunnel

# Penghapusan kode/layanan milik installer, data tetap disimpan:
nathaya-uninstall
```

Update tidak mengganti konfigurasi, akun, SSL atau CA. Cron opsional backup/autokill/reboot menggunakan ownership yang sama sehingga dapat dibersihkan uninstaller; semua nonaktif sampai dipilih operator. Aksi restart menu hanya mengelola service Nathaya, bukan SSH administrator. Uninstaller hanya menghapus output yang tercatat dan hash-nya masih cocok; database, key, backup dan konfigurasi privat dipertahankan. Lihat [uninstall.md](uninstall.md).

## Batas yang diketahui

- **SlowDNS:** tidak ada implementasi receiver di source Alrescha lokal. Installer tidak mengarang daemon/key atau menambahkan redirect DNS53.
- Pool UDP OpenVPN `20.8.0.0/24` dipertahankan dari Alrescha, tetapi merupakan ruang alamat publik; perhatikan konflik/rute dan akses klien ke subnet publik tersebut.
- Untuk kompatibilitas template WS/gRPC, Xray dipin pada **v25.3.6**, bukan klaim versi terbaru. Binary BadVPN/UDP Custom berasal dari source lokal; perilaku/kompatibilitasnya belum dijalankan di sesi ini.
- OpenVPN mempertahankan autentikasi PAM `login`/akun Unix, bukan sertifikat per akun. CA/server key dibuat unik saat pemasangan; profil hanya berisi CA publik dan meminta kredensial Unix. Cipher none/auth none/compression lama diganti TLS1.2+ dan AES-GCM.
- Profil OpenVPN disimpan privat di `/root/nathaya-clients`. Tampilan SSH/trial mengarahkan pengiriman profil/account melalui kanal privat; nginx81 menolak distribusi file. Tidak ada ZIP atau URL unduh publik.
- Pembaruan Dropbear menggunakan maintenance APT manual. Menu tidak mengompilasi versi lama atau mengganti executable paket Ubuntu.
- NAT/forwarding IPv4 ditambahkan dengan label khusus; tidak ada flush/policy rewrite. Firewall ingress tetap tanggung jawab operator. Tidak mengubah IP utama, Netplan, DNS, IPv6, default route atau daemon SSH administrator.
- Pengubahan domain/renewal ACME dapat menghentikan proxy Nathaya sebentar; primary SSH tetap berjalan. CA/CRL OpenVPN memerlukan pemeliharaan operator, tidak diperbarui dengan passphrase tersimpan.

## Lisensi

Backend upstream **MIT**, Copyright (c) 2025 **Anggun Caksono (Alrescha79)**. Pemberitahuan dipertahankan pada [LICENSE](LICENSE). Repository distribusi: [Yusuf2790/nathaya-tunnel](https://github.com/Yusuf2790/nathaya-tunnel).
