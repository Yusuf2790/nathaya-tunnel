# Audit parity Alrescha → Nathaya

## Status dan batas bukti

**Bukan installer full yang sudah selesai, bukan klaim lolos VPS.** Target baru ialah root VPS Ubuntu 24.04 amd64/x86_64 dengan systemd PID 1, bukan Android/Termux/proot. `setup.sh` default `full` berhenti pada gate artefak di `nt_preflight`, **sebelum lock, staging, apt, firewall, deployment atau mutasi layanan**. `installer/artifacts.py` selalu mengembalikan blocker OpenVPN, UDP Custom dan BadVPN; mengubah status JSON saja tidak membuka full.

`--profile core` adalah opt-in **subset parsial**: source untuk SSH/Dropbear/WS/TLS/Nginx/HAProxy/Xray dan expiry SSH tersedia. Ini bukan OpenVPN/UDP/IP-limiter/panel akun Xray. **Core tidak pernah reboot**, termasuk ketika hasilnya `CORE_SUCCESS`. Reboot hanya dirancang setelah `FULL_SUCCESS` dan semua gate wajib; full saat ini tidak dapat mencapai hasil tersebut. Failure/help/plan/test/update tidak boleh reboot. Tidak ada reboot harian.

Peta audit yang dipertahankan berasal dari pembacaan sebelumnya atas aturan `AGENTS.md` Nathaya/Alrescha, referensi lokal `setup.sh:1–1306`, `update.sh:1–258`, `menu.sh:1–115`, `package-gohide.sh:1–58`, serta konfigurasi aktual yang disebut di bawah. Penyelarasan dokumentasi ini membaca aturan/current code dan memeriksa ulang blok template client `setup.sh:817–946`; tidak mengklaim mengaudit ulang seluruh snapshot referensi. Referensi upstream berubah-ubah; nomor baris adalah snapshot lokal `../alrescha-source`, bukan janji semua revisi GitHub identik. Pembacaan melengkapi audit parent/agen terdahulu; **tidak mengubah referensi**.

Pengguna pernah melaporkan installer **dasar** exit 0, dashboard, serta status service/socket SSH. Itu laporan pengguna atas tahap sebelumnya, bukan eksekusi agen atau bukti full/core baru lolos. Tool sesi ini hanya storage/content dan web: tidak dapat menjalankan Bash/Python/Git, installer, test, parser binary atau VPS. Semua tes baru **BELUM DIJALANKAN**. Tidak ada `git status`/diff yang dieksekusi; tree tidak diasumsikan bersih. Kelima dokumen publik diselaraskan dengan source saat ini; matriks ini tetap membedakan implementasi source baru dari hasil tahap dasar lama.

## Peta lengkap blok setup referensi

Path kolom Nathaya relatif terhadap root proyek. “Source” berarti implementasi tertulis, bukan sudah terpasang/teruji. Pengamanan yang sengaja berbeda tidak disebut parity identik.

| `alrescha-source/setup.sh` | Perilaku referensi | Nathaya / status aktual |
|---|---|---|
| 1–129 | Warna/UI, Telegram HTML, kredensial bawaan encoded, informasi sistem | `installer/ui.sh`; `modules/common/{ui,telegram,functions,bootstrap}.sh`. UI Nathaya/payload akun dipertahankan; tidak membawa identitas/token bawaan. Telegram baru OFF, konfigurasi sebagai data. Notifikasi sukses instalasi full tidak boleh disamakan dengan sender akun. |
| 130–260 | mkdir/chmod 777, domain, nohup/log, DNS hanya peringatan, seed DB/log, URL remote | `installer/{lib,domain,preflight,runtime}.sh`, `setup.sh:nt_setup_main/nt_worker`. DNS mismatch ditolak; worker mengabaikan HUP, viewer terpisah, log permanen privat. Manifest lokal, staging/hash/backup/lock; hanya public/drop boleh 777. URL binary dibatasi `external-lock.json`/`artifacts.py`. |
| 261–384 | Root/OS, apt update/upgrade/dist-upgrade, purge exim/UFW/firewalld, paket/debconf | `installer/{dependencies,policy,firewall,preflight}.sh`. Upgrade OS diizinkan dengan simulasi/removal-critical guard dan preservasi admin SSH. UFW/firewalld diinventarisasi/backup sebelum removal; tidak mewarisi purge exim atau keyboard global. |
| 385–531 | City/ISP, Node 22 + npm latest, build vnstat 2.13, timezone, repo Nginx, repo/PPA HAProxy | `modules/common/functions.sh` untuk informasi/cache; `installer/dependencies.sh` memakai paket Ubuntu Noble. Tidak memasang Node/npm, build vnstat, repo nginx.org/PPA HAProxy atau mengganti timezone untuk menyatakan parity. Source core tidak membutuhkan komponen tersebut. |
| 532–650 | Dropbear init/default + private DSS host key remote, port SSH, banner/PAM, ws.py, gotop, haproxy/apache removal | `installer/{dropbear,openssh,websocket}.sh`, `services/ws_proxy.py`, `installer/render.py`. Host key unik lokal; admin SSH tidak diganti. Listener SSH tambahan loopback harus lolos pemeriksaan efektif. Tidak mengunduh private key, gotop, mengganti PAM/banner admin, menghapus unit Dropbear paket atau purge Apache secara diam-diam. Konflik ditolak. |
| 651–748 | HAProxy/Nginx/Xray configs, UDP/badvpn binary, BBR remote, sysctl | `installer/{render.py,proxies.sh,xray.sh,artifacts.py}`, `config/ports.json`. Routing deterministik, binary Xray terkunci; UDP/BadVPN BLOCKED. Tidak menjalankan bbr.sh remote atau menerapkan seluruh sysctl referensi sebagai efek samping. |
| 749–787 | UDP 53→5300, MASQUERADE 10.8.0.0/24 dan 20.8.0.0/24, ip_forward, iptables persistence | `installer/firewall.sh`. Core tidak perlu NAT. **Redirect 53 dikecualikan**: tidak ada listener 5300 yang terbukti. Tidak flush provider rules; NAT OpenVPN **tidak diaktifkan**, masih BLOCKED. |
| 788–816 | Installer Xray remote, acme.sh remote, stop proxy, sertifikat/key dan PEM HAProxy | `installer/{xray,tls,tls-renew}.sh`, `installer/artifacts.py`, `services/nathaya-cert-renew.*`. Xray pinned; Certbot paket/ACME standalone, consent eksplisit, validasi lineage/domain/key, preservasi sertifikat valid. Tidak curl-pipe-shell/acme auto-upgrade. |
| 817–944 | openvpn.zip server, tiga client + CA inline + ZIP publik, autostart, config UDP :2100 | `installer/openvpn.sh` adalah gate BLOCKED, bukan server pengganti; `installer/udp.sh` juga gate. `templates/openvpn/*.ovpn.in`, `tools/audit-openvpn.py` dan `tools/openvpn-clients.py` kini ada untuk audit offline/fixture client legacy; bukan server installer. Renderer menyiapkan allowlist URL unduhan; core tidak menghasilkan client/ZIP/PKI. Kontrak client tepat di bawah dipertahankan. |
| 945–1008 | Cron expiry/warning/logclear, rewrite root .profile dan /etc/shells, hapus history, daily_reboot disabled | `installer/maintenance.sh`, `services/nathaya-ssh-expire.*`, `modules/maintenance/ssh-expire.sh`; dashboard hook `services/nathaya-dashboard.sh` → `/etc/profile.d/nathaya-dashboard.sh`. Tidak overwrite root profile/shells/history. Tidak memasang cron legacy, warning/logclear atau reboot harian. |
| 1009–1142 | Unit empat Xray instance, xray drop-in, disable stock services, WS/UDP/limitip/quota/BadVPN | `installer/render.py:render_core/unit`, `installer/proxies.sh`, `services/*.service`. Empat instance + lima unit core terpisah; tidak menyalin limiter/quota/UDP opaque atau monitor DB lama. Lihat inventaris unit. |
| 1143–1198 | /root/.key, random seed akun Xray, npm Express/upload, swap 1G, fail2ban permanen | Fresh Xray `clients: []`; key server Shadowsocks baru lokal diperlukan engine, **bukan akun seed**, config existing dipertahankan (`installer/proxies.sh`). Tidak menulis /root/.key, npm, swap/fstab atau fail2ban ban permanen. Tidak mengklaim fitur itu tersedia. |
| 1199–1249 | Enable/start/restart services, netfilter-persistent, unduh menu dan alias CLI | `installer/{proxies,maintenance,runtime,verify}.sh`; wrapper `installer/menu-wrapper.sh`, `modules/menu/*`, `updater/*`. Unit nyata diverifikasi; tidak bootstrap seluruh project/* remote. CRUD SSH Nathaya tersedia, CRUD Xray/panel protokol belum tersedia. |
| 1250–1306 | Telegram sukses, pesan siap, countdown 10 detik, reboot | `setup.sh:nt_worker/nt_worker_exit`, `installer/ui.sh:nt_can_reboot/nt_reboot_countdown`. Status tahap/result/exit-code/log privat; gagal dapat meninggalkan mutasi parsial. Countdown full 30 detik/cancel root hanya setelah semua gate; full masih BLOCKED; **core never reboot**. |

### Bootstrap menu dan updater referensi

- `menu.sh:1–115` referensi bukan dashboard: downloader puluhan `project/*` ke `/usr/bin`, termasuk add/check/dell/renew/trial semua protokol, exp/warning, backuprestore, features, logclear, quota dan limiter; chmod executable. Nama download tidak menjamin target ada atau sukses. Nathaya hanya membawa manifest lokal/SSH sendiri, tidak menyalin DB/script monitoring Alrescha.
- `package-gohide.sh:1–58` memasang alias `add-*`, `del-*`, `check-*`, `renew-*` ke `/usr/local/bin` dari `main`. Tidak ada installer alias penuh Nathaya yang ekuivalen; jangan menyebut semua CLI selesai.
- `update.sh:1–258` referensi melakukan overwrite selektif check/del/renew/menu dari mutable `main`, memeriksa keberadaan dan mencetak sukses meskipun download tertentu gagal. Nathaya `updater/{main.py,release.py,release-policy.json,update.sh}` memisahkan deployment kode dari OS/setup, memakai stable release `https://github.com/Yusuf2790/nathaya-tunnel`, validator/allowlist lokal, satu versi tervalidasi, backup+jurnal dan rollback kode. Tidak migrasi DB, upgrade apt, menjalankan setup atau reboot. Auto-update default disabled sampai manual verification sukses dan opt-in. Ini desain/source yang belum diuji ulang, bukan bukti release publik siap.

## Peta port, WS/gRPC dan PROXY protocol

Diperiksa pada file aktual `fodder/Haproxy/haproxy.cfg`, `fodder/nginx/{xray.conf,nginx.conf}`, `fodder/examples/{dropbear,sshd}`, `fodder/websocket/ws.py`, dan keempat `VMess-VLESS-Trojan+Websocket+gRPC/*/config.json`; bukan hanya daftar di README. Peta Nathaya berasal dari `config/ports.json` + renderer.

| Transport/protokol | Referensi | Nathaya core yang dirender |
|---|---|---|
| Multiplexer publik TCP | HAProxy 80, 443, 8080 | 0.0.0.0:80/443/8080; sniff TLS/SSH/HTTP, satu backend per protokol |
| Download | Nginx TLS 81, seluruh root /var/www/html, TLS 1.1 juga diizinkan | TLS 81, TLS 1.2/1.3, empat nama allowlist saja; file core belum disediakan |
| Admin OpenSSH | Tambah 22/2222/2223 ke config existing | Port/auth admin existing dipertahankan, termasuk ssh.socket; tidak menjanjikan admin 22 |
| Raw SSH | backend 2223 plain; 2222 sesudah TLS | 127.0.0.1:2223 plain; :2222 TLS-decrypted, unit tambahan nathaya-sshd |
| Dropbear | 143 + 109 (default tidak dibatasi loopback) | Publik 143; internal 127.0.0.1:109; root login Dropbear ditolak (-w) |
| SSH WS | ws.py 0.0.0.0:10015; default target 109; daftar target termasuk 2223/2222/1194; fallback path /fightertunnelssh | Relay 127.0.0.1:10015 → **hanya** 127.0.0.1:109; `/ssh` dan fallback HTTP tetap ke relay sama |
| Frontend HTTP/WS internal | Nginx 1010 + proxy_protocol | 127.0.0.1:1010 + proxy_protocol |
| Frontend gRPC internal | Nginx 1013 http2 + proxy_protocol | 127.0.0.1:1013 http2 + proxy_protocol |
| VMess | /vmess → 10002; vmess-grpc → 10006; stats 20001 | Sama; seluruh backend/stats loopback |
| VLESS | /vless → 10001; vless-grpc → 10005; stats 20002 | Sama; seluruh backend/stats loopback |
| Trojan | /trojan-ws → 10003; trojan-grpc → 10007; stats 20003 | Sama; seluruh backend/stats loopback |
| Shadowsocks | /ss-ws → 10004; ss-grpc → 10008; stats 20004; template network tcp,udp | Port/path sama; core SS2022 `2022-blake3-aes-256-gcm`, network tcp; tidak menyatakan UDP parity |
| OpenVPN | Client TCP 1194, UDP 2200, SSL-over-TCP 443; HAProxy default fallback ke 1194 | **BLOCKED**; tidak ada listener/fallback OpenVPN, unduhan atau NAT aktif |
| UDP Custom | Config :2100; unit exclude 2200,7300,7200,7100,323,10008,10004 | **BLOCKED**, binary/provenance/lisensi belum disetujui |
| BadVPN | Unit loopback 7100/7200/7300, max-clients 500 | **BLOCKED**, binary/provenance/lisensi belum disetujui |
| DNS redirect | UDP 53→5300 pada interface default | Dikecualikan: listener 5300 belum dibuktikan |

**Bug referensi yang tidak diwarisi:** `payload_backend` HAProxy melakukan `balance roundrobin` atas port protokol berbeda 10001–10008 dan SSH 10015. Itu bukan failover protokol yang sah; koneksi dapat masuk parser salah. Catch-all path juga mendahului ACL khusus, sehingga sebagian routing sulit/ tidak tercapai. Recirculation memakai PROXY v2 (`send-proxy-v2`/`accept-proxy`), sedangkan HAProxy→Nginx memakai v1 `send-proxy` dan Nginx mengharuskan `proxy_protocol`; PROXY header tidak boleh diteruskan sembarangan ke SSH/Xray yang tidak mengharapkannya.

**Determinisme baru:** TLS hello → abstract socket `abns@nathaya-tls` (PROXY v2/accept-proxy); ALPN h2 → Nginx 1013; SSH prefix → SSH 2222 sesudah TLS atau 2223 plain; HTTP → Nginx 1010. Kedua hop HAProxy→Nginx memakai PROXY v2 yang diterima Nginx. Nginx memilih exact WS path atau prefix `/<grpc-service>/`, bukan roundrobin antarprotokol; upstream Xray/SSH tidak menerima PROXY header. Unknown gRPC → 404, unknown HTTP → relay SSH fixed target. Relay baru menghitung RFC6455 accept dan memvalidasi masked binary frames; mode legacy tanpa Sec-WebSocket-* memakai raw bytes setelah 101, bukan `Sec-WebSocket-Accept: foo` referensi. Header `X-Real-Host` tidak boleh memilih target arbitrary. Perubahan ini source-level, bukan bukti handshake eksternal berhasil.

## OpenVPN: kontrak client tidak boleh diganti diam-diam

**`setup.sh:835–909` adalah sumber tiga template tepat**. Semua directive dan urutannya sama kecuali `proto`/`remote` berikut (substitusi `$ip` adalah alamat VPS):

| Berkas | proto | remote |
|---|---|---|
| client-tcp.ovpn | tcp | `$ip 1194` |
| client-udp.ovpn | udp | `$ip 2200` |
| client-ssl.ovpn | tcp | `$ip 443` |

Urutan isi literal setiap template, dengan dua placeholder yang hanya mewakili baris tabel di atas:

```text
auth-user-pass
client
dev tun
proto <tcp-atau-udp-sesuai-tabel>
remote <alamat-VPS-dan-port-sesuai-tabel>
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
auth none
```

Ini dokumentasi, **bukan template deployment dengan placeholder**. Referensi kemudian menambah `<ca>` dari `/etc/openvpn/ca.crt`, menyalin tiga client ke `/var/www/html` dan membuat `allovpn.zip` (910–935). Tidak ada private client key yang boleh ditebak/dibagikan untuk mengisi kekosongan audit.

`fodder/openvpn/openvpn.zip` ada, tetapi binary ZIP **tidak dapat dibaca/diinspeksi dengan tools sesi ini**. Tidak ada klaim telah melihat daftar member, server.conf, auth hook, PKI, CA, private key, subnet, lisensi atau keamanan ekstraksinya. Perintah `unzip` referensi bukan bukti inspeksi. **Audit archive aktual belum dijalankan; server/PKI tetap BLOCKED.**

Alat kini **sudah ada**: `tools/audit-openvpn.py` melakukan inventaris ZIP offline read-only berbatas ukuran/member/ekspansi, menolak path/link/metadata tidak aman, tidak mengekstrak/menjalankan member. Output tidak menampilkan nama/identity/hash/raw config/PEM; optional `--sanitized-report` hanya directive port/proto/dev/local/server yang dikanonisasi. Heuristik/count bukan audit PKI, lisensi/provenance atau persetujuan server dan tidak membuka installer.

`templates/openvpn/client-{tcp,udp,ssl}.ovpn.in` menyimpan directive dan urutan referensi tepat, ditambah komentar atribusi dan `@HOST@`. `tools/openvpn-clients.py` memerlukan `--acknowledge-legacy-insecure`, host tervalidasi dan **public CA** caller; memvalidasi struktur sertifikat (bukan signature/provenance/trust), menulis tiga profile dan optional ZIP allowlist saja ke direktori **baru** di bawah temporary directory (700/file 600). Tidak mengimpor server archive, membuat PKI/client private key, menyentuh runtime atau mengaktifkan OpenVPN/NAT/download core. Keberadaan tool/test bukan hasil audit atau compatibility PASS.

**Keputusan keamanan/kompatibilitas belum selesai:** `cipher none` bermaksud tanpa enkripsi data; `auth none` meniadakan HMAC data non-AEAD; TLS kontrol tidak otomatis mengenkripsi semua data. Kompresi `comp-lzo` membawa risiko kebocoran (termasuk kelas VORACLE), deprecated, dan dapat bertabrakan dengan kebijakan compression/DCO 2.6. Dalam mode TLS OpenVPN 2.6, `cipher` bukan pemilih negosiasi; `data-ciphers` yang mengendalikan cipher data. Exact legacy client/server tanpa cipher bersama diperkirakan mengalami **data-ciphers negotiation failure**. Ini ekspektasi berdasar manual, **bukan hasil test** terhadap ZIP yang tak terbaca. Jangan diam-diam menambah `data-ciphers`, `data-ciphers-fallback`, AES, menghapus `comp-lzo`, atau mengubah `auth none` untuk mengaku parity. Perlu keputusan pengguna eksplisit setelah audit server dan uji klien tepat; sampai itu selesai full tetap BLOCKED.

## Unit, data, maintenance dan dependensi

### Inventaris unit

| Referensi | Nathaya / batas |
|---|---|
| vmess@config.service, vless@config.service, trojan@config.service, shadowsocks@config.service | Nama instance sama, executable `/opt/nathaya/bin/xray`; JSON `/etc/nathaya-tunnel/xray/<protokol>/config.json`; unit dirender ke `/etc/systemd/system`. Tidak memakai xray.service tunggal sebagai indikator keempatnya. |
| xray.service dinonaktifkan, xray@.service drop-in, Dropbear init/penghapusan unit paket | Tidak menyalin drop-in/merusak unit paket; stock nginx/haproxy/dropbear baru dinonaktifkan untuk unit Nathaya. Existing enabled stock unit adalah konflik yang perlu keputusan manual. |
| ssh.service (dan Ubuntu ssh.socket), dropbear.service, ws.service, nginx.service, haproxy.service | Admin SSH paket dipreservasi; unit baru nathaya-sshd.service, nathaya-dropbear.service, nathaya-ws.service, nathaya-nginx.service, nathaya-haproxy.service. |
| udp.service, badvpn.service | Tidak dipasang; BLOCKED. |
| limitip.service (limitipssh + limitip), limitquota.service (/usr/bin/quota) | Tidak dipasang. Referensi command/unit tidak membuktikan script tersedia; beberapa target tidak ditemukan dalam snapshot. Tidak ada panel/limiter/quota Xray Nathaya. |
| cron.service, vnstat.service, fail2ban.service, netfilter-persistent | Tidak mengaku parity maintenance ini; core tidak memasang cron legacy, vnstat/fail2ban/netfilter-persistent atau NAT. |
| Cron expiry referensi | nathaya-ssh-expire.service + .timer: source monitor **sudah ditulis**, OnBootSec=15s/OnUnitInactiveSec=15s, AccuracySec=1s. |
| TLS renewal acme.sh | nathaya-cert-renew.service + .timer: 03:25 dan 15:25, random delay ≤1800s, persistent. |
| Tidak ada updater tepercaya ekuivalen pada update.sh lama | nathaya-update.service + .timer: daily + random ≤1h, persistent; **tidak di-enable installer**, manual gate lalu opt-in. |

Expiry `modules/maintenance/ssh-expire.sh` membaca DB tujuh kolom Nathaya saja, mengambil operations.lock lalu DB lock, re-read record/validasi identity UID non-root/home/shell, `chage -E 0`, menghentikan sesi UID itu, dan menandai expired. Regular sampai akhir tanggal; trial timestamp lokal. Tidak menghapus user, meng-unlock password/lock admin otomatis, atau mengimpor DB lain. Penolakan public-key bergantung account policy/PAM yang benar. **IP collector real peer belum ada → enforcement limit_ip BLOCKED**, bukan aktif karena kolom atau unit/timer expiry tersedia. SSH Login berbasis proses bukan collector IP lintas WS/Dropbear/OpenVPN.

### DB dan path

| Referensi (tidak disalin) | Nathaya |
|---|---|
| /root/.vars, /root/.key; /etc/xray/domain, city, isp | `/etc/nathaya-tunnel/config.conf` empat key allowlist literal: DOMAIN, TELEGRAM_STATUS, TELEGRAM_BOT_TOKEN, TELEGRAM_ADMIN_ID; bukan source shell. Cache lokasi `/var/cache/nathaya-tunnel/location.cache`. |
| /etc/ssh/.ssh.db; /etc/xray/ssh/.ssh.db; /etc/xray/{vmess,vless,trojan,shadowsocks}/.<protokol>.db; direktori /etc/{vmess,vless,trojan,shadowsocks}; metadata per-user/limit/usage | Satu `/opt/nathaya/data/ssh/accounts.db`: `username|created|expiry|limit_ip|status|lock_until|account_type`; accounts.lock dan operations.lock di direktori sama. Tidak ada DB Xray disalin/migrasi diam-diam. |
| /etc/xray/<protokol>/config.json; /usr/bin/xray (direktori buatan), /usr/local/bin/xray | `/etc/nathaya-tunnel/xray/<protokol>/config.json`; `/opt/nathaya/bin/xray`; metadata `/etc/nathaya-tunnel/xray-binary.json`. Fresh clients kosong, existing dipreservasi. |
| /var/log/xray/{access,error}.log, log akun di /etc/xray, /var/log/nginx | `/opt/nathaya/logs`: install-*.log, stages/result terkait run, telegram.log, ssh-reconcile.log, unit/parser/error logs. Logging Xray warning/access none, bukan IP audit feed. |
| /etc/haproxy/haproxy.cfg, /etc/nginx/{nginx.conf,conf.d/xray.conf} | `/etc/nathaya-tunnel/services/{haproxy.cfg,nginx.conf}`; managed-services.json menyimpan identitas/hash file, bukan DB akun. |
| /root/.acme.sh; /etc/xray/xray.crt, xray.key; /etc/haproxy/yha.pem | Certbot `/etc/letsencrypt/{live,archive}/<domain>/`; salinan privat `/etc/nathaya-tunnel/tls/{fullchain.pem,privkey.pem,haproxy.pem}`. |
| /etc/openvpn/*; /var/www/html/*.ovpn, allovpn.zip | OpenVPN BLOCKED; renderer hanya alias empat nama ke `/opt/nathaya/public/openvpn`, bukan seluruh webroot. `/opt/nathaya/public/drop` sama sekali tidak disajikan atau dikonsumsi root. |

Backup/staging/jurnal baru ada di `/var/backups/nathaya-tunnel/run.*` dan renewal `renew.*`; kode `/opt/nathaya`; cache `/var/cache/nathaya-tunnel`; lock installer/updater/renewal `/run/nathaya-tunnel-setup.lock`. Updater state/transaction privat `/opt/nathaya/updater-state`. Detail mode: [permissions.md](permissions.md).

Cron referensi yang diaudit: `xp_all` 00:02 `/usr/bin/exp`; `exp_warning` 09:00 dan 18:00 `/usr/bin/exp-warning`; `logclear` tiap enam jam; `daily_reboot` komentarnya disabled dan `/home/daily_reboot` berisi jam 5. Nathaya tidak memasang job itu atau menghapus history admin; login hook hanya root SSH interaktif login TTY, sekali, bukan SCP/SFTP/remote command, dan kegagalan dashboard tidak mengganti shell.

Dependensi core aktual (`installer/dependencies.sh`): openssh-server, ca-certificates, curl, python3, util-linux, procps, iproute2, bash, coreutils, passwd, libc-bin, hostname, mawk, grep, ncurses-bin, findutils, sed, openssl, dropbear, nginx, haproxy, certbot, nftables; tambah **bind9-dnsutils hanya bila `dig` belum ada**. Preflight sendiri memerlukan utilitas dasar Ubuntu/apt/dpkg/systemd/ss/ip/tar/hash dan ruang root ≥3 GiB sebelum upgrade (bukan estimasi cukup untuk semua transaksi). Tidak meminta paket dnsutils jika executable dig sudah tersedia. Daftar build/dev besar referensi, easy-rsa/openvpn, npm/Node, vnstat build, gotop, swap/fail2ban bukan dependensi core yang telah diterapkan.

Apt update/upgrade/dist-upgrade adalah maintenance OS terotorisasi, terpisah dari updater kode. Simulasi menolak removal komponen kritis, opsi confold menjaga config, lock apt ditunggu bukan dihapus, unattended-upgrades tidak dibunuh. Binary/proses dapat berganti karena upgrade; admin port/auth, enablement dan akses SSH tetap wajib dipreservasi/diverifikasi, bukan janji tidak pernah restart proses. Removal UFW/firewalld dapat mengubah kebijakan miliknya setelah inventaris/backup; tidak mengotorisasi global flush provider. Tidak ada rollback OS otomatis.

TLS: ACME standalone perlu domain A menuju IPv4 VPS/port 80, persetujuan ToS eksplisit; valid cert/key dipreservasi, lineage diarahkan hanya ke archive domain sama, SAN/expiry/key cocok diverifikasi tanpa mencetak key. Renewal berbagi lock, backup/sync salinan privat, parser checks dan pemulihan proxy setelah challenge. Belum ada bukti renewal/reload sukses di VPS.

## Artefak dan atribusi

- Referensi Alrescha berlisensi **MIT, Copyright (c) 2025 Anggun Caksono**. Pertahankan `NOTICE` dan teks izin/disclaimer lengkap yang **sudah ada** di `licenses/Alrescha79-MIT.txt`; atribusi tidak dihapus ketika layout/nama berubah.
- Nama/komentar pihak lain pada WS/UDP/unit (mis. FATKAY, ePro/HC, GerhanaTunnel) diperlakukan sebagai atribusi referensi, **bukan bukti seluruh artefak berlisensi MIT**. Lisensi asal/versi/source UDP Custom, BadVPN, ZIP OpenVPN dan binary pihak lain belum ditetapkan. Tidak didistribusikan atau dijalankan agar tampak full.
- Referensi berisi **private host key** (contoh file DSS Dropbear dan isi lain yang belum boleh diasumsikan aman). Jangan menyalin, mencetak, mengunduh atau menggunakan ulang identitas itu. OpenSSH/Dropbear membuat host key unik di VPS dan menjaga valid existing key. Audit nama/path bukan izin membaca isinya.
- Xray terkunci pada **v26.11.9**, asset `Xray-linux-64.zip`; SHA-256 dalam `installer/external-lock.json`: `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82`. Itu digest lock yang disediakan, bukan hash binary yang dijalankan agen. `artifacts.py` mensyaratkan metadata GitHub stable/tag/asset/digest cocok, hash download, bounded ZIP aman, ELF64 amd64, dan LICENSE; menyalin lisensi Xray tersendiri. Digest HTTPS bukan signature penerbit atau reproducible-build proof. gRPC/WS pinned dinyatakan deprecated-supported oleh desain; binary parser dan integration test masih wajib.

Sumber eksternal aktual yang dibaca untuk konteks (tidak mengeksekusi download):

1. Xray release: https://github.com/XTLS/Xray-core/releases/tag/v26.11.9
2. Metadata yang wajib diverifikasi installer: https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.11.9
3. Asset terkunci: https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip
4. OpenVPN 2.6 manual, opsi cipher/auth/data-ciphers/comp-lzo/compression: https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/ dan https://build.openvpn.net/man/openvpn-2.6/openvpn.8.html

Pembacaan web release bukan konfirmasi ulang semua byte asset; penerimaan digest tetap gate runtime fail-closed.

## Integrasi source yang sudah diperbaiki dan gerbang tersisa

Temuan lama **manifest dasar, endpoint health hilang dan reload unit hilang sudah diperbaiki di source**: `nt_program_files`/`nt_source_files` sekarang membawa installer/runtime/services/ports/monitor/updater/VERSION/NOTICE/lisensi; renderer menyediakan exact `/healthz` dan `ExecReload` Nginx/HAProxy. Policy eksplisit juga mencakup lima dokumen publik **artifact-only**, bukan instalasi docs; tidak membawa progress, tests, data atau `.git`. Hindari angka jumlah manifest/policy yang mudah basi. Ini verifikasi konten, bukan parser/unit/VPS PASS.

Dashboard kini memeriksa SSH service **atau socket**, empat instance Xray, Dropbear/Nginx unit Nathaya, VERSION kode, SSH count dari DB dan total protokol dari config. Panel CRUD Xray tetap unavailable. Set Domain menolak migrasi bila identitas layanan terkelola ada, dengan lock bersama. Expiry 15s menggunakan shared operations/DB locks dan guard UID managed; password/admin locks tidak di-unlock. Limit IP lintas transport tetap tidak ada.

Worker private persistent log/status terpisah dari viewer, mengabaikan HUP; viewer tidak melepas lock worker. Cleanup melacak unit/timer yang baru aktif dan enablement baru, bukan rollback seluruh sistem. Full power request dirancang hanya sesudah gate sukses dan finalisasi cleanup/result/exit-code/log; jalur full tetap unreachable fail-closed, core tidak reboot.

`state.py` sekarang inspect/prepare/validate-prepared/commit: preflight menolak downgrade/inconsistency/pending recovery, snapshot diperiksa ulang, installed.json hanya dipublikasikan postverification; same-version mempertahankan byte baseline cocok. Setup gagal tidak memiliki rollback code/OS otomatis. Updater wrapper/unit/private state sudah terintegrasi tetapi auto timer tidak di-enable; artifact manual check wajib sebelum opt-in. Stable origin tersanitasi cocok Yusuf2790/nathaya-tunnel; release belum dipastikan ada. Required installed non-deploy trust base missing/drift memblokir routine update untuk reviewed manual source reinstall. Routine scope hanya menu/modules/example/VERSION, bukan WS/service glue/binary/key/config aktif/DB/OS/reboot. Lihat [update.md](update.md).

Gerbang berikut: review manifest/policy/dependency source; pengguna menjalankan fixture/mocks melalui runner yang kini tersedia `bash tests/run-local.sh` (Bash, Python 3, GNU utils), atau `tests/{foundation,installer,expiry,full}.sh` dan `tests/{services_test,openvpn_test,update_test,integration_test}.py`; lalu VPS disposable dengan backup/rescue/admin second session untuk listener/internal exposure, preservasi service+socket/auth/port/key, WS RFC6455+legacy, TLS/gRPC/empat parser Xray, expiry trial/regular/PAM/UID, renewal/reinstall/update/rollback/disconnect/failure dan postboot manual setelah core PASS. Semua itu **belum dijalankan agen**. OpenVPN memerlukan audit ZIP dan keputusan keamanan/kompatibilitas 2.6; opaque UDP memerlukan provenance/lisensi sebelum full dapat dibuka. Jangan menyatakan “full completed”, “semua layanan aktif”, atau “VPS tested”.
