# Arsitektur Nathaya Tunnel — source 2.0.0

## Scope dan batas bukti

Target root Ubuntu 24.04 amd64/x86_64 dengan systemd PID 1; Acode/Termux hanya pengembangan. Source saat ini mengimplementasikan **core parsial** SSH/Dropbear/WS/TLS/Nginx/HAProxy/Xray/expiry SSH/hook dashboard dan integrasi updater. Default **full BLOCKED preflight sebelum mutasi** oleh archive server OpenVPN belum teraudit serta provenance/lisensi UDP Custom/BadVPN. Mengubah JSON saja tidak membuka gate. **Core tidak reboot.** Full reboot fail-closed saat ini unreachable.

Laporan pengguna installer **dasar lama** exit 0/dashboard/SSH service/socket bukan bukti core/full baru lolos. Tugas dokumentasi ini hanya membaca/menulis konten: tidak menjalankan test, parser, Bash/Python/Git, binary, service atau VPS. Badge/status lokal bukan tes koneksi; tidak ada klaim full completed atau VPS baru verified.

## Hubungan komponen

```text
setup.sh → installer/{lib,preflight,openssh,domain,dependencies,policy,...}.sh
  ├─ full: artefak gate BLOCKED; core: opt-in subset
  ├─ state.py inspect → prepare → validate-prepared → commit postverification
  ├─ lock bersama → staging/hash/backup → worker HUP-independent/log privat
  ├─ apt OS maintenance → dependencies → key/firewall → manifest deployment
  ├─ TLS/Certbot + pinned Xray → render.py/checks.py → unit core
  └─ maintenance + local verification → CORE_SUCCESS (tanpa reboot)

/usr/local/bin/menu → /opt/nathaya/menu.sh
  ├─ common/bootstrap.sh: path kode/runtime + parser config literal
  ├─ common/{ui,functions,telegram}.sh: UI/informasi/status/sender HTML
  ├─ dashboard + modules/menu/* (panel protokol unavailable eksplisit)
  └─ modules/ssh/* → akun Linux + account-db.sh (satu DB/shared locks)

services/nathaya-dashboard.sh → root SSH login interaktif sekali, shell tetap ada
services/nathaya-ssh-expire.timer → modules/maintenance/ssh-expire.sh --once
services/nathaya-cert-renew.timer → installer/tls-renew.sh
/usr/local/bin/nathaya-update → updater/main.py + validator/policy LOKAL
  └─ stable GitHub artifact → bounded validation → routine code transaction
     auto timer default tidak di-enable; manual verification + opt-in wajib
```

`nt_program_files`/`nt_source_files` di `installer/lib.sh` kini mencakup consumer installer, renderer/checks/state, ports, maintenance, services, updater, VERSION/NOTICE/lisensi; bukan manifest SSH dasar lama. Jumlah tidak dijadikan kontrak dokumentasi. `updater/release-policy.json` memisahkan file deploy dari package-only; lima dokumen publik ini ikut artefak **saja**, tidak dipasang ke VPS. `docs/progress.md`, `.git`, tests, DB/data/log/cache/config aktif dan secret tidak dipaketkan. Tool/template OpenVPN dan builder juga package-only.

## Runtime dan permission

| Kebutuhan | Lokasi produksi |
|---|---|
| Program/modules/installer/services/updater/VERSION | `/opt/nathaya` |
| Wrapper | `/usr/local/bin/menu`, `/usr/local/bin/nathaya-update` |
| Config utama | `/etc/nathaya-tunnel/config.conf` |
| Proxy, Xray, TLS | `/etc/nathaya-tunnel/{services,xray,tls}` |
| Identitas file terkelola / binary Xray | `/etc/nathaya-tunnel/{managed-services.json,xray-binary.json}` |
| DB dan locks | `/opt/nathaya/data/ssh/{accounts.db,accounts.lock,operations.lock}` |
| Log | `/opt/nathaya/logs` |
| Cache lokasi | `/var/cache/nathaya-tunnel/location.cache` |
| Backup/staging/jurnal setup dan renewal | `/var/backups/nathaya-tunnel/{run.*,renew.*}` |
| Updater state/transactions | `/opt/nathaya/updater-state` |
| Lock setup/updater/renewal/Set Domain | `/run/nathaya-tunnel-setup.lock` |
| Unduhan OpenVPN (belum dihasilkan core) | `/opt/nathaya/public/openvpn` |
| Drop nonrahasia, tidak served/consumed | `/opt/nathaya/public/drop` |

Root-owned: code dirs 755/file 644, entrypoint/binary 755; config/DB/key/state/log/backup private dirs 700/file 600; unit/hook 644. **Hanya public/drop 777 nonrekursif**; parent/kode/data/key tidak pernah 777. Jangan gunakan drop sebagai input operasi root. Detail termasuk Certbot lineage dan UID layanan: [permissions.md](permissions.md).

Bootstrap memisahkan lokasi kode (`NATHAYA_BASE`, ditemukan relatif terhadap file) dari data. Checkout tidak memindahkan DB/cache/log ke checkout. Source helper hanya definisi/path/warna, tanpa mkdir/chown/akun/network/menu saat dimuat. Runtime initialization eksplisit; cache/log ditulis saat fungsi terkait benar-benar dipanggil.

Override fixture dari caller tepercaya: `NATHAYA_BASE`, `NATHAYA_CONFIG`/`NATHAYA_CONFIG_FILE`, `NATHAYA_CACHE`, `NATHAYA_LOG_DIR`, `NATHAYA_SSH_DIR`, serta DB/lock/operations-lock. Tetapkan sebelum bootstrap pertama, arahkan **semua** path data ke temporary fixture. Config tidak dapat menetapkan override tersebut. Installer/launcher produksi memakai tujuan tetap/environment bersih, bukan API untuk mengarahkan instalasi root ke path arbitrary.

## Config literal dan domain

`config/config.conf.example` berisi empat default inert:

```ini
DOMAIN=""
TELEGRAM_STATUS="OFF"
TELEGRAM_BOT_TOKEN=""
TELEGRAM_ADMIN_ID=""
```

`load_nathaya_config` tidak source shell. Hanya empat key diterbitkan; assignment lain tidak mengubah PATH/helper/runtime. Literal kutip tunggal/ganda atau simple unquoted didukung, bukan escape/ekspansi/command substitution/export/inline comment. Baris kosong/komentar awal, CRLF dan akhir tanpa newline didukung; assignment berulang terakhir menang. Missing/unreadable return 1, invalid return 2, semua default aman tanpa partial publish/secret output. Telegram status hanya ON/OFF dan admin ID kosong/angka (boleh negatif). Sender HTML opt-in memeriksa respons, bukan management bot. Payload akun dapat menampilkan/mengirim password; perlindungan file tidak menjamin privasi pihak ketiga.

Set Domain memvalidasi domain dan A record via dua resolver lalu menyimpan config secara atomic di bawah lock bersama. **Jika managed-services.json ada, menu menolak migrasi domain/TLS/proxy.** Setup juga menolak domain existing berbeda. Tidak mengubah DNS provider atau menyelaraskan semua identitas layanan lewat menu.

## DB akun, operasi dan expiry

Satu flat file:

```text
username|created|expiry|limit_ip|status|lock_until|account_type
```

`created` YYYY-MM-DD; regular expiry berlaku sampai akhir tanggal; trial timestamp lokal YYYY-MM-DD HH:MM:SS. `limit_ip` 1–100 **metadata saja**, status active/locked/expired bukan bukti semua transport terblokir. Password tidak disimpan dalam DB. Tidak ada DB Xray/Alrescha paralel atau migrasi diam-diam. Legacy enam kolom dipreservasi, bukan ditebak tipe akunnya; operasi yang mensyaratkan regular/trial menolak legacy/invalid. Delete legacy memerlukan pemeriksaan Linux/konfirmasi operator.

Create/Delete/Lock/Unlock/Renew/Trial dan expiry berbagi **operations.lock sebelum DB lock**, writer memakai flock/temporary replacement. Operasi Linux dan DB bukan satu transaksi atomic; kegagalan parsial perlu rekonsiliasi. Create/Trial membuat akun/password/expiry dan record; Renew regular memperpanjang expiry **tanpa auto-unlock password**. Lock/Unlock regular mengikuti kebijakan password/PAM admin; Login mengamati proses SSH, bukan IP collector. Listing menafsirkan DB, bukan mematikan layanan.

Expiry **sudah ada**: `nathaya-ssh-expire.service/.timer`, boot 15s dan 15s setelah unit selesai, accuracy 1s; bukan janji hard realtime. Worker root memvalidasi tujuh kolom, re-read record di bawah shared locks, memeriksa identity Linux non-root UID ≥1000 bukan 65534, home `/home/<user>` dan shell `/bin/bash`, serta UID konsisten. Baru `chage -E 0`, kill sesi **UID terverifikasi**, dan tandai expired dengan metadata lock tetap. Tidak menghapus user, meng-unlock password atau lock admin otomatis. Public-key denial memerlukan account/PAM policy yang benar dan uji nyata. Trial timestamp kini memiliki worker enforcement; presisi dan semua jalur auth masih harus diuji.

**Tidak ada enforcement IP lintas SSH/WS/Dropbear/OpenVPN, auto-unlock scheduler, panel CRUD Xray, management bot, quota collector atau monitor DB Alrescha.** Unit expiry bukan IP limiter. Menu fitur/protokol yang belum ada menyatakan unavailable.

## Layanan, routing dan dashboard

Unit core: `nathaya-{sshd,dropbear,ws,nginx,haproxy}.service`, `vmess@config.service`, `vless@config.service`, `trojan@config.service`, `shadowsocks@config.service`. SSH admin tetap unit Ubuntu `ssh.service`/`ssh.socket`; host key unik lokal dan port/auth/PAM admin dipreservasi. Dropbear menolak root login. Nginx/HAProxy memakai konfigurasi privat Nathaya, bukan overwrite global stock config. Konflik stock unit/port/hook tidak diselesaikan dengan memindahkan port admin.

`config/ports.json` → renderer: publik TCP 80/443/8080 multiplexer, 81 TLS download allowlist, 143 Dropbear; SSH tambahan 127.0.0.1:2222/2223, Dropbear 109, WS 10015→109 fixed-target. Nginx HTTP 1010/gRPC 1013 dan semua backend/stats Xray loopback. Ini **rencana render, bukan listener aktif terverifikasi**; peta exact WS/gRPC/port dan mapping referensi ada di [alrescha-parity.md](alrescha-parity.md).

TLS recirculation memakai PROXY v2/accept-proxy, HAProxy→Nginx juga PROXY v2. Pemilihan protokol deterministic, tidak roundrobin lintas parser. Nginx mengarahkan exact WS/prefix gRPC ke protokolnya; unknown gRPC 404, HTTP fallback ke relay SSH target tetap. Header klien tidak memilih arbitrary target. WS mendukung RFC6455 masked binary frames dan legacy raw upgrade. Tidak mengklaim handshake eksternal telah diuji.

Renderer kini menyediakan exact **`/healthz`** untuk HTTPS local verification dan **`ExecReload`** Nginx/HAProxy untuk renewal; temuan source lama tentang keduanya sudah diperbaiki. Parser/unit/listener/curl lokal bukan bukti gRPC/WS/client login lolos. Xray binary pinned diperiksa metadata/digest/hash/ELF/license; fresh clients kosong, Shadowsocks server secret lokal bukan seed akun, config/clients existing preserved. Pin bukan signature atau bukti binary pernah dijalankan agen.

Dashboard sekarang membaca SSH **service ATAU socket**, empat instance Xray (semuanya harus active untuk badge ON), unit Nathaya Dropbear/Nginx, serta VERSION dari kode. Total SSH dari record DB tujuh kolom yang diterima counter; total VMess/VLESS/Trojan dari unique client identity config masing-masing, bukan Linux users atau literal nol. Angka ini bukan online count/audit konsistensi Linux. OpenVPN ditampilkan BLOCKED. Tidak ada panel CRUD Xray walau engine/unit/badge tersedia.

Hook `/etc/profile.d/nathaya-dashboard.sh` hanya root SSH login shell interaktif dengan TTY, sekali per sesi; tidak exec/mengganti parent shell dan kegagalan mengembalikan shell. SCP/SFTP/remote command bukan target. Tidak overwrite `/root/.profile`, `/etc/shells` atau history.

## Worker, lifecycle dan identity installer

Preflight memeriksa `state.py inspect_install` sebelum mutasi: canonical VERSION, downgrade, schema/installed identity tidak konsisten dan pending updater ditolak. Setelah lock, `prepare` menyimpan baseline/hash privat; sesudah staging `validate-prepared` menolak source/baseline berubah. **Commit installed.json hanya setelah semua verifikasi**, bukan saat runtime directory dibuat. Same-version rerun mempertahankan byte baseline jika isinya cocok; setup gagal tidak otomatis memulihkan kode/OS, sehingga identity lama dapat tersisa dan memerlukan rekonsiliasi.

Worker HUP-independent menulis install log privat permanen serta stages/result/exit-code/worker.pid pada run. Viewer boleh terputus, **tidak membatalkan worker atau melepas lock miliknya**. Cleanup gagal berusaha stop unit/timer baru-active dan disable enablement baru bila gates belum lolos, restore temporary policy dan release lock. Tidak mengembalikan semua layanan existing/OS/firewall/code/account. Jurnal dan backup adalah alat recovery manual, bukan atomic tree deployment.

Core gate memeriksa SSH baseline/`sshd -t`, unit/timer, empat parser Xray, listener dan HTTPS `/healthz`; core sukses **tanpa reboot**. Full gate tetap menolak OpenVPN/UDP. Reboot full hanya setelah FULL_SUCCESS + semua gate, countdown 30s/cancel root dan finalisasi cleanup/status/log **sebelum** request power; kini unreachable. Tidak ada daily reboot.

## Maintenance, updater dan hal yang tidak diwarisi

OS maintenance `apt update/upgrade/dist-upgrade` terpisah dari deployment aplikasi. Simulasi/removal-critical guard, backup/firewall inventory dan baseline admin SSH tidak menghapus risiko upgrade/restart. Core tidak global-flush firewall provider, memasang NAT/ip_forward/persistence atau DNAT 53→5300 tanpa listener. NAT OpenVPN 10.8.0.0/24 dan 20.8.0.0/24 tetap BLOCKED bersama server. Tidak mewarisi cron expiry/warning/logclear, Node/npm, vnstat build, remote bbr.sh, swap/fstab, fail2ban permanen atau private key referensi.

Certbot paket/ACME standalone: DNS, ToS, inbound 80, validasi SAN/expiry/key dan lineage terbatas; valid cert/key existing dipreservasi. Renewal timer 03:25/15:25, jitter ≤30 menit, lock bersama, private backup, sync PEM, parser checks, reload dan recovery HAProxy. Source reload tersedia; runtime renewal belum terverifikasi.

Updater wrapper/unit/state privat **sudah diintegrasikan installer**, auto timer tidak di-enable. Source stable GitHub `Yusuf2790/nathaya-tunnel` cocok dengan origin tersanitasi yang telah dikonfirmasi; ini bukan konfirmasi release tersedia. Validator/policy terpasang, mandatory GitHub SHA-256 digest, bounded USTAR/exact manifest dan versi/schema monotonic; tidak menjalankan kode remote untuk memvalidasi dirinya. Required installed non-deploy trust base missing/drift **BLOCKED** sampai reviewed manual source reinstall. Routine apply hanya menu/modules/example config/VERSION, bukan service glue/WS binary/key/config aktif/DB/OS/reboot; rollback kode tersendiri. Detail publish/user-only Git/check/opt-in/recovery: [update.md](update.md).

## OpenVPN, atribusi dan gerbang

`templates/openvpn/*.ovpn.in`, `tools/audit-openvpn.py` dan `tools/openvpn-clients.py` **sudah ada**. Audit offline read-only/bounded/redacted tidak mengekstrak/menjalankan member; generator fixture hanya public CA caller + insecure acknowledgement, output baru privat di temporary directory. Tidak membuat PKI server atau mengaktifkan service/NAT/download core. **Audit archive aktual belum dijalankan**, isinya tidak dapat diinspeksi tools sesi ini; server/PKI tetap BLOCKED. Exact `cipher none`, `auth none`, `comp-lzo` dipertahankan beserta risiko; kompatibilitas OpenVPN 2.6 memerlukan test/keputusan eksplisit, bukan substitusi AES/data-ciphers/comp-mode diam-diam.

Pertahankan `NOTICE` dan lisensi MIT lengkap `licenses/Alrescha79-MIT.txt`: **Copyright (c) 2025 Anggun Caksono**. Adaptasi layout/protocol/client bukan izin mendistribusikan opaque binaries/ZIP/private key, dan bukan bukti lisensi semua komponen sama. Peta referensi rinci serta URL eksternal terverifikasi sebelumnya tetap di [alrescha-parity.md](alrescha-parity.md).

Gerbang berikut: review source/manifest/policy dan fixture/mock tests (runner tersedia: `bash tests/run-local.sh`; Bash/Python 3/GNU utils), lalu VPS disposable dengan backup/konsol/admin second session. Uji socket/service/port/auth/key, WS/TLS/gRPC/parser, expiry/PAM/UID/locks, renewal/reinstall/updater/rollback/disconnect/failure dan postboot **manual**. Tidak ada test run atau PASS baru diklaim di sini.
