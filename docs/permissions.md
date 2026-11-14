# Permission, otorisasi dan preservasi

Dokumen ini membedakan **izin membangun source installer**, aksi yang dirancang pada VPS target, dan hasil uji. Bukan izin menjalankan installer di Acode/Android/Termux. Rujukan: `AGENTS.md`, `setup.sh`, `installer/{lib,preflight,dependencies,policy,firewall,openssh,dropbear,runtime,tls,proxies,maintenance}.sh`, `installer/{render,artifacts,checks,state}.py`, `services/*`, `updater/*`. Audit parity/range referensi: [alrescha-parity.md](alrescha-parity.md).

## Scope terotorisasi dan gate

- Target instalasi: **root Ubuntu 24.04 amd64/x86_64, systemd PID 1**, source tepercaya terpisah dari `/opt/nathaya`. Tujuan produksi tetap; tidak menerima destination override caller.
- Scope pengguna mengizinkan apt update/upgrade/dist-upgrade, removal UFW/firewalld yang diinventarisasi/backed up, tunnel/TLS/maintenance/updater, satu direktori public/drop 777, dan reboot akhir **full setelah seluruh gate sukses**. Ini bukan izin memutasi host pengembangan.
- Default `full` kini **BLOCKED sebelum mutasi**, oleh ZIP server OpenVPN yang belum dapat diinspeksi dan binary UDP Custom/BadVPN yang provenance/lisensinya belum disetujui. `artifacts.py:full_blockers` tidak dibuka hanya dengan mengganti JSON.
- Explicit `core` ialah subset parsial; **tidak pernah reboot**. Tidak mencakup OpenVPN, UDP Custom, BadVPN, IP enforcement atau panel CRUD Xray. Source bukan bukti layanan berjalan.
- Tidak menjalankan apt, firewall, systemctl, akun, installer, reboot, Git/real commands dalam tugas dokumentasi ini. Tidak commit/push/publish. Pertahankan perubahan pengguna dan penghapusan `nathaya.txt`.

## Ownership/mode yang diperbolehkan

Prinsip: **root:root**, tidak writable oleh user layanan/akun tunnel untuk kode, config, DB, key, unit dan parent-nya. Gunakan umask 077 bagi worker/metadata/key/log/transaksi privat. Tidak ada recursive 777 atau recursive permission relaxation.

| Kelas/path produksi | Owner dan mode | Batas |
|---|---|---|
| `/opt/nathaya`, subdir kode modules/config/installer/services/updater/bin/licenses | root:root, direktori 755 | Parent tidak group/world-writable; file code tidak boleh diganti akun tunnel. Manifest aktual mencakup consumer installer/services/maintenance/updater, VERSION/NOTICE/lisensi; bukan manifest dasar lama. |
| `menu.sh`, `/opt/nathaya/updater/update.sh`, `/usr/local/bin/menu`, `/usr/local/bin/nathaya-update`, binary `/opt/nathaya/bin/xray` | root:root 755 | Hanya entrypoint/binary yang perlu executable. Wrapper milik aplikasi lain tidak ditimpa. |
| Modul/helper Python/Bash, example config nonrahasia, VERSION/NOTICE/lisensi | root:root 644 | Library dipanggil interpreter/source tepercaya, bukan menjadikan semua file executable. Example tidak boleh berisi secret. |
| Unit/timer `/etc/systemd/system/*.service`, `*.timer`; `/etc/profile.d/nathaya-dashboard.sh` | root:root 644 | Hanya unit/hook milik Nathaya terverifikasi; konflik/edited foreign unit ditolak. Tidak chmod direktori systemd global menjadi privat/777. |
| `/etc/nathaya-tunnel`, services, tls, xray dan subdir protokol | root:root, direktori 700 | Config JSON/proxy/TLS/metadata privat; bukan code source dari user. |
| `/etc/nathaya-tunnel/config.conf`, services/{nginx.conf,haproxy.cfg}, xray/*/config.json, xray-binary.json, managed-services.json | root:root 600 | Config aktif/clients/key preserved. Config utama allowlist data, tidak dieksekusi sebagai shell. |
| `/opt/nathaya/data`, data/ssh | root:root, direktori 700 | Satu DB, bukan area upload/export. |
| `data/ssh/{accounts.db,accounts.lock,operations.lock}` | root:root 600 | Jangan copy DB workspace/Alrescha, truncate, migrate, menambah kolom atau menghapus record diam-diam. |
| `/opt/nathaya/logs` | root:root direktori 700; file privat 600 | Install/Telegram/reconcile/unit/parser/error logs dapat sensitif; bukan download publik. Ikuti kebutuhan runtime yang diaudit, jangan mengatasi error akses dengan 777. |
| `/var/cache/nathaya-tunnel`, location.cache | root:root direktori 700, file 600 | Bukan sumber executable/config untuk root. |
| `/var/backups/nathaya-tunnel`, run.*/renew.*/stage/replaced | root:root direktori 700, file 600 | Backup config/key/jurnal/apt inventory/log bersifat privat. Executable Xray dalam staging hanya sementara 700 untuk validasi. Jangan publish arsip backup. |
| `/opt/nathaya/updater-state`, transactions/run-* | root:root direktori 700; state/marker/jurnal/backup 600 | installed/manual-verification/auto/pending JSON bukan data publik. Jangan menghapus pending journal untuk memaksa update. |
| `/run/nathaya-tunnel-setup.lock` | root:root direktori 700 | Lock bersama setup/updater/renewal; stale perlu inspeksi manual, bukan diambil paksa. |
| `/run/sshd` | root:root 755 | Direktori runtime OpenSSH; jangan ubah ke 777. |
| `/etc/dropbear`, dropbear_ed25519_host_key | root:root direktori 700, private key 600 | Valid existing key dipertahankan; unik lokal pada first install. |
| `/etc/ssh/ssh_host_*_key` | root:root 600 | Existing key valid dipreservasi, hanya missing key dibuat lokal; jangan mencetak isi. Public `.pub` bukan private key, tidak perlu world-writable. |
| `/etc/nathaya-tunnel/tls/{fullchain.pem,privkey.pem,haproxy.pem}` | root:root 600, parent 700 | Combined HAProxy PEM memuat private key. Jangan menyamakan certificate publik dengan izin membuka combined PEM. |
| `/etc/letsencrypt/live/<domain>/*` dan archive terkait | Tata kelola Certbot, parent privat/root-controlled | Pengecualian symlink **hanya lineage tervalidasi** ke archive domain sama, tidak symlink arbitrary destination. Jangan chmod rekursif tree Certbot. |
| `/opt/nathaya/public`, `/opt/nathaya/public/openvpn` | root:root direktori 755 | Bukan 777. Bila OpenVPN kelak disetujui, hanya artefak client nonrahasia yang ditinjau boleh file 644 untuk web worker; saat ini core tidak menghasilkan file itu. |
| **`/opt/nathaya/public/drop` saja** | **root:root direktori 777, nonrekursif** | **Satu-satunya pengecualian**; tidak disajikan web, tidak dieksekusi/disource, tidak dibaca/diimpor/dipakai sebagai input root. Bukan tempat staging updater, config, DB, TLS atau backup. |
| Runtime Nginx `/run/nathaya-nginx` | Unit RuntimeDirectoryMode=0750; body cache www-data:www-data 0700 | Akses worker eksplisit sebatas cache/runtime; bukan izin mengubah kode/config/TLS atau parent privat. |

Mode 755/644 untuk kode tidak berarti rahasia boleh ditaruh di kode. Mode 700/600 untuk data tidak berarti root kebal terhadap source berbahaya. Direktori drop 777 sengaja mengizinkan pembuatan/penghapusan file nonrahasia oleh user lain; tidak ada jaminan kerahasiaan/integritas/retensi. **Jangan menggunakannya sebagai transport ke operasi root**, termasuk symlink, nama file, job, hook, atau binary update. Parent `/opt/nathaya`, `/opt/nathaya/public` dan seluruh parent kode/private **tidak boleh 777**. Tidak memperluas pengecualian ke `/etc/xray`, `/var/log`, webroot, home, DB atau key seperti referensi.

## Path, source, config dan transaksi

`nt_safe_path` menolak symlink pada komponen destination, tipe salah dan regular file dengan hardlink >1; `nt_secure_parents` menuntut direktori existing root-owned tanpa group/world-write. Periksa **sebelum** apt/deploy, bukan sesudah menerima file berbahaya. Pengecualian public/drop bukan alasan menonaktifkan validasi parent tujuan lain. Lineage Certbot adalah kasus khusus yang diverifikasi terpisah.

Helper source hanya mendefinisikan fungsi/path/warna; tidak menjalankan jaringan/mkdir/chown/akun/menu ketika dimuat. Entry point root membersihkan environment, menggunakan PATH tetap, interpreter dan path kode tepercaya. Override bootstrap untuk fixture tidak menjadi izin mengganti destination produksi.

`config.conf` hanya menerbitkan DOMAIN, TELEGRAM_STATUS, TELEGRAM_BOT_TOKEN, TELEGRAM_ADMIN_ID melalui parser literal. Bukan `source config.conf`; tidak menerima PATH/helper/runtime override, ekspansi shell/perintah atau secret bawaan. Baru dibuat dari example kosong/Telegram OFF hanya bila belum ada. Existing tidak diganti dengan example. Pengiriman akun Telegram opt-in masih berpotensi mengirim informasi login; izin file bukan jaminan privasi layanan pihak ketiga. Jangan mencetak token/ID privat/password/key ke log/laporan atau menyimpannya ke Git.

Backup sebelum replacement, staging privat, SHA-256 snapshot dan validasi source ulang diperlukan. Ganti file atomik dengan mode/owner benar, catat replaced-files/new-files, publish wrapper terakhir. Jangan menyalin `.git`, tests, config aktif, DB, log/cache/identitas workspace atau secret referensi. Rerun menjaga clients/key/config/DB; invalid key atau foreign/edited unit harus berhenti, bukan regenerate/overwrite diam-diam. Instalasi gagal dapat meninggalkan OS/firewall/service/kode parsial; jurnal/backup **bukan rollback OS otomatis**.

## Apt, firewall dan akses administrator

Upgrade/dist-upgrade OS **diizinkan** oleh scope baru. Simulasi paket harus menolak removal komponen kritis (OpenSSH/PAM/NSS/systemd/network/kernel/apt/dpkg/essential/protected dan lain-lain sesuai `dependencies.sh`), menyimpan rencana/hasil privat, memakai confdef/confold dan memeriksa SSH sebelum/sesudah. Paket/proses dapat diganti/direstart selama maintenance; janji lama “tidak upgrade apa pun” tidak berlaku untuk scope baru. Jangan menghapus lock apt atau membunuh unattended-upgrades; tunggu/batalkan aman.

Policy-rc.d sementara dan NEEDRESTART_SUSPEND menahan aksi layanan standar pada instalasi dependensi; policy existing dibackup dan dipulihkan. Itu **bukan sandbox** terhadap maintainer script/hook apt kustom yang memanggil systemctl langsung. Gunakan maintenance window, rescue console dan sesi admin kedua.

Simpan/inventarisasi konfigurasi UFW/firewalld yang terpasang dan snapshot iptables/nft sebelum disable/purge manager itu. Guard rencana removal tetap berlaku. Removal boleh mengubah rules milik manager terkait, tetapi **tidak mengizinkan global flush nft/iptables, menghapus provider/foreign rules, atau mengganti firewall provider**. Core tidak perlu NAT; tidak menambah DNAT/REDIRECT/MASQUERADE/ip_forward/persistence untuk menutupi layanan yang belum ada. Redirect UDP 53→5300 referensi dikecualikan karena tidak ada listener 5300 terbukti. NAT OpenVPN subnet 10.8.0.0/24 dan 20.8.0.0/24 **tidak aktif, BLOCKED** bersama server; bukan firewall siap OpenVPN.

Admin port/auth/config/key dan enablement service/socket wajib dipreservasi. Ubuntu socket activation berarti `ssh.service` inactive sendiri bukan bukti SSH mati: periksa juga `ssh.socket` dan listener. Tidak rewrite sshd_config/root login/password/public-key/admin PAM untuk menyesuaikan akun VPN. Daemon tambahan loopback 2222/2223 harus diuji dengan config efektif agar ListenAddress existing tidak mengeksposnya. Konflik port/stock unit/foreign hook berhenti sebelum mutasi, bukan memindahkan SSH admin. Baseline fingerprint bukan audit lengkap semua Match/Include kustom; akses admin eksternal tetap wajib diuji operator.

## Privilege layanan dan monitor

- Renderer membuat unit core dengan UMask 0077, hardening systemd dan capability/write-path terbatas; Xray port tinggi/stats loopback tidak perlu low-port capability. HAProxy/Nginx memerlukan bind/UID/GID sesuai unit, worker Nginx memiliki akses cache saja.
- Relay `nathaya-ws` DynamicUser, fixed `127.0.0.1:10015 → 127.0.0.1:109`; tidak menerima arbitrary target dari header/CLI. Xray backend dan stats loopback, Nginx internal hanya menerima PROXY dari HAProxy lokal. Tidak membuka stats API ke publik.
- SSH/Dropbear memerlukan privilege PAM/switch UID normal; renderer sengaja tidak menerapkan NoNewPrivileges/empty capabilities yang mematahkan login. Ini bukan izin mengurangi isolasi semua unit. Dropbear `-w` menolak root login; admin OpenSSH tetap terpisah.
- Source expiry SSH **sudah ada**, bukan sekadar placeholder: service/timer `nathaya-ssh-expire.*`, worker `modules/maintenance/ssh-expire.sh`. Worker root memakai satu DB/locks Nathaya, validasi record/identity non-root dan re-read sebelum `chage -E 0`, kill sesi UID terverifikasi, status expired. Tidak menghapus user atau auto-unlock password/admin locks. Trial timestamp vs regular akhir tanggal tetap kontrak yang harus diuji.
- Tidak ada real-peer **IP collector** lintas SSH/WS/Dropbear/OpenVPN: limit_ip **BLOCKED**, metadata tidak boleh dipasarkan sebagai enforcement. Tidak memasang limitip/limitquota/DB monitor Alrescha. Tidak ada CRUD panel akun Xray atau DB protokol hasil copy.
- Dashboard **kini membaca** unit aktual: SSH service atau socket, empat instance Xray (semua active untuk ON), Dropbear/Nginx unit Nathaya; versi dari VERSION kode, SSH count dari DB dan total protokol dari config, bukan literal nol/akun Linux. Ini bukan tes koneksi atau panel CRUD Xray. Hook login membatasi root SSH interaktif/login TTY sekali, tidak mengganti shell; SCP/SFTP/noninteractive bukan target, root profile/history tidak dihapus.
- Set Domain mengambil lock bersama dan menolak migrasi jika managed-services.json ada; tidak mengganti identitas TLS/proxy terkelola lewat menu. Worker/viewer terpisah: HUP tidak membatalkan worker, viewer tidak pernah melepas lock worker. Cleanup failure melacak unit/timer baru-active dan enablement baru, bukan rollback layanan existing/OS/firewall/code menyeluruh.

Mode/hardening yang tertulis belum membuktikan worker bisa membaca key/log/cache dengan izin efektif. Jangan “memperbaiki” deployment yang gagal memakai chmod 777; perbaiki kontrak UID/path/capability secara terarah dan uji.

## TLS, binary dan OpenVPN

Certbot paket dan ACME standalone memerlukan domain menuju VPS, port 80 dan consent ToS; valid certificate/key existing dipertahankan. Validasi domain/masa berlaku/public-key match dan lineage sebelum sync private copy/combined PEM. Renewal berbagi lock, backup dan pemulihan proxy; tidak mengunduh acme.sh atau menjalankan script remote. Reissue paksa/replace identity bukan cara menutupi mismatch; kegagalan berhenti. Renewal/reload masih perlu uji nyata.

`installer/external-lock.json` mengunci Xray **v26.11.9**, `Xray-linux-64.zip`, SHA-256 `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82`. Downloader memeriksa release metadata/tag/digest/asset HTTPS, batas ukuran, redirect allowlist, ZIP member aman dan ELF64 amd64; tidak `extractall` atau execute script remote. Digest lock yang disediakan **bukan** bukti agen telah men-download/hash/run binary, signature penerbit atau reproducible build. Pertahankan LICENSE Xray terpisah; binary UDP/BadVPN dan archive OpenVPN tetap tidak disetujui.

Referensi mengandung private host key; **jangan copy/download/reuse**. Key SSH/Dropbear dibuat unik lokal, valid existing dipertahankan; jangan keluarkan isi key ke tool/log/laporan. PKI OpenVPN belum boleh ditebak: ZIP tidak terbaca oleh tools sesi ini dan audit archive aktual belum dijalankan, **tidak ada inspected-member claim**. `tools/audit-openvpn.py` kini ada (offline read-only/bounded/redacted, tanpa ekstraksi/eksekusi); itu bukan persetujuan PKI/provenance/lisensi. `templates/openvpn/*.ovpn.in` dan `tools/openvpn-clients.py` juga ada: generator fixture dengan insecure acknowledgement/public CA caller, hanya output baru privat di temporary directory, tanpa server PKI/runtime/NAT. Server tetap BLOCKED.

Client referensi `setup.sh:835–909` harus tetap tepat, termasuk `cipher none`, `auth none`, `comp-lzo`. Directive itu membawa risiko encryption/integrity/compression; OpenVPN 2.6 memakai data-ciphers untuk negosiasi TLS dan exact legacy profile dapat gagal negosiasi tanpa cipher bersama. **Diperkirakan, belum diuji**; perlu keputusan pengguna setelah server/archive dapat diaudit. Tidak diam-diam menambah data-ciphers/fallback/AES, menghapus kompresi atau mengubah auth agar terlihat kompatibel. Full tetap BLOCKED, OpenVPN NAT/download/service tidak diaktifkan.

Sumber eksternal aktual: [Xray release v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9), [metadata GitHub yang digate](https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.11.9), [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/). Pin/digest dari external-lock, bukan tebakan versi “latest”.

## Maintenance, updater dan reboot

Tidak menyalin cron legacy: expiry 00:02, warning 09:00/18:00, logclear tiap enam jam, atau daily reboot. Nathaya menggunakan timer expiry 15 detik dan certificate check 03:25/15:25 + jitter ≤30 menit; keduanya source belum diuji. Tidak overwrite /root/.profile, /etc/shells atau history. Tidak membuat swap/fstab, fail2ban ban permanen, Node/npm/vnstat build tanpa implementasi dan keputusan terkait.

Updater kode terpisah (`updater/*`) memakai stable GitHub `Yusuf2790/nathaya-tunnel`, policy/validator lokal tepercaya, versi/schema/manifest/hash, lock bersama, backup+jurnal dan rollback kode. **Tidak menyentuh config aktif, DB, key, akun, upgrade OS, setup atau reboot.** Timer update daily+jitter ≤1h tidak diaktifkan installer; manual verification sukses dan opt-in diperlukan. Tidak melemahkan validasi apabila release tidak tersedia. Recovery parsial/pending journal perlu inspeksi manual; rollback kode bukan rollback OS/account/data.

Installer state.py sudah melakukan inspect/check sebelum mutasi, prepare sesudah lock, validate-prepared sesudah staging dan commit **hanya postverification**. Downgrade, baseline/schema inconsistency dan pending recovery ditolak; same-version baseline cocok dipertahankan byte-nya. Runtime tidak menulis installed.json lebih awal. Kegagalan setup tidak rollback code/OS otomatis; jangan reset identity/pending untuk menutupi partial install.

Reboot hanya full + FULL_SUCCESS + seluruh mandatory gate sukses, countdown 30 detik dengan cancel root. Cleanup/status/exit-code/log difinalisasi **sebelum** permintaan power. Core, failure, help, plan, fixture dan updater **tidak reboot**. Full saat ini unreachable fail-closed sebelum mutasi; jangan mengiklankan reboot terbukti terjadi. Operator hanya mempertimbangkan reboot core **manual sesudah test PASS**, backup/konsol siap dan wajib cek login eksternal lagi sesudah boot.

## Lisensi dan verifikasi

Pertahankan `NOTICE` dan `licenses/Alrescha79-MIT.txt` yang sudah ada: **MIT, Copyright (c) 2025 Anggun Caksono**, termasuk notice izin/disclaimer lengkap pada salinan substansial adaptasi. Jangan menganggap MIT Alrescha otomatis melisensikan semua binary/ZIP/template pihak ketiga; atribusi lain dan lisensi binary yang belum diketahui tetap dicatat, bukan dihapus. Jangan memasukkan secret/private key referensi ke artefak lisensi/audit.

Pengguna melaporkan tahap **dasar** pernah exit 0 dengan dashboard dan service/socket SSH. Itu laporan pengguna, bukan eksekusi agen, dan tidak membuktikan core/full baru. Tool sesi ini tidak mengeksekusi Bash/Python/Git, tests, binary, apt/systemctl/firewall atau VPS; **seluruh tes baru belum dijalankan**, status Git tidak diasumsikan bersih. Keberadaan test/source/unit bukan PASS.

Temuan source lama tentang manifest dasar/consumer, dashboard stock lookup, endpoint `/healthz` dan reload **sudah diperbaiki**: manifest runtime lengkap untuk consumer baru, dashboard membaca unit/DB/config/VERSION, renderer menyediakan health endpoint serta ExecReload Nginx/HAProxy. Lima dokumen publik ini package-only dalam policy, tidak dipasang ke VPS; progress/tests/data/.git dikecualikan. Required installed non-deploy trust base updater yang missing/drift tetap BLOCKED untuk reviewed manual source reinstall, bukan self-update validator dari release.

Gate sebelum deploy tetap ownership/hardening efektif, parser/syntax/fixture tests, kemudian VPS disposable dengan backup/rescue/admin second session, `sshd -t`, service+socket/listener serta login eksternal baru sebelum menutup sesi lama. Pengguna dapat memakai runner yang kini tersedia `bash tests/run-local.sh`; butuh Bash, Python 3, GNU utils. Keberadaan source health/reload bukan bukti renewal sukses. Lihat [alrescha-parity.md](alrescha-parity.md). Tidak memperluas tugas menjadi edit kode/eksekusi nyata; tidak ada klaim full completed/production-ready/VPS-tested.
