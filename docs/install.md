# Instalasi dari source — core parsial, full BLOCKED

## Status dan prasyarat

Source `VERSION` saat ini **2.0.0**. Target hanya **root VPS Ubuntu 24.04, x86_64/amd64, systemd PID 1**. Acode/Android/Termux/proot/chroot bukan target installer. Implementasi tertulis tidak membuktikan layanan terpasang atau VPS lolos uji.

- Default `full` **BLOCKED pada preflight sebelum lock/staging/apt/firewall/deployment**: archive server OpenVPN belum dapat diinspeksi dengan tools sesi ini; provenance/lisensi binary UDP Custom dan BadVPN belum disetujui. Mengedit status JSON saja tidak membuka gate.
- `--profile core` adalah opt-in subset: OpenSSH, Dropbear, WS fixed-target, TLS Certbot, Nginx, HAProxy, empat instance Xray, expiry SSH dan hook dashboard. **Tidak ada OpenVPN/UDP Custom/BadVPN, enforcement IP lintas transport, atau panel CRUD Xray. Core tidak reboot.**
- Kedua profil instalasi mengotorisasi **apt update, upgrade, dist-upgrade**, removal UFW/firewalld terinventarisasi, serta `/opt/nathaya/public/drop` 777 nonrekursif/nonrahasia. Ini perubahan sistem besar, bukan installer SSH dasar lama. Tidak ada rollback OS/kode otomatis bila setup gagal.

Sebelum rebuild: snapshot/backup privat config, DB, key, sertifikat dan data aplikasi; pastikan restore dapat dilakukan dan konsol/rescue provider berfungsi. Catat port/metode autentikasi admin dan firewall provider; pertahankan port itu saat membuka port layanan. Removal firewall manager dapat membuka akses yang dahulu ditolak atau meninggalkan aturan lain: tinjau kebijakan provider secara terpisah, jangan menganggap semua port terbuka/aman. Upgrade paket dapat mengganti binary dan me-restart proses.

Gunakan maintenance window tanpa apt/installer/operasi akun paralel. Root filesystem perlu ≥3 GiB kosong pada preflight, **bukan jaminan cukup untuk upgrade**. Preflight memerlukan Bash, Python 3, utilitas GNU dasar, apt/dpkg, systemd, `ss`, `ip`, `tar` dan SHA-256; jangan mengasumsikan bootstrap dapat memasang prasyarat preflight yang belum ada. Akses repo Ubuntu, GitHub HTTPS dan CA/ACME diperlukan.

Domain nyata harus menunjuk IPv4 publik VPS; ACME standalone memerlukan inbound TCP 80 dan consent ToS eksplisit. Port 80 yang telah dipakai aplikasi lain adalah konflik, bukan alasan menghentikannya sembarangan. Renewal juga memerlukan DNS/CA/port 80 dan menghentikan HAProxy terkelola yang semula aktif sebentar ketika challenge due, lalu memulihkannya. Hanya proxy aktif yang divalidasi/reload; Nginx yang sengaja berhenti dan tidak punya direktori runtime tidak menghalangi reload HAProxy aktif. DNS/sertifikat valid bukan bukti koneksi semua transport berhasil.

## Pemeriksaan pengembangan sebelum VPS

**Pengguna yang menjalankan**, sebagai user non-root dari checkout tepercaya yang bisa diakses Termux. Butuh Bash, Python 3 dan GNU coreutils/findutils/grep/sed serta utilitas yang diminta test. Runner `tests/run-local.sh` kini tersedia; gunakan setelah source tes ditinjau:

```sh
cd nathaya-tunnel
bash tests/run-local.sh
```

Alternatif individual yang sudah ada:

```sh
bash tests/foundation.sh
bash tests/installer.sh
bash tests/expiry.sh
bash tests/full.sh
python3 -I -B tests/integration_test.py
python3 -I -B tests/services_test.py
python3 -I -B tests/openvpn_test.py
python3 -I -B tests/update_test.py
```

Fixture/mock bukan sandbox untuk source tidak tepercaya dan bukan uji apt/systemd/akun/jaringan/VPS. **Tidak ada test atau command sistem/Git yang dijalankan agen dalam tugas dokumentasi ini.** Jangan menandai PASS hanya karena file test ada. Pengguna pernah melaporkan installer **dasar lama** exit 0 dengan dashboard dan SSH service/socket; itu terpisah dari validasi core/full baru.

## Menjalankan core pada VPS staging/rebuild

Hanya **setelah tes lokal benar-benar PASS**, review source, backup dan akses konsol siap. Source harus lengkap, tepercaya dan terpisah dari `/opt/nathaya`, misalnya `/root/nathaya-source`; lokasi source berasal dari script, bukan cwd. Tidak ada override tujuan produksi. Jangan membawa `.git`, DB/config aktif, log/cache atau secret workspace; `nathaya.txt` yang dihapus pengguna tidak diperlukan dan tidak dipulihkan. Jangan `curl | bash`.

```sh
# Bantuan read-only:
bash /root/nathaya-source/setup.sh --help

# HANYA pada VPS target; ganti domain contoh dengan domain nyata milik Anda:
sudo bash /root/nathaya-source/setup.sh --profile core \
  --domain vpn.example.org --accept-acme-tos
```

Tanpa `--profile core`, default full tetap menolak; `--plan` melaporkan blocker dan dapat exit nonzero secara sengaja. Jangan melemahkan gate, mengganti cipher/auth/compression OpenVPN, atau memasang binary pengganti agar setup tampak sukses.

## Urutan aktual dan preservasi

1. **Preflight read-only:** root/OS/arsitektur/PID1, manifest serta sintaks Bash/Python/JSON, source/target terpisah, config allowlist, wrapper/hook/unit/port conflict, symlink/hardlink/tipe/parent tujuan, dpkg, ruang disk, domain/DNS, baseline SSH dan metadata Xray pinned. Full ditolak pada gate artefak. `installer/state.py` menolak downgrade, identity/schema tidak konsisten dan pending recovery updater. Domain existing berbeda ditolak, bukan dimigrasi.
2. Ambil lock bersama `/run/nathaya-tunnel-setup.lock` 700. Buat run privat `/var/backups/nathaya-tunnel/run.*`, snapshot baseline `updater-before.json` melalui `prepare`; staging allowlist dengan SHA-256 dan validasi ulang (`validate-prepared`) sebelum mutasi OS. Tidak menghitung manifest dengan angka tetap: `nt_program_files`/`nt_source_files` di `installer/lib.sh` adalah sumber daftar.
3. Worker terpisah mengabaikan HUP, stdin `/dev/null`, log permanen privat `/opt/nathaya/logs/install-*.log`. Viewer menampilkan log; **menutup viewer/sesi SSH tidak membatalkan worker dan viewer tidak pernah melepas lock worker**. Run menyimpan `worker.pid`, `stages.tsv`, `result`, `exit-code`; jangan menganggap viewer exit 0 berarti instalasi sukses.
4. Apt update lalu simulasi/upgrade/dist-upgrade dengan guard removal komponen kritis dan confdef/confold; pasang dependensi core yang belum ada. Apt lock ditunggu terbatas, bukan dihapus; unattended-upgrades tidak dibunuh. Policy-rc.d sementara deny-101 + NEEDRESTART_SUSPEND pada pemasangan dependensi menahan aksi standar, **bukan sandbox maintainer script/hook apt kustom**, dan bukan janji OS upgrade tanpa restart. Policy existing dibackup/dipulihkan.
5. Buat hanya host key yang hilang secara lokal; key valid existing dipertahankan. Inventaris/backup konfigurasi UFW/firewalld dan snapshot rules bila utilitas tersedia sebelum disable/purge. Tidak global flush provider/foreign rules, NAT, ip_forward atau persistence core. DNAT UDP 53→5300 referensi **tidak dibuat** karena listener 5300 belum terbukti; NAT OpenVPN masih BLOCKED.
6. Deploy kode allowlist per file dengan backup, init config/DB hanya bila belum ada, pasang wrapper menu/updater, hook dan template unit. Config baru Telegram OFF/token/admin kosong. `public/drop` saja 777; tidak disajikan web, dieksekusi, disource atau dikonsumsi root. Lihat [permissions.md](permissions.md).
7. Issue/preserve TLS tervalidasi, download Xray pinned hanya jika metadata/digest/hash/lisensi lolos, render/validasi/start unit core dan timer expiry/renewal. Fresh Xray clients kosong, existing config/clients dipertahankan; panel akun Xray tetap unavailable. Auto-updater **tidak di-enable**.
8. Verifikasi `sshd -t`, baseline akses admin, unit/timer, parser empat Xray, listener dan HTTPS lokal `/healthz`. Renderer kini menyediakan endpoint itu dan `ExecReload` Nginx/HAProxy. Ini pemeriksaan lokal, bukan login eksternal atau PASS VPS.
9. **Sesudah verifikasi**, `state.py commit` menerbitkan `updater-state/installed.json` untuk VERSION yang cocok. Rerun versi sama mempertahankan byte baseline existing bila identik; tidak me-reset identity sebelum gate sukses. Core menghasilkan `CORE_SUCCESS`, exit-code/log permanen, **tanpa reboot**. Full-success/reboot sekarang tidak terjangkau karena fail-closed.

SSH admin existing tidak ditulis ulang: port, authentication/PAM, host key, sshd_config/Include dan enablement service/socket dipertahankan. Selama upgrade OS proses boleh berganti; sesudahnya baseline proses/socket diperbarui untuk pemeriksaan tahap aplikasi. `ssh.service` inactive sendiri bukan kegagalan jika `ssh.socket` aktif. Existing OpenSSH tanpa service/socket aktif ditolak untuk keputusan admin manual. Untuk paket baru, start/enable service seperlunya mengikuti unit Ubuntu. Fingerprint standar/`sshd -T` bukan audit semua konteks Match/Include. Akun menu tidak otomatis mendapat password login bila kebijakan admin melarangnya.

## Hasil, rerun dan kegagalan

Kode `/opt/nathaya`; wrapper `/usr/local/bin/menu` dan `/usr/local/bin/nathaya-update`; config `/etc/nathaya-tunnel`; satu DB `/opt/nathaya/data/ssh/accounts.db`; cache `/var/cache/nathaya-tunnel`; state updater `/opt/nathaya/updater-state`. Permission dan unit lengkap: [architecture.md](architecture.md), [permissions.md](permissions.md).

Rerun dari source terpisah menjaga config, DB tujuh kolom/legacy, key, clients, log/cache dan file tak dikenal. Tidak ada migrasi diam-diam atau pengosongan runtime. Target asing/edited unit tidak ditimpa untuk memaksakan pemasangan. Set Domain menolak perubahan bila `managed-services.json` ada: identitas TLS/proxy memerlukan migrasi terkoordinasi, bukan edit menu.

Bila gagal, hasil `GAGAL`, tahap/log/backup privat adalah bukti yang perlu diperiksa. Trap berusaha memulihkan temporary policy, menghentikan unit/timer yang tadinya tidak aktif dan men-disable enablement yang baru diubah bila gates belum sukses, lalu melepas lock. Ini **bukan rollback service/OS/firewall/kode/akun menyeluruh**; unit existing yang sudah di-restart tidak otomatis dikembalikan. `replaced-files`/`new-files` dan backup mode 600 membantu recovery manual; kembalikan owner/mode runtime yang tepat, bukan menyalin seluruh `/opt/nathaya` di atas data.

SIGKILL/power loss/storage failure dapat meninggalkan lock/policy/pending/instalasi parsial. Jangan menghapus lock atau pending JSON untuk memaksa lanjut; pastikan worker/apt/updater/renewal tidak aktif, periksa jurnal sebagai **data**, dan pulihkan melalui konsol. Baseline installed lama dapat tertinggal walau sebagian kode/VERSION berubah pada kegagalan; rekonsiliasi manual diperlukan, bukan reset identity. Updater memiliki rollback kode sendiri, berbeda dari setup; lihat [update.md](update.md).

Full yang kelak lolos seluruh gate dirancang countdown 30 detik dengan cancel root; cleanup/status/exit-code/log difinalisasi **sebelum** permintaan power. Saat ini jalur itu unreachable. Tidak ada reboot harian, reboot core, reboot updater atau reboot pada failure/help/plan/test.

## Checklist VPS disposable dan sesudah rebuild

1. Simpan baseline `sshd -t`, konfigurasi/key, admin port/auth, status+enablement **ssh.service dan ssh.socket**, socket/listener, serta snapshot firewall provider. Gunakan konsol dan sesi admin kedua.
2. Jalankan core hanya dengan syarat di atas; baca result/exit-code worker. Periksa `sshd -t`, service/socket, unit Nathaya/empat Xray dan `ss -lntup` secara nyata. Peta port dalam audit adalah rencana konfigurasi, bukan bukti port aktif.
3. Dari mesin lain, buka **login SSH baru dengan port dan metode admin semula** sebelum menutup sesi existing. Uji `sudo menu`, hook login interaktif, SCP/SFTP/noninteractive tanpa dashboard; cek version, counts DB/config dan badge unit.
4. Uji WS RFC6455 dan legacy, TLS/CA/gRPC, routing deterministic/PROXY protocol dan backend loopback; cek tidak ada stats API publik. Xray config kosong bukan akun uji tersedia. Uji expiry trial/regular/PAM/key, shared locks, guard UID dan preservasi password/admin lock; limit_ip bukan enforcement.
5. Pada snapshot terpisah uji reinstall/preservasi byte/key, konflik port/unit/domain, kegagalan apt/parser/download/disk/disconnect, cleanup timer/enablement dan recovery. Uji renewal due/staging CA secara terencana (DNS/inbound 80/konflik port/reload/pemulihan proxy), bukan reissue production berulang. Updater perlu release stable nyata, digest dan check manual sebelum opt-in.
6. **Hanya setelah tes core PASS**, bila maintenance OS memerlukan reboot, operator dapat reboot **manual** pada maintenance window dengan konsol siap. Core tidak menjadwalkannya. Setelah boot ulang ulangi unit/socket/listener dan login eksternal baru; jangan menyebut postboot verified sebelum benar-benar diuji. Full/OpenVPN/UDP tetap BLOCKED.

Tidak ada klaim full completed, semua layanan aktif, production-ready atau VPS baru terverifikasi.

Referensi desain (bukan bukti uji):
- Ubuntu 24.04/OpenSSH socket: https://documentation.ubuntu.com/release-notes/24.04/
- Policy layanan/status 101: https://manpages.ubuntu.com/manpages/noble/man8/invoke-rc.d.8.html
- needrestart: https://discourse.ubuntu.com/t/needrestart-changes-in-ubuntu-24-04-service-restarts/44671
- Hook suspend: https://github.com/liske/needrestart/blob/master/ex/apt/apt-pinvoke

Adaptasi Alrescha tetap beratribusi MIT, Copyright (c) 2025 Anggun Caksono; pertahankan `NOTICE` dan izin/disclaimer lengkap `licenses/Alrescha79-MIT.txt`. Lisensi itu bukan persetujuan binary pihak ketiga.
