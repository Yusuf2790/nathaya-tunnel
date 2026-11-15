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
8. Verifikasi `sshd -t`, baseline akses admin, unit/timer, parser empat Xray, listener, identitas master/worker HAProxy dari `/proc` dan HTTPS lokal `/healthz`. Renderer menyediakan endpoint itu dan `ExecReload` Nginx/HAProxy. Gate identitas dirinci pada [diagnosis HAProxy](#haproxy-2830-diagnosis-dan-reinstall). Ini pemeriksaan lokal, bukan login eksternal atau PASS VPS.
9. **Sesudah verifikasi**, `state.py commit` menerbitkan `updater-state/installed.json` untuk VERSION yang cocok. Rerun versi sama mempertahankan byte baseline existing bila identik; tidak me-reset identity sebelum gate sukses. Core menghasilkan `CORE_SUCCESS`, exit-code/log permanen, **tanpa reboot**. Full-success/reboot sekarang tidak terjangkau karena fail-closed.

SSH admin existing tidak ditulis ulang: port, authentication/PAM, host key, sshd_config/Include dan enablement service/socket dipertahankan. Selama upgrade OS proses boleh berganti; sesudahnya baseline proses/socket diperbarui untuk pemeriksaan tahap aplikasi. `ssh.service` inactive sendiri bukan kegagalan jika `ssh.socket` aktif. Existing OpenSSH tanpa service/socket aktif ditolak untuk keputusan admin manual. Untuk paket baru, start/enable service seperlunya mengikuti unit Ubuntu. Fingerprint standar/`sshd -T` bukan audit semua konteks Match/Include. Akun menu tidak otomatis mendapat password login bila kebijakan admin melarangnya.

## Hasil, rerun dan kegagalan

Kode `/opt/nathaya`; wrapper `/usr/local/bin/menu` dan `/usr/local/bin/nathaya-update`; config `/etc/nathaya-tunnel`; satu DB `/opt/nathaya/data/ssh/accounts.db`; cache `/var/cache/nathaya-tunnel`; state updater `/opt/nathaya/updater-state`. Permission dan unit lengkap: [architecture.md](architecture.md), [permissions.md](permissions.md).

Rerun dari source terpisah menjaga config, DB tujuh kolom/legacy, key, clients, log/cache dan file tak dikenal. Tidak ada migrasi diam-diam atau pengosongan runtime. Target asing/edited unit tidak ditimpa untuk memaksakan pemasangan. Set Domain menolak perubahan bila `managed-services.json` ada: identitas TLS/proxy memerlukan migrasi terkoordinasi, bukan edit menu.

Bila gagal, hasil `GAGAL`, tahap/log/backup privat adalah bukti yang perlu diperiksa. Trap berusaha memulihkan temporary policy, menghentikan unit/timer yang tadinya tidak aktif dan men-disable enablement yang baru diubah bila gates belum sukses, lalu melepas lock. Ini **bukan rollback service/OS/firewall/kode/akun menyeluruh**; unit existing yang sudah di-restart tidak otomatis dikembalikan. `replaced-files`/`new-files` dan backup mode 600 membantu recovery manual; kembalikan owner/mode runtime yang tepat, bukan menyalin seluruh `/opt/nathaya` di atas data.

SIGKILL/power loss/storage failure dapat meninggalkan lock/policy/pending/instalasi parsial. Jangan menghapus lock atau pending JSON untuk memaksa lanjut; pastikan worker/apt/updater/renewal tidak aktif, periksa jurnal sebagai **data**, dan pulihkan melalui konsol. Baseline installed lama dapat tertinggal walau sebagian kode/VERSION berubah pada kegagalan; rekonsiliasi manual diperlukan, bukan reset identity. Updater memiliki rollback kode sendiri, berbeda dari setup; lihat [update.md](update.md).

Full yang kelak lolos seluruh gate dirancang countdown 30 detik dengan cancel root; cleanup/status/exit-code/log difinalisasi **sebelum** permintaan power. Saat ini jalur itu unreachable. Tidak ada reboot harian, reboot core, reboot updater atau reboot pada failure/help/plan/test.

<a id="haproxy-2830-diagnosis-dan-reinstall"></a>

## HAProxy 2.8.30: diagnosis `Cannot set uid 109` dan reinstall

**Status: penyebab aktual kegagalan `setuid` masih UNKNOWN/BLOCKED diagnosis.** Pesan `Cannot set uid 109` tidak menyertakan errno syscall atau membuktikan capability mana yang hilang. Angka 109 adalah UID pada host pelapor, bukan kontrak instalasi. Perubahan capability di bawah memperbaiki kekurangan izin **signal lintas UID untuk lifecycle USR2**, bukan bukti bahwa penurunan UID telah diperbaiki. Fixture/mocks tidak menjalankan `setuid` nyata atau systemd.

### Model privilege dan pemeriksaan runtime

- Tetap root master: unit systemd `User=root`, `Group=root`, `ExecStart` HAProxy `-W -db`; config HAProxy tetap `user haproxy` dan `group haproxy`. Jangan menjalankan seluruh service sebagai `User=haproxy` sebagai jalan pintas.
- Bounding set sempit menjadi **empat** capability: `CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_KILL` (mask `0x4e0`), dari tiga sebelumnya (`0x4c0`). `CAP_KILL` diperlukan root master untuk mengirim signal kepada worker berbeda UID ketika reload/reexec USR2; UID 0 saja tidak menggantikan izin signal bila capability dibatasi. `AmbientCapabilities=` tetap kosong, `NoNewPrivileges=true` dan hardening lain dipertahankan. Jangan memberi semua capability atau mematikan hardening untuk menyatakan sukses.
- Pada upstream **v2.8.30**, `src/linuxcap.c` menginisialisasi `caplist` ke nol; `prepare_caps_for_setuid`/`finalize_caps_after_setuid` melewati perubahan capability bila nol. Daftar itu diisi oleh directive HAProxy `setcap`, yang tidak ditambahkan renderer ini. Build flag `+LINUX_CAP` saja **bukan bukti sebab**. Directive tersebut berbeda dari metadata file capability binary. `CapabilityBoundingSet` adalah batas, **bukan pengukuran CapEff/CapPrm proses** dan bukan errno syscall.
- TLS tetap root:root: direktori `/etc/nathaya-tunnel/tls` 0700 dan PEM/key 0600. Root master memuat PEM saat start/reexec sebelum worker menjatuhkan UID. Jangan menyalin secret, memberi akses worker lewat chmod/chown, atau memakai chmod 777 pada TLS. Perubahan ini tidak mengubah SSH admin maupun kebijakan autentikasinya.
- Pasangan UNIX abstract tetap konsisten: backend `abns@nathaya-tls send-proxy-v2` menuju frontend `bind abns@nathaya-tls accept-proxy ...`. Jangan mencampur `abns`/`abnsz`, mengganti hanya salah satu nama, atau menghilangkan pasangan PROXY protocol.

Gate baru memperoleh `MainPID` unit, membaca master dan **children master itu** dari `/proc/<MainPID>/task/<MainPID>/children`, bukan memilih sembarang proses bernama haproxy. Master wajib UID/GID real/effective/saved/fs semuanya 0, `CapEff=CapPrm=0x4e0`, `CapAmb=0`, `NoNewPrivs=1`. Harus ada worker HAProxy anak langsung dengan UID/GID yang cocok akun/grup `haproxy` host (padankan `getent passwd haproxy` dan `getent group haproxy`, **jangan hardcode 109**); seluruh UID/GID worker harus unprivileged, supplementary groups kosong/hanya GID haproxy, dan `CapEff=CapPrm=CapAmb=0`, `NoNewPrivs=1`. Executable dan snapshot identitas/children juga diperiksa; proses hilang atau generasi berubah saat snapshot membuat gate menolak, bukan mengulang tanpa batas. Ini verifikasi keadaan sesaat, belum membuktikan cold start/reload produksi.

### Diagnosis manual VPS terbatas dan reversible — sebelum klaim UID fixed

**Operator saja pada VPS staging/maintenance dengan konsol dan backup; bukan di Acode/Termux, bukan dijalankan agen.** Dahulukan observasi read-only, jangan restart/override unit utama untuk memperoleh bukti. Pada kegagalan start/reload/identity, diagnostik menampilkan **nama unit** `nathaya-haproxy.service`, lokasi file privat `/opt/nathaya/logs/nathaya-haproxy.log (`%N` menghapus suffix `.service`)` dan perintah `journalctl -u nathaya-haproxy.service --no-pager` **sebelum cleanup**. Yang ditampilkan hanya petunjuk, bukan dump jurnal. Jika operator perlu menjalankan perintah jurnal itu, arahkan stdout/stderr langsung ke file bukti privat, bukan konsol/chat; jangan otomatis mencetak jurnal, sertifikat atau key.

1. Simpan bukti dengan `umask 077` dalam direktori kerja baru milik root mode 0700, file 0600; pertahankan log/backup lama. Catat waktu kegagalan, versi/hash binary dan metadata, bukan isi PEM. Baca properti **effective unit** melalui `systemctl show nathaya-haproxy.service`: `FragmentPath`, `DropInPaths`, `LoadState`, `User`, `Group`, `ExecStart`, `MainPID`, `CapabilityBoundingSet`, `AmbientCapabilities`, `NoNewPrivileges`, `SecureBits`, `SystemCallFilter`, `SystemCallErrorNumber` dan pembatas namespace terkait. Jangan hanya membaca template source. Mask/vendor/runtime fragment atau drop-in dapat membuat konfigurasi efektif berbeda.
2. Bila `getcap` **sudah tersedia**, baca metadata file capability `/usr/sbin/haproxy`; tidak memasang paket/apt dan tidak menjalankan `setcap` untuk mengubah binary. Catat hasil `getent passwd haproxy` dan `getent group haproxy` serta kecocokan primary GID. Ketiadaan alat/bukti harus dilabeli unavailable, bukan dianggap nol/sukses.
3. Dari `MainPID` yang tervalidasi dan children miliknya, simpan field `/proc/<pid>/status`: `Pid`, `PPid`, `Uid`, `Gid`, `CapEff`, `CapPrm`, `CapBnd`, `CapAmb`, `NoNewPrivs` (E/P/B/A/NNP); baca juga `/proc/<pid>/uid_map` dan `gid_map`, serta identitas executable. Jika proses sudah exit, laporkan tidak teramati; snapshot setelah exit tidak menjelaskan privilege pada syscall yang gagal. Cari denial kernel/LSM (misalnya AppArmor/SELinux/seccomp) pada rentang waktu yang sama **secara privat**; jangan menerbitkan log mentah.
4. Jika belum diketahui syscall dan **errno** yang gagal, tetap **BLOCKED diagnosis** dan minta bukti errno yang disanitasi melalui review privat. Bedakan `setuid`/`setgid`/`setgroups`, penyiapan capability dan kegagalan signal; jangan menebak bahwa perubahan bounding set mengatasi semuanya. Korelasikan hanya dengan restriction yang terbukti, lalu review perbaikan tersempit yang reversible; jangan melonggarkan service produksi sebagai eksperimen.

### Tool probe staging yang opt-in

Prosedur probe kini diimplementasikan dalam `tools/diagnose-haproxy.sh`, self-contained (Python stdlib di dalam heredoc), **checkout-only**: tidak dipasang installer dan tidak ditambahkan ke policy updater/rilis. Dari source tepercaya:

```sh
# Bantuan saja; tidak memerlukan root dan tidak membaca/mengubah layanan.
bash tools/diagnose-haproxy.sh --help
# HANYA operator pada VPS staging Ubuntu 24.04 amd64/systemd PID1.
# Perintah ini menjalankan transient probe, BUKAN untuk Acode atau suite offline.
sudo bash tools/diagnose-haproxy.sh --run
```

Tool menolak lock installer yang ada tanpa mengambil/menghapusnya. Fragment utama harus path root-owned yang dikenal, tanpa drop-in atau perubahan yang belum daemon-reload, dengan directive renderer lama/baru yang diaudit; restriction lain yang tidak didukung ditolak. Properti efektif disimpan privat lalu diperiksa, bukan dievaluasi sebagai shell. Bounding tiga capability lama **disalin persis** bila itu keadaan unit; tidak ada percobaan menambah CAP_KILL/CAP_SYS_PTRACE. Ambient tetap kosong, NNP dan hardening dipertahankan. Hanya nilai SecureBits=0 dan filter syscall empty-deny `~` yang didukung, bukan menebak filter allow-list kosong setara. Private network/user namespace/root image tak didukung ditolak karena reservasi endpoint dilakukan di namespace host.

- Workdir baru `/run/nathaya-haproxy-probe.*` 0700, seluruh evidence 0600; nonce membuat dua nama unit dan socket abstract unik. TCP loopback high-port dan abstract address direservasi untuk memastikan bebas, lalu dilepas tepat sebelum gate startup. Bila race bind tetap terjadi, hasilnya kegagalan nyata, bukan alasan memakai endpoint produksi. Config hanya master root/worker haproxy, loopback menuju socket abstract unik yang menolak koneksi; tidak ada backend eksternal, key/PEM atau payload jaringan.
- Setiap transient unit menggunakan **RuntimeMaxSec=8s**, Restart=no, start timeout 5s, stop/abort timeout 2s. Anggaran nominal start + runtime + stop adalah 15 detik, bukan janji kernel dapat menghentikan task uninterruptible. Pre-start gate menahan HAProxy: tool membandingkan seluruh properti efektif sumber/probe sebelum memberi izin eksekusi. Perbedaan metadata/lifecycle/logging yang memang disengaja ditulis privat; restriction/field berbeda yang tidak dikenal, properti yang gagal dibaca, atau deadline gate terlewat menghentikan probe tanpa retry dengan hardening lebih lemah. Hanya StandardOutputFile/StandardErrorFile yang opsional karena sebagian systemd tidak mengeksposnya; tidak ditampilkan berarti metadata unavailable, bukan path kosong terverifikasi atau kegagalan seluruh query. Mode StandardOutput/StandardError tetap wajib append. Path log produksi tidak diperlukan atau dievaluasi. Kedua tujuan probe harus ditetapkan eksplisit, tepat sekali, ke append:workdir/phase/combined.log; jika properti File probe tersedia, nilainya wajib cocok. Properti keamanan lain tidak ikut fallback. Hook Exec kosong ditangani terpisah: hanya daftar Pre/Post/Condition/Stop yang eksplisit pada sumber, sesudah fragment tepercaya terbukti tidak mendefinisikannya, DropInPaths kosong dan tidak ada command efektif Base/Ex tambahan. Probe tetap wajib memiliki ExecStartPre gate dengan argv yang cocok; Reload/Post/Condition/Stop yang memang tidak dideklarasikan boleh absent/empty. Varian aktif tetap ditolak kecuali command wajib yang telah dicocokkan. Perbandingan snapshot menerima representasi absent/empty hanya dengan bukti konteks tervalidasi, bukan pengecualian umum untuk Exec* atau restriction keamanan.
- Run `plain` dilakukan lebih dahulu. Snapshot UID/GID/groups/capability/NNP dan executable master/worker hanya berasal dari cgroup unit milik run ini, dengan directory-FD /proc yang di-anchor, pemeriksaan starttime/keanggotaan ulang sebelum menyimpan. uid_map/gid_map membantu diagnosis namespace; tidak membaca mem, maps, cmdline, environment atau key. Process yang terlalu cepat exit atau akses /proc yang ditolak dicatat unavailable, bukan identitas karangan. Return systemd-run atau parser bukan bukti worker hidup; observed-running memerlukan observasi identitas stabil.
- Hanya kegagalan runtime plain yang memicu unit `trace` terpisah. `/usr/bin/strace` yang sudah tersedia memakai whitelist eksplisit UID/GID/groups, capget/capset, prctl dan fork/clone/wait/exit/signal-send yang diperlukan. Tidak ada execve/%process, read/write, payload jaringan, memory syscall atau dump key; prctl/clone ditampilkan raw agar tidak mendekode struktur memori. Trace memakai stderr yang sudah dibuka systemd ke evidence, sehingga ReadWritePaths tidak diperluas untuk mengizinkan trace-file. Bila tracing ditolak/tidak lengkap, status trace unavailable; tidak mengubah Yama/LSM/seccomp atau memberi SYS_PTRACE.
- Ringkasan hanya startup status, syscall/errno/count yang dikenali dan lokasi evidence. Error parsial tetap berlabel parsial dan tidak membuktikan run tanpa tracing. Daftar error dapat mencakup teardown/cleanup; misalnya kill EPERM bukan otomatis sebab setuid gagal. Korelasikan syscall dengan status startup dan urutan evidence privat. Log mentah, arguments, ID host dan konfigurasi tidak dicetak. Run traced **tidak otomatis mewakili** perilaku tanpa tracing.
- EXIT/INT/TERM melakukan cleanup berbatas hanya untuk unit dengan Id/Description nonce/Transient/fragment/cgroup milik run ini. Intent dicatat sebelum create untuk menangani interupsi saat pembuatan. Tidak mengirim kill ke PID lepas, menyentuh unit utama, lock, backup, registry, baseline updater, firewall, sertifikat atau SSH. Cleanup yang tak bisa dikonfirmasi dilaporkan; evidence tidak dihapus. **/run bersifat volatil**: salin evidence secara privat sebelum reboot, jangan unggah seluruh direktori/log mentah.

Exit 0 berarti worker plain teramati stabil pada probe minimal; bukan kesehatan konfigurasi produksi. Exit 2 berarti diagnosis belum sukses/unsupported/unavailable, termasuk plain gagal walau traced berhasil; 64 untuk argumen salah dan 130 untuk interupsi. Bila berhenti karena format/properti systemd yang belum didukung, tinjau `comparison.json` dan evidence privat, jangan menghapus restriction untuk memaksa lanjut. Tool belum diuji systemd/setuid nyata dalam sesi pengembangan ini. Pemeriksaan offline mengekstrak dan mengompilasi Python embedded secara eksplisit, menguji fixture API dengan host operations dimock, dan tidak pernah menjalankan probe.

Sesudah restriction penyebab benar-benar terbukti dan perbaikannya direview, masih perlu uji manual VPS nyata: **cold startup dan UID/GID worker**, USR2 menghasilkan generasi baru dan mengakhiri generasi lama dengan benar, bind low ports, pairing socket abstract/PROXY, serta adopsi sertifikat fresh saat reload/reexec tanpa membuka permission. Probe high-port tidak membuktikan low ports, fixture tidak membuktikan systemd/setuid, dan `CAP_KILL` tidak menutup diagnosis UID yang belum diketahui.

### Audit properti systemd 255 dan watchdog

WatchdogUSec adalah pengaturan perilaku layanan, **bukan** metadata yang dikecualikan. Tool mewajibkan properti itu dan menetapkan `WatchdogSec=0` pada transient probe tepat sekali (dictionary dan argumen CLI); alias WatchdogUSec yang menimpa request ditolak. Pada source v255, service_start_watchdog menghentikan timer bila timestamp_is_set bernilai false: hanya `0` dan `infinity` yang terbukti sama-sama disabled. Getter dapat mengembalikan watchdog_original_usec yang awalnya infinity; ini bukan bukti bahwa unit file mengatur WatchdogSec=infinity. Nilai raw tetap disimpan, finite/empty/missing/format lain ditolak, dan kesetaraan ini **tidak** diterapkan pada timeout/limit/security field lain. RuntimeMaxSec 8s tetap guard terpisah.

Sebelum menolak snapshot, auditor mengumpulkan kegagalan independen (properti wajib, capabilities, address families, argv, unused hook, logging, watchdog dan seluruh perbedaan key/value yang disuplai) ke satu hasil privat:

- `source-audit.json`: pemeriksaan sumber, scope source-only-preflight; bukan persetujuan seluruh pasangan.
- `plain/comparison.json` atau `trace/comparison.json`: source/original/current/probe, semua validation issues, presence flag, nilai raw dan inventory setiap properti yang disuplai.
- `<phase>/live-comparison.json`: audit ulang snapshot gate terakhir; `<phase>/release-audit.json` merekam alasan penolakan deadline/lock terakhir sebelum file go dibuat. gate_released=false pada record itu berarti gate belum dilepas saat pengecekan, bukan bukti hasil proses kemudian.

Klasifikasi membedakan missing-source/missing-probe, value-different, normalized-equal, unsupported-value (misalnya dua nilai finite identik yang tetap tidak didukung), metadata disengaja dan hook kosong dengan bukti. Properti runtime yang hilang tetap unsafe, bukan sekaligus dimasukkan sebagai ignored. Scope pair-required tidak boleh ok bila salah satu snapshot tidak tersedia; complete/coverage hanya mencakup input yang diberikan, **bukan sertifikasi snapshot VPS lengkap**. Console hanya berisi nama/reason yang disanitasi; nilai mentah tetap privat. Tidak ada prefix exception atau keamanan yang dibuat opsional. Logging juga memeriksa alias -p/--property agar duplicate assignment tidak menimpa tujuan privat.

**Batas bukti saat checkpoint 14:** yang diterima hanya tiga baris pengguna (WatchdogUSec=infinity, WatchdogTimestamp kosong, WatchdogTimestampMonotonic=0). Full snapshot sumber/probe tidak terlampir/tertemukan; pengguna memilih lanjut audit parsial. Karena nilai probe tidak diketahui, tidak dapat dipastikan penolakan terdahulu disebabkan missing property atau value-different. Sebelumnya comparator memang menolak kedua kondisi itu dan tidak menormalisasi watchdog. Jangan menebak probe bernilai 0 dari pesannya.

`tests/fixtures/systemd255-haproxy/` memisahkan partial report tersebut dari overlay pasangan **SYNTHETIC** yang tersanitasi dan berprovenance eksplisit. Overlay memakai profil renderer/fixture yang diketahui; bukan dump penuh atau hasil VPS. Tests menuntut audit seluruh supplied keys dan semua mismatch sekaligus, sekaligus memastikan restriction nyata, read failure, gate dan isolasi tetap fail-closed. Fixture baru belum dijalankan dalam sesi pengembangan ini; startup/setuid tetap belum terverifikasi.

Referensi semantik v255:
- https://raw.githubusercontent.com/systemd/systemd/v255/src/core/service.c (service_start_watchdog)
- https://raw.githubusercontent.com/systemd/systemd/v255/src/core/service.h (service_get_watchdog_usec)
- https://raw.githubusercontent.com/systemd/systemd/v255/src/basic/time-util.h (timestamp_is_set)

### Reinstall tepercaya dan recovery registry

`checks.py` memvalidasi registry `/etc/nathaya-tunnel/managed-services.json` secara strict (schema/owner/hash/path dan privacy root:root 0700 parent/0600 file). Existing unit diperbolehkan bila **hash bytes saat ini cocok hash lama yang tercatat**, meskipun hash renderer baru berbeda: ini upgrade unit terkelola, bukan konflik semata karena source baru. Effective HAProxy harus `LoadState=loaded`, fragment persis `/etc/systemd/system/nathaya-haproxy.service`, **tanpa DropInPaths**; mask, runtime/vendor override dan fragment lain ditolak. Fresh unit hanya boleh `not-found` bila file/fragment benar-benar absent dan belum terdaftar; unit yang hash-nya tercatat tetapi file-nya hilang adalah drift, bukan fresh install. Pemeriksaan dilakukan saat preflight dan diulang **di bawah shared lock sebelum worker memutasi OS**. Ini bukan izin mengadopsi unit asing.

Reinstall dilakukan manual dari source lengkap yang tepercaya dan direview, sesuai prasyarat core di atas. Ini **tetap installer dengan maintenance OS (apt upgrade/dist-upgrade), bukan patch unit-only**. Routine updater menolak perubahan kode installer/trust base immutable; jangan mengubah policy agar perubahan HAProxy bisa lewat updater. Lihat [batas trust updater](update.md#trust-dan-batas-deployment).

- `nt_replace_file` sudah menyimpan bytes unit lama secara privat di `"$NT_RUN/replaced/etc/systemd/system/nathaya-haproxy.service"` mode 0600, dengan inventaris `replaced-files`/`new-files`; backup privat bukan unit runtime 0644 yang tinggal disalin massal.
- Pencatatan internal `record-services --backup "$NT_RUN"` menyimpan **bytes asli** registry ke `"$NT_RUN/managed-services.before.json"` 0600 pada penulisan pertama, atau marker `managed-services.absent` bila semula tidak ada. Snapshot pertama tetap sama pada pencatatan kedua; bukan serialisasi ulang atau snapshot registry yang sudah berubah.
- Registry service bisa sudah diterbitkan **sebelum verification** ketika install gagal, sedangkan `installed.json` hanya di-commit setelah verification: baseline dapat absent atau masih lama. Keberadaan registry bukan bukti sukses. Baseline schema 1 hanya merekam versi, bukan kesehatan service; baseline versi sama yang sudah ada juga bukan bukti repair berhasil. Jangan menjalankan/menjadwalkan routine updater di antara install gagal dan recovery yang direview, walau versi terlihat konsisten. Partial mismatch kode/`VERSION`/baseline memerlukan restore backup manual yang **koheren** (unit, registry, kode/VERSION dan baseline terkait), setelah memeriksa proses aktif/lock dan meninjau bukti; tidak ada rollback OS otomatis.
- Unit lama tanpa registry yang cocok, hash mismatch atau drop-in tetap **BLOCKED** untuk recovery eksplisit yang direview. Jangan blind adoption, menghapus unit/registry/`installed.json`, mengarang hash/baseline atau menjalankan `record-services` manual untuk memaksa lolos. Pulihkan hanya state yang dapat dibuktikan dari backup; bila bukti tidak cukup, berhenti untuk review operator.

Referensi teknis (bukan hasil uji VPS):
- [HAProxy v2.8.30 linuxcap.c](https://git.haproxy.org/?p=haproxy-2.8.git;a=blob_plain;f=src/linuxcap.c;hb=v2.8.30)
- [HAProxy v2.8.30 haproxy.c](https://git.haproxy.org/?p=haproxy-2.8.git;a=blob_plain;f=src/haproxy.c;hb=v2.8.30)
- [Linux capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) dan [specifier unit (%N)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) (dokumen latest; cocokkan dengan versi systemd VPS).

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
