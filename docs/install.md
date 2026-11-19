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

**Status: penyebab aktual kegagalan `setuid` masih UNKNOWN/BLOCKED diagnosis.** Pesan `Cannot set uid 109` saja tidak menyertakan errno syscall atau membuktikan capability mana yang hilang; **laporan runtime terbaru memberi errno dan mask, bukan root cause** (lihat kontrol capability di bawah). Angka 109 adalah UID pada host pelapor, bukan kontrak instalasi. Perubahan capability di bawah memperbaiki kekurangan izin **signal lintas UID untuk lifecycle USR2**, bukan bukti bahwa penurunan UID telah diperbaiki. Fixture/mocks tidak menjalankan `setuid` nyata atau systemd.

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

Untuk `--run`, exit 0 berarti worker plain teramati stabil pada probe minimal; bukan kesehatan konfigurasi produksi. Exit 2 berarti diagnosis belum sukses/unsupported/unavailable, termasuk plain gagal walau traced berhasil; 64 untuk argumen salah dan 130 untuk interupsi. Bila berhenti karena format/properti systemd yang belum didukung, tinjau `comparison.json` dan evidence privat, jangan menghapus restriction untuk memaksa lanjut. Agen tidak menjalankan systemd/setuid nyata dalam sesi pengembangan ini; evidence runtime berasal dari pengguna. Source tes offline dirancang mengekstrak dan mengompilasi Python embedded secara eksplisit serta menguji fixture API dengan host operations dimock, tanpa menjalankan probe; keberadaan tes bukan hasil PASS.

Sesudah restriction penyebab benar-benar terbukti dan perbaikannya direview, masih perlu uji manual VPS nyata: **cold startup dan UID/GID worker**, USR2 menghasilkan generasi baru dan mengakhiri generasi lama dengan benar, bind low ports, pairing socket abstract/PROXY, serta adopsi sertifikat fresh saat reload/reexec tanpa membuka permission. Probe high-port tidak membuktikan low ports, fixture tidak membuktikan systemd/setuid, dan `CAP_KILL` tidak menutup diagnosis UID yang belum diketahui.

### Bukti capability terbaru dan kontrol opsional `--cap-boundaries`

**Laporan runtime sebelumnya dari pengguna, bukan fixture** (kontrol terbaru dirinci pada bagian matriks di bawah): worker mencatat `setgid(112) = 0` lalu `setuid(109) = -1 EPERM`. Snapshot gate Python, strace dan HAProxy menunjukkan `CapEff=CapPrm=0x440`, `CapBnd=0x4c0`, `NoNewPrivs=1`. Jadi bit `CAP_SETUID=0x80` sudah tidak ada di E/P **sebelum HAProxy**, bukan kehilangan yang unik pada kode HAProxy. Bounding masih memuat bit itu tetapi **batas bukan grant**. Titik kehilangan paling awal dan penyebabnya tetap UNKNOWN; ini bukan bukti perbaikan produksi atau keberhasilan core/full.

`prctl(0x17, ...)` adalah `PR_CAPBSET_READ`, query bounding set, bukan mutasi capability. Whitelist literal trace sudah mencakup `capset`; `trace/selector.json` kini mencatat selector aktual dan jumlah kemunculannya, sementara `trace/sanitised.json` memuat `capset_records`. Angka itu hanya jumlah record lengkap yang dikenali dari **combined output**, bukan autentikasi/coverage proof. Tidak terlihat dalam cuplikan, atau hitungan nol, tidak membuktikan tidak pernah terjadi. Strace baru mulai **sesudah PID 1 menyiapkan kredensial unit**; bahkan trace lengkap tidak dapat membuktikan tidak ada perubahan capability sebelumnya.

Untuk mempersempit batas observasi tanpa menjalankan aplikasi, tersedia mode **opsional, operator root pada VPS staging Ubuntu 24.04 amd64/systemd PID 1 saja**, sesudah review source/fixture. Ini bukan langkah installer, bukan otomatis setelah failure dan **jangan dijalankan di Acode/Android/Termux**:

```sh
# Dari akar checkout tepercaya, HANYA operator pada VPS staging tersebut:
sudo bash tools/diagnose-haproxy.sh --cap-boundaries
```

- Preflight tetap mengaudit source fragment/effective profile, trusted paths, lock dan profil bounding **tiga atau empat capability yang sudah ada**. Dua transient unit bernonce dengan suffix `cap-gated` dan `cap-direct` memakai payload Python tetap saja, bounding sumber yang sama dan hardening yang sama. Tidak menambah capability, mengubah konfigurasi PID 1/unit produksi, memasang paket atau mengubah akun. Mode ini **tidak menjalankan HAProxy (termasuk `-vv`), strace, reservasi socket atau listener**; metadata executable dibaca saja.
- `cap-gated` merekam `gate-entry`/`gate-exit` melalui `ExecStartPre`, lalu helper `ExecStart` merekam `control-entry`, menunggu izin berbatas dan melakukan **satu self-exec Python tetap** dengan `-I -B`, lalu merekam `after-exec`. `cap-direct` menjalankan helper yang sama tanpa pre-start gate. Tidak ada operasi setuid/setgid. **ExecStartPre keluar; PID 1 memulai ExecStart secara independen**, bukan gate mengeksekusi HAProxy/helper atau mewariskan kredensialnya sebagai parent.
- Hanya direct control dengan exact argv/plan Python metadata yang telah dibatasi boleh mulai helper harmless **sebelum perbandingan effective profile**; helper menunggu sebelum self-exec. Perbandingan source/current/probe/live dan exact argv/plan tetap wajib sebelum release; gated control juga mengaudit helper sebelum self-exec. Ini bukan pengecualian untuk aplikasi tak tervalidasi: gate pre-exec HAProxy normal pada `--run` tetap mandatory, urutan plain lalu trace kondisional tidak berubah.
- Kedua mode merekam snapshot read-only controller sendiri dan PID 1 tetap, bukan inventory proses global; metadata executable mencatat binary **yang benar-benar di-resolve** melalui symlink/parent tepercaya root-owned serta xattr `security.capability`. Daftar tetap mencakup Python, env, systemd-run, strace, HAProxy, systemd-executor dan executable PID 1 yang teramati. Tidak membaca payload binary/key untuk laporan metadata; absent filecap dibedakan dari akses unavailable.
- Snapshot memuat UID/GID/groups, PID/PPid, exe, kelima set `CapInh/CapPrm/CapEff/CapBnd/CapAmb` dan `NoNewPrivs`; record helper menyertakan `TracerPid`/`Seccomp` bila tersedia. Gate/helper menulis ke **FD append privat yang diwarisi**, bukan membuka tujuan baru. Environment hanya boolean **kehadiran nama terpilih** (LD_PRELOAD, LD_LIBRARY_PATH, PYTHONHOME, PYTHONPATH, BASH_ENV, ENV, GLIBC_TUNABLES), tidak nilainya dan tidak membaca `/proc/*/environ`. `env -i` launcher/`FIXED_ENV` membersihkan konteks client, **bukan bukti environment unit yang disiapkan PID 1**; environment PID 1 tidak dikumpulkan.
- Snapshot helper pertama sudah **sesudah inisialisasi Python**, bukan sebelum exec Python. `boundaries.report.json` melaporkan urutan observasi dan `first_observed_missing_SETUID_EP`, **bukan rantai inheritance atau titik/cause kehilangan paling awal**. Headline memilih task unit dengan EUID root saja, bukan controller/manager independen atau worker nonroot yang normalnya kehilangan capability sesudah UID drop. State credential/capability berbeda yang teramati kemudian tetap dicatat beserta sampelnya. Gated/direct sama atau berbeda tetap observasi, bukan pembuktian root cause.

Artefak baru: `boundaries.initial.json`, `boundaries.executables.json`, `boundaries.report.json`, `<phase>/boundaries.json`; kontrol juga menyimpan `comparison.json`, `live-comparison.json`, `control-result.json`, `helper-comparison.json` bila relevan dan `boundaries.control-comparison.json` bila kedua profil tersedia. Intent/exact command dan combined output tetap privat. Semuanya root:root, file **0600** dalam direktori **0700** run/phase yang sama; jangan unggah raw log, nilai environment, credentials atau path privat runtime.

Kontrol mempertahankan `RuntimeMaxSec=8s`, start timeout **5s**, stop/abort **2s**, Restart=no dan cleanup berbatas berbasis ownership nonce/cgroup; tidak kill PID lepas atau menyentuh layanan utama. Artefak **dipertahankan**, bukan dihapus cleanup; `/run` volatil, simpan salinan privat sebelum reboot. Exit 0 mode ini hanya berarti kedua urutan kontrol tercatat dan cleanup terkonfirmasi, **bukan HAProxy sehat atau UID fixed**; unavailable/refusal/cleanup tak terkonfirmasi exit 2, argumen salah 64, interupsi 130.

Akar masalah dan production fix tetap belum terbukti. Jangan menjadikan NNP/gate produksi opsional, menambah capability, melonggarkan hardening produksi atau mempertahankan worker root untuk memaksa sukses. Variasi kontrol Python tetap hanya di fixed unit `--cap-matrix` yang terpisah di bawah; eksperimen startup HAProxy `--nnp-ab` memiliki scope dan validator tersendiri, bukan izin mengubah produksi. Angka **111 metode (20 baru)** dan **22 kontrak tekstual** adalah catatan historis checkpoint 15, bukan validasi revisi matriks; baseline checkpoint 16 **117 metode** juga hitungan statis, bukan PASS. Jumlah fixture final dan review/hasil revisi baru menunggu parent. Tidak ada klaim PASS, startup/reload VPS atau full-scope success.

### Matriks request terbatas `--cap-matrix` — Python saja, staging opsional

**Laporan kontrol pengguna sebelumnya, bukan hasil fixture/agen** (enam observasi matriks yang lebih baru dirinci pada bagian A/B): kontrol `cap-gated` dan `cap-direct` sama-sama menunjukkan `CapBnd=0x4c0`, `CapEff=CapPrm=0x440`, seluruh UID/GID real/effective/saved/fs root, `NoNewPrivs=1`, `Seccomp=2` dan `TracerPid=0`. Tidak teramati injection pada nama environment yang diperiksa atau file capability; keadaan entry/self-exec stabil. Jadi kehilangan bit SETUID E/P dapat direproduksi **tanpa HAProxy, tracing atau gate**. Ini mempersempit observasi, **belum membuktikan restriction tertentu sebagai penyebab**. Entry kedua kontrol tetap sesudah inisialisasi Python; tidak ada operasi UID/GID, dan ini bukan observasi sebelum exec Python.

Mode baru adalah eksperimen request terbatas, bukan installer, production gate atau perbaikan. **Operator root saja, dari akar checkout tepercaya yang sama, pada VPS staging Ubuntu 24.04 x86_64/amd64 dengan systemd PID 1**, sesudah review source dan hasil fixture aktual. Jangan jalankan di Acode/Android/Termux/proot. Contoh berikut petunjuk operator, bukan command yang dijalankan agen:

```sh
# HANYA operator root pada staging tersebut, dari akar checkout yang sama:
bash tools/diagnose-haproxy.sh --cap-matrix
```

#### Ruang eksperimen dan invariants

- Payload selalu helper Python tetap `/usr/bin/python3 -I -B`: `control-entry`, tunggu release berbatas, satu self-exec tetap, `after-exec`. Tidak ada listener/reservasi endpoint, HAProxy (termasuk `-vv`), strace, operasi akun atau perubahan unit produksi/PID 1. File renderer, rendered unit dan konfigurasi produksi **tidak diubah**.
- `matrix_plan(directory, nonce, caps, index, enabled_knob_names)` menghasilkan plan/argv/properties tetap; `matrix_entry_state(records, caps, executable, entry_only=True)` memvalidasi entry sebelum release; pemanggilan default memvalidasi kedua tahap. `Controller.validate_matrix` terpisah dari validator lama. Dalam mode matriks, hanya CLI `--cap-matrix` dengan fixed Python unit boleh meminta variasi restriction ini; gate produksi `--run` dan kontrol lama tidak dijadikan opsional atau dilonggarkan.
- Semua attempt tetap `User=root`/`Group=root`, `UMask=0077`, append stdout/stderr ke FD/log privat, bounding **persis sumber tiga/empat capability** (0x4c0/0x4e0), tanpa tambahan capability, ambient kosong. `SecureBits=0` wajib diverifikasi sebagai effective default, **bukan** mengarang request transient nol. Runtime 8s, start 5s, stop/abort 2s, `Restart=no`, watchdog disabled serta cleanup nonce/ownership/cgroup tetap.
- Source fragment/effective profile diaudit sebelum setiap attempt dan sebelum release terhadap baseline; perubahan source ditolak, bukan disalin sebagai baseline baru. Metadata Python actual-resolved melalui path root-owned tepercaya dibandingkan sebelum/release/sesudah. Filecap Python wajib **terbukti absent**, bukan unavailable; metadata berubah, filecap present/tak terbaca atau repeat tidak stabil menolak eksperimen. P/E boleh berubah saat self-exec dan direkam sebagai `selfexec_capability_changed`; identitas/PID/PPid, bounding, credential lain dan metadata tetap wajib konsisten. Penentuan missing memakai **control-entry**, bukan after-exec. Jangan memodifikasi binary/xattr atau memakai `setcap` untuk melewati guard.

Ada tepat **11 knob**, dalam urutan berikut. Semua yang tidak dipilih diberi request **OFF eksplisit**, bukan dibiarkan memakai default. Minimal berarti nol knob opsional yang diminta ON dengan invariants di atas; **bukan profil produksi lengkap dikurangi NNP**.

| Knob (urutan pengujian) | Request OFF | Request ON |
| --- | --- | --- |
| NoNewPrivileges | no | yes |
| PrivateTmp | no | yes |
| ProtectSystem | no | strict |
| ProtectHome | no | yes |
| ProtectKernelTunables | no | yes |
| ProtectKernelModules | no | yes |
| ProtectControlGroups | no | yes |
| RestrictSUIDSGID | no | yes |
| LockPersonality | no | yes |
| RestrictAddressFamilies | string kosong | AF_INET AF_INET6 AF_UNIX |
| ReadWritePaths | string kosong | /opt/nathaya/logs |

Label production dalam matriks berarti seluruh sebelas request ON pada **helper Python**, bukan menjalankan HAProxy/unit produksi. Variasi hardening hanya pada transient unit eksperimen ini.

#### Urutan terarah, konfirmasi dan STOP

1. Jalankan minimal lalu production-request. Jika minimal sudah missing SETUID E/P, **ulang minimal lalu STOP**: hasil stabil hanya `confirmed-zero-optional-settings`, bukan menyalahkan restriction. Repeat gagal/tidak stabil tetap inconclusive. Jika production-request tidak mereproduksi kehilangan, STOP `not-reproduced-inconclusive`.
2. Bila minimal sehat dan production-request missing, uji **NoNewPrivileges sendiri dahulu**, kemudian tiap knob lain sendiri hanya bila diperlukan. Berhenti pada kandidat missing pertama; tidak mencoba arbitrary subsets.
3. Hanya bila tidak ada single culprit, uji pasangan **NNP + satu knob lain**. Kedua komponen tunggal harus sudah sehat; bandingkan pasangan terhadap masing-masing komponen. Tidak ada pasangan lain, powerset, rekursi atau pencarian orde lebih tinggi. Bila tidak ditemukan kandidat, STOP `higher-order-unresolved`/exit 2, bukan menyatakan semua restriction aman.
4. Untuk kandidat satu/dua knob, **ulang kedua sisi** perbandingan (reference sehat dan kandidat missing), cek kestabilan runtime dan effective snapshots. Kegagalan repeat bukan confirmed finding.
5. Supplement kondisional hanya untuk kandidat single: jika NNP sendiri kandidat, uji production-minus-NNP; jika single X kandidat, uji X+NNP. Untuk kandidat pasangan, simpan bukti kedua komponen sehat. Ini pemeriksaan interaksi NNP terbatas, bukan membuktikan actual NNP off atau memberi rekomendasi produksi. Setelah konfirmasi/supplement yang diperlukan, STOP.

Batas keras **28 attempt pembuatan** dengan suffix `mx00`–`mx27`, termasuk pembuatan gagal. Jalur terarah maksimal **23 eksplorasi + dua repeat + satu supplement**; sisa headroom tidak mengizinkan perluasan pencarian. Cleanup unit milik nonce harus terkonfirmasi **sebelum attempt berikutnya**; bila tak terkonfirmasi, STOP tanpa membuat unit baru, pertahankan bukti dan periksa secara privat. Tidak kill PID lepas atau menyentuh unit produksi.

#### Request bukan keadaan kernel: cara membaca hasil

Pisahkan tiga lapisan: **requested properties**, seluruh effective properties dari `systemctl show --all`, dan **actual `NoNewPrivs`/`Seccomp` serta capability/credential `/proc`** pada entry dan sesudah self-exec. `NoNewPrivileges=no` hanya request; bahkan root tidak dapat menghapus NNP yang sudah diwarisi. Jangan menyebut NNP off hanya dari request atau show: baca `layers`, `forced_or_inherited`, `actual_NNP_off` dan kedua snapshot proses. Seccomp=2 sendiri tidak mengidentifikasi filter atau syscall yang ditolak.

Perbandingan menyimpan inventory raw semua properti yang disuplai, expected/request versus applied/show, presence/mismatch dan `effective_differences`; `unexpected_requested_values` bukan dihapus agar terlihat cocok. Baca perubahan efektif turunan (termasuk NNP/Seccomp runtime) bersama request delta: **satu knob request dapat menghasilkan beberapa perubahan efektif**, bukan bukti satu mekanisme kernel. Audit terbatas pada snapshot/input aktual. Field runtime/intended yang tersimpan sebagai ignored tetap evidence, bukan pembuktian ekuivalensi; unknown/missing tidak boleh diasumsikan aman. Validator hanya menerima domain OFF/ON tetap dan applied value sesuai request, kecuali request NNP=no dapat menjadi show=yes. Mismatch lain atau nilai di luar domain ditolak sebelum release. TracerPid/Seccomp harus tersedia, entry divalidasi sebelum release, dan show NNP=yes dengan proc=0 ditolak. Unknown non-knob differences juga menghentikan eksperimen; fixture yang menyalin baseline sintetis belum membuktikan semua default/metadata VPS kompatibel. Jangan mengklaim audit seluruh perilaku kernel selesai.

`minimum_tested_requested_profile` hanya profil **minimum TESTED REQUESTED** dengan nol/satu/dua setting opsional yang teramati, bukan global minimum, set restriction efektif minimal atau root cause. Nol berarti kehilangan sudah pada minimal; satu/dua berarti kandidat dalam pencarian terarah dan repeat ini. Higher-order tetap unresolved bila jalur terbatas tidak menemukan kandidat. Tidak ada production fix sebelum repeat VPS membedakan kedua sisi.

Menurut dokumentasi kernel [no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html), NNP diwariskan melalui fork/clone/exec dan tidak dapat di-unset; ia membatasi privilege baru lewat exec (set-ID/filecap), **tidak dengan sendirinya melarang privileged `setuid(2)`** atau perubahan credential non-exec yang memang diizinkan. Jadi NNP=1 tidak membuktikan penyebab EPERM ini. Halaman referensi kernel dibaca penuh sebagai riset web read-only pada tugas ini. Tidak ada klaim versi upstream systemd tertentu sebagai akar masalah atau jalur exec-invoke telah terbukti.

#### Artefak, exit dan status validasi

- Run privat yang sama menyimpan `matrix.report.json` dan `matrix.python.initial.json`, ditambah `boundaries.initial.json`, `boundaries.executables.json`, `production.show`, `production.fragment` dan `source-audit.json` dari preflight.
- Per-attempt `mxNN/`: `request.json`, `intent.json` bila creation diminta, `source-before/source-release.fragment`, `*.show.json`/`*.audit.json` source, `before/release/after.python.json`, `entry.json`, `entry/release/after.show.json` bila tersedia, `source-comparison.json`, `release-comparison.json`, `after-comparison.json` bila relevan, `boundaries.json` dan `result.json` (state/layers/requested values). Perbandingan sisi/repeat disimpan sebagai `against-mxNN.json`; `combined.log` tetap privat. Attempt yang ditolak dapat memiliki bukti parsial saja, bukan hasil sukses yang dikarang.
- File root:root **0600**, direktori run/attempt **0700**, evidence dipertahankan oleh cleanup; `/run` volatil. Console metadata/status saja; jangan menyalin raw logs, secret, nilai environment atau path runtime privat ke chat. Environment hanya presence nama terpilih, bukan seluruh environment atau nilainya.
- Exit **0** hanya confirmed finding (termasuk zero-optional baseline) **dan cleanup terkonfirmasi**, bukan fix, HAProxy startup atau keberhasilan installer. Exit **2** untuk inconclusive/refusal/error/cleanup unconfirmed, **130** interupsi, **64** argumen salah. Baca status/limits/report bersama exit; jangan menyamakan bukti parsial dengan konfirmasi.

Baseline historis checkpoint 16 adalah **117 metode menurut hitungan statis**, bukan PASS; dua kegagalan tes VPS yang dilaporkan di sana tidak ditulis ulang sebagai PASS. Pada checkpoint 17 buffer berjumlah **140 metode, termasuk 23 regresi matriks**; review read-only dan **40 kontrak tekstual JavaScript** saat itu bukan syntax check atau eksekusi unittest. Angka revisi mount terbaru dicatat di bawah. Tidak menjalankan command, tes, Git, probe, installer atau layanan; riset web hanya membaca referensi publik. Full tetap BLOCKED (artefak OpenVPN/provenance UDP Custom/BadVPN), IP enforcement lintas transport dan panel CRUD Xray tetap belum tersedia/terbukti; cold start/reload/renewal dan sukses VPS full tetap belum terverifikasi.

### Catatan mount dependencies untuk --cap-matrix

Laporan pengguna untuk revisi lama: **140 fixture PASS**, tetapi run pertama mx00 (enabled kosong, attempt_count=1, unavailable/RequiresMountsFor, cleanup=true, inconclusive/exit 2) **belum membandingkan capability matriks**. Row attempt dicatat sebelum creation, jadi count=1 bukan bukti payload berjalan. Raw RequiresMountsFor kedua sisi/stage masih UNKNOWN; jangan menyimpulkan PrivateTmp adalah penyebab aktual. Angka/review checkpoint 17 di atas bersifat historis. Buffer revisi mount kini berjumlah **150 metode, termasuk 10 regresi mount**; review read-only dan **38 kontrak tekstual JavaScript** sesuai. Pemindaian leksikal bracket/string serta footer tidak menemukan bagian terputus setelah interupsi, tetapi bukan parser/syntax check atau tes PASS. Fixture drift log juga diperbaiki agar mutasinya benar-benar mengubah fragment renderer, bukan no-op. Unittest, Bash/Python syntax check, Git/diff dan probe belum dijalankan.

Proof murni Controller.matrix_mount_audit hanya berlaku pada fixed owned matrix plan/output privat tanpa shadow assignment, manager **Version 255 terverifikasi**, full source fragment tepercaya tanpa explicit [Unit] RequiresMountsFor (termasuk blank), serta effective WorkingDirectory/RootDirectory/RootImage dan Runtime/State/Cache/Logs/ConfigurationDirectory yang seluruhnya hadir-kosong. Dalam scope itu saja, PrivateTmp OFF mengharuskan empty, ON tepat **/var/tmp**. v255 memakai weak After/Wants tmp.mount secara terpisah; **/tmp bukan path RequiresMountsFor di aturan ini**. Getter menampilkan registered paths, bukan mount names/prefix closure. Append stdout/stderr/log paths dan ReadWritePaths bukan generator pada jalur ini, tetapi tetap divalidasi/direkam, bukan logging exception. Missing key, path lain, %, escape, .. atau duplicate tidak didukung; kedua key absent tetap coverage unknown. Row dikenal dianotasi, tidak dihapus; comparator umum dan source drift tetap strict, tanpa prefix exception.

matrix.mount-manager.json merekam satu bounded read-only sampel **manager**, bukan client version, hanya sebelum unit mode matriks baru; belum dijalankan agen. Comparison privat yang sudah ada dan matrix.report.json menyimpan raw/presence/requested None bila absent, PrivateTmp/producer/log context, reason dan artifact/stage; drift source juga menyimpan comparison sebelum refusal. Mismatch unsupported/unproved tetap memblokir release. Budget 8/5/2, max28, cleanup dan root:root dir0700/file0600 tidak berubah; tidak ada capability/production fix baru.

**Untuk kasus mx00 ini, jangan rerun probe/ubah produksi.** Mohon hanya row terkait dan key/presence/value tersanitasi dari comparison/show/request/audit run yang **sudah ada**, beserta artifact/stage/sisi, PrivateTmp, producer di atas, konteks logging/ReadWritePaths dan manager Version bila tersedia. Nyatakan yang absent; jangan unggah file/log privat utuh, credentials, private path atau nilai environment (nama key/presence saja). Snapshot aktual diperlukan sebelum menghubungkan aturan source dengan penolakan VPS.

Referensi v255: [unit_add_exec_dependencies](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/unit.c#L1177-L1252), [getter D-Bus](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/dbus-unit.c#L169-L195), [systemd.exec 255](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html). Aturan ini conditional, bukan dump host atau bukti SETUID/VPS telah diperbaiki.

### A/B HAProxy TLS-config startup `--nnp-ab` — belum ada perbaikan produksi

**Konteks baru dari laporan pengguna VPS, bukan eksekusi agen/fixture:** enam observasi kontrol matriks adalah (1) minimal requested dengan actual NNP=0 mempertahankan SETUID E/P, (2) production-request dengan actual NNP=1 kehilangan bit itu, (3) NNP-only dengan actual NNP=1 juga kehilangan, (4) repeat minimal tetap sehat, (5) repeat NNP-only tetap missing, dan (6) production-minus-NNP menunjukkan effective/request NNP=no serta actual `/proc` NNP=0 dan SETUID E/P ada; cleanup dilaporkan true. Ini bukti **environment/control-specific**, bukan bukti Linux NNP selalu menghapus CAP_SETUID atau melarang syscall setuid. Kontrol Python tidak membuktikan startup HAProxy. Root cause mekanisme dan production fix tetap belum terbukti; langkah berikutnya hanya membandingkan startup HAProxy, **belum menjalankan USR2**.

#### Scope, operator dan rencana tertutup

Mode baru sudah tertulis pada buffer source, **belum diverifikasi lewat tes/run baru**. Operator root saja pada **VPS staging Ubuntu 24.04 amd64, systemd PID 1**, dari akar checkout lengkap yang tepercaya dan sudah direview. Dahulukan tes offline aktual (`python3 -I -B tests/diagnose_haproxy_test.py`), review source dan hasilnya; jangan memakai keberadaan fixture sebagai PASS. **Jangan menjalankan contoh ini di Acode/Android/Termux/proot; agen tidak mengeksekusinya.** Tidak perlu menjalankan installer untuk eksperimen ini.

```sh
# HANYA operator root pada staging tersebut, setelah review + tes offline aktual:
bash tools/diagnose-haproxy.sh --nnp-ab
```

- Tepat **A = `nnp-yes` lalu B = `nnp-no`**; tidak ada trace/fallback matriks atau pencarian endpoint alternatif. API aktual: `make_ab_config(port, abstract_name, private_pem)`, `nnp_ab_plan(directory, nonce, caps, phase)`, `Controller.validate_nnp_ab(probe, plan)`, `compare_nnp_ab(a, b, a_plan, b_plan)` dan `run_nnp_ab()`. Validator A/B terpisah; `validate_fragment`, `validate_effective` sumber dan validator probe normal tetap mewajibkan NNP=yes. Tidak ada global ignored-NoNewPrivileges atau adopsi source drift.
- Kedua arm menjalankan exact `haproxy -W -db -f` dengan **config, PEM, high loopback TCP port dan nama abstract yang sama** dalam satu run; nonce/nama endpoint unik antar-run, bukan diganti antar-A/B. Reservasi `abns@` adalah alamat abstract **108 byte termasuk leading NUL dan zero padding**, bukan pathname/`abnsz`. Reservasi dipegang sebelum setiap release gate; A wajib cleanup terkonfirmasi sebelum B me-reserve/rebind endpoint yang persis sama. Konflik menolak eksperimen, bukan memilih port/nama baru; pelepasan reservasi bukan jaminan race-free terhadap proses asing.
- Bounding **persis source tiga/empat capability** (0x4c0/0x4e0), tidak dipromosikan dari tiga menjadi empat dan tidak ditambah CAP_KILL untuk eksperimen. Ambient kosong; executable HAProxy/Python/OpenSSL harus metadata tepercaya, tanpa set-ID/filecap, lalu dicek ulang. Tidak memodifikasi binary/xattr, menambah capability, mengganti worker menjadi root atau memakai `insecure-setuid-wanted`.
- Selain NNP, hardening sama: root master, UMask0077, PrivateTmp, ProtectSystem=strict, ProtectHome, proteksi kernel/control-group, RestrictSUIDSGID, LockPersonality, address families dan ReadWritePaths tetap. Runtime **8s/start5s/stop-abort2s**, Restart=no, watchdog disabled, effective SecureBits0/SystemCallFilter kosong-deny terverifikasi. **ExecStartPre gate mandatory untuk kedua arm**, audit source/original/current/probe/live, exact argv/hook/log assignment, lock dan assets sebelum release. Gate bukan parent pewaris credential HAProxy: PID 1 memulai ExecStart sendiri.
- Satu-satunya **security delta** yang boleh lolos inventory A/B adalah raw NoNewPrivileges yes→no **setelah proof exact plan/effective masing-masing sisi**. Source original→current tetap strict; unknown/missing restrictions tetap menolak. Perbedaan incidental Description, phase-private append log destination dan path go pada ExecStartPre divalidasi eksplisit, bukan izin path/hook arbitrer. A/B tidak menggunakan waiver mount matriks.

#### TLS privat ephemeral, bukan sertifikat produksi

Probe normal `make_config` tetap **NO_TLS**. A/B menambahkan bind loopback `ssl crt` pada config bersama. Sebelum unit A/B dibuat, controller memakai OpenSSL lokal `req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc -days 1 -subj /CN=localhost` dengan tujuan key/cert eksplisit: **satu EC self-signed CN=localhost satu hari**, lalu membuat PEM gabungan privat. Ini bukan ACME, trust-store install, penyalinan sertifikat produksi atau bukti hostname/CA/handshake. Stdout **dan** stderr generator menuju DEVNULL; evidence hanya argv tetap, status/elapsed/errno/class dan metadata/hash, **tidak menyalin private bytes ke JSON/log**. Key/cert/PEM root:root0600 dalam direktori root:root0700. Root master memuat PEM sebelum UID drop; worker haproxy tidak dapat menelusuri parent privat. Tidak membuka permission demi worker.

Ownership key/cert/PEM didaftarkan dari FD eksklusif **sebelum byte privat ditulis**; write/flush/close failure atau interupsi tidak menghilangkan identitas cleanup. Penghapusan memeriksa owner/mode0600/single-link/device/inode tiap secret secara independen; identitas berbeda/missing tak diasumsikan aman. Drift config/gate/executable menolak reuse/eksekusi tetapi tidak menahan secret yang masih terbukti owned; foreign replacement tidak dihapus dan file owned lain tetap dicoba. Setelah **seluruh unit milik run dipastikan berhenti**, cleanup hanya menghapus generated `nnp-ab/private.key`, `private.crt` dan `private.pem`; config/log/metadata evidence tetap disimpan. Jika stop/ownership cleanup tidak terkonfirmasi, key ditahan privat, `tls_cleanup_confirmed=false` dan **exit2**; jangan menganggap RuntimeMaxSec sendiri bukti berhenti. Kegagalan penghapusan secret juga exit2; bila terinterupsi, exit tetap130 dan kegagalan cleanup dicatat. Tidak menghapus sertifikat/log/backup produksi. `/run` volatil; simpan evidence secara privat sebelum reboot, tanpa membagikan key, raw log, nilai environment atau path privat run.

#### Expected versus actual: master dan worker

Tabel berikut **kriteria validator**, bukan hasil pengukuran baru. Mask `M` adalah bounding source persis 0x4c0 atau 0x4e0; I/P/E/B/A berarti CapInh/CapPrm/CapEff/CapBnd/CapAmb.

| Peran | Expected credential/capability | Expected actual NoNewPrivs |
| --- | --- | --- |
| A master | current MainPID HAProxy, empat UID/GID root; I=0, P=E=B=M, A=0 | 1 |
| B master | current MainPID HAProxy, empat UID/GID root; I=0, P=E=B=M, A=0 | 0 |
| A worker | anak langsung master; seluruh UID/GID akun/grup haproxy host; supplementary groups kosong/hanya GID itu; I=P=E=A=0, B=M | 1 |
| B worker | syarat nonroot/capability sama dengan A | **0 atau 1, catat aktual** |

Pemilihan master memakai **current MainPID**, bukan sembarang root HAProxy dalam cgroup. Capture anchored `/proc` memeriksa PID/starttime/exe/cgroup; identitas dan credential master+worker harus stabil ≥2 detik dalam window observasi berbatas dan cocok pada final sample. Bad masks/NNP yang teramati tetap direkam. Untuk pembanding A yang failed saja, lima-set master yang dapat diterima adalah I=A=0, B=M, P=E=M atau hanya kehilangan bit SETUID (M & ~0x80), UID/GID root dan NNP1. Anomali lain menjadi inconclusive-A-credentials, bukan pembeda terkonfirmasi; startup A yang observed-running tetap harus memenuhi mask penuh seperti tabel. A yang exit terlalu cepat dapat tidak mempunyai master sample: tulis **unavailable**, jangan menyalin NNP dari request/show/record gate Python. `actual_master_NNP.A/B` berisi daftar hasil yang benar-benar tertangkap atau string unavailable, bukan boolean inferred.

B worker NNP=1 dapat berasal dari HAProxy yang memasang NNP sendiri, bukan bukti B master=1 atau A/B gagal. Upstream **v2.8.0** memiliki worker-only `!master` / `PR_SET_NO_NEW_PRIVS` pada build yang mendukungnya; itu referensi perilaku yang mungkin, **bukan pembuktian versi/source/build binary terpasang**. Jangan mematikannya dengan insecure-setuid-wanted demi memperoleh worker=0. Worker NNP=1 **tidak mengembalikan barrier NNP master**.

#### Report, artefak dan arti exit aktual

Report utama tepat **`nnp-ab.report.json`**, bukan matrix/boundaries report. Baca `status`, `arms.nnp-yes/nnp-no` (`startup`, `proc_samples`, `proc_identity`, `effective_NNP`, `gate_boundaries`, `cleanup_confirmed`), `actual_master_NNP`, `comparative_verification` bila tercapai, `startup_candidate`, `confirmed_startup_difference` dan `diagnostic_finding_completed` bersama `cleanup_confirmed`, `tls_cleanup_confirmed`, `interrupted`, `exitcode`. Field terakhir cleanup TLS adalah bukti agregat penghapusan generated secrets; **tidak ada field per-file removed yang dikarang**. `complete=false`, `production_applied=false`, `reload_usr2_tested=false`, `reload_required=true` tetap; finding selesai bukan production fix lengkap.

- B tidak stable-observed dengan master aktual dan effective NNP=no → `inconclusive`/exit2.
- A dan B sama-sama observed-running → `no-NNP-startup-differentiator`, `comparative_verification=both-started`, diagnostic_finding_completed=true/exit0 dengan cleanup sukses; **bukan confirmed_startup_difference** dan bukan kandidat fix.
- B stable-observed + kedua arm cleanup sukses → dapat `CANDIDATE-startup-only`/`startup_candidate=true`. Exit0/confirmed_startup_difference=true hanya bila A startup=failed **dan master A benar-benar tertangkap root/NNP1 dengan lima-set failed-arm yang valid**, sementara seluruh master B tertangkap NNP0 dan mask penuh. Observasi credential/capability A yang anomali menolak kandidat walaupun B sehat. Ini `comparative_verification=confirmed-startup-only`, bukan reload/health proof. A tidak tertangkap atau bukan failed → kandidat tetap parsial, comparative_verification=incomplete, diagnostic_finding_completed=false, **exit2**; jangan mengklaim perbedaan komparatif penuh.
- Refusal/unavailable bisa menyisakan NOTSTARTED/incomplete/refused dan artifact parsial; baca issues serta file yang benar-benar ada. Cleanup unit/TLS gagal → `cleanup-unconfirmed`/exit2 dan flag candidate/finding/difference dibatalkan. Interupsi tetap exit130, termasuk ketika cleanup gagal; status/flag cleanup dan pembatalan kandidat tetap dicatat. Argumen salah64. Gagal menyimpan report juga bukan sukses meskipun status sebelumnya kandidat.

Evidence privat aktual, file0600/dir0700: preflight `production.show`/`production.fragment`/`source-audit.json`, `boundaries.initial.json`/`boundaries.executables.json`, metadata HAProxy/account; `nnp-ab/tls-intent.json`, `tls-generation.json`, `assets.json`, `haproxy.cfg` dan `comparison.json` (A↔B bila tercapai). Per-phase `nnp-yes/` dan `nnp-no/` menyimpan `intent.json` berisi exact command/requested properties, `combined.log`, `source-gate.fragment.json`/`source-gate.metadata.json`/`source-gate.show.json`, `probe-gate.show.json`/`probe-live.show.json`, aggregate `comparison.json`/`live-comparison.json`, `logging-metadata.json`/`release-audit.json`, `before.show.json`/`after.show.json`, `sample-*.json` dengan per-PID status/exe/cgroup/uid_map/gid_map bila tersedia, `observation.json`/`startup.json` dan file go bila release. Actual masks/NNP ada di proc samples, bukan request yang diasumsikan aktual. Stop/show/kill unit-only beserta returncode/stdout/stderr disimpan di `command-NNNNN.*`; **tidak ada stop.json atau request.json khusus A/B**. Evidence/log/config dipertahankan; generated secrets saja dihapus sesudah cleanup terkonfirmasi. Tidak semua file harus ada pada failure awal, dan tidak ada boundaries.report.json baru dari jalur main A/B.

#### Risiko dan gerbang berikutnya

`prospective_fix` hanya **HAProxy-specific NoNewPrivileges=no, NOT APPLIED**; bukan global NoNewPrivileges fix. Jika kelak dipertimbangkan, master serta descendants yang belum memasang NNP kehilangan **kernel exec privilege-gain barrier terhadap set-ID/filecap**. Bounding sempit dan hardening lain tetap diperlukan tetapi **bukan pengganti barrier itu**; worker yang memasang NNP sendiri tidak melindungi exec master. NNP irreversible/diwariskan dan tidak otomatis melarang privileged setuid(2); temuan kontrol host ini tidak boleh digeneralisasi menjadi aturan Linux.

Eksperimen ini **tidak melakukan handshake/client connection, routing/health check, USR2/reload/reexec, verifikasi exit worker lama atau low-port production test**. Yang diamati hanya stable master/nonroot-worker pada TLS-config startup. Bahkan kandidat dengan exit0 tetap incomplete sampai review risiko dan uji terpisah USR2 menghasilkan reexec/generasi baru serta worker lama exit, lalu cold start, low ports, abstract/PROXY routing, TLS/renewal dan seluruh rest checks nyata. Tidak memberi izin migrasi default, mengubah source unit/renderer/installer/updater/akun/SSH, melonggarkan production validator atau menerapkan NNP=no sekarang. Core/full belum terbukti; full tetap BLOCKED legacy artefak OpenVPN/provenance UDP Custom/BadVPN, tanpa menghapus blocker lain.

**Review statis selesai, runtime belum diverifikasi.** Buffer akhir berjumlah **168 metode, termasuk 18 A/B baru**; review read-only independen dan **49 kontrak tekstual JavaScript** sesuai, footer lengkap tanpa trailing whitespace/control characters. Ini bukan syntax check atau hasil unittest PASS. Riwayat checkpoint19 tetap: 150 tes dilaporkan pengguna dengan satu ERROR, fixture diperbaiki tetapi belum diklaim rerun PASS. Tidak menjalankan Bash/Python/syntax check/Git/probe/VPS/layanan/installer, commit atau push; tidak mengklaim tree clean atau startup A/B berhasil. Jalankan tes offline dahulu; hasil VPS A/B dan USR2/reload tetap belum tersedia.

Referensi primer (semantik, bukan bukti binary/run host): [kernel no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html), [OpenSSL 3.0 req](https://docs.openssl.org/3.0/man1/openssl-req/) dan [HAProxy v2.8.0 worker NNP](https://raw.githubusercontent.com/haproxy/haproxy/v2.8.0/src/haproxy.c).

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
- [PR_CAPBSET_READ: query bounding set](https://man7.org/linux/man-pages/man2/PR_CAPBSET_READ.2const.html)
- [Python 3.12 os.getxattr: path atau file descriptor](https://docs.python.org/3.12/library/os.html#os.getxattr)
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
