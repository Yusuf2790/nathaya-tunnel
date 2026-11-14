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

**Probe opsional, bukan langkah wajib atau script siap jalan:** bila observasi belum cukup, operator berpengalaman boleh merancang transient unit terisolasi dengan syarat berikut. Ini tidak mengubah unit utama, SSH, shared lock atau instalasi.

- Buat config/bukti dalam workdir privat baru di atas, nama unit acak unik yang dicek belum ada dan dicatat sebagai milik probe. Gunakan binary yang sama dan **restriction efektif yang sama**, root master `User/Group=root`, `-W -db`, config `user/group haproxy`, NNP/hardening tetap, ambient kosong. A mereproduksi tiga capability lama; B opsional adalah unit terpisah dengan empat capability untuk membandingkan **lifecycle**. Jangan mencampur hasil A/B sebagai bukti penyebab `setuid`.
- Batasi `RuntimeMaxSec=45s`, `Restart=no`, semua listener TCP hanya loopback **high port** yang diperiksa belum terpakai sebelum start (batalkan bila bind konflik); socket abstract memakai nama acak unik, diperiksa belum terpakai, dengan nama/proxy pairing yang sama di kedua sisi. Jangan memakai port publik/low port atau `abns@nathaya-tls` produksi. Pakai backend lokal harmless/respons uji saja, tidak ada relay ke layanan utama atau target eksternal/arbitrary target.
- TLS hanya membaca PEM root existing di path aslinya; jangan copy, mencetak, melonggarkan permission atau mengambil secret dari config/log. Bila pembatas unit tidak mengizinkan pembacaan itu, berhenti dan catat, bukan mengubah TLS. Seluruh stdout/stderr probe menuju bukti privat.
- Sebelum start, rencanakan penanganan EXIT/INT/TERM (trap bila memakai shell) dan stop berbatas waktu **hanya unit probe yang terbukti dibuat run ini**; RuntimeMaxSec tetap menjadi batas tambahan. Jangan menghentikan unit yang kebetulan bernama sama, me-restart/override unit utama, mengubah SSH atau menghapus lock siapa pun. Pertahankan evidence 0700/0600; tidak ada `rm -rf` blanket atau cleanup backup/log otomatis.
- `strace` opsional **hanya bila sudah tersedia**: `-f`, whitelist syscall identitas (`getuid`/`geteuid`/`getgid`/`getegid`, `setuid`/`setreuid`/`setresuid`, `setgid`/`setregid`/`setresgid`, `setgroups`), `capget`/`capset` dan `prctl` untuk return/errno, output privat. **Bukan** trace `read`/`write`, konten key, seluruh syscall, atau dump memory. Jangan menambah grant luas `CAP_SYS_PTRACE`; bila ditolak, catat keterbatasannya. Tracing mengubah timing/perilaku privilege dan **bukan bukti run tanpa instrumentasi**; hasil traced harus dibandingkan dengan run terisolasi tanpa tracing.

Sesudah restriction penyebab benar-benar terbukti dan perbaikannya direview, masih perlu uji manual VPS nyata: **cold startup dan UID/GID worker**, USR2 menghasilkan generasi baru dan mengakhiri generasi lama dengan benar, bind low ports, pairing socket abstract/PROXY, serta adopsi sertifikat fresh saat reload/reexec tanpa membuka permission. Probe high-port tidak membuktikan low ports, fixture tidak membuktikan systemd/setuid, dan `CAP_KILL` tidak menutup diagnosis UID yang belum diketahui.

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
