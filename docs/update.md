# Release dan updater terpisah (schema 1)

**Implementasi tersedia, belum dijalankan/diuji di VPS.** Tidak ada release yang
sudah dipastikan tersedia, artefak yang dipublikasikan, atau klaim VPS verified.
Updater ini bukan installer dan tidak menjalankan `setup.sh`, apt, upgrade OS,
reboot, migrasi akun, atau restart/konfigurasi layanan tunnel/SSH.

## Trust dan batas deployment

- Identitas source tetap: GitHub **Yusuf2790/nathaya-tunnel**, channel `stable`.
  Tidak menerima URL, token, environment override, atau `--root` dari CLI.
- `updater/release-policy.json` adalah allowlist lokal tepercaya yang dipelihara
  bersama manifest program installer. Builder tidak menjalankan installer untuk
  memperoleh daftar file; validator tidak pernah diambil dari candidate release.
- Semua entri policy dipaketkan; hanya `deploy: true` yang diganti di
  `/opt/nathaya`: menu/modules/example config/VERSION, bukan service glue, WS
  binary, key, config aktif, DB, OS atau reboot. Daftar eksplisit kini mencakup
  program installer/runtime, VERSION/NOTICE/lisensi, trust base updater, tools
  dan template OpenVPN, serta **lima dokumen publik** (`install`, `architecture`,
  `update`, `alrescha-parity`, `permissions`) sebagai **package-only** bila
  `deploy: false`. Dokumen tidak dipasang ke VPS; `docs/progress.md`, tests, data
  dan `.git` tidak masuk artefak. Jumlah entri bukan kontrak tetap; baca policy
  dan `nt_program_files`/`nt_source_files` aktual. Missing/extra file ditolak.
- Trust base `updater/`, `tools/`, `installer/`, termasuk policy dan template unit,
  **tidak** diganti oleh routine update. Perubahan validator/policy/skema/daftar
  file memerlukan integrasi manual dari source tepercaya terlebih dahulu;
  release tidak bisa memperluas allowlist-nya sendiri. Sesudah validasi artefak,
  `main.py` mewajibkan file non-deploy yang harus terpasang (installer, services,
  updater, ports, notice/lisensi) ada dan byte-identik dengan candidate.
  Missing/drift **BLOCKED**, bukan diabaikan sambil menaikkan VERSION.
  `setup.sh`, `tools/`, `templates/`, `docs/` adalah pengecualian artifact-only,
  tidak diwajibkan ada di installed tree. Jangan melemahkan policy atau menerima
  validator remote; perubahan trust base memerlukan reviewed manual source reinstall.
- Runtime config `/etc/nathaya-tunnel/config.conf`, akun/database, key, cache,
  log, wrapper `/usr/local/bin/menu`, dan unit systemd tidak diganti oleh apply.
  `config/config.conf.example` adalah template program, bukan config aktif.
  Validator mewajibkan empat default publik inert (domain/admin/token kosong,
  Telegram OFF), tanpa unknown/duplicate key; perubahan kontrak example harus
  direview manual pada trust base. Tidak ada pemindaian rekursif source; `.git`, `.env`, data dan secret bukan
  input packaging. Jangan menaruh secret dalam file program yang di-allowlist.

## Integrasi installer aktual dan baseline

Integrasi **sudah ada** di `installer/lib.sh`, `runtime.sh`, `state.py` dan
`setup.sh`. Manifest memasang main.py, release.py, policy, launcher dan unit
templates di `/opt/nathaya/updater`; runtime memasang fixed-path launcher
`/usr/local/bin/nathaya-update`, unit/timer di `/etc/systemd/system`, dan state
root:root 0700. File kode/template 0644, launcher 0755; parent root-owned tanpa
group/world-write, symlink/hardlink ditolak. Python 3 stdlib, CA trust dan Bash
diperlukan; target tetap Ubuntu 24.04.

Lifecycle `state.py`:

1. Preflight `inspect_install` (`check`) menolak downgrade VERSION canonical,
   schema/identity tidak konsisten dan pending updater recovery sebelum mutasi.
2. Setelah lock, `prepare` menyimpan identity/hash privat ke run/updater-before.json.
   Sesudah staging, `validate-prepared` memastikan source/baseline belum berubah.
3. **Hanya sesudah verification gate**, `commit` memastikan deployed VERSION cocok
   lalu menerbitkan `/opt/nathaya/updater-state/installed.json` root:root 0600
   schema 1/versi candidate. Source VERSION sekarang `2.0.0`. Rerun versi sama
   mempertahankan byte baseline existing bila nilainya cocok.

Installer tidak membuat manual-verification marker dan **tidak meng-enable/start
updater timer**. Keberadaan unit bukan opt-in. Baseline hilang/tidak cocok pada
operasi updater memblokir, bukan ditebak/reset. Setup gagal **tidak memiliki
rollback kode/OS otomatis**: partial deployment/VERSION dan baseline lama dapat
memerlukan rekonsiliasi manual. Jangan memalsukan installed.json untuk lanjut.
Full tetap BLOCKED oleh OpenVPN/UDP provenance; core subset tidak reboot.
Tidak ada instalasi atau uji sistem yang dijalankan di editor.

## Build offline

Dari checkout tepercaya, dengan direktori output yang sudah ada:

```sh
# Pengguna menjalankan dari root source, bukan agen; output di luar source:
release_dir=$(mktemp -d)
python3 -I -B tools/build-release.py --output-dir "$release_dir"
```

Output directory harus sudah ada dan eksternal/temporary. Jangan overwrite
atau memakai `../nathaya-tunnel.zip` sebagai output; ZIP root workspace lama
bukan release updater dan tidak dibangun ulang in-place.

`--source` opsional untuk source terpisah; policy dan validator selalu berasal
*dari checkout tool yang dijalankan*, bukan source candidate. Jalankan tool
sebagai user pengembang biasa. Interpreter isolated `-I` dan `-B` menghindari
module injection dari cwd/PYTHONPATH serta penulisan bytecode. Tidak ada git,
network, publish, atau eksekusi installer. Output tidak pernah overwrite.

Artefak: `nathaya-vVERSION.tar.gz`, tanpa enclosing directory, dengan
`manifest.json` di root. JSON manifest memuat:

- `schema` integer 1, `version` canonical MAJOR.MINOR.PATCH, `channel: stable`;
- `files` daftar lengkap entri `path`, SHA256 konten aktual (`sha256`), ukuran
  byte (`size`), dan mode eksplisit (`0644` atau `0755`) sesuai policy.

Builder menggunakan USTAR, uid/gid 0, timestamp 0, gzip timestamp 0 dan urutan
stabil. Validator lokal memeriksa hasil build, termasuk `bash -n` dan compile
syntax Python **tanpa eksekusi/import source archive**. Builder menghitung
checksum nyata; checksum output lokal bukan pengganti digest tepercaya client.

Publishing/tagging/upload tidak diimplementasikan atau dijalankan. Publisher
harus menggunakan tag `vVERSION` dan asset dengan nama tepat di atas. Tidak ada
hash contoh/fallback yang dipercaya.

## Verifikasi download

Updater meminta metadata JSON HTTPS dari endpoint public GitHub `releases/latest`
dan memeriksa source API, draft/prerelease false, tag canonical, asset unik,
state uploaded, ukuran dan URL download yang persis cocok. Tidak membaca token,
netrc atau proxy environment. Metadata redirect ditolak; redirect asset hanya
HTTPS ke CDN GitHub yang di-allowlist, maksimum tiga. Error tidak mencetak
response body, header, signed redirect URL atau isi file privat.

`digest` asset dari metadata **wajib** berupa `sha256:<64 lowercase hex>`.
Jika GitHub tidak menyediakan digest, atau release/asset belum ada: **BLOCKED**.
Tidak fallback ke hash di archive, checksum file dari release, atau hash yang
baru dihitung sendiri. SHA256 archive harus cocok metadata sebelum parsernya
berjalan. Ini mempercayai GitHub HTTPS dan kontrol repository, **bukan** sistem
signature independen atau bukti source-code review publisher.

Validator stdlib terpasang membatasi: metadata 1 MiB, archive 32 MiB, expanded
archive 64 MiB, file 4 MiB, manifest 128 KiB, maksimal 256 member. Expansion gzip
dibatasi sebelum membaca header tar. Hanya regular USTAR file diterima: absolute
path, `..`, dot/empty component, symlink, hardlink, direktori, special file,
GNU/PAX extension, duplikat, extra/missing path, privilege mode dan mismatch
hash/size/mode/manifest/schema/VERSION ditolak. Tidak memakai `extractall`.
Archive scripts tidak di-source/import/dieksekusi; shell hanya di-parse lewat
`bash --noprofile --norc -n` dengan environment bersih.

Dokumentasi API yang diperiksa:
- https://docs.github.com/en/rest/releases/releases (latest full published release)
- https://docs.github.com/en/rest/releases/assets (asset `digest`, size dan download URL)

## Operasi manual di VPS, setelah instalasi core terverifikasi

Launcher menggunakan path absolut dan environment bersih. Contoh berikut
**belum dijalankan**:

```sh
sudo /usr/local/bin/nathaya-update status
sudo /usr/local/bin/nathaya-update --check
# Hanya bila ingin menerapkan versi yang benar-benar lebih baru:
sudo /usr/local/bin/nathaya-update --apply
# Opt-in terpisah HANYA setelah manual artifact check berhasil:
sudo /usr/local/bin/nathaya-update enable-auto
# Untuk menutup gate lagi:
sudo /usr/local/bin/nathaya-update disable-auto
```

Jangan menjalankan blok itu tanpa meninjau setiap tahap. `--check` memerlukan
release stable/asset nyata dan digest GitHub; remote yang benar bukan jaminan
release tersedia. Origin tersanitasi telah dikonfirmasi cocok
`Yusuf2790/nathaya-tunnel`; tidak ada release existence claim.

Semua operasi CLI production harus root pada path tetap. `status` offline;
menyatakan installed identity, auto gate, manual verification dan pending
recovery, bukan status konektivitas VPS. Output sukses berupa JSON ringkas.

`--check` mendownload dan memvalidasi artefak lengkap, bukan hanya metadata.
Versi sama boleh diperiksa untuk membangun gate awal, tetapi tidak di-apply
ulang. Apply wajib versi numerik lebih baru; downgrade dan same-version replay
ditolak. Skema deployment lokal wajib didukung sebelum network/apply.

Hanya manual `--check`/`--apply` yang berhasil menulis
`updater-state/manual-verification.json` root 0600: source, policy SHA256,
artifact SHA256, versi verified, dan versi installed. Marker tidak pernah
berisi credential. `--check` **tidak mengaktifkan auto-update**.

`enable-auto` memerlukan manual marker yang cocok source/policy serta installed
version, template unit terpasang identik, dan systemd sebagai PID 1. Baru
kemudian menulis gate `auto.json` root 0600 dan enable/start **hanya timer
updater**. Kegagalan systemd menutup gate. Marker absent/default berarti OFF;
memulai timer/service secara manual tidak melewati gate. `auto` adalah command
unit timer: tetap memvalidasi metadata/digest/artefak, tidak membuat manual
verification, dan tidak apply ulang versi yang sama.

`disable-auto` menutup gate terlebih dahulu lalu disable/stop timer; jika
systemd tidak tersedia/gagal, gate tetap OFF meskipun CLI melaporkan gagal.
Perubahan policy membatalkan kecocokan marker: lakukan verifikasi manual baru.
Timer/service bukan otomatis aktif karena file templatenya tersedia.

## Lock, aktivasi dan recovery

Semua command CLI memakai direktori lock **yang sama dengan installer**,
`/run/nathaya-tunnel-setup.lock` (mkdir eksklusif, 0700). Tidak memakai flock
terpisah, tidak menunggu tanpa batas atau mencuri/menghapus stale lock. Jangan
menghapus lock sebelum memastikan proses installer/updater tidak aktif.

Apply mem-backup hanya tracked code yang akan diganti, `VERSION` dan deployed
schema identity ke `updater-state/transactions/run-*/`; direktori 0700, file
backup/journal 0600. Tidak menyalin config/akun/key/wrapper. Private journal
mencatat original bytes lewat numbered backup, path, mode dan file baru.
`pending.json` diterbitkan sebelum mengganti kode. File dipublikasikan melalui
temporary file + fsync + rename; seluruh tree tidak atomik untuk proses menu
lain yang sudah berjalan. Hindari aktivitas menu saat apply.

Aktivasi memeriksa bytes yang terpasang cocok candidate, VERSION/skema dan
syntax deployed script (`bash -n`), tanpa menjalankan full setup atau memulai
kode archive. Ini hanya pemeriksaan aktivasi lokal, **bukan health check tunnel
atau bukti VPS lulus**. Jika penulisan/aktivasi gagal, tracked files, mode,
VERSION dan installed identity dipulihkan, file baru dihapus. Backup dipertahankan.
Kegagalan menulis manual marker setelah commit dapat melaporkan BLOCKED walau
kode sudah berubah; periksa `status`/backup dan lakukan `--check` lagi.

SIGINT/SIGTERM yang tertangani memicu rollback. Power loss/SIGKILL/storage error
bukan transaksi OS atomik: pending journal dan/atau stale lock dapat tertinggal;
operasi baru memblokir pending state. Gunakan konsol maintenance untuk memeriksa
numbered backup dan journal secara **data**, pulihkan hanya path tracked di
`/opt/nathaya` plus identity/version yang cocok, verifikasi owner/mode/syntax,
baru bersihkan pending/stale lock ketika aman. Jangan menjalankan journal atau
script recovery dari archive, jangan hapus backup secara buta. Rollback yang
juga gagal memerlukan recovery manual; storage failure ekstrem bahkan dapat
menggagalkan penulisan recovery marker. Tidak ada reboot otomatis, retry apt,
penghapusan backup otomatis atau pemulihan global layanan.

## Git, tag dan upload — pengguna saja

**Agen tidak menjalankan Git, commit, push, tag atau publish.** Berikut panduan
untuk pengguna dari root source, bukan perintah untuk dijalankan otomatis.
Origin sudah ada dan branch kerja `main`; jangan `git init`, mengganti remote,
atau mengarang URL repository baru. Tinjau status/diff lokal termasuk file baru
untuk secret/private key/config/DB sebelum staging; jangan menempelkan nilai
privat ke chat atau release.

```sh
cd nathaya-tunnel
git status --short
git diff --check
git diff
```

`git diff` tidak menampilkan isi untracked: inspeksi file baru secara terpisah.
Pertahankan penghapusan `nathaya.txt` yang memang disengaja; jangan restore
untuk sekadar membuat tree bersih. **Hanya bila seluruh perubahan tracked sudah
ditinjau dan memang hendak disertakan**, `git add -u` berikut men-stage semuanya,
termasuk deletion `nathaya.txt` **jika sebelumnya tracked**. Bila tidak semuanya
dimaksudkan, stage path/hunk yang disetujui saja, jangan jalankan `-u` global.

Contoh Bash: tambah hanya path source yang diketahui, bukan `git add .`/`-A`.
Tinjau ulang daftar terhadap file aktual, tambahkan file baru lain hanya setelah
review. Path docs/progress tidak dicantumkan di daftar eksplisit ini (parent
memeliharanya); `-u` global tetap dapat men-stage perubahannya jika tracked.

```bash
# Prasyarat: semua tracked changes memang dimaksudkan dan sudah direview.
git add -u
git add -- AGENTS.md setup.sh menu.sh VERSION NOTICE \
  licenses/Alrescha79-MIT.txt config/config.conf.example config/ports.json \
  installer/{lib,policy,openssh,domain,dependencies,firewall,dropbear,websocket,udp,openvpn,ui,runtime,tls,tls-renew,xray,proxies,maintenance,verify,preflight,menu-wrapper}.sh \
  installer/{artifacts,render,checks,state}.py installer/external-lock.json \
  modules/common/{bootstrap,functions,telegram,ui}.sh \
  modules/dashboard/dashboard.sh modules/menu/{domain,main,set_domain,ssh}.sh \
  modules/ssh/{account-db,create,delete,list-expired,list-member,lock,login,renew,trial,unlock}.sh \
  modules/maintenance/ssh-expire.sh \
  services/{login-policy,nathaya-dashboard}.sh services/ws_proxy.py \
  services/nathaya-{ssh-expire,cert-renew}.{service,timer} \
  updater/{main,release}.py updater/release-policy.json updater/update.sh \
  updater/nathaya-update.{service,timer} \
  tools/{build-release,audit-openvpn,openvpn-clients}.py \
  templates/openvpn/client-{tcp,udp,ssl}.ovpn.in \
  tests/{foundation,installer,expiry,full,run-local}.sh tests/expiry-fixtures.txt \
  tests/{services_test,openvpn_test,update_test,integration_test}.py \
  docs/{install,architecture,update,alrescha-parity,permissions}.md
git diff --cached --check
git diff --cached --stat
git diff --cached
# HANYA sesudah staged diff bebas secret dan sesuai niat pengguna:
git commit -m "Integrate guarded core installer and release updater"
git push origin main
```

Jangan stage runtime `data/`, `.git/`, active config/key/log/backup atau ZIP
workspace `../nathaya-tunnel.zip`. Daftar staging source/tests bukan policy
release: builder tetap hanya mengambil allowlist (tests tidak dipaketkan).
Jika file privat pernah tracked, `git add -u` bukan perlindungan secret;
hentikan dan review sebelum commit/push.

**Tag v2.0.0 hanya setelah tes lokal dan VPS staging benar-benar PASS**, termasuk
preservasi akses admin, expiry, TLS/renewal, failure/reinstall/update/recovery yang
relevan; bukan karena VERSION sudah 2.0.0. Full tetap BLOCKED dan tidak boleh
menjadi klaim release. Tinjau commit final, pastikan tag belum ada, build artefak
dengan builder ke direktori temporary eksternal yang sudah ada (bagian Build
Offline), lalu pengguna sendiri dapat melakukan:

```sh
git tag -a v2.0.0 -m "Nathaya 2.0.0 core partial; full blocked"
git push origin v2.0.0
```

Pengguna membuat release stable pada repository origin yang sama dan mengunggah
`nathaya-v2.0.0.tar.gz` hasil builder, **bukan ZIP seluruh workspace**. Isi deskripsi
release/README yang dipublikasikan harus menyatakan core parsial/full BLOCKED,
hasil tes yang benar-benar terjadi, gate digest/trust base serta auto default OFF.
Tidak ada README/release baru dibuat oleh tugas dokumentasi ini. Sesudah upload,
verifikasi metadata/asset digest dan manual updater `--check` nyata sebelum
`enable-auto`. Release tanpa digest tetap BLOCKED; jangan mengganti dengan
checksum self-declared. Perubahan policy/validator/service glue memerlukan review
dan source reinstall manual, bukan diakali lewat routine release.

## Pengujian fixture dan keterbatasan

Runner terpadu `tests/run-local.sh` sudah tersedia; pengguna dapat menjalankan
`bash tests/run-local.sh` dari source tepercaya di Termux non-root dengan
Bash, Python 3 dan GNU utils. Alternatif individual:

```sh
python3 -I -B tests/update_test.py
```

Test memakai temporary roots dari API Python internal, HTTP double, syntax
checker double yang dilabeli eksplisit, dan systemd double. Panggilan subprocess
atau HTTP nyata ditolak oleh fixture; tidak ada apt/systemd/akun atau penulisan
root host. Coverage mencakup allowlist/build, traversal/link/extra/duplicate,
size caps, digest/corruption, manifest/mode/schema/version, monotonic/replay,
manual/auto gate, target safety, preservasi runtime/wrapper/unit, dan rollback
bytes/mode/version akibat activation failure. Tidak membuktikan Bash parser asli
atau systemd berjalan benar.

Pada sesi implementasi ini hanya pembacaan/penulisan dan review statis dilakukan;
**test Python, Bash syntax, packaging, download release, dan uji VPS belum
berjalan** karena tidak tersedia execution tool. Git status/diff juga belum
bisa diperiksa via Git; tidak ada asumsi tree bersih, commit atau push.
