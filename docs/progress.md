# Checkpoint pengembangan

## 1 — Rekonsiliasi setelah interupsi

- Selesai: baca ulang AGENTS.md dan source aktual; audit read-only menemukan 64 file manifest deployment, 71 file kebijakan rilis, helper modular dan validator/updater yang sudah ditulis. Tidak ada reset/Undo atau pemulihan nathaya.txt. Folder kosong `templates (2)/` dibiarkan.
- Pemeriksaan: pembacaan source dan metadata Git saja; branch main. Bash/Git/eksekusi Python tidak tersedia melalui tools sesi ini. Belum ada git diff, bash -n, atau test yang dijalankan ulang.
- Belum selesai: badge/version/EOF dashboard, cleanup timer dan reboot, baseline updater, kontradiksi test manifest, dokumentasi lama dan tes integrasi.
- Gate tetap: full BLOCKED oleh arsip server OpenVPN serta provenance UDP Custom/BadVPN; core bukan full; IP limiter dan panel akun Xray tidak diklaim tersedia.
- Berikutnya: tuntaskan hook/dashboard serta pelaporan tanpa mengubah kode yang sudah benar; lalu updater, test dan dokumentasi.

## 2 — Dashboard dan mode login

- Selesai: badge SSH membaca service/socket; Xray membaca empat instance; Dropbear/Nginx membaca unit Nathaya. Hitungan akun SSH berasal dari DB Nathaya, hitungan Xray dari JSON aktual. OpenVPN ditampilkan BLOCKED, versi dibaca dari VERSION. Mode `--login` menolak non-TTY; semua read menu menangani EOF agar kembali ke shell.
- File: `menu.sh`, `modules/common/functions.sh`, `modules/dashboard/dashboard.sh`.
- Pemeriksaan: review statis penggantian terfokus; tidak mengubah format notifikasi Telegram. Bash/test belum dijalankan.
- Berikutnya: tutup gap cleanup timer/renewal, kesiapan extra sshd setelah boot, dan finalisasi status sebelum reboot; kemudian baseline updater.

## 3 — Hook, cleanup dan reboot

- Selesai: extra sshd membuat /run/sshd saat boot; timer/service baru dilacak terpisah dari enablement yang sudah ada; cleanup gagal mempertahankan state lama. Renewal tidak menyalakan proxy yang awalnya berhenti. Set Domain menu menolak perubahan identitas layanan terkelola dan memakai lock bersama untuk instalasi dasar.
- Reboot memakai hasil gate aktual, bukan literal 0; status, log dan cleanup wajib difinalisasi sebelum permintaan reboot. Full tetap BLOCKED dan core tidak reboot.
- File: setup.sh, installer/{ui,maintenance,proxies,tls-renew,render}.py/.sh, modules/menu/set_domain.sh.
- Pemeriksaan: review statis branch dan referensi; syntax/test belum dieksekusi.
- Berikutnya: validasi baseline updater sebelum mutasi, commit baseline setelah verifikasi, tolak trust-base hilang/berbeda; sesuaikan test dan dokumentasi aktual.

## 4 — Baseline updater dan paket rilis

- Selesai: preflight menolak downgrade, identitas tidak konsisten, schema tidak dikenal dan pending recovery. Snapshot baseline dibuat setelah lock; dicek lagi setelah staging; installed.json baru diterbitkan sesudah semua verifikasi. Reinstall versi sama mempertahankan baseline byte-for-byte.
- Trust-base installed yang hilang kini memblokir update; paket tidak dapat mengabaikan file root yang hilang/berbeda. Dokumentasi publik disertakan sebagai package-only, tidak mencakup checkpoint atau data privat. Auto-update tetap perlu verifikasi manual dan opt-in.
- File: installer/{state.py,runtime.sh,preflight.sh}, setup.sh, updater/{main.py,release.py,release-policy.json}.
- Pemeriksaan: review statis schema, urutan check/prepare/commit dan daftar paket. Belum ada eksekusi test atau rilis aktual.
- Berikutnya: regression fixture baseline/manifest/trust-base; tes hook/routing/reboot/dig/upgrade; pembaruan docs yang masih menyebut tahap 2.

## 5 — Regression fixture dan dokumentasi aktual

- Selesai ditulis: runner lokal eksplisit; regression manifest, baseline baru/reinstall/upgrade/downgrade/pending, missing/drift trust-base, hook/EOF/unit dashboard, dig, rencana upgrade, gate reboot dan laporan gagal. Test installer lama tidak lagi melarang direktori installer yang kini memang ada dalam manifest; mock Listen tetap memeriksa preservasi port.
- File: tests/{installer.sh,full.sh,integration_test.py,run-local.sh}; docs/{install,architecture,update,alrescha-parity,permissions}.md.
- Dokumentasi kini membedakan core parsial dari full BLOCKED, mencatat tool OpenVPN yang tersedia, baseline post-verification dan batas updater immutable.
- Pemeriksaan: pembacaan/review source dan kecocokan daftar; belum ada test/syntax yang dieksekusi. Berikutnya: review keamanan akhir, enumerasi referensi dan pemeriksaan statis otomatis lewat file tools; berikan perintah runner kepada pengguna.

## 6 — Review akhir dan pemeriksaan yang tersedia

- Temuan akhir diperbaiki: renewal hanya memvalidasi/reload proxy aktif secara independen; kasus Nginx berhenti tidak memblokir HAProxy aktif. Gate akhir memastikan admin service/socket aktif juga pada host baru. Source-validation sebelum apt mencakup parse Bash/Python/JSON dengan error generik tanpa nilai privat. Fixture temp Python dikanonikalisasi tanpa melemahkan tes symlink.
- Pemeriksaan yang benar-benar dijalankan lewat file tools/JavaScript: parse tiga JSON utama, 64 path program unik/76 path rilis lengkap, seluruh helper orchestrator ada, tidak ada path runtime/secret/test/checkpoint dalam paket; VERSION canonical; notice MIT identik; directive tiga template klien identik dengan referensi (selain komentar atribusi dan placeholder host); source GitHub cocok remote origin aktual dan branch main.
- Review independen read-only atas worker, baseline, updater, rollback dan tes tidak menemukan blocker baru setelah perbaikan yang dicatat. Ini bukan parser Bash atau uji layanan.
- Belum dijalankan: git status/diff/diff --check, bash -n, Python/test suite, build artifact, download updater, installer dan uji VPS. Tools sesi ini tidak menyediakan eksekusi Bash/Python/Git. Working tree tidak diklaim clean dan seluruh perubahan pengguna tetap dipertahankan.
- Langkah pengguna: dari source tepercaya jalankan `bash tests/run-local.sh`, lalu `git diff --check` dan `git status --short`; tinjau untracked secara terpisah. Setelah PASS dan backup/konsol siap, uji core pada VPS disposable sesuai docs/install.md. Full tetap BLOCKED; jangan mengedit gate agar terlihat sukses. Updater/auto-update belum diuji dan timer tidak diaktifkan installer.

Tidak ada installer, apt, layanan/firewall/akun, reboot, commit/push/publish yang dijalankan selama pengembangan.
