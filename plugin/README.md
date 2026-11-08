# Nathaya support over the native Alrescha backend

This document adapts the field descriptions in the read-only Alrescha
[`plugin/README.md`](https://github.com/alrescha79-cmd/sc-vpn/blob/main/plugin/README.md).
It does **not** install or claim an account API, web-panel server or framework.
The native account databases and Unix expiry logic remain authoritative; Nathaya
provides presentation and the shared optional Telegram transport.

## Historical panel fields

These are upstream field descriptions, **not** a new HTTP or CLI contract:

| Operation | Protocol | Upstream fields |
| --- | --- | --- |
| Create | VMess, VLESS, Trojan, Shadowsocks | username, password/UUID, exp (days), quota (GB), limit (IP count) |
| Create | SSH | username, password, exp (days), limit |
| Check/delete | All five | username |
| Renew | Four Xray protocols | username, exp (days), quota (GB), limit |
| Renew | SSH | username, exp (days), limit |

Do not infer endpoints, authentication or argument ordering from this table.

## Private backup/restore

Use the installed `backuprestore` help/usage for root-only local archive commands.
The optional Node built-in UI remains on `127.0.0.1:5000`, authenticated with a
32+ character runtime `NATHAYA_BACKUP_SECRET` (Basic username `admin`), over an
SSH local port forward. No Express, public archive URL or Telegram backup upload.

Payload: native four-protocol Xray trees (including DBs, limits and usage),
`/etc/ssh` (including SSH DB/limits), Unix account DBs, OpenVPN/CA state,
`/etc/letsencrypt`, HAProxy PEM, Xray certificate/key and domain/city/ISP,
`/root/.vars`, `/etc/nathaya-tunnel/config.conf`, and existing native log/banner
files. Archives include private keys and notification credentials: keep them
under private root-owned directories, never a web root. Archives remain 0600.

Bounded manual extraction, the closed path policy, link/special-file rejection,
and explicit privileged-overwrite confirmation remain in place. In-tree
OpenVPN/Let's Encrypt regular-file aliases are snapshotted as regular files;
links outside those trees and directory links are refused. Restore **still
refuses existing destination links**, including Certbot live symlinks: review
that layout locally first, without deleting private keys. Review/reconstruct
Certbot live-to-archive links before future renewal; snapshots do not preserve
symlink identity. Private restore data is root:root 0700/0600; passwd/group stay
0644. Restore never starts/restarts services. Review service access and restore
any narrowly needed executable permissions manually. Multi-file restore is not
transactional; retain a separate backup before privileged overwrite.

## Conservative uninstall interface

`uninstall.sh` requires root on systemd Ubuntu 24.04 and the interactive phrase
`UNINSTALL NATHAYA KEEP DATA`. There is no force option or data purge.

Setup/runtime installers must maintain `/var/lib/nathaya-tunnel/owned-files.tsv`
as a private root-owned regular file (0600, single link) with unique records:

```text
SHA256<TAB>ABSOLUTE_PATH
```

Each digest is the SHA256 of the **final installed bytes**; upsert the record
after an approved update, never bless an unknown administrator edit. No headers
or shell code. Only the uninstaller's pinned manifest code destinations, exact
custom VPN units/cron entries, proxy configurations and deploy hook are removable.
Out-of-policy/unrecorded paths remain, even if installer-looking. Any missing,
unsafe or changed removal target stops for manual review before deletion.
Runtime updates share `/opt/nathaya/.runtime.lock`; uninstall also holds its
private state lock. Use an exclusive maintenance window for other writers.

Only verified recorded custom units are stopped/disabled (the BadVPN template
expands to ports 7100/7200/7300). No generic Xray/OpenVPN or SSH stop/restart.
If a verified shared nginx/HAProxy configuration is removed, the packaged proxy
service is stopped; custom replacements/drop-ins require manual review.
Originals and their index under `/var/lib/nathaya-tunnel/originals` are retained,
never automatically restored or overwritten: inspect the index, restore the
correct original shared configuration if required, validate it, and then start
only that proxy. The uninstaller assumes no originals-index schema.

Network teardown is limited to `down` on the recorded, hash-matching root-trusted
`/usr/local/lib/nathaya/openvpn-forward.sh`; absent that record, network rules
remain for manual review. That helper must remove only the exact installer rules
tagged `nathaya-openvpn`. No independent firewall flush or sysctl restoration.

Accounts, databases/limits, private configuration/keys, SSL/CA state, notification
credentials, backups, originals, packages, logs and host network/SSH settings are
kept. This is **not** a claim that all installation effects/data are removed.
Removal is not transactional; the retained ownership ledger becomes historical
after removal, so review missing records before retrying after any interruption.

## Native expiry

`exp` keeps the upstream `### username YYYY-MM-DD ...` rows and Unix account
expiry/deletion. It loads `/opt/nathaya/modules/common/telegram.sh` and the
account-presentation helper, with no separate credential parser or curl sender.
It uses the actual shared `nathaya_account_html_field(label, value)` and
`nathaya_account_send_html(message)` interfaces for escaped/paged notifications.
Only an affected, already-active VMess/VLESS/Trojan/Shadowsocks instance is
restarted; inactive units are not started. Failures require manual review and
produce a nonzero exit, not an all-success notification. SSH is never restarted.
