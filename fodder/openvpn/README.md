# Fresh-install OpenVPN

`setup.sh` sources `lib/configure-openvpn.sh` and calls `configure_openvpn` after installing Ubuntu packages. The helper creates a fresh installation-local CA and server identity, server configurations, CA-only client profiles and two native systemd units. Sourcing it only defines the function. Authentication preserves Alrescha's packaged PAM/Unix-account model: no client certificate/key, archive import, embedded credential, custom authentication hook or separate account database is used.

## Parent installer contract

```bash
# Already called by setup.sh after the Ubuntu package phase:
source "$ROOT/lib/configure-openvpn.sh"
configure_openvpn "$ROOT" "$DOMAIN"
```

- Run as root with Bash, an operator controlling TTY, and the parent installer lock held. `ROOT` is the existing source directory; the helper needs no template assets from it. `DOMAIN` is a validated DNS hostname resolving to this VPS's IPv4 address; the parent checks resolution, port availability and subnet collisions **before calling**.
- Supply shell functions `msg TEXT` and `fail TEXT`. `fail` should report failure; the helper exits its subshell nonzero even if `fail` returns. The parent must abort installation on a nonzero result. No parent `install_owned` API is used.
- Install distro packages `openvpn` (2.6+), `easy-rsa`, `openssl`, `libpam-modules`, plus normal Debian/Ubuntu coreutils, util-linux and dpkg utilities first. The distro's existing `/etc/pam.d/login` and its normal includes must be present and remain unchanged. EasyRSA must be `/usr/share/easy-rsa/easyrsa`; the PAM plugin's real file is located from `dpkg-query -L openvpn`, not an architecture-specific guess.
- `/var/lib/nathaya-tunnel` must already exist with trusted root-owned, non-writable ancestry. An existing `owned-files.tsv` must be a root:root 0600, single-link regular file containing complete `SHA256<TAB>absolute-path` lines. The helper preserves old records, appends its own records by same-directory atomic replacement under `owned-files.tsv.lock` (`flock`), and never records passphrases. Other inventory writers must use the same stable sibling lock, not the replaceable TSV inode. The parent installer lock is still required.
- Only a fresh `/etc/openvpn` is accepted: absent, or the package's empty `server`/`client` directories and optional packaged `update-resolv-conf`. Existing PKI, profiles, configurations, output directories, own units or own drop-ins cause refusal before key generation. No old tree is deleted, imported, rotated or repaired. Destination ancestry must be root-owned, real directories, not writable by group/others. This is intentionally **not rerunnable** over a completed or interrupted installation.
- The existing Alrescha account backend remains the only account writer and metadata authority. Keep its existing expiry/CSV metadata and daily expiry job unchanged; it must create/update/expire/lock the corresponding **Unix accounts**. The helper neither creates users nor reads/copies account metadata, and adds no account database, membership registry or authorization scheduler.

### Networking and activation belong to the parent

The helper installs files only. It does **not** execute systemctl, configure NAT/firewalls/sysctls, change host DNS, disable IPv6, alter packaged OpenVPN units, or install a TLS frontend. `setup.sh` supplies the forwarding unit and HAProxy TCP443 demultiplexer, then performs daemon reload and activates `nathaya-openvpn-tcp.service` and `nathaya-openvpn-udp.service` after configuration is complete.

Both units have `Requires=` and `After=nathaya-openvpn-forward.service`, the parent's persistent forwarding/NAT unit. That unit must be installed and ready before activation, handle both pools and named TUN devices below, and keep IPv4 forwarding, return routing, firewall forwarding and masquerading in place across reboot. It is not an authentication manager. The operator must allow the public listener ports in existing ingress/provider firewalls; setup does not reset those policies. Packaged umbrella units are not used for these two instances.

| Transport | Listener | Pool | Device | Configuration |
| --- | --- | --- | --- | --- |
| TCP | IPv4 TCP 1194 | `10.8.0.0/24` | `tun-nathaya-tcp` | `/etc/openvpn/server-tcp.conf` |
| UDP | IPv4 UDP 2200 | `20.8.0.0/24` | `tun-nathaya-udp` | `/etc/openvpn/server-udp.conf` |

The confirmed original ZIP configurations are the compatibility baseline: these paths, ports and pools, `verify-client-cert none`, `username-as-common-name` and packaged PAM `login` authentication are preserved. The official-API-decoded configurations were confirmed to match the historical ZIP exactly; the helper does not import that ZIP or any old keys. **`20.8.0.0/24` is public address space, not RFC1918.** It is retained deliberately as requested: it can shadow legitimate Internet destinations. The parent must reject route/pool collisions; this helper does not silently renumber it.

Both units use `WorkingDirectory=/etc/openvpn` and `ExecStart=/usr/sbin/openvpn --config /etc/openvpn/server-{tcp,udp}.conf` respectively. The original relative status names `server-tcp.log` and `server-udp.log` therefore resolve under `/etc/openvpn`; they use the default classic status format (version 1). These are status snapshots, not the separate daemon diagnostic logs. Parent preflight/status consumers must use these paths, not the former `/etc/openvpn/server/nathaya-*.conf` or private `.status` paths.

The historical `client-ssl.ovpn` filename means **native OpenVPN TCP to port 443**, not HTTPS or an independently configured third daemon. It works only if the parent provides transparent TCP 443 forwarding/demultiplexing to TCP 1194 without consuming OpenVPN's own TLS. A plain `.ovpn` does not implement an outer stunnel connection; such a deployment needs a separately configured client wrapper. Do not advertise 443 as working until the parent supplies the appropriate frontend.

## Credentials and authentication

EasyRSA runs interactively on `/dev/tty` with a clean environment and an explicit root-private vars file. It creates only a new RSA-3072 CA, server certificate/key and signed CRL in `/etc/openvpn/easy-rsa/pki`: **no client certificate or client private key is generated**. Installation-random CA/server identities are used; clients authenticate the server with the inline public CA, `remote-cert-tls server` and the actual server CN (`Nathaya-server-<random-id>`) pinned by `verify-x509-name ... name`. At the CA Common Name prompt, enter the exact random CA name displayed by the helper, replacing any other default; older packaged EasyRSA versions ignore `--req-cn` as an interactive default. The resulting CA CN is checked. Accept normal signing confirmations.

- Enter a strong, nonempty **CA passphrase directly at the EasyRSA prompts**. No passphrase is accepted through helper arguments, inherited environment variables, shell variables, answer files or unattended input. Do not run through terminal/session recording. The CA key must be encrypted PEM; otherwise installation stops. Keep its passphrase backed up securely. There is no client-key passphrase or second client-key prompt.
- Only the server key uses `nopass`, for unattended boot; it is root:root 0600 inside 0700 directories. The original `user nobody`/`group nogroup` drop is deliberately not retained: both units run as root to retain access to the root-private PKI/CRL paths during reloads. The packaged auth-pam plugin already uses its own native privileged worker for PAM authentication/account checks; this is not a new account controller or database.
- Both servers use `verify-client-cert none`, `username-as-common-name` and `plugin <packaged-plugin-path> login`. The plugin runs the existing `login` service's authentication and account-management stack, including its normal policy/includes, rather than a new two-line Unix-only PAM service. The helper does **not** create `/etc/pam.d/nathaya-openvpn`, replace `/etc/pam.d/login`, or bypass login policy. It does not open an interactive login session. Site-specific PAM/TTY/account restrictions may reject a login; diagnose that deployed policy rather than silently switching stacks or weakening checks.
- PAM checks the **Unix account**, not the backend's expiry/CSV metadata. A metadata-only expiry/deletion/limit that the backend does not apply to Unix account state is not enforced here. Any Unix account accepted by the existing `login` authentication/account stack can authenticate; there is no extra metadata-membership allowlist or client-certificate gate. Existing Alrescha account management remains authoritative.
- `username-as-common-name` makes the authenticated Unix username the OpenVPN common name/status identity. Retained `duplicate-cn` permits concurrent connections using the same account; no new per-user certificate mapping is involved. SSH IP limits, user quotas, instant account disconnects and session limits are **not** claimed for OpenVPN. Unix account expiry/lock is checked by PAM on authentication/reauthentication; existing sessions are not immediately killed when account metadata changes.

Both sides require TLS 1.2+ and negotiate only AES-256-GCM/AES-128-GCM, with compression disabled. The original `cipher none` and `auth none` settings are deliberately removed as an obsolete/insecure compatibility mode, not carried forward byte-for-byte; there is no LZO downgrade or weakened OpenSSL policy. Use clients supporting this modern TLS/AEAD configuration. Clients request only their Unix username/password interactively (`auth-user-pass`, no credential filename) and do not cache it (`auth-nocache`); reauthentication can prompt again. No profile contains a username/password or client certificate/private key.

The server pushes IPv4 full-tunnel routing (`redirect-gateway def1 bypass-dhcp`) and client DNS `1.1.1.1`. Those affect clients, not the VPS's resolver. DNS application depends on the client's OpenVPN integration; some Linux clients need their own resolver integration. IPv6 is **not tunneled or blocked** here and can bypass this IPv4 VPN; clients/operators must choose their own IPv6 policy. No host-wide IPv6 changes are made.

## CA-only profiles and ownership

All generated PKI files and EasyRSA vars are root:root 0600 with 0700 directories under `/etc/openvpn/easy-rsa`. Server configs are 0600; the two non-secret unit files are 0644. Profiles contain only the inline **public CA certificate** and public connection settings, with no `<cert>`/`<key>` block or embedded login credentials. The helper keeps its output copies root-private by default:

- `/etc/openvpn/client/client-{tcp,udp,ssl}.ovpn` (0600, directory 0700)
- `/root/nathaya-clients/client-{tcp,udp,ssl}.ovpn` (0600, directory 0700)

The helper never prints profile/key contents, exports to `/var/www`, or generates a ZIP/archive with credentials. The final installer keeps these CA-only profiles private: transfer copies through an authenticated SSH/SFTP channel. nginx81 returns 403 for file distribution; no public profile/account download URL or credential ZIP is installed. Never publish the EasyRSA tree, CA/server private keys, Unix passwords or credential-bearing archives.

Appended ownership records cover the EasyRSA vars, every generated regular PKI file, both server configs, both own unit files and all six profile files; no PAM file is installed or recorded. The helper creates/protects `/etc/openvpn`, the directories above and `/var/log/nathaya-openvpn` (0700). Each foreground daemon creates `/etc/openvpn/server-{tcp,udp}.log` status snapshots and separate `/var/log/nathaya-openvpn/{tcp,udp}.log` diagnostic logs with umask 0077. These mutable operational files, directories, the lock and inventory itself are not content-hashed inventory entries. There is no management listener, reconciliation timer or new authorization scheduler. Logs/status can contain account names and client addresses: keep them private and apply operator-managed retention. Parent-owned forwarding/frontend artifacts and service enablement links belong to setup.sh, not this helper.

A failure leaves generated keys/CA and installed outputs intact; only the helper's private temporary staging is removed. Inventory entries already appended remain. Generation can fail before all PKI files are recorded: an incomplete installation is not a rollback, and must not be blindly retried or deleted. Investigate/securely back up the existing material and decide recovery manually; this function never reinitializes it.

## Operator maintenance

The initial CRL lasts **365 days**, the server certificate **825 days**, and CA **3650 days**. Monitor certificate expiry and CRL `nextUpdate`; keep the CRL current while it is referenced by the server configurations. With client certificates disabled, that CRL is **not** a Unix-account revocation/expiry mechanism: access decisions remain with PAM and the existing backend. There is intentionally no unattended CA unlock or auto-renewal framework. Back up the entire EasyRSA PKI and its encrypted CA key securely; a private-key passphrase is not a replacement for a backup.

To refresh the CRL, an operator uses a root controlling TTY and the installed packaged EasyRSA, with the same explicit vars file and PKI (example only; not run by this change):

```bash
cd /etc/openvpn/easy-rsa
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C TERM=dumb \
  EASYRSA_PKI=/etc/openvpn/easy-rsa/pki \
  /usr/share/easy-rsa/easyrsa --vars=/etc/openvpn/easy-rsa/vars gen-crl
chmod 0600 /etc/openvpn/easy-rsa/pki/crl.pem
```

Unlock the CA interactively; do not put its passphrase in the command/environment. Keep the referenced CRL readable by the root daemons. Coordinate PKI maintenance and updated ownership records with the parent lock/inventory convention. There is no generic or per-user client certificate to revoke; manage Unix account expiry/locks through the existing Alrescha backend/PAM policy instead. Renew the server certificate before expiry using operator-controlled EasyRSA procedures. If the CA or pinned server CN changes, regenerate/distribute matching CA-only profiles. This helper does not orchestrate renewal or active-session eviction.

## Scope of this change

Integration is implemented in `setup.sh`, `lib/openvpn-forward.sh`, the proxy helper, dashboard/service actions, private backup/restore and data-preserving uninstall. Server/unit/profile text is generated locally by the helper; no archive/template private keys are required. Profiles use the root-level configuration/status paths and are distributed privately. Keep service names, TUN names and the `nathaya-openvpn-forward.service` dependency aligned when maintaining the source. No installer, runtime test or VPS action was executed in this editor session; live `login` PAM/TLS/routing/frontend/client interoperability remains unverified.

References: [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/), [packaged-PAM authentication model](https://openvpn.net/community-docs/using-alternative-authentication-methods/), [auth-pam native worker/service selection](https://github.com/OpenVPN/openvpn/blob/release/2.6/src/plugins/auth-pam/README.auth-pam), [auth-pam auth/account implementation](https://github.com/OpenVPN/openvpn/blob/release/2.6/src/plugins/auth-pam/auth-pam.c), [EasyRSA usage](https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Readme.md), [EasyRSA configuration](https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Advanced.md).
