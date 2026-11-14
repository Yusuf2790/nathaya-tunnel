#!/usr/bin/env bash
# Isolated unit/integration checks. NEVER invoke setup's installation main.
# Requires Bash + GNU coreutils/findutils; runnable as a normal Termux user.
set -euo pipefail
umask 077
project="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
work="$(CDPATH= cd -- "$work" && pwd -P)"
trap 'rm -rf -- "$work"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
expect_fail() { if "$@"; then fail 'operation unexpectedly succeeded'; fi; }

# No installed code, tests, packages, services or account commands are executed.
for cmd in apt apt-get dpkg systemctl useradd userdel chpasswd chage passwd pkill reboot shutdown curl wget; do
    eval "$cmd() { printf 'forbidden operation: %s\\n' '$cmd' >&2; exit 97; }"
done
for cmd in mkdir touch install chown chmod cp mv rm; do
    eval "$cmd() { printf 'blocked source operation\n' >> \"\$work/source-blocked\"; exit 97; }"
done
source "$project/installer/lib.sh"
source "$project/setup.sh"                  # definitions only, guarded main
for cmd in mkdir touch install chown chmod cp mv rm; do unset -f "$cmd"; done
[[ ! -e "$work/source-blocked" ]] || fail 'source attempted filesystem operation'
# Replace ownership calls for fixture tests; never change Linux ownership here.
nt_set_owner() { [[ "$1" == "$work/"* ]] || fail 'ownership outside temporary root'; }
chown() { fail 'unexpected chown command'; }

# Explicit help is the only successful setup execution performed by this test.
env -i PATH="$PATH" "$BASH" "$project/setup.sh" --help > "$work/help"
grep -q 'Ubuntu 24.04' "$work/help" || fail 'help content'
expect_fail env -i PATH="$PATH" "$BASH" "$project/setup.sh" --root "$work/unsafe"
[[ ! -e "$work/unsafe" ]] || fail 'unsupported override created a path'

mkdir -p -- "$work/source"
while IFS= read -r relative; do
    mkdir -p -- "$(dirname -- "$work/source/$relative")"
    cp -- "$project/$relative" "$work/source/$relative"
done < <(nt_source_files)
nt_validate_source "$work/source"
nt_validate_config "$work/source/config/config.conf.example" "$work/source/modules/common/bootstrap.sh" yes
# Non-manifest repository contents must never be deployed.
mkdir -p -- "$work/source/.git" "$work/source/tests" "$work/source/data/ssh" "$work/source/logs" "$work/source/cache"
printf 'do-not-install\n' > "$work/source/.git/marker"
printf 'do-not-install\n' > "$work/source/tests/marker"
printf 'do-not-install\n' > "$work/source/data/ssh/accounts.db"
printf 'do-not-install\n' > "$work/source/logs/marker"
printf 'DOMAIN="workspace.invalid"\n' > "$work/source/config/config.conf"

root="$work/fresh"
nt_deploy "$work/source" "$root" "$work/backup-first"
[[ "$NT_CONFIG_RESULT" == created && "$NT_DB_RESULT" == created ]] || fail 'first-run result'
cmp -- "$root/etc/nathaya-tunnel/config.conf" "$project/config/config.conf.example" || fail 'initial config'
[[ ! -s "$root/opt/nathaya/data/ssh/accounts.db" ]] || fail 'source DB copied'
# installer/ is part of the explicit 64-file program manifest, not an exclusion.
manifest_count=0
while IFS= read -r relative; do
    [[ -f "$root/opt/nathaya/$relative" && ! -L "$root/opt/nathaya/$relative" ]] || fail 'manifest file missing'
    cmp -s -- "$work/source/$relative" "$root/opt/nathaya/$relative" || fail 'manifest bytes differ'
    manifest_count=$((manifest_count + 1))
done < <(nt_program_files)
[[ "$manifest_count" == 64 ]] || fail 'unexpected program manifest count'
{ nt_program_files; printf '%s\n' data/ssh/accounts.db data/ssh/accounts.lock data/ssh/operations.lock; } | LC_ALL=C sort > "$work/expected-installed"
find "$root/opt/nathaya" -type f -printf '%P\n' > "$work/actual-installed-unsorted"
LC_ALL=C sort "$work/actual-installed-unsorted" > "$work/actual-installed"
cmp -s -- "$work/expected-installed" "$work/actual-installed" || fail 'installed file set differs from exact manifest plus runtime DB/locks'
for path in .git tests logs/marker cache data/ssh/marker setup.sh config/config.conf; do
    [[ ! -e "$root/opt/nathaya/$path" ]] || fail 'non-manifest deployed'
done
nt_check_wrapper "$root/usr/local/bin/menu"
for path in etc/nathaya-tunnel/config.conf opt/nathaya/data/ssh/accounts.db opt/nathaya/data/ssh/accounts.lock opt/nathaya/data/ssh/operations.lock; do
    [[ "$(stat -c %a -- "$root/$path")" == 600 ]] || fail 'private file mode'
done
for path in etc/nathaya-tunnel opt/nathaya/data opt/nathaya/data/ssh opt/nathaya/logs var/cache/nathaya-tunnel; do
    [[ "$(stat -c %a -- "$root/$path")" == 700 ]] || fail 'private directory mode'
done
[[ "$(stat -c %a "$root/opt/nathaya/menu.sh")" == 755 ]] || fail 'menu mode'
[[ "$(stat -c %a "$root/opt/nathaya/modules/common/bootstrap.sh")" == 644 ]] || fail 'library mode'

# Repeat deployment must preserve runtime bytes, unknown files, shared dir mode.
printf 'DOMAIN="kept.example.invalid"\nTELEGRAM_STATUS="OFF"\n' > "$root/etc/nathaya-tunnel/config.conf"
printf 'demo|2026-01-01|2026-12-31|1|active|0|regular\nlegacy|2026-01-01|2026-12-31|1|active|0\n' > "$root/opt/nathaya/data/ssh/accounts.db"
printf 'existing lock bytes\n' > "$root/opt/nathaya/data/ssh/accounts.lock"
printf 'existing operation bytes\n' > "$root/opt/nathaya/data/ssh/operations.lock"
printf 'keep log\n' > "$root/opt/nathaya/logs/telegram.log"
printf 'keep cache\n' > "$root/var/cache/nathaya-tunnel/location.cache"
printf 'unknown file\n' > "$root/opt/nathaya/unknown-user-file"
chmod 750 -- "$root/usr/local/bin"
cp -- "$root/etc/nathaya-tunnel/config.conf" "$work/config-before"
cp -- "$root/opt/nathaya/data/ssh/accounts.db" "$work/db-before"
cp -- "$root/opt/nathaya/menu.sh" "$work/menu-before"
printf '\n# fixture update\n' >> "$work/source/menu.sh"
nt_deploy "$work/source" "$root" "$work/backup-second"
[[ "$NT_CONFIG_RESULT" == preserved && "$NT_DB_RESULT" == preserved ]] || fail 'repeat result'
cmp -- "$work/config-before" "$root/etc/nathaya-tunnel/config.conf" || fail 'config overwritten'
cmp -- "$work/db-before" "$root/opt/nathaya/data/ssh/accounts.db" || fail 'DB modified or migrated'
cmp -- "$work/menu-before" "$work/backup-second/replaced/opt/nathaya/menu.sh" || fail 'old code backup missing'
[[ "$(stat -c %a "$work/backup-second/replaced/opt/nathaya/menu.sh")" == 600 ]] || fail 'backup mode'
[[ "$(stat -c %a "$root/usr/local/bin")" == 750 ]] || fail 'shared directory changed'
grep -q 'fixture update' "$root/opt/nathaya/menu.sh" || fail 'code not updated'
grep -q 'unknown file' "$root/opt/nathaya/unknown-user-file" || fail 'unknown file removed'
grep -q 'keep log' "$root/opt/nathaya/logs/telegram.log" || fail 'log lost'
grep -q 'keep cache' "$root/var/cache/nathaya-tunnel/location.cache" || fail 'cache lost'
grep -q 'existing lock bytes' "$root/opt/nathaya/data/ssh/accounts.lock" || fail 'lock truncated'
grep -q 'existing operation bytes' "$root/opt/nathaya/data/ssh/operations.lock" || fail 'operation lock truncated'

# A foreign wrapper must fail before even creating a backup/code directory.
foreign="$work/foreign"
mkdir -p -- "$foreign/usr/local/bin"
printf '#!/bin/sh\necho foreign\n' > "$foreign/usr/local/bin/menu"
expect_fail nt_deploy "$work/source" "$foreign" "$work/foreign-backup"
[[ ! -e "$foreign/opt" && ! -e "$work/foreign-backup" ]] || fail 'wrapper conflict mutated destination'
grep -q foreign "$foreign/usr/local/bin/menu" || fail 'foreign wrapper changed'

# Leaf/ancestor symlinks and hardlinks cannot redirect privileged writes.
printf 'sentinel\n' > "$work/sentinel"
rm -- "$foreign/usr/local/bin/menu"
ln -s -- "$work/sentinel" "$foreign/usr/local/bin/menu"
expect_fail nt_deploy "$work/source" "$foreign" "$work/symlink-backup"
[[ ! -e "$work/symlink-backup" ]] || fail 'symlink wrapper caused mutation'
ln -s -- "$work/sentinel" "$root/opt/nathaya/logs/ssh-reconcile.log"
expect_fail nt_deploy "$work/source" "$root" "$work/log-symlink-backup"
rm -- "$root/opt/nathaya/logs/ssh-reconcile.log"
ln -- "$root/opt/nathaya/data/ssh/accounts.db" "$work/db-hardlink"
expect_fail nt_deploy "$work/source" "$root" "$work/hardlink-backup"
rm -- "$work/db-hardlink"
cmp -- "$work/db-before" "$root/opt/nathaya/data/ssh/accounts.db" || fail 'unsafe path test changed DB'
[[ "$(cat "$work/sentinel")" == sentinel ]] || fail 'symlink target changed'
mkdir -p -- "$work/ancestor"
ln -s -- "$work/sentinel" "$work/ancestor/opt"
expect_fail nt_check_targets "$work/ancestor"

# In-place source/target and incomplete source are rejected before mutation.
mkdir -p -- "$work/inplace/opt"
cp -R -- "$work/source" "$work/inplace/opt/nathaya"
expect_fail nt_deploy "$work/inplace/opt/nathaya" "$work/inplace" "$work/inplace-backup"
[[ ! -e "$work/inplace-backup" ]] || fail 'in-place copy started'
mv -- "$work/source/modules/ssh/trial.sh" "$work/trial-saved"
expect_fail nt_deploy "$work/source" "$work/incomplete" "$work/incomplete-backup"
[[ ! -e "$work/incomplete" && ! -e "$work/incomplete-backup" ]] || fail 'incomplete source mutated destination'
mv -- "$work/trial-saved" "$work/source/modules/ssh/trial.sh"

# Apt plan parsing is tested as DATA, never by running apt/dpkg.
nt_package_installed() { [[ "$1" == openssh-server || "$1" == libc6 ]]; }
printf 'Inst new-package (1.0 repo [amd64])\n' > "$work/apt-plan"
nt_check_apt_plan "$work/apt-plan"
printf 'Inst openssh-server [old] (new repo [amd64])\n' > "$work/apt-plan"
expect_fail nt_check_apt_plan "$work/apt-plan"
printf 'Remv some-package [old]' > "$work/apt-plan"
expect_fail nt_check_apt_plan "$work/apt-plan"
printf 'Inst openssh-server [old] (new repo [amd64])' > "$work/apt-plan"
expect_fail nt_check_apt_plan "$work/apt-plan"

# Backup journals must not follow symlinks or hardlinks, even inside a supplied backup root.
mkdir -p -- "$work/bad-backup"
ln -s -- "$work/sentinel" "$work/bad-backup/replaced-files"
expect_fail nt_deploy "$work/source" "$root" "$work/bad-backup"
[[ "$(cat "$work/sentinel")" == sentinel ]] || fail 'backup journal followed symlink'

# Policy lifecycle uses explicit fixture paths; production /usr/sbin is never touched.
nt_policy_owner() { [[ "$1" == "$work/"* ]] || fail 'policy owner outside fixture'; }
NT_RUN="$work/policy-run"
mkdir -p -- "$NT_RUN" "$work/policy-dir"
policy="$work/policy-dir/policy-rc.d"
nt_hold_services "$policy"
grep -q 'exit 101' "$policy" || fail 'temporary policy missing'
nt_restore_policy
[[ ! -e "$policy" ]] || fail 'temporary policy not removed'
printf '#!/bin/sh\nexit 0\n' > "$policy"
chmod 750 -- "$policy"
cp -p -- "$policy" "$work/policy-before"
nt_hold_services "$policy"
nt_restore_policy
cmp -- "$policy" "$work/policy-before" || fail 'original policy bytes changed'
[[ "$(stat -c %a "$policy")" == 750 ]] || fail 'original policy mode changed'
# Even when original contents equal the deny guard, its mode must be restored.
cp -- "$NT_RUN/policy-deny" "$policy"
chmod 700 -- "$policy"
nt_hold_services "$policy"
nt_restore_policy
[[ "$(stat -c %a "$policy")" == 700 ]] || fail 'equal-content policy metadata lost'
nt_hold_services "$policy"
printf '# administrator replacement\n' > "$policy"
expect_fail nt_restore_policy
grep -q 'administrator replacement' "$policy" || fail 'unrelated policy overwritten'
NT_POLICY_ACTIVE=0

# Read-only SSH state comparisons with fixture providers, never a real systemctl.
(
    nt_package_installed() { [[ "$1" == openssh-server ]]; }
    service_state=active socket_state=inactive service_enabled=enabled socket_enabled=disabled
    service_stamp=123 socket_identity=socket-one socket_listen='[::]:22 (Stream)'
    NT_OS_MAINTENANCE=0  # identity preservation is mandatory outside explicit OS maintenance
    nt_unit_active() { if [[ "$1" == ssh.service ]]; then printf '%s' "$service_state"; else printf '%s' "$socket_state"; fi; }
    nt_unit_enabled() { if [[ "$1" == ssh.service ]]; then printf '%s' "$service_enabled"; else printf '%s' "$socket_enabled"; fi; }
    systemctl() {
        case "$*" in
            'show ssh.service -p ExecMainStartTimestampMonotonic --value') printf '%s' "$service_stamp" ;;
            'show ssh.socket -p ActiveEnterTimestampMonotonic -p InvocationID -p Listen') printf '%s' "$socket_identity" ;;
            'show ssh.socket -p Listen --value') printf '%s' "$socket_listen" ;;
            *) fail 'unexpected systemctl mock request' ;;
        esac
    }
    nt_ssh_config_fingerprint() { printf 'fixture fingerprint\n'; }
    nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-before"
    nt_ssh_snapshot
    nt_verify_preserved_ssh
    service_stamp=456
    expect_fail nt_verify_preserved_ssh
    service_state=inactive socket_state=active
    nt_ssh_snapshot
    nt_verify_preserved_ssh
    socket_identity=socket-two
    expect_fail nt_verify_preserved_ssh
    socket_identity=socket-one
    socket_listen='[::]:2222 (Stream)'
    expect_fail nt_verify_preserved_ssh
    socket_listen='[::]:22 (Stream)'
    socket_enabled=enabled
    expect_fail nt_verify_preserved_ssh
    service_state=inactive socket_state=inactive
    expect_fail nt_ssh_snapshot
)

# Simulate a late code-copy failure: runtime contents still must be untouched.
(
    eval "$(declare -f nt_replace_file | sed '1s/nt_replace_file/nt_original_replace_file/')"
    nt_replace_file() {
        [[ "$5" != opt/nathaya/modules/ssh/trial.sh ]] || return 89
        nt_original_replace_file "$@"
    }
    expect_fail nt_deploy "$work/source" "$root" "$work/partial-backup"
)
cmp -- "$work/config-before" "$root/etc/nathaya-tunnel/config.conf" || fail 'partial failure changed config'
cmp -- "$work/db-before" "$root/opt/nathaya/data/ssh/accounts.db" || fail 'partial failure changed DB'
[[ -f "$work/partial-backup/replaced/opt/nathaya/menu.sh" ]] || fail 'partial failure lost backup'
printf 'PASS: isolated installer checks; ownership mocked, no apt/services/accounts/VPS execution.\n'
