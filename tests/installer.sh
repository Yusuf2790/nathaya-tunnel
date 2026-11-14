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

# SSH preservation: strict fixture providers only, NEVER a real systemctl/worker.
(
    NT_SOURCE="$project" NT_RUN="$work/ssh-preserve" NT_OS_MAINTENANCE=0
    mkdir -m 700 -- "$NT_RUN"
    nt_package_installed() { [[ "$1" == openssh-server ]]; }
    service_state=active socket_state=active service_enabled=enabled socket_enabled=enabled
    service_stamp=123 socket_stamp=321 socket_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    socket_listen=$'0.0.0.0:22 (Stream)\n[::]:22 (Stream)\n'
    query_fail='' query_partial='' fingerprint='fixture fingerprint'
    systemctl() {
        [[ $# == 5 && "$1" == show && "$3" == -p && "$5" == --value ]] || fail 'unexpected systemctl mock request'
        printf '%s\n' "$2/$4" >> "$NT_RUN/queries"
        if [[ "$2/$4" == "$query_fail" ]]; then printf '%s' "$query_partial"; return 44; fi
        case "$2/$4" in
            ssh.service/ActiveState) printf '%s\n' "$service_state" ;;
            ssh.socket/ActiveState) printf '%s\n' "$socket_state" ;;
            ssh.service/UnitFileState) printf '%s\n' "$service_enabled" ;;
            ssh.socket/UnitFileState) printf '%s\n' "$socket_enabled" ;;
            ssh.service/ExecMainStartTimestampMonotonic) printf '%s\n' "$service_stamp" ;;
            ssh.socket/ActiveEnterTimestampMonotonic) printf '%s\n' "$socket_stamp" ;;
            ssh.socket/InvocationID) printf '%s\n' "$socket_identity" ;;
            ssh.socket/Listen) printf '%s' "$socket_listen" ;;
            *) fail 'unexpected systemctl property' ;;
        esac
    }
    nt_ssh_config_fingerprint() { printf '%s\n' "$fingerprint"; }
    nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-before"
    nt_ssh_snapshot
    original_raw="$NT_SOCKET_LISTEN_BEFORE" original_identity="$NT_SOCKET_IDENTITY_BEFORE"
    printf '%s' "$original_raw" > "$NT_RUN/expected.raw"
    queries_before="$(wc -l < "$NT_RUN/queries")"
    # Change the PROVIDER before persistence: persistence must not recollect it.
    socket_listen=$'[::]:22 (Stream)\n0.0.0.0:22 (Stream)\n'
    nt_ssh_persist_baseline
    [[ "$(wc -l < "$NT_RUN/queries")" == "$queries_before" ]] || fail 'persistence recaptured baseline'
    cmp -s -- "$NT_RUN/expected.raw" "$NT_RUN/ssh-listen-before.raw" || fail 'raw baseline/newlines changed'
    (
        # Model exactly the fork boundary, not nt_worker or setup's install main.
        nt_ssh_assert_baseline
        [[ "$NT_SOCKET_LISTEN_BEFORE" == "$original_raw" ]] || fail 'worker lost preflight listener'
        nt_verify_preserved_ssh
        printf 'inherited\n' > "$NT_RUN/worker-fixture"
    )
    [[ -f "$NT_RUN/worker-fixture" ]] || fail 'worker fixture did not verify'
    cmp -s -- "$NT_RUN/ssh-listen-before.canonical.json" "$NT_RUN/ssh-listen-after-1.canonical.json" || fail 'order changed canonical set'
    if cmp -s -- "$NT_RUN/ssh-listen-before.raw" "$NT_RUN/ssh-listen-after-1.raw"; then fail 'raw order fixture was not changed'; fi
    NT_SSH_VERIFY_SEQ=1  # The fixture child has its own shell counter, like any fork.
    socket_listen=$' \t[::]:22\t( Stream ) \n\t0.0.0.0:22   (Stream) \n\n'
    nt_verify_preserved_ssh  # Equal whitespace AND identity outside maintenance.
    service_stamp=456
    expect_fail nt_verify_preserved_ssh
    service_stamp=123
    socket_identity=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    expect_fail nt_verify_preserved_ssh
    socket_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa socket_stamp=654
    expect_fail nt_verify_preserved_ssh
    socket_stamp=321

    # OS may restart units, but must pass ALL guards before expected IDs advance.
    NT_OS_MAINTENANCE=1
    service_stamp=456 socket_stamp=654 socket_identity=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    nt_ssh_accept_post_os_identity
    [[ "$NT_SSH_START_BEFORE" == 123 && "$NT_SOCKET_IDENTITY_BEFORE" == "$original_identity" ]] || fail 'OS overwrote original identity'
    [[ "$NT_SSH_START_EXPECTED" == 456 && "$NT_SOCKET_IDENTITY_EXPECTED" != "$original_identity" ]] || fail 'post-OS identity not accepted'
    NT_OS_MAINTENANCE=0
    socket_listen="$original_raw"  # A second representation change after OS.
    nt_verify_preserved_ssh
    socket_identity=cccccccccccccccccccccccccccccccc
    expect_fail nt_verify_preserved_ssh
    socket_identity=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

    for socket_listen in \
        '0.0.0.0:22 (Stream)' \
        '[::]:22 (Stream)' \
        '127.0.0.1:22 (Stream) [::]:22 (Stream)' \
        '0.0.0.0:22 (Stream) [::1]:22 (Stream)' \
        '0.0.0.0:22 (Datagram) [::]:22 (Stream)' \
        '0.0.0.0:22 (Stream) [::]:22 (Stream) 127.0.0.1:23 (Stream)' \
        '' '   ' 'unparsed data' \
        '0.0.0.0:2222 (Stream) [::]:22 (Stream)'; do
        expect_fail nt_verify_preserved_ssh
    done
    diff="$NT_RUN/ssh-listen-after-${NT_SSH_VERIFY_SEQ}.diff.json"
    grep -Fq '"removed":[' "$diff" || fail 'missing removed-listener diagnostic'
    grep -Fq '"added":[' "$diff" || fail 'missing added-listener diagnostic'
    grep -Fq '"port":2222' "$diff" || fail 'missing changed-port diagnostic'
    socket_listen="$original_raw"
    for query_fail in ssh.socket/Listen ssh.service/ActiveState ssh.socket/ActiveState \
        ssh.service/UnitFileState ssh.socket/UnitFileState ssh.service/ExecMainStartTimestampMonotonic \
        ssh.socket/ActiveEnterTimestampMonotonic ssh.socket/InvocationID; do
        query_partial=''
        expect_fail nt_verify_preserved_ssh
    done
    query_fail=ssh.socket/Listen query_partial="$original_raw"
    expect_fail nt_verify_preserved_ssh  # Valid-looking partial output, exit 44.
    query_fail='' query_partial=''
    socket_enabled=disabled
    expect_fail nt_verify_preserved_ssh
    socket_enabled=enabled service_enabled=disabled
    expect_fail nt_verify_preserved_ssh
    service_enabled=enabled socket_state=inactive
    expect_fail nt_verify_preserved_ssh
    socket_state=active fingerprint='changed authentication/config fingerprint'
    expect_fail nt_verify_preserved_ssh
    fingerprint='fixture fingerprint'

    # Lost/corrupt inherited values must FAIL, never become a fresh baseline.
    ( unset NT_SOCKET_LISTEN_BEFORE; expect_fail nt_ssh_assert_baseline )
    ( unset NT_SSH_BASELINE_READY; expect_fail nt_ssh_assert_baseline )
    (
        NT_SOCKET_LISTEN_BEFORE='127.0.0.1:2222 (Stream)'
        NT_SOCKET_CANON_BEFORE="$(printf '%s' "$NT_SOCKET_LISTEN_BEFORE" | nt_ssh_listener_tool canonical-ssh-listeners)"
        expect_fail nt_ssh_assert_baseline
    )
    ( socket_listen=''; expect_fail nt_ssh_snapshot; [[ "$NT_SSH_BASELINE_READY" == 0 ]]; expect_fail nt_ssh_persist_baseline )
    ( query_fail=ssh.socket/Listen query_partial="$original_raw"; expect_fail nt_ssh_snapshot; [[ "$NT_SSH_BASELINE_READY" == 0 ]] )
    ( socket_stamp=''; expect_fail nt_ssh_snapshot )
    ( service_state=inactive socket_state=inactive; expect_fail nt_ssh_snapshot )
    # A failed preservation check must also prevent post-OS identity acceptance.
    (
        NT_OS_MAINTENANCE=1 socket_listen='127.0.0.1:2222 (Stream)'
        saved_expected="$NT_SOCKET_IDENTITY_EXPECTED" saved_start="$NT_SSH_START_EXPECTED"
        expect_fail nt_ssh_accept_post_os_identity
        [[ "$NT_SOCKET_IDENTITY_EXPECTED" == "$saved_expected" && "$NT_SSH_START_EXPECTED" == "$saved_start" ]] || fail 'failed OS guard accepted identity'
    )
    for dropped_service in inactive failed; do
        (
            NT_OS_MAINTENANCE=1 service_state="$dropped_service"
            saved_expected="$NT_SOCKET_IDENTITY_EXPECTED" saved_start="$NT_SSH_START_EXPECTED"
            expect_fail nt_ssh_accept_post_os_identity
            [[ "$NT_SOCKET_IDENTITY_EXPECTED" == "$saved_expected" && "$NT_SSH_START_EXPECTED" == "$saved_start" ]] || fail 'inactive service advanced post-OS identities'
        )
    done
    nt_ssh_assert_baseline
    cmp -s -- "$NT_RUN/expected.raw" "$NT_RUN/ssh-listen-before.raw" || fail 'baseline raw overwritten'
    [[ "$(stat -c %a -- "$NT_RUN")" == 700 ]] || fail 'SSH run directory not private'
    for artifact in "$NT_RUN"/ssh-*; do
        [[ "$(stat -c %a -- "$artifact")" == 600 ]] || fail 'SSH snapshot not private'
    done
    # Existing service-only admin still works; only INACTIVE socket may be empty.
    (
        NT_RUN="$work/ssh-service-only" socket_state=inactive socket_listen=''
        mkdir -m 700 -- "$NT_RUN"
        nt_ssh_config_fingerprint > "$NT_RUN/ssh-config-before"
        nt_ssh_snapshot
        nt_ssh_persist_baseline
        nt_verify_preserved_ssh
        service_stamp=789
        expect_fail nt_verify_preserved_ssh
    )
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
