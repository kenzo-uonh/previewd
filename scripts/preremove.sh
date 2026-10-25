#!/bin/sh
# Package pre-remove script for previewd (nfpm.yaml), run as root by dpkg
# (prerm remove|upgrade|...) and rpm (%preun, $1 = 0 on erase, 1 on upgrade).
# On a real removal it stops the daemon and the units it owns and leaves no
# staged secret or transient credential in memory: the secrets staging root
# is unmounted, and emptied if it cannot be.
#
# Never touched, on purpose: /var/lib/previewd (the SQLite database holds the
# audit trail, which is never pruned: `previewd backup` first), /etc/previewd
# (site settings, no secret), /etc/credstore.encrypted (sealed credentials,
# the operator's), the docker group and the previewd user.
#
# Best effort: a failure here warns and never blocks the removal.
set -u

PATH=/usr/sbin:/usr/bin:/sbin:/bin

SECRETS_DIR=/run/previewd/secrets
RUN_DIR=/run/previewd
CREDENTIALS_DIR=/run/credentials/previewd.service

# An upgrade runs the old package's pre-remove: the daemon keeps its secrets
# and the new files take over at the next restart.
case "${1:-}" in
remove | purge | 0) ;;
*) exit 0 ;;
esac

warn() { echo "previewd: warning: $*" >&2; }

# Stopping the mount unit unmounts the ramfs, which discards every file in it.
if [ -d /run/systemd/system ]; then
	systemctl stop previewd.service previewd-proxy.service run-previewd-secrets.mount >/dev/null 2>&1 ||
		warn "could not stop previewd.service, previewd-proxy.service or run-previewd-secrets.mount"
fi

# A ramfs mounted by hand, or one the unit did not release.
if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$SECRETS_DIR" 2>/dev/null; then
	umount "$SECRETS_DIR" 2>/dev/null ||
		warn "cannot unmount $SECRETS_DIR (in use?): emptying it instead"
fi

# empty_dir removes everything below dir without leaving its file system and
# without following a link: dir itself must be a real directory.
empty_dir() {
	[ -d "$1" ] && [ ! -L "$1" ] || return 0
	find "$1" -xdev -mindepth 1 -delete 2>/dev/null ||
		warn "could not empty $1: remove its contents by hand"
}

empty_dir "$SECRETS_DIR"
empty_dir "$CREDENTIALS_DIR"
# Succeeds only on an empty directory that is no longer a mount point.
rmdir "$SECRETS_DIR" 2>/dev/null || true
rmdir "$RUN_DIR" 2>/dev/null || true
rmdir "$CREDENTIALS_DIR" 2>/dev/null || true

exit 0
