#!/bin/sh
# Post-install checks of the previewd package, run by `make test-packages`
# inside a throwaway container after apt-get/dnf installed, then reinstalled
# (postinstall run twice, as on an upgrade), the package.
set -eu

fail() { echo "FAIL: $*" >&2; exit 1; }

getent passwd previewd >/dev/null || fail "user previewd missing"
shell=$(getent passwd previewd | cut -d: -f7)
[ "$shell" = /bin/false ] || fail "previewd shell is $shell, want /bin/false"
home=$(getent passwd previewd | cut -d: -f6)
[ ! -e "$home" ] || fail "previewd home $home exists"
uid=$(id -u previewd)
[ "$uid" -lt 1000 ] || fail "previewd uid $uid is not a system uid"
id -nG previewd | tr ' ' '\n' | grep -qx docker || fail "previewd not in group docker"

[ -f /usr/local/bin/previewd ] && [ -x /usr/local/bin/previewd ] || fail "/usr/local/bin/previewd missing or not executable"
for f in /lib/systemd/system/previewd.service \
	/etc/systemd/system/previewd-builds.slice \
	/etc/systemd/system/docker.service.d/previewd-builds.conf; do
	[ -f "$f" ] || fail "$f missing"
done

echo "OK: $(id previewd); /usr/local/bin/previewd $(stat -c '%a %U:%G' /usr/local/bin/previewd)"
