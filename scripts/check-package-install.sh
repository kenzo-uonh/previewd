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

[ -f /usr/bin/previewd ] && [ -x /usr/bin/previewd ] || fail "/usr/bin/previewd missing or not executable"
for f in /usr/lib/systemd/system/previewd.service \
	/usr/lib/systemd/system/previewd-builds.slice \
	/usr/lib/systemd/system/docker.service.d/previewd-builds.conf; do
	[ -f "$f" ] || fail "$f missing"
done

echo "OK: $(id previewd); /usr/bin/previewd $(stat -c '%a %U:%G' /usr/bin/previewd)"
