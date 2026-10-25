#!/bin/sh
# Package checks of previewd, run by `make test-packages` inside a throwaway
# container, in the order the Makefile calls them:
#
#   refused      the install was refused (no Docker Engine): nothing is there
#   stub-docker  stand in for Docker Engine, so the install can go on; the
#                container's own cgroup v2 is what preinstall.sh then checks
#   installed    after apt-get/dnf installed, then reinstalled (postinstall
#                run twice, as on an upgrade), the package
#   stage-secret leave a staged secret behind, as a running daemon would
#   removed      after the package was removed: files gone, secret discarded
set -eu

fail() { echo "FAIL: $*" >&2; exit 1; }

mode_of() { stat -c '%a' "$1"; }

case "${1:-installed}" in
refused)
	[ ! -e /usr/bin/previewd ] || fail "/usr/bin/previewd exists after a refused install"
	[ ! -e /usr/lib/systemd/system/previewd.service ] || fail "previewd.service exists after a refused install"
	! getent passwd previewd >/dev/null || fail "user previewd exists after a refused install"
	echo "OK: the install was refused and left nothing"
	;;

stub-docker)
	printf '#!/bin/sh\nexit 0\n' >/usr/bin/docker
	printf '#!/bin/sh\nexit 0\n' >/usr/bin/dockerd
	chmod 755 /usr/bin/docker /usr/bin/dockerd
	echo "OK: Docker Engine stand-in installed"
	;;

installed)
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
		/usr/lib/systemd/system/docker.service.d/previewd-builds.conf \
		/usr/lib/systemd/system/run-previewd-secrets.mount \
		/usr/lib/systemd/system/previewd-proxy.service \
		/etc/previewd/traefik.yml \
		/etc/sysctl.d/99-previewd.conf; do
		[ -f "$f" ] || fail "$f missing"
		[ "$(mode_of "$f")" = 644 ] || fail "$f has mode $(mode_of "$f"), want 644"
	done

	# The site-editable files are conffiles: an upgrade keeps the operator's copy.
	for f in /etc/previewd/traefik.yml /etc/sysctl.d/99-previewd.conf; do
		if command -v dpkg-query >/dev/null 2>&1; then
			dpkg-query -W -f='${Conffiles}\n' previewd | grep -q "^ $f " || fail "$f is not a conffile"
		else
			rpm -qc previewd | grep -qx "$f" || fail "$f is not a config file"
		fi
	done

	# The installed scripts are the package's, not an empty shell.
	if command -v dpkg-query >/dev/null 2>&1; then
		[ -s /var/lib/dpkg/info/previewd.preinst ] && [ -s /var/lib/dpkg/info/previewd.prerm ] || fail "preinst or prerm missing"
	else
		rpm -q --scripts previewd | grep -q "cgroup2fs" || fail "%pre does not check cgroup v2"
		rpm -q --scripts previewd | grep -q "run-previewd-secrets" || fail "%preun does not clean the secrets staging root"
	fi

	echo "OK: $(id previewd); /usr/bin/previewd $(stat -c '%a %U:%G' /usr/bin/previewd)"
	;;

stage-secret)
	mkdir -p /run/previewd/secrets
	echo 'TOKEN=hunter2' >/run/previewd/secrets/staged.env
	echo "OK: a secret is staged in /run/previewd/secrets"
	;;

removed)
	[ ! -e /usr/bin/previewd ] || fail "/usr/bin/previewd remains after removal"
	[ ! -e /usr/lib/systemd/system/previewd.service ] || fail "previewd.service remains after removal"
	[ ! -e /run/previewd/secrets/staged.env ] || fail "the staged secret survived the removal"
	[ ! -d /run/previewd/secrets ] || [ -z "$(ls -A /run/previewd/secrets)" ] || fail "/run/previewd/secrets is not empty after removal"
	echo "OK: removed; no staged secret remains"
	;;

*)
	fail "unknown mode ${1:-}"
	;;
esac
