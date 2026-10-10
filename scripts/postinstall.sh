#!/bin/sh
# Package post-install script for previewd (nfpm.yaml), run as root by dpkg
# (postinst configure) and rpm (%post) on every install and upgrade. It is
# idempotent and never starts, restarts or enables a service: the host
# controls (credentials, ramfs, Traefik, docs/deployment.md) must be in place
# first, and restarting docker.service for the drop-in is the operator's call.
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin

# The Engine API socket group. Docker's own packages create it as a system
# group when missing and keep an existing one, so creating it first is
# compatible with a later Docker install.
if ! getent group docker >/dev/null; then
	groupadd --system docker
fi

# System account: no login shell, no home directory, no password.
if ! getent passwd previewd >/dev/null; then
	useradd --system --user-group --no-create-home --home-dir /nonexistent \
		--shell /bin/false --comment "previewd agent" previewd
fi

# Supplementary group for the socket (previewd.service also runs Group=docker).
usermod --append --groups docker previewd

# Pick up the unit, the slice and the docker.service drop-in. No systemd
# running (containers, image builds): nothing to reload.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi
