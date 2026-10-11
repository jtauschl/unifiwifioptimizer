#!/bin/sh
# Start dropbear (22) and sshd (2222) in the foreground of one process group; reset the stub state.
set -eu

: >/run/ifstate/apcli0.up
: >/run/ifstate/ra0.up
: >/run/ifstate/rai0.up
rm -f /run/ifstate/apclii0.up /run/stub/*

# -R: generate host keys on first start; -E: log to stderr; -F: foreground; -w: no root logins.
dropbear -R -E -F -w -p 22 &
/usr/sbin/sshd -D -e &
wait
