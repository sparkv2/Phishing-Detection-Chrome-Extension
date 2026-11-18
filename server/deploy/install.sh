#!/bin/sh
# Installs or updates the Tripwire server on Ubuntu. Run as root from a copy of the repo:
#   sh server/deploy/install.sh /path/to/repo
# Code goes to /opt/tripwire (owned by root, read-only to the service); data lives in /var/lib/tripwire.
set -eu
SRC=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
export DEBIAN_FRONTEND=noninteractive

command -v node >/dev/null || apt-get -y -q install nodejs
id tripwire >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tripwire --shell /usr/sbin/nologin tripwire

# Only what the server needs: shared detection data, the feed builder and the server itself.
install -d -o root -g root -m 0755 /opt/tripwire /opt/tripwire/src /opt/tripwire/tools /opt/tripwire/server
install -o root -g root -m 0644 "$SRC"/src/data.js "$SRC"/src/analyzer.js "$SRC"/src/intel.js /opt/tripwire/src/
install -o root -g root -m 0644 "$SRC"/tools/build-threat-intel.mjs /opt/tripwire/tools/
install -o root -g root -m 0644 "$SRC"/server/tripwire-server.mjs "$SRC"/server/db.mjs "$SRC"/server/fetch-intel.mjs \
  "$SRC"/server/tripwire-admin.mjs /opt/tripwire/server/
install -o root -g root -m 0644 "$SRC"/server/deploy/tripwire-server.service "$SRC"/server/deploy/tripwire-intel.service \
  "$SRC"/server/deploy/tripwire-intel.timer /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now tripwire-server.service tripwire-intel.timer
systemctl restart tripwire-server.service
[ -f /var/lib/tripwire/intel/threat-intel.bin ] || systemctl start tripwire-intel.service
systemctl --no-pager --lines=0 status tripwire-server.service | head -3
