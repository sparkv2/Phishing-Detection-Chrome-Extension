#!/bin/sh
# Second hardening pass for the Tripwire server. Safe to re-run. Run as root.
#  1. Outbound firewall: the server may not start connections to the home network (only the DHCP lease renewal to
#     the router). Replies to your own SSH sessions still work, because those connections started on your side.
#  2. cloudflared runs as an unprivileged throwaway user in a sandbox, and can't reach the home network either.
#     Even if someone took over the Cloudflare account and re-pointed the tunnel, it could only reach localhost.
#     If the tunnel doesn't come back within 30 seconds, this change is undone automatically.
set -eu
GW=$(ip route | awk '/^default/ {print $3; exit}')

echo "== outbound firewall"
ufw allow out to "$GW" port 67 proto udp comment 'DHCP lease renewal with the router'
for net in 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 100.64.0.0/10 169.254.0.0/16 fc00::/7; do
  ufw deny out to "$net" comment 'no connections into the home network'
done
ufw reload

echo "== cloudflared sandbox"
install -d /etc/systemd/system/cloudflared.service.d
cat > /etc/systemd/system/cloudflared.service.d/10-tripwire-sandbox.conf <<'EOF'
[Service]
# Run as a throwaway unprivileged user; the token is handed over read-only by systemd.
DynamicUser=yes
LoadCredential=token:/etc/cloudflared/token
ExecStart=
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file ${CREDENTIALS_DIRECTORY}/token
# Never the home network: only Cloudflare (internet) and the local Tripwire service.
IPAddressDeny=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 fc00::/7 fe80::/10
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryMax=256M
EOF
systemctl daemon-reload
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart cloudflared
ok=0
for i in $(seq 1 30); do
  sleep 1
  if journalctl -u cloudflared --since "$since" -o cat | grep -q 'Registered tunnel connection'; then ok=1; break; fi
done
if [ "$ok" = 1 ] && systemctl is-active -q cloudflared; then
  echo "cloudflared is up in its sandbox, running as: $(ps -o user= -C cloudflared | head -1)"
else
  echo "cloudflared did not reconnect; undoing the sandbox change"
  journalctl -u cloudflared --since "$since" -o cat | tail -5
  rm -f /etc/systemd/system/cloudflared.service.d/10-tripwire-sandbox.conf
  systemctl daemon-reload; systemctl restart cloudflared
  exit 1
fi
systemd-analyze security cloudflared.service | tail -1
