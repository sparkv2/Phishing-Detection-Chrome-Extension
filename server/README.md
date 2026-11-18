# Tripwire server

A small, dependency-free Node 22 service at `https://tripwire.sparkv2.com`. It does two things:

1. **Threat-list mirror.** Every 6 hours, `tripwire-intel.timer` rebuilds the compact threat list from the public feeds (`tools/build-threat-intel.mjs --out /var/lib/tripwire/intel`). Extensions download one 1.5 MB file instead of eight feeds.
2. **Community reports (opt-in).** Extensions may send SHA-256 fingerprints of domains their user reported (`sha256("tripwire-report-v1|" + domain)`). A fingerprint is published in `/v1/community.json` once **3 different networks** reported it. The extension shows those domains as **yellow** (suspicious), never red.

| Endpoint | |
|---|---|
| `GET /v1/health` | `{ "ok": true }` |
| `GET /v1/intel/threat-intel.bin`, `/v1/intel/threat-intel.meta.json` | The compact list (ETag, cached 30 min) |
| `GET /v1/community.json` | `{ v, generated, threshold, prefix, hashes: [...] }` (cached 10 min) |
| `POST /v1/reports` | `{ "v": 1, "hashes": ["<64 hex>", …] }`, up to 20 per request and 50 per network per day |

## Privacy and abuse controls
- No IP addresses are stored. Reporters are counted by an HMAC (secret key in `/var/lib/tripwire/hmac.key`) of their /24 (IPv4) or /48 (IPv6) network, read from Cloudflare's `CF-Connecting-IP` header.
- Reports older than 90 days are deleted.
- Fingerprints of brand, free-mail, tracking, link-shortener and shared-hosting domains are refused, so nobody can get `gmail.com` or `github.com` flagged.
- No request logging.

## How it runs (a dedicated Ubuntu server or VM)
```
Internet → Cloudflare (HTTPS, WAF) → Cloudflare Tunnel → cloudflared on the server → 127.0.0.1:8787 (tripwire-server)
```
- **No inbound ports.** `ufw` denies everything incoming except SSH from the local network. cloudflared connects *out* to Cloudflare, so the router forwards nothing and the server's IP stays hidden.
- **`tripwire-server.service`** runs as the unprivileged `tripwire` user in a strict systemd sandbox. It can only talk to localhost (`IPAddressAllow=localhost`), can't write outside `/var/lib/tripwire`, and has no capabilities. `systemd-analyze security` rates it 1.1 (OK).
- **`tripwire-intel.service`** (the feed builder) is sandboxed the same way, but may make outbound HTTPS requests.
- **Code** lives in `/opt/tripwire` (owned by root, read-only to the service). Data lives in `/var/lib/tripwire`.
- **Host hardening:**
  - SSH: keys only, root key-only, local network only, 3 auth attempts, no forwarding.
  - fail2ban on SSH.
  - Automatic security updates (including cloudflared), with a reboot at 04:30 when needed.
  - Network sysctls hardened, and unneeded services disabled.

## Deploy or update
From a copy of the repo on the server, as root:
```
sh server/deploy/install.sh /path/to/repo
```

## Cloudflare setup (once)
1. In the Cloudflare dashboard, go to **Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared**, and give it a name.
2. Copy the install command it shows (`cloudflared service install <token>`) and run it on the server **yourself**. The token is a secret: never commit it or paste it anywhere public.
3. Under **Public Hostname**, add `tripwire.sparkv2.com` with service type `HTTP` and URL `localhost:8787`.
4. Recommended: under **Security → WAF → Rate limiting rules** for sparkv2.com, limit `POST` requests to `/v1/reports` to 30 per minute per IP.
