# Tripwire server

A small, dependency-free Node 22 service at `https://tripwire.sparkv2.com`. It does two things:

1. **Signed threat-list mirror.** GitHub Actions (`.github/workflows/publish-intel.yml`) rebuilds the compact threat list from the public feeds every 6 hours, **signs it**, and publishes it as the `intel-latest` release. The server fetches it every hour (`server/fetch-intel.mjs`), checks the signature, and hands it out. Extensions download one 1.5 MB file instead of eight feeds, and check the signature again themselves. The same release carries the signed webmail layout rules (`selectors.json`), mirrored the same way.
2. **Community reports (opt-in).** Extensions may send SHA-256 fingerprints of domains their user reported (`sha256("tripwire-report-v1|" + domain)`). A fingerprint is published in `/v1/community.json` once **3 different networks** reported it **and** its first report is at least a day old. The extension shows those domains as **yellow** (suspicious), never red.

| Endpoint | |
|---|---|
| `GET /v1/health` | `{ "ok": true }` |
| `GET /v1/intel/threat-intel.bin`, `…/threat-intel.meta.json`, `…/threat-intel.meta.json.sig` | The signed compact list (ETag, cached 30 min) |
| `GET /v1/intel/selectors.json`, `…/selectors.json.sig` | Signed webmail layout rules (see the main README, "Fixing a layout change without a new release") |
| `GET /v1/community.json` | `{ v, generated, threshold, prefix, hashes: [...] }` (cached 10 min) |
| `POST /v1/reports` | `{ "v": 1, "hashes": ["<64 hex>", …] }`, up to 20 per request and 50 per network per day |

## Why the list is signed
The signing key exists only as the GitHub secret `TRIPWIRE_SIGNING_KEY`. The server and the extension only hold the public key (`SIGNING_PUBLIC_KEY` in `src/intel.js`). Someone who took over the server, the tunnel or the Cloudflare account could withhold updates, but not forge a list. Any list is refused if:
- its signature doesn't check out, or the list file doesn't match the checksum in the signed `meta.json`;
- it's older than the list already in use (a replay of an old list);
- it's more than 3 days old (updates are being withheld). The extension then falls back to the public feeds.

The extension also never flags brands, free-mail providers, trackers or shared platforms as a whole, whatever a list says.

**Rotating the key:**
1. Run `node tools/sign-intel.mjs --generate-key DIR`.
2. Put the printed public key in `src/intel.js`, and the private key in the GitHub secret.
3. Release a new extension version, then redeploy the server.

## Privacy and abuse controls
- No IP addresses are stored. Reporters are counted by an HMAC (secret key in `/var/lib/tripwire/hmac.key`) of their network: /24 for IPv4, /32 for IPv6. IPv6 is grouped that coarsely because one free IPv6 tunnel account yields many /48s. The address comes from Cloudflare's `CF-Connecting-IP` header.
- A domain needs 3 networks, and its first report must be a day old, before it's published.
- Reports older than 90 days are deleted. The store holds at most 500,000 reports, so a flood can't fill the disk.
- Fingerprints of brand, free-mail, tracking, link-shortener and shared-hosting domains are refused.
- No request logging.

### Removing a false report
```
sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs check   some-site.example
sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs suppress some-site.example "legitimate business"
sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs unsuppress some-site.example
sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs stats
```
`suppress` deletes the domain's reports, takes it off the public list within 10 minutes, and refuses new reports for it.

## How it runs (a dedicated Ubuntu server or VM)
```
Internet → Cloudflare (HTTPS, WAF, cache) → Cloudflare Tunnel → cloudflared → 127.0.0.1:8787 (tripwire-server)
```
- **No inbound ports.** `ufw` denies everything incoming except SSH from the local network.
- **No connections into the home network.** `ufw` also denies *outgoing* connections to private address ranges, except DHCP to the router. A compromised service couldn't scan or attack other home devices.
- **`cloudflared`** runs as a throwaway unprivileged user (`DynamicUser`), receives its tunnel token read-only from systemd, and is barred from private address ranges. Even if the Cloudflare account were taken over and the tunnel re-pointed, it could only reach the Tripwire service on localhost. `systemd-analyze security` rates it 1.5 (OK). See `deploy/harden-network.sh`.
- **`tripwire-server.service`** runs as the unprivileged `tripwire` user in a strict sandbox: localhost only, no writes outside `/var/lib/tripwire`, no capabilities. It's rated 1.1 (OK).
- **`tripwire-intel.service`** fetches and verifies the signed list from GitHub. It's sandboxed the same way and barred from private ranges, and rated 1.5 (OK).
- **Code** lives in `/opt/tripwire` (owned by root, read-only to the services). Data lives in `/var/lib/tripwire`.
- **Host hardening:**
  - SSH: keys only, root key-only, local network only, 3 auth attempts, no forwarding.
  - fail2ban on SSH.
  - Automatic security updates (including cloudflared), with a reboot at 04:30 when needed.
  - Network sysctls hardened, and unneeded services disabled.

## Deploy or update
From a copy of the repo on the server, as root:
```
sh server/deploy/install.sh /path/to/repo
sh server/deploy/harden-network.sh      # once: outbound firewall + cloudflared sandbox
```

## Cloudflare setup (once)
1. In the Cloudflare dashboard, go to **Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared**, and give it a name.
2. Copy the install command it shows (`cloudflared service install <token>`) and run it on the server **yourself**. The token is a secret: never commit it or paste it anywhere public.
3. Under **Public Hostname**, add `tripwire.sparkv2.com` with service type `HTTP` and URL `localhost:8787`.
4. **Cache the list at Cloudflare**, so downloads don't use the server's upload bandwidth. Under **Caching → Cache Rules → Create rule**:
   - **Name:** `Tripwire list`
   - **When:** Hostname equals `tripwire.sparkv2.com` **and** URI Path starts with `/v1/intel/`
   - **Then:** Eligible for cache, Edge TTL **Use cache-control header if present**, Browser TTL **Respect origin**
5. **Rate-limit reports.** Under **Security → WAF → Rate limiting rules → Create rule**:
   - **When:** Hostname equals `tripwire.sparkv2.com` **and** URI Path equals `/v1/reports` **and** Request Method equals `POST`
   - **Rate:** 30 requests per 1 minute, counted per IP
   - **Then:** Block for 10 minutes
6. Under **SSL/TLS → Edge Certificates**, turn on **Always Use HTTPS**, **HSTS**, and **Minimum TLS Version 1.2**.
7. Turn on **two-factor authentication** for the Cloudflare and GitHub accounts. They control the tunnel and the signing key.
