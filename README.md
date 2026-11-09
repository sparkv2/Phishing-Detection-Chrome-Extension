# Tripwire: Chrome extension

Spots phishing in webmail, colours risky emails in the inbox, explains *why* each one is risky, scores every opened email from 0 to 100, and stops you before you click a dangerous link.

## Install (developer mode)
1. Open `chrome://extensions` and turn on **Developer mode** (top right).
2. Click **Load unpacked** and select this `tripwire` folder.
3. Optional, to try the demo inbox: on the extension's **Details** page, turn on **Allow access to file URLs**, then open `demo/demo-inbox.html` in Chrome.

## What it does
| Feature | Where |
|---|---|
| Inbox rows: **red** = known (confirmed) phishing only, **yellow** = suspicious but unconfirmed | `src/content.js`, `src/content.css` |
| Banner at the top of an opened email: summary, what it asks you to do, safety score 0–100, plain-language reasons, what to do next | `src/ui.js` |
| Warns before you open risky links; hover any link to see its real destination | `src/content.js` → `guardLinks` |
| Report button (with provider-specific how-to) plus a local block list; "I know this sender" trust list | `src/content.js`, popup |
| Detection engine | `src/analyzer.js`, `src/data.js` |

### Detection signals
- **Sender:** brand name shown in the display name while the address is a free account or another domain, lookalike domains (paypa1, rnicrosoft, Cyrillic letters, `brand-secure-login.com`, typos), an email address written in the display name, risky TLDs.
- **Links:** text shows one domain but the link goes to another, IP-address links, punycode, `@` tricks, a brand's real domain used as a subdomain (`paypal.com.evil.ru`), shorteners, http, unusual ports, `javascript:`/`data:` links, sign-in forms inside the email. Outlook Safe Links and Google redirect links are unwrapped first.
- **Wording:** urgency, threats and fear, requests for passwords or codes, payment, gift-card or wire requests, prizes, generic greetings, secrecy or "quick favour" (CEO fraud), risky attachment types.
- **Known threats:** the compiled threat-intelligence list (below), plus senders the user reported.

### Known-threat list (`data/threat-intel.json`)
About 193,000 known-bad domains, IPs and URLs, compiled from free public feeds:

| Category | Source | What it contains |
|---|---|---|
| Phishing | [OpenPhish](https://openphish.com/) | Live phishing URLs (matched by exact page, so shared hosts aren't flagged) |
| Phishing | [phishing-filter](https://gitlab.com/malware-filter/phishing-filter) | Phishing domains aggregated from PhishTank, OpenPhish, PhishStats |
| Phishing | [CERT Polska warning list](https://cert.pl/en/warning-list/) | Phishing and scam domains |
| Malware | [URLhaus](https://urlhaus.abuse.ch/) via urlhaus-filter | Sites currently serving malware |
| C2 | [Feodo Tracker](https://feodotracker.abuse.ch/) | Active botnet command-and-control IPs (Emotet, QakBot, Dridex…) |
| C2 | [botnet-filter](https://gitlab.com/malware-filter/botnet-filter) | Malicious server IPs based on abuse.ch data |
| C2 | [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | Cobalt Strike and other C2 IPs and domains seen in the last 30 days |

- **Rebuild the bundled file:** `powershell -ExecutionPolicy Bypass -File tools\build-threat-intel.ps1`
- **Live updates:** the background worker re-downloads the same feeds every 12 hours (popup toggle) and stores them in the Cache API. The bundled file is the offline fallback.
- **How lookups work:** tabs send only the hosts/URLs found in an email to the extension's own background worker, which checks them against an in-memory index. Parent domains are matched too (`a.evil.com` matches a listed `evil.com`).
- **Shared-platform safety:** big shared services (GitHub, Google Drive/Docs, Dropbox, Discord CDN, OneDrive, S3, bit.ly…) and every brand, free-mail and mail-tracking domain are never flagged as a whole. Only the exact listed URL is. Customer subdomains on hosting platforms (`evil.vercel.app`, `x.duckdns.org`) are flagged individually. See `src/intel.js`.
- **Not available:** abuse.ch's ThreatFox and the raw URLhaus downloads now need a free account key, so they aren't used directly.

### Scoring and false-positive controls
- **Red** only when the sender or a link is on the known-threat list, the built-in list, or reported by the user. Score is 0. The banner names the threat type (phishing, malware or C2) and the source list.
- **Yellow** when the score is 10–69 and the email isn't on a known list. Below 35 the banner says "Very suspicious" and shows the stronger advice.
- **Safe** at 70 or above. Score = 100 − weighted signals; unconfirmed emails never go below 10.
- Wording alone is capped at 45 points, so pushy marketing only scores a little lower.
- Mail from a brand's real domain with clean links gets wording penalties reduced by 60%; trusted senders by 70%.
- Brand claims only count when the display name is *just* the brand ("Chase Security"), not a person ("Chase Miller").
- Brand names that are common words (apple, office, chase…) need a phishing keyword next to them before a domain counts as a lookalike.

## Privacy
- All analysis happens in the page, in memory. No email content, sender, or URL is ever transmitted.
- The only network requests are GETs that download the public threat lists (can be turned off in the popup; the bundled list still works).
- Stored on the device: on/off settings, counts, the user's trusted and reported lists, the downloaded threat lists.

## Supported providers
Gmail and Yahoo have dedicated adapters. Outlook and other webmail use an ARIA-based generic adapter. On any other webmail, click the toolbar icon → **Check emails on this site**.
Webmail sites change their HTML often. If highlighting stops on a provider, update its selectors in `src/providers.js`.

## Tests
Open `test/analyzer-tests.html` in Chrome (with file access allowed). It runs 80 checks:
- phishing samples and false-positive traps
- phishing, malware and C2 list matches
- that every source in the compiled list is detected
- that 37 popular legitimate sites (Gmail, GitHub, Drive, banks…) are never flagged
