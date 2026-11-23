# Tripwire: a phishing checker for your email

Tripwire is a Chrome extension (also Edge and Firefox) that checks your email for scams while you read it. It works in Gmail, Outlook, Yahoo and other webmail, and it never sends your emails anywhere: every check runs on your own computer.

**In your inbox**
- Confirmed scams are coloured **red**, and suspicious emails are coloured **yellow**.
- Open any email and a banner at the top shows a **safety score from 0 to 100**, a short summary, what the email wants you to do, and the reasons for any warning, in plain language.

**What it catches**
- Fake sender addresses, including ones that copy a real company's address exactly (SPF/DKIM/DMARC checks).
- Lookalike websites such as "paypa1.com" or "rnicrosoft.com".
- Links that say one thing but go somewhere else, and shortened links that hide where they lead.
- QR codes that send you to fake login pages.
- Dangerous attachments, like a "PDF" that is really a web page or a program.
- Pressure tactics: urgent threats, requests for passwords or payment, and "quick favour" gift-card scams.
- A familiar name, like your boss or a supplier, writing from a new address.
- Sites on public lists of known phishing and malware, kept up to date automatically.

**Before you click:** if you click a risky link, Tripwire stops you first, shows where the link really goes, and explains the danger.

**Optional extras:** protection on pages you open, a password alert, Chrome's on-device AI for emails in any language, and a practice mode with short "spot the red flag" lessons.

**Your privacy:** your emails are never uploaded, stored or shared. Tripwire keeps only your settings, simple counts, and the senders you've trusted or reported, all on your device.

See [CHANGELOG.md](CHANGELOG.md) for what's new.

## Install (developer mode)
1. Open `chrome://extensions` and turn on **Developer mode** (top right).
2. Click **Load unpacked** and select this folder (the one containing `manifest.json`).
3. Optional, to try the demo inbox: on the extension's **Details** page, turn on **Allow access to file URLs**, then open `demo/demo-inbox.html` in Chrome. Its **Compose** button opens a draft, which should *not* get a banner.

Edge: load the same folder at `edge://extensions`. Firefox 128+: run `npm run package` and load `dist/firefox/manifest.json` from `about:debugging`.

## How it works
| Feature | Where |
|---|---|
| Inbox rows: **red** = known (confirmed) phishing only, **yellow** = suspicious but unconfirmed | `src/content.js`, `src/content.css` |
| Banner at the top of an opened email (read view only, never in compose): summary, what it asks you to do, safety score 0–100, plain-language reasons, what to do next | `src/ui.js` |
| Warns before you open risky links, and follows shortened links to their real destination; hover any link to see where it goes | `src/content.js` → `guardLinks`, `background.js` |
| Report button (with provider-specific how-to) plus a local block list; "I know this sender" trust list | `src/content.js`, popup |
| Detection engine | `src/analyzer.js`, `src/data.js` |
| Optional page guard and password alert | `src/guard.js` |
| Optional on-device AI | `offscreen/ai.js` |
| Practice mode | `practice/` |

### Detection signals
- **Authentication:** On Gmail, the message's own `Authentication-Results` header is read through Gmail's "Show original" page, on the device. DMARC pass makes a brand address "verified". DMARC fail on a brand address means the From line is forged. Other providers don't expose headers, so a brand address there is "matching, not verified" and earns less trust.
- **Sender:** a brand name shown in the display name while the address is a free account or another domain; lookalike domains (paypa1, rnicrosoft, Cyrillic letters, `brand-secure-login.com`, typos); an email address written in the display name; risky TLDs.
- **Sender history:** "first email from this sender" (only counts when it also asks for money, details or secrecy), and "familiar name, new address", the CEO and vendor fraud pattern. Stored as salted SHA-256 hashes; collection needs 14 days or 150 senders before "first email" is used.
- **Reply-chain hijack:** in a Gmail conversation, a reply from a different company than the earlier messages, flagged strongly when it's a look-alike (`northwind` → `northwlnd`). Anywhere, a new address that's one character off a domain or address you regularly hear from is flagged. This is found by fingerprinting the possible originals, never by storing who you email. A "Re:" subject from someone you've never heard from is also flagged.
- **Payment changes:** wording such as "our bank details have changed" or "pay the new account", in its own scoring bucket. Bank numbers (IBANs, US routing numbers, UK sort codes) are recognised by their checksums. Each known sender's bank details are remembered as fingerprints, so *different* details from a familiar supplier raise a strong warning, with advice to call the supplier on a number you already have.
- **"Show me":** every reason in the banner has a button that scrolls to and highlights the exact sender, link, words, attachment or QR image it refers to. Text is marked with the browser's CSS Custom Highlight API, so the email's page is never altered.
- **Links:** link text shows one domain but the link goes to another; IP-address links; punycode; `@` tricks; a brand's real domain used as a subdomain (`paypal.com.evil.ru`); shorteners (followed on click); http; unusual ports; `javascript:`/`data:` links; sign-in forms inside the email. Outlook Safe Links and Google redirect links are unwrapped first.
- **QR codes:** images in the email are decoded with jsQR in the background worker, and their URLs are checked like links.
- **Attachments:** names from the page's attachment list: double extensions, programs, disk images, macro documents, locked archives, reversed (RTLO) names. Gmail HTML attachments are read for login forms and redirects.
- **Wording:** urgency, threats and fear, requests for passwords or codes, payment, gift-card or wire requests, prizes, generic greetings, secrecy or "quick favour" (CEO fraud).
- **On-device AI (optional):** Chrome's built-in Gemini Nano judges intent in any language and writes the summary. It's capped so it can make an email yellow on its own, never red.
- **Known threats:** the compiled threat-intelligence list (below), plus senders the user reported.

### Known-threat list (`data/threat-intel.bin`)
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

- **Format:** a sorted array of 53-bit hashes (cyrb53) plus a one-byte source index, 8 bytes per entry, about 1.5 MB. `data/threat-intel.meta.json` holds source names, counts and dates. The chance of a clean site colliding with a listed one is about 1 in 40 billion per lookup. See "compact index" in `src/intel.js`.
- **Rebuild the bundled file:** `npm run build:intel` (Node 20+, no dependencies). A weekly GitHub Action does this and opens a pull request.
- **Live updates:** the background worker re-downloads the same feeds every 12 hours (popup toggle) and merges them into the index. The bundled file is the offline fallback.
- **How lookups work:** tabs send only the hosts/URLs found in an email to the extension's own background worker. Parent domains are matched too (`a.evil.com` matches a listed `evil.com`).
- **Shared-platform safety:** big shared services (GitHub, Google Drive/Docs, Dropbox, Discord CDN, OneDrive, S3, bit.ly…) and every brand, free-mail and mail-tracking domain are never flagged as a whole. Only the exact listed URL is. Customer subdomains on hosting platforms (`evil.vercel.app`, `x.duckdns.org`) are flagged individually.

### Scoring and false-positive controls
- **Red** only when the sender or a link (or QR code) is on the known-threat list, the built-in list, or reported by the user. Score is 0.
- **Yellow** when the score is 10–69 and the email isn't on a known list. Below 35 the banner says "Very suspicious".
- **Safe** at 70 or above. Score = 100 − weighted signals; unconfirmed emails never go below 10.
- Wording alone is capped at 45 points. AI is capped at 32. Attachments are capped at 60.
- Mail from a proven brand address (DMARC pass) with clean links gets wording penalties reduced by 60%, an unverified brand address by 40%, trusted senders by 70%. Trusting a sender never hides a failed anti-forgery check.
- Brand claims only count when the display name is *just* the brand ("Chase Security"), not a person ("Chase Miller").

## Permissions
The content script runs only on known webmail sites (Gmail, Outlook, Yahoo, AOL, Proton, Zoho, Fastmail, iCloud). On any other webmail, click the toolbar icon → **Check emails on this site**. Chrome asks for permission for that one site. Turning on **Protect the pages I open** asks for all-sites access. Turning it off gives it back. See `STORE_LISTING.md` for a justification of each permission.

## Privacy
The full policy is in [PRIVACY.md](PRIVACY.md). In short:
- All analysis happens on the device. No email content, sender or URL is ever sent to a server.
- Network requests: public threat-list downloads (can be turned off), redirect lookups at link shorteners for links you click (can be turned off), Gmail's own "Show original" and attachment pages (same site, your session), and re-fetching images already shown in the email (for QR codes).
- Stored on the device: settings, counts, trusted and reported lists, the downloaded threat lists, salted hashes of past senders, which kinds of warning signs you've received (for practice mode), and, only if password alert is on, a 4-byte fragment of a slow salted hash of your mail password.

## Supported providers
Gmail and Yahoo have dedicated adapters. Outlook and other webmail use an ARIA-based generic adapter. Webmail sites change their HTML often. When a known site shows an inbox but Tripwire finds nothing, the toolbar icon shows **!** and the popup explains it.

### Fixing a layout change without a new release
Every site-specific selector lives in **`data/selectors.json`**, the webmail layout rules. To fix a broken site:
1. Edit the selector in `data/selectors.json` and raise its `version` by 1.
2. Copy the same change into `src/selectors.js` (the built-in copy; `npm test` fails if they differ).
3. Push to `main`.

The "Publish signed threat list" workflow runs straight away. It signs the file with the project key and publishes it, and the Tripwire server verifies and mirrors it. Every installed Tripwire picks it up at its next update, or within minutes on a site that just broke. The health check asks for new rules as soon as detection stops working.

Updated rules are data only: CSS selectors, each validated before use. A rules file needs a valid signature and a higher version, and `minExtension` stops rules from reaching versions too old to understand them. For every lookup, the updated selector is tried first and the built-in one second, so a bad update can't make detection worse than before.

## Development
```
npm test              # unit tests: analyzer, auth parsing, threat index, signatures, server, lessons, manifest
npm run test:e2e      # browser tests (needs CHROME_PATH, see below)
npm run build:intel   # re-download the feeds into data/
npm run package       # dist/ folders and zips for chrome, edge, firefox
npm run store:assets  # store screenshots and promo tile into store/ (needs CHROME_PATH)
```
The same analyzer cases also run in the browser: open `test/analyzer-tests.html`.

### Browser tests
`test/e2e/run.mjs` loads the extension into a real Chrome and opens fake Gmail, Outlook and Yahoo pages at their real addresses. The browser has no network: mail-site requests are answered from `test/e2e/fixtures.mjs`. It checks:
- inbox colours, and the banner on the email being read (not on compose boxes)
- Gmail's "Show original" authentication check, the HTML-attachment check and "Show me"
- the link warning
- that a simulated redesign sets the **!** badge, and new layout rules fix it
- that the popup and practice mode work, and no page throws an error

It needs no npm packages, only Node 22+ and **Chrome for Testing**: regular Chrome no longer loads extensions from the command line. Download it from https://googlechromelabs.github.io/chrome-for-testing/ and set `CHROME_PATH` to its `chrome` executable. CI does this automatically (the `browser` job).

The fake pages copy the structure of the real sites. When a site changes, update `data/selectors.json` (see below) and the matching fixture.

## Tripwire server
`server/` holds the small service at `tripwire.sparkv2.com`. It mirrors the threat list and collects opt-in community reports (SHA-256 fingerprints of domains only), published once 3 different networks report a domain. See [server/README.md](server/README.md) for the setup, the hardening and the Cloudflare Tunnel.
