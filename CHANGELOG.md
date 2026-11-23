# Changelog

## Unreleased
- **Red for direct requests.** An email that asks you to send a password, security code or personal details (an SSN, card or bank number, date of birth...) is now red, even when no threat list knows the sender. So is an email telling you to send money, gift cards or cryptocurrency, unless it comes from someone you trust, a brand address that passed authentication, or someone you've emailed with before. Warnings such as "we will never ask for your password" don't count.
- **Look-alike company addresses are red.** A sender address that misspells the company the email names (`support@menrds.com` from "Menards", `billing@hartwe1llumber.com` from "Hartwell Lumber") is flagged even for companies Tripwire has never heard of. Look-alikes of known brands and of people you email with are now red too. 18 more brands were added to the built-in list (The Home Depot, Lowe's, Menards, Target, Costco, Best Buy, Verizon, AT&T, T-Mobile, Xfinity, Instagram, WhatsApp, TikTok, Norton, McAfee, Hulu, Disney+).
- **"Not sure this is the official address."** When the sender's domain contains the company's full name plus something else (`hartwelllumbermail.com` for "Hartwell Lumber"), Tripwire can't tell if it's real, so the email is yellow and the Summary says so, with an **I know this sender** button. Clicking it remembers the domain on this device (listed in the popup under "Sender addresses you know", where it can be removed) and re-checks the email. Later emails from that domain are no longer questioned about who sent them, but their contents (requests for passwords, links, attachments...) are still checked in full.
- **Red for strong signs of a scam.** Emails whose warning signs add up to a score below 35 (what used to be the yellow "Very suspicious") are now red. Yellow is kept for milder warning signs.

## 1.4.1 (2026-11-20)
- **Fix: sender authentication on live Gmail.** Gmail keeps the message ID one level above where Tripwire looked, so "Show original" was never fetched, and real brand mail showed "not verified" instead of "✓ verified". Found by checking Tripwire on a real Gmail account. The headers are now also read as plain text, which works with Gmail's Trusted Types security policy.
- **Browser tests** (`npm run test:e2e`, the `browser` job in CI): the extension is loaded into Chrome for Testing and checked on fake Gmail, Outlook and Yahoo pages, including a simulated Gmail redesign recovered by updated layout rules.
- **Store preparation:** screenshots and a promo tile generated from the real extension (`npm run store:assets`, in `store/`). Store packages no longer include the local demo-file permission. The Firefox add-on ID is `tripwire@sparkv2.com`.

## 1.4.0 (2026-11-19)
- **Reply-chain hijack detection.**
  - In Gmail conversations, a reply from a different company than the earlier messages is flagged, strongly when it's a look-alike address.
  - Anywhere, a new address that's a near-copy of a domain or address you regularly hear from is flagged, using fingerprints only.
  - Fake "Re:" subjects from strangers are flagged.
- **Payment-change alerts.**
  - Detects requests to send money to a new account, scored separately because that scam's wording is often calm.
  - Recognises IBANs, US routing numbers and UK sort codes by their checksums.
  - Warns strongly when a known supplier's bank details differ from the ones they sent before.
  - Gives specific advice to confirm by phone first.
- **"Show me".** Each reason in the banner can scroll to and highlight the exact part of the email it's about.
- **Webmail layout fixes without a new release.**
  - Every site-specific selector now lives in `data/selectors.json`, the webmail layout rules.
  - A change pushed to `main` is signed by GitHub Actions, mirrored by the Tripwire server, and verified by the extension, which picks it up at its next update.
  - When the health check notices a site has broken, the extension looks for a fix immediately.
  - Updated selectors are tried first and the built-in ones second, so a bad update can't make detection worse.
- A practice lesson about invoice fraud.

## 1.3.1 (2026-11-18): security hardening
- **Signed threat list.** GitHub Actions builds and signs the list every 6 hours. The server and the extension only accept it with a valid Ed25519 signature, a matching checksum, and a date that is newer than the current list and less than 3 days old. The signing key never touches the server.
- **The extension never flags protected sites** (brands, free mail, trackers, shared platforms) as a whole, even if a downloaded list includes them.
- **Community reports are harder to fake.** IPv6 reporters are grouped by /32 instead of /48, a domain's first report must be a day old before it's published, and the store is capped at 500,000 reports. An admin tool (`server/tripwire-admin.mjs`) can check, suppress and restore domains.
- **Server network isolation.** The server can no longer open connections into the home network. `cloudflared` runs as an unprivileged, sandboxed user that can't reach private addresses either.
- GitHub Actions are pinned to exact commits.

## 1.3.0 (2026-11-18)
- **Tripwire server** at `tripwire.sparkv2.com` (see `server/`). Live list updates now download one compact file from the server, which rebuilds it from the public feeds every 6 hours. If the server is down, the extension downloads the feeds directly, as before.
- **Community reports.** An opt-in setting, **Share my reports anonymously**, sends a SHA-256 fingerprint of a reported scam domain, and nothing else. Domains reported from 3 or more different networks get a yellow warning for every Tripwire user. They're never shown as a confirmed (red) scam.
- **Fix:** live feed updates no longer crash on very large lists (a stack overflow when merging more than 100,000 entries).
- The privacy policy has been updated to describe the server.

## 1.2.0 (2026-11-18)

### Detection
- **Sender authentication.** On Gmail, Tripwire reads the message's own `Authentication-Results` header (through Gmail's "Show original", on the device). A brand address only counts as real ("✓ verified PayPal address") when DMARC passes. A brand address that *fails* DMARC is flagged as forged. On other providers, where headers aren't available, a matching brand address gets less trust than a proven one.
- **QR codes.** Images in an email are decoded on the device (jsQR), and any web address inside is checked like a normal link, including against the known-threat lists.
- **Attachments.** Tripwire reads the attachment list the webmail page shows and flags double extensions (`invoice.pdf.html`), programs, disk images, macro documents, password-locked archives and reversed (RTLO) names. On Gmail, HTML attachments are opened as text, on the device, to look for login forms and hidden redirects.
- **Sender history.** "First email from this sender" and "familiar name, new address", the classic CEO and vendor fraud pattern. Only salted hashes are stored, on the device.
- **On-device AI (optional, off by default).** Chrome's built-in model (Gemini Nano) judges the intent of opened emails in any language and writes the summary. It can nudge the score to yellow, never to red.
- **Shortened links** (bit.ly and others) are followed one redirect at a time when you click them, and judged by where they really lead. The destination page is never opened.

### Protection beyond the inbox
- **Page guard (optional).** On pages you open, Tripwire blocks known scam and malware sites, and warns when a lookalike page, or a page opened from a risky email, asks for a password.
- **Password alert (optional).** Tripwire warns when you type your Google, Microsoft or Yahoo password on another site. It stores only a 4-byte fragment of a slow salted hash.

### Fixes
- The summary banner no longer appears on emails you're **writing** (new message, reply, forward). It used to show up in Outlook's compose box, which is also labelled "Message body".

### Engineering
- **Narrower permissions.** The content script runs only on known webmail sites instead of `<all_urls>`. Other sites are enabled one at a time from the popup, using Chrome's permission prompt. The page guard asks for all-sites access only when you turn it on.
- **Compact threat list:** 4.2 MB of JSON became a 1.5 MB sorted array of 53-bit hashes. It loads without parsing JSON or building a 193k-entry map.
- **Health check:** when a known webmail page shows an inbox but Tripwire finds no rows for a while, the toolbar icon shows a "!" and the popup explains that detection may be off.
- **Tests run anywhere:** `npm test` (Node's built-in test runner, no dependencies) runs on GitHub Actions. The in-browser test page uses the same cases.
- **Node build script** (`tools/build-threat-intel.mjs`) replaces the PowerShell one. A weekly GitHub Action rebuilds the list and opens a pull request.
- **Packaging** for Chrome, Edge and Firefox: `npm run package`.
- Practice mode: "spot the red flag" lessons built on the real analyzer.
- Added LICENSE (MIT), this changelog, STORE_LISTING.md and a privacy policy (PRIVACY.md).

## 1.1.0
- Threat-intelligence list compiled from OpenPhish, phishing-filter, CERT Polska, URLhaus, Feodo Tracker, botnet-filter and C2IntelFeeds. Live updates every 12 hours.

## 1.0.0
- First release: inbox highlighting, safety score, plain-language reasons, link warnings, report and trust lists.
