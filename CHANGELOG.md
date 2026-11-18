# Changelog

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
- Added LICENSE (MIT), this changelog and STORE_LISTING.md.

## 1.1.0
- Threat-intelligence list compiled from OpenPhish, phishing-filter, CERT Polska, URLhaus, Feodo Tracker, botnet-filter and C2IntelFeeds. Live updates every 12 hours.

## 1.0.0
- First release: inbox highlighting, safety score, plain-language reasons, link warnings, report and trust lists.
