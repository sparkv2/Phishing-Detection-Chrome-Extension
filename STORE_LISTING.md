# Chrome Web Store listing

Draft text for the store submission form. The upload file is `dist/tripwire-<version>-chrome.zip` (from `npm run package`).

## Name
Tripwire — Phishing Email Checker

## Summary (132 characters max)
Spots phishing in Gmail, Outlook and Yahoo, explains why in plain language, and stops risky clicks. Runs privately on your device.

## Description
Tripwire checks your email for scams while you read it.

• Red rows for confirmed phishing, yellow for suspicious emails
• A safety score from 0 to 100 on every email you open, with plain-language reasons
• Stops you before you open a dangerous link, and shows where shortened links really go
• Catches forged sender addresses, lookalike domains, QR-code phishing, dangerous attachments, and "boss needs gift cards" fraud
• Optional: warns you on fake login pages and when you type your email password on the wrong site
• Optional: Chrome's built-in on-device AI understands scams in any language
• Practice mode teaches you to spot the tricks yourself

Private by design: emails are analysed on your computer. Their content is never uploaded, stored or shared.

## Category
Productivity (or Privacy & Security)

## Single purpose
Detect phishing and fraud in webmail and warn the user before they act on it.

## Permission justifications
| Permission | Why |
|---|---|
| `storage` | Saves settings, counts, the user's trusted and reported senders, and hashed sender history, on the device. |
| `alarms` | Refreshes the public threat lists every 12 hours. |
| `activeTab` | Lets the popup see which site is open so it can offer "Check emails on this site". |
| `scripting` | Turns Tripwire on for extra webmail sites the user picks, and for the optional page guard. |
| `webRequest` | Reads the redirect header from link shorteners (bit.ly…) so a short link can be judged by its destination without opening it. |
| `offscreen` | Runs Chrome's built-in on-device AI model (optional feature). The Prompt API isn't available in service workers. |
| Host: webmail sites (content script) | Reads the emails the user opens in order to check them. |
| Host: tripwire.sparkv2.com | The Tripwire server: downloads the threat list and the community reports list. Uploads only opt-in report fingerprints. |
| Host: openphish.com, gitlab.io, github, cert.pl, abuse.ch | Fallback: downloads the public threat lists directly if the Tripwire server is down. Nothing is uploaded. |
| Host: googleusercontent.com, mail.google.com | Re-reads images shown in an email to decode QR codes, on the device. |
| Host: link shorteners | Asks the shortener where a link goes (see `webRequest`). |
| Optional: all sites | Requested only if the user turns on "Protect the pages I open" or enables an extra webmail site. |

## Privacy policy URL
https://github.com/sparkv2/Phishing-Detection-Chrome-Extension/blob/main/PRIVACY.md

## Privacy practices (data disclosure form)
- Does not collect or transmit personal data, email content, browsing history or authentication information.
- Data stays on the device: settings, counts, trusted and reported lists, salted hashes of past senders, and (if password alert is on) a 4-byte fragment of a slow salted hash of the user's email password.
- Network requests: threat-list and community-list downloads (from the Tripwire server, with the public feeds as a fallback), opt-in report fingerprints, shortener redirect lookups for links the user clicks, and re-fetching images already shown in an email.
- No ads, no analytics, no remote code.

## Screenshots to prepare (1280×800)
1. Inbox with red and yellow rows (demo/demo-inbox.html)
2. Opened phishing email with the banner and reasons
3. Link warning dialog showing the real destination of a shortened link
4. Popup with stats and Extra protection
5. Practice mode lesson
