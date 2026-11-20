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

- "Remote code": none. The extension downloads only data: the threat list and the webmail layout rules (CSS selectors), both signed and verified before use. All code ships in the package.

## Store images (in `store/`, regenerate with `npm run store:assets`)
All made from the demo inbox (made-up emails) with the real extension running, so they show exactly what Tripwire draws.

| File | Size | Shows |
|---|---|---|
| `screenshot-1.png` | 1280×800 | Inbox colours and the invoice-fraud warning ("bank details changed") |
| `screenshot-2.png` | 1280×800 | A confirmed phishing email: score 0 and the reasons |
| `screenshot-3.png` | 1280×800 | The warning before a dangerous link opens, with its real destination |
| `screenshot-4.png` | 1280×800 | Practice mode: a lesson with its explanation |
| `screenshot-5.png` | 1280×800 | The popup |
| `promo-small.png` | 440×280 | Small promo tile |
| `icons/icon128.png` | 128×128 | Store icon |

## Packages (`npm run package`)
| Store | Upload | Notes |
|---|---|---|
| Chrome Web Store | `dist/tripwire-<version>-chrome.zip` | |
| Microsoft Edge Add-ons | `dist/tripwire-<version>-edge.zip` | Same code as Chrome |
| Firefox (addons.mozilla.org) | `dist/tripwire-<version>-firefox.zip` | Add-on ID `tripwire@sparkv2.com` (set `TRIPWIRE_GECKO_ID` to change it before the *first* upload; it can never change afterwards). The on-device AI option shows "not supported" in Firefox. Mozilla may ask for the source: point them to the GitHub repo (no build step: the zip is the source). |

Store packages leave out the `file:///…demo-inbox.html` match used for local testing.

## What only you can do (accounts and fees)
1. **Chrome Web Store:** register a developer account at https://chrome.google.com/webstore/devconsole (one-time US$5 fee, Google account, 2-step verification required). Then *New item* → upload the Chrome zip → fill in this listing, the privacy fields and the images → *Submit for review*. Review usually takes a few days; extensions with broad host permissions can take longer.
2. **Microsoft Edge Add-ons:** register at https://partner.microsoft.com/dashboard/microsoftedge (free) → *Create new extension* → upload the Edge zip → reuse this listing.
3. **Firefox:** create an account at https://addons.mozilla.org/developers (free) → *Submit a New Add-on* → *On this site* → upload the Firefox zip.
4. Publisher contact email and website: use a contact address you're happy to make public (the stores show it), and `https://github.com/sparkv2/Phishing-Detection-Chrome-Extension` as the website.
