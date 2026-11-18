# Tripwire privacy policy

**Effective date:** 18 November 2026 · Applies to Tripwire version 1.3.0 and later, for Chrome, Edge and Firefox.

Tripwire is a browser extension that checks your email for phishing and scams. It was built so that your email never leaves your computer. This policy explains exactly what Tripwire does with data.

## The short version
- Tripwire checks your emails **on your own device**. Email content is never uploaded, sold, shared or stored.
- Tripwire's own server (`tripwire.sparkv2.com`) only hands out lists of dangerous sites. It receives something from you only if you turn on **Share my reports**, and even then only a fingerprint of a scam domain.
- It doesn't collect analytics, show ads or track you.
- The little that Tripwire saves stays on your device, in the browser's extension storage, and you can delete it at any time.

## What Tripwire reads
To check an email, Tripwire reads the parts of it that the webmail page shows you: the sender's name and address, the subject, the text, the links, the attachment names and the images. On Gmail it can also read the message's technical headers (the same ones Gmail's "Show original" shows) and the text of HTML attachments. It fetches these from Gmail itself, using your existing session.

All of this is analysed in your browser's memory and discarded afterwards. None of it is written to disk or sent anywhere.

## What Tripwire stores on your device
| Data | Why | How long |
|---|---|---|
| Your settings (on/off switches, sites you enabled) | So Tripwire remembers your choices | Until you change them or remove Tripwire |
| Counts (emails checked, flagged, risky clicks stopped) | Shown in the popup | Until you remove Tripwire |
| Trusted and reported senders | So your own "I know this sender" and "Report" choices stick | Until you remove them in the popup |
| Public lists of known scam and malware sites | To recognise dangerous links offline | Replaced at each update |
| Scrambled fingerprints of past senders (salted SHA-256 hashes) | To warn about a first-time sender, or a familiar name from a new address | About the 6,000 most recent senders are kept |
| Which kinds of warning sign you've received (counts only, for example "lookalike address: 3") | To order practice-mode lessons | Until you remove Tripwire |
| **Only if you turn on password alert:** a 4-byte fragment of a slow salted hash (PBKDF2) of your Google, Microsoft or Yahoo password, and its length | To warn you if you type that password on another website | Until you turn password alert off, which deletes it |

The sender fingerprints and password fragment can't be turned back into names, addresses or passwords. The password fragment is deliberately too short to recover a password from, even by guessing.

Tripwire keeps a few things in memory only, never saved: which links in an open email it has already checked, and which tab you opened from a risky email. These are forgotten when the tab or the browser closes.

## When Tripwire uses the internet
Tripwire makes only these network requests. None of them contain your email content or anything that identifies you.

1. **Threat-list updates.** About twice a day it downloads the list of known phishing, malware and botnet sites from the Tripwire server (`tripwire.sparkv2.com`). The project rebuilds and digitally signs the list every 6 hours from public sources, and Tripwire uses it only if the signature checks out. If the server can't be reached, it downloads the same public lists directly from OpenPhish, GitLab/GitHub (phishing-filter, urlhaus-filter, botnet-filter, C2IntelFeeds), CERT Polska and abuse.ch. These are ordinary downloads. Nothing is uploaded. *You can turn this off in the popup.*
2. **Community reports list.** With the same updates, it downloads the list of fingerprints of domains that at least 3 different Tripwire users reported, at least a day apart from the first report. A domain on it gets a yellow warning, never a "confirmed scam" label. Nothing is uploaded. *You can turn this off in the popup.*
3. **Sharing your reports (off unless you turn it on).** If you turn on **Share my reports anonymously** and click "Report phishing", Tripwire sends the server one value: a SHA-256 fingerprint of the scam email's domain (for example, of `paypa1-security.com`). It never sends the email, its content, the sender's address, your address or anything about you. Domains of shared email providers, such as gmail.com, are never sent.
4. **Shortened links.** When you click a shortened link (bit.ly and similar), Tripwire asks that link service where the link leads, without opening the destination page. The link service sees the request, as it would if you clicked the link. *You can turn this off in the popup.*
5. **Gmail headers and attachments.** On Gmail, Tripwire asks Gmail for an email's technical headers and for the text of HTML attachments. These requests go only to Gmail, which already holds this data.
6. **Images, for QR codes.** Tripwire downloads images that are already shown in an email again, so it can look for QR codes in them. These requests go to wherever the image is hosted (for Gmail, Google's image servers), just as when the email first displayed it.

### What the Tripwire server keeps
- **For shared reports:** the domain fingerprint, the day it was reported, and a scrambled code for the reporter's *network*. That code is an HMAC, made with a secret key, of the first three parts of an IPv4 address (like `203.0.113.x`) or the first two groups of an IPv6 address. The code only lets the server count how many *different* networks reported a domain, and limit each network to 50 reports a day. It can't be turned back into an IP address, and your full IP address is never stored. Reports are deleted after 90 days.
- **For downloads:** nothing. The server doesn't log requests.
- The server is reached through Cloudflare, which handles the connection and may keep its own short-term technical logs under [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/).

The optional on-device AI uses the language model built into Chrome. It runs on your computer and sends nothing over the network. The first time you turn it on, Chrome may download the model from Google.

## What Tripwire never does
- It never sends your email content, contacts, browsing history or passwords to anyone.
- It doesn't sell, rent or share data, and it doesn't use data for advertising or credit decisions.
- It doesn't run code downloaded from the internet. All of its code ships inside the extension. The server sends only data (lists), never code.
- It has no accounts and no sign-up.

## Permissions
- **By default,** Tripwire runs only on major webmail sites: Gmail, Outlook, Yahoo, AOL, Proton, Zoho, Fastmail and iCloud.
- **Another email site:** it runs there only after you click "Check emails on this site" and approve Chrome's permission prompt.
- **All websites:** it asks for this only if you turn on "Protect the pages I open", and gives it back when you turn it off.

The full list of permissions, with the reason for each, is in [STORE_LISTING.md](STORE_LISTING.md).

## Your choices
- **Turn features off:** use the popup to switch off protection, list updates, community warnings, report sharing, shortened-link checks, page protection, password alert or the on-device AI.
- **Remove saved senders:** clear your trusted and reported senders from the popup.
- **Delete everything:** remove Tripwire from the browser. This deletes everything it stored on your device.

## Children
Tripwire doesn't knowingly collect any personal information from anyone, including children.

## Changes to this policy
If Tripwire ever changes how it handles data, this file will be updated, with a new effective date and a note in [CHANGELOG.md](CHANGELOG.md), before the change ships.

## Contact
Questions or concerns: open an issue at https://github.com/sparkv2/Phishing-Detection-Chrome-Extension/issues
