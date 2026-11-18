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

## Get started
The extension lives in the [`tripwire/`](tripwire/) folder. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick that folder.

Full documentation, including how detection and scoring work, development and testing: [`tripwire/README.md`](tripwire/README.md) · Changes: [`tripwire/CHANGELOG.md`](tripwire/CHANGELOG.md)
