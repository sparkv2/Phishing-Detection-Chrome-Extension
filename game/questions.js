// Question bank for Inbox Expedition (game/game.html). Every answer matches what Tripwire actually checks, so playing
// the game teaches the same red flags the extension warns about. Used by game/engine.js; checked by test/game.test.js.
//
// Each question: { id, topic, q, options: [2-4 strings], answer: index of the right option, explain }.
// `topic` lets a landmark ask about its own theme (Look-alike Lake asks about look-alike addresses, and so on).
(function (root) {
  'use strict';
  const QUESTIONS = [
    // ---------- passwords and codes ----------
    { id: 'pw-reply', topic: 'passwords', q: 'An email says: "Please reply with your email and password so we can fix your account." What do you do?',
      options: ['Reply, since they need it to help', 'Reply with only the password', 'Don\'t reply: no real company asks for your password by email', 'Forward it to a friend to check'],
      answer: 2, explain: 'Real companies never ask for your password by email. Tripwire marks any email that asks you to send a password red.' },
    { id: 'pw-code', topic: 'passwords', q: 'A "support agent" emails asking for the 6-digit code that was just texted to your phone. What is that code for?',
      options: ['Proving to them who you are', 'Logging in to your account: whoever has it can get in', 'Nothing important', 'Unsubscribing from texts'],
      answer: 1, explain: 'One-time codes let someone finish logging in as you. Never share them. Tripwire flags emails that ask for verification codes.' },
    { id: 'pw-never', topic: 'passwords', q: 'Your bank\'s email says "We will never ask for your password or PIN." Is that sentence itself a warning sign?',
      options: ['Yes, it mentions passwords', 'No, it\'s advice, not a request', 'Only if it has a link', 'Yes, banks never mention PINs'],
      answer: 1, explain: 'Tripwire looks for requests, not just words. "Never share your password" is a warning to you, so it doesn\'t count against the email.' },
    { id: 'pw-alert', topic: 'passwords', q: 'Tripwire\'s optional password alert warns you when…',
      options: ['Your password is too short', 'You type your Google, Microsoft or Yahoo password on a different website', 'Someone changes your password', 'Your password appears in an email'],
      answer: 1, explain: 'Fake login pages copy the real ones. The password alert notices your email password being typed somewhere it doesn\'t belong. It stores only a scrambled fragment, never the password.' },
    { id: 'pw-ssn', topic: 'passwords', q: '"HR" emails from a personal Gmail address asking for your Social Security number to "keep your paycheck coming." Tripwire shows…',
      options: ['No colour: HR needs it', 'Yellow: maybe fine', 'Red: it asks for personal details by email', 'Nothing, because it\'s from Gmail'],
      answer: 2, explain: 'Requests for an SSN, bank details, card numbers or your date of birth by email are red. Check with HR in person or on a number you already have.' },

    // ---------- look-alike addresses ----------
    { id: 'look-menards', topic: 'lookalike', q: 'An email signed "Menards" comes from support@menrds.com. What\'s wrong?',
      options: ['Nothing, it\'s the hardware store', 'The address misspells the company name', 'Support addresses are always fake', '.com is unusual'],
      answer: 1, explain: '"menrds" is missing an "a". Scammers register near-identical names. Tripwire marks a misspelling of the company an email names red.' },
    { id: 'look-paypa1', topic: 'lookalike', q: 'Which of these addresses is the real PayPal?',
      options: ['service@paypa1.com', 'service@paypal.com', 'service@paypal-secure-login.com', 'service@paypal.com.verify-id.net'],
      answer: 1, explain: '"paypa1" uses a number 1 for the letter l. "paypal-secure-login" glues extra words on. In the last one, the part that matters is the end: verify-id.net.' },
    { id: 'look-subdomain', topic: 'lookalike', q: 'In the web address paypal.com.account-check.ru, which company actually owns the site?',
      options: ['PayPal', 'Whoever owns account-check.ru', 'The Russian government', 'Google'],
      answer: 1, explain: 'Read addresses from the right. The real owner is the last name before the ending: account-check.ru. "paypal.com" at the start is decoration.' },
    { id: 'look-cyrillic', topic: 'lookalike', q: 'An address looks exactly like apple.com, but Tripwire says it uses "disguised characters." How is that possible?',
      options: ['It\'s a display bug', 'Letters from another alphabet can look identical to Latin ones', 'Apple has two domains', 'Capital letters'],
      answer: 1, explain: 'A Cyrillic "а" looks just like a Latin "a". Tripwire spots these mixed-alphabet look-alikes (they often start with "xn--" behind the scenes).' },
    { id: 'look-unsure', topic: 'lookalike', q: 'Tripwire says: "We\'re not sure hartwelllumbermail.com is Hartwell Lumber\'s official email address." You do business with them and know it\'s theirs. What should you click?',
      options: ['Report phishing', '"I know this sender"', 'Nothing, ignore it forever', 'Unsubscribe'],
      answer: 1, explain: '"I know this sender" remembers the address on your computer, so Tripwire stops asking. Their emails are still checked for scams, though.' },
    { id: 'look-colleague', topic: 'lookalike', q: 'You always email dana@northwind-supplies.com. Today\'s invoice comes from dana@northwlnd-supplies.com. Tripwire warns because…',
      options: ['Dana changed jobs', 'It imitates someone you email with: "wind" became "wlnd"', 'Invoices are always fake', 'The email is too long'],
      answer: 1, explain: 'Tripwire remembers (as scrambled fingerprints) who you correspond with, and flags near-copies of their addresses. This is how invoice fraud starts.' },

    // ---------- links ----------
    { id: 'link-mismatch', topic: 'links', q: 'A link\'s text says www.chase.com, but it really goes to chase-alerts-login.example. What is this called?',
      options: ['A redirect', 'A lying link: the text doesn\'t match the destination', 'A shortcut', 'Normal marketing'],
      answer: 1, explain: 'Anyone can write any text on a link. Tripwire compares the text with the real destination and stops you before you open a mismatch.' },
    { id: 'link-hover', topic: 'links', q: 'What\'s the safest way to check where a link goes before clicking?',
      options: ['Click it and look at the page', 'Hover over it and read the real address', 'Trust the blue text', 'Reply and ask'],
      answer: 1, explain: 'Hovering shows the real address without opening it. Tripwire also checks links for you and warns before a risky one opens.' },
    { id: 'link-short', topic: 'links', q: 'A link is a bit.ly short link. What does Tripwire do when you click it?',
      options: ['Opens it immediately', 'Asks bit.ly where it leads (without opening the page) and judges the real destination', 'Blocks every short link', 'Deletes the email'],
      answer: 1, explain: 'Short links hide their destination. Tripwire follows them one step at a time, without loading the page, and warns if the real site is risky.' },
    { id: 'link-at', topic: 'links', q: 'A link looks like https://www.amazon.com@evil.example/login. Where does it really go?',
      options: ['amazon.com', 'evil.example', 'Both', 'Nowhere'],
      answer: 1, explain: 'Browsers ignore everything before the "@" in a web address. The real destination is evil.example. Tripwire flags "@" tricks.' },
    { id: 'link-ip', topic: 'links', q: 'A "bank" link goes to http://198.51.100.7/login instead of a name. Why is that suspicious?',
      options: ['Numbers are slower', 'Real companies use their own names, not raw number addresses', 'It\'s fine if it says http', 'Banks only use numbers'],
      answer: 1, explain: 'A raw number address avoids showing whose site it is. Tripwire flags links that go to an IP address.' },
    { id: 'link-http', topic: 'links', q: 'A sign-in page starts with http:// (no "s"). What does the missing "s" mean?',
      options: ['Nothing', 'The connection isn\'t encrypted, so never type passwords there', 'It\'s a government site', 'It loads faster'],
      answer: 1, explain: 'Without https, what you type can be read on the way. Never enter passwords or card numbers on an http page.' },

    // ---------- QR codes ----------
    { id: 'qr-why', topic: 'qr', q: 'Why do scammers put QR codes in emails instead of normal links?',
      options: ['They look nicer', 'Scanning with your phone skips the link checks your computer does', 'QR codes are encrypted', 'Email can\'t show links'],
      answer: 1, explain: 'A QR code moves you to your phone, away from your computer\'s protections. Tripwire decodes QR codes in emails and checks the address inside.' },
    { id: 'qr-mfa', topic: 'qr', q: '"IT" emails: "Scan this QR code within 24 hours to keep your multi-factor login." What\'s the safest move?',
      options: ['Scan it quickly', 'Contact IT through a channel you already know', 'Forward to coworkers', 'Screenshot and scan later'],
      answer: 1, explain: 'Urgency plus a QR code is a common trick to steal logins. Confirm with IT directly, never through the email.' },

    // ---------- attachments ----------
    { id: 'att-double', topic: 'attachments', q: 'An attachment is named Invoice_4471.pdf.html. What kind of file is it really?',
      options: ['A PDF', 'A web page (.html), dressed up to look like a PDF', 'A picture', 'A zip file'],
      answer: 1, explain: 'Only the last ending counts. HTML attachments can show a fake login page. Tripwire flags double extensions and checks HTML attachments for login forms.' },
    { id: 'att-exe', topic: 'attachments', q: 'Which attachment is most dangerous to open?',
      options: ['photo.jpg', 'notes.txt', 'PayrollUpdate.exe', 'report.pdf'],
      answer: 2, explain: '.exe files are programs: opening one runs it. Tripwire warns about programs, disk images, macro documents and similar files.' },
    { id: 'att-zip', topic: 'attachments', q: 'An email includes a zip file and says "the password is 4471." Why would a scammer lock the file?',
      options: ['To protect your privacy', 'So security scanners can\'t look inside', 'Zip files need passwords', 'To make it smaller'],
      answer: 1, explain: 'A locked archive stops scanners from seeing the malware inside. Tripwire flags password-protected archives sent with their password.' },

    // ---------- money and gift cards ----------
    { id: 'gift-ceo', topic: 'money', q: 'Your "CEO" emails from a Gmail address: "I\'m in a meeting. Buy 5 gift cards for a client and send me the codes." What is this?',
      options: ['A normal task', 'A classic gift-card scam', 'A bonus', 'A team-building game'],
      answer: 1, explain: 'Bosses don\'t pay clients in gift cards. Secrecy, urgency and gift-card codes together are a top scam. Tripwire marks demands for gift cards red.' },
    { id: 'pay-bank-change', topic: 'money', q: 'A supplier emails: "Our bank details have changed. Pay the invoice to this new account." What should you do first?',
      options: ['Pay the new account', 'Call the supplier on a number you already have', 'Reply to the email to confirm', 'Pay half to each account'],
      answer: 1, explain: 'Replying reaches the scammer. Call a number from an old invoice or their website. Tripwire warns strongly when a known supplier\'s bank details change.' },
    { id: 'money-stranger', topic: 'money', q: 'A stranger says they\'re stuck abroad and asks you to wire $500 today. Tripwire shows this email as…',
      options: ['Safe', 'Yellow', 'Red: a money demand from a sender it can\'t verify', 'Hidden'],
      answer: 2, explain: 'Demands to send money, gift cards or crypto from someone Tripwire can\'t vouch for are red. Friends you\'ve emailed before don\'t trigger it.' },
    { id: 'money-prize', topic: 'money', q: '"You\'ve won $1,000! Just pay a $4.99 processing fee." What\'s the catch?',
      options: ['No catch', 'Real prizes don\'t charge fees: it\'s a scam to get your card details', 'The fee is a tax', 'You must reply first'],
      answer: 1, explain: 'Unexpected winnings that need a payment are bait. If it sounds too good to be true, it is.' },
    { id: 'money-crypto', topic: 'money', q: 'An email claims to have hacked your camera and demands Bitcoin within 48 hours. Best response?',
      options: ['Pay quickly', 'Don\'t pay or reply; report it and change any password it mentions', 'Reply to negotiate', 'Forward it to everyone'],
      answer: 1, explain: 'These extortion emails are sent to millions with no real hack behind them. Paying only marks you as a target.' },

    // ---------- the sender ----------
    { id: 'sender-freemail', topic: 'sender', q: '"Microsoft 365 Security" emails you from ms365.security.team@gmail.com. What\'s the giveaway?',
      options: ['The name is too long', 'Microsoft doesn\'t send security email from a Gmail account', 'Gmail is always safe', 'Security teams use Yahoo'],
      answer: 1, explain: 'Companies use their own domains. A company name on a free-mail address is a warning sign Tripwire shows.' },
    { id: 'sender-forged', topic: 'sender', q: 'An email shows a real address, service@paypal.com, but Tripwire says "Forged PayPal address." How can it tell?',
      options: ['It can\'t', 'The email failed PayPal\'s anti-forgery check (DMARC), so someone else sent it', 'PayPal told Tripwire', 'The subject line'],
      answer: 1, explain: 'The From line is easy to fake. On Gmail, Tripwire reads the email\'s own authentication results; a failed DMARC check means it wasn\'t really PayPal.' },
    { id: 'sender-relay', topic: 'sender', q: 'A buyer emails from g7x2k9pq4m@privaterelay.appleid.com. What is that address?',
      options: ['A fake Apple address', 'Apple\'s Hide My Email relay: a real service that hides the person\'s real address', 'A virus', 'An Apple employee'],
      answer: 1, explain: 'Hide My Email gives people private forwarding addresses. The address isn\'t a warning sign, but Tripwire still checks what the email says.' },
    { id: 'sender-reply', topic: 'sender', q: 'An email\'s subject starts with "RE:" but you\'ve never emailed this sender. Why?',
      options: ['A server glitch', 'Faking a conversation makes a scam feel familiar', 'They replied to someone else', 'It\'s a newsletter'],
      answer: 1, explain: 'A fake "RE:" pretends you were already talking. Tripwire notices when a stranger\'s email pretends to be a reply.' },

    // ---------- using Tripwire ----------
    { id: 'tw-red', topic: 'tripwire', q: 'In your inbox, a red row in Tripwire means…',
      options: ['An important email', 'A confirmed or likely scam: don\'t click, don\'t reply', 'An unread email', 'Spam that\'s harmless'],
      answer: 1, explain: 'Red is for confirmed scams, look-alike senders, requests for passwords, personal details or money, and emails with strong signs of a scam.' },
    { id: 'tw-yellow', topic: 'tripwire', q: 'A yellow row means…',
      options: ['Definitely safe', 'Some warning signs: check the sender and links before acting', 'Confirmed phishing', 'Read later'],
      answer: 1, explain: 'Yellow means milder warning signs. Open it and read Tripwire\'s reasons before doing anything it asks.' },
    { id: 'tw-privacy', topic: 'tripwire', q: 'Where does Tripwire read and check your emails?',
      options: ['On a cloud server', 'On your own computer: email content is never uploaded', 'On Google\'s servers', 'It sends them to a security team'],
      answer: 1, explain: 'All checks run on your device. If you turn on anonymous sharing, only a scrambled fingerprint of a reported scam domain is sent, never the email.' },
    { id: 'tw-report', topic: 'tripwire', q: 'What happens when you click "Report phishing" in Tripwire?',
      options: ['The email is sent to the police', 'Tripwire warns you about that sender from now on (and, if you opted in, shares an anonymous fingerprint of the domain)', 'Your account is closed', 'The sender is notified'],
      answer: 1, explain: 'Reports protect you right away. With sharing on, domains reported by several different people warn other Tripwire users too.' },
    { id: 'tw-trust', topic: 'tripwire', q: 'When should you click "I know this sender"?',
      options: ['Whenever an email is yellow', 'Only when you\'re sure the address really belongs to someone you know', 'To make warnings go away', 'Never'],
      answer: 1, explain: 'Scammers copy names of people and companies you know. Only vouch for an address you\'re sure of.' },
    { id: 'tw-showme', topic: 'tripwire', q: 'Tripwire\'s "Show me" button next to a reason…',
      options: ['Opens the link', 'Highlights the exact part of the email the reason is about', 'Deletes the email', 'Shows the sender\'s photo'],
      answer: 1, explain: '"Show me" scrolls to and highlights the sender, link, words or attachment a warning refers to, so you learn what to look for.' },
  ];
  if (typeof module === 'object' && module.exports) module.exports = QUESTIONS;
  root.TW_GAME_QUESTIONS = QUESTIONS;
})(typeof self !== 'undefined' ? self : globalThis);
