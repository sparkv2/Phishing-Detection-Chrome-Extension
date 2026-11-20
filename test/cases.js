// Shared test cases for the analyzer and the threat index.
// Run in Node with `node --test` (test/*.test.js) or in Chrome by opening test/analyzer-tests.html.
(function (root) {
  'use strict';
  const T = (entries) => ({ threats: new Map(entries) });

  // [name, input, expected level(s), lists]
  const EMAILS = [
    // ---------- phishing ----------
    ['PayPal lookalike + blocklist + IP link', { senderName: 'PayPal', senderEmail: 'service@paypa1-security.com', subject: 'Your account has been limited',
      body: 'Dear Customer, We noticed unusual activity on your PayPal account. Your account has been limited and will be closed within 24 hours unless you verify your account. Please confirm your password and billing information immediately to restore access.',
      links: [{ href: 'http://paypa1-security.com/login', text: 'Log in to PayPal' }, { href: 'http://198.51.100.23/secure', text: 'www.paypal.com' }] }, 'phishing'],
    ['Microsoft from gmail + shortener', { senderName: 'Microsoft 365 Support', senderEmail: 'it.helpdesk.office365@gmail.com', subject: 'ACTION REQUIRED: Password expires today',
      body: 'Dear user, Your Office 365 password expires today. Failure to verify will result in your mailbox being disabled. Click below to keep your current password. You will need to enter your password to confirm.',
      links: [{ href: 'https://bit.ly/3xYz-o365', text: 'Keep my password' }] }, 'suspicious'],
    ['DHL fee scam', { senderName: 'DHL Express', senderEmail: 'noreply@dhl-delivery-notice.top', subject: 'Package on hold: delivery fee unpaid',
      body: 'Dear Customer, Your package could not be delivered because a processing fee of $1.99 is unpaid. Pay the fee within 48 hours or your package will be returned.',
      links: [{ href: 'https://dhl.com.redelivery-fee.top/pay', text: 'Pay now' }] }, 'suspicious'],
    ['Apple homoglyph (cyrillic a) sender', { senderName: 'Apple', senderEmail: 'id@аpple.com', subject: 'Your Apple ID was locked', body: 'Your Apple ID has been locked for security reasons. Sign in to unlock your account.', links: [{ href: 'https://xn--pple-43d.com/unlock', text: 'Unlock' }] }, 'suspicious'],
    ['CEO gift card (content only)', { senderName: 'Mark (CEO)', senderEmail: 'mark.ceo.office@outlook.com', subject: 'Quick favor',
      body: "Hi, Are you available? I need a favor. I'm in a meeting and can't talk. I need you to buy 5 gift cards for a client today, keep this confidential. Reply with the codes as soon as possible.", links: [] }, 'suspicious'],
    ['Link text mismatch only', { senderName: 'Billing', senderEmail: 'billing@smallshop.example', subject: 'Invoice', body: 'Please see your invoice.',
      links: [{ href: 'https://evil-login.example/x', text: 'https://www.chase.com/invoice' }] }, 'suspicious'],
    ['User-reported domain', { senderName: 'Bob', senderEmail: 'bob@scammy.example', subject: 'hi', body: 'hello there friend how are you', links: [] }, 'phishing', { blocked: new Set(['scammy.example']) }],
    ['Feed-listed link', { senderName: 'News', senderEmail: 'news@site.example', subject: 'Read', body: 'An article you might like to read today.', links: [{ href: 'https://bad.phish.example/a', text: 'Read more' }] }, 'phishing', { feed: new Set(['bad.phish.example']) }],
    ['Display name contains other email', { senderName: 'support@paypal.com', senderEmail: 'x83@mailer.ru', subject: 'Receipt', body: 'Your payment details need to be updated. Update your payment now.', links: [] }, 'suspicious'],

    // ---------- legitimate (false-positive traps) ----------
    ['Real Google security alert', { senderName: 'Google', senderEmail: 'no-reply@accounts.google.com', subject: 'Security alert',
      body: 'A new sign-in on Windows. We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don\'t need to do anything. If not, we\'ll help you secure your account. Check activity. You can also see security activity at https://myaccount.google.com/notifications',
      links: [{ href: 'https://accounts.google.com/AccountChooser?continue=https://myaccount.google.com/alert', text: 'Check activity' }, { href: 'https://myaccount.google.com/notifications', text: 'https://myaccount.google.com/notifications' }] }, 'safe'],
    ['Real Amazon shipping', { senderName: 'Amazon.com', senderEmail: 'shipment-tracking@amazon.com', subject: 'Your order has shipped', body: 'Hello Jordan, Your order of "USB-C Charging Cable (2-pack)" has shipped and should arrive on Thursday. You can track your package anytime from Your Orders.', links: [{ href: 'https://www.amazon.com/gp/your-account/order-history', text: 'View your order' }] }, 'safe'],
    ['Coworker named Chase', { senderName: 'Chase Miller', senderEmail: 'chase.miller@gmail.com', subject: 'Lunch?', body: 'Hey, want to grab lunch tomorrow around noon? Let me know.', links: [] }, 'safe'],
    ['Newsletter with tracking links + limited time', { senderName: 'Bean Box Coffee', senderEmail: 'hello@beanbox.example', subject: 'Limited time: 20% off', body: 'Our fall roasts are here. For a limited time, get 20% off your next bag. Shop now and enjoy free shipping on orders over $30. Unsubscribe here.',
      links: [{ href: 'https://u12345.ct.sendgrid.net/ls/click?upn=abc', text: 'beanbox.example/shop' }, { href: 'https://u12345.ct.sendgrid.net/ls/click?upn=def', text: 'Shop now' }] }, 'safe'],
    ['Real password reset from service', { senderName: 'Dropbox', senderEmail: 'no-reply@dropbox.com', subject: 'Reset your Dropbox password', body: 'Hi Jordan, Someone requested a new password for your Dropbox account. If you didn\'t make this request, you can ignore this email. Reset password.', links: [{ href: 'https://www.dropbox.com/password_reset?token=abc', text: 'Reset password' }] }, 'safe'],
    ['Apple pie recipe site', { senderName: 'Grandma', senderEmail: 'grandma@family.example', subject: 'Recipe', body: 'Here is the recipe I told you about, it is delicious and easy to make.', links: [{ href: 'https://apple-pie-recipes.example/classic', text: 'Classic apple pie' }] }, 'safe'],
    ['Company intranet office subdomain', { senderName: 'Facilities', senderEmail: 'facilities@mycompany.example', subject: 'Office closed Monday', body: 'The office will be closed Monday for the holiday. Enjoy the long weekend everyone.', links: [{ href: 'https://office.mycompany.example/calendar', text: 'Holiday calendar' }] }, 'safe'],
    ['Outlook safelink to real site', { senderName: 'Sarah Kim', senderEmail: 'sarah@acme.example', subject: 'Notes', body: 'Thanks for a great meeting today, notes are in the shared doc for review before Friday.', links: [{ href: 'https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdocs.google.com%2Fdocument%2Fd%2Fx&data=1', text: 'docs.google.com/document' }] }, 'safe'],
    ['Bank statement ready (real chase)', { senderName: 'Chase', senderEmail: 'no.reply.alerts@chase.com', subject: 'Your statement is ready', body: 'Your credit card statement is available. Your payment is due on 11/28. Sign in to chase.com to view it.', links: [{ href: 'https://www.chase.com/statements', text: 'chase.com' }] }, 'safe'],
    ['Trusted sender overrides wording', { senderName: 'Dad', senderEmail: 'dad@family.example', subject: 'URGENT', body: 'Urgent! Please send me the bank account routing number immediately for the house payment.', links: [] }, 'safe', { trusted: new Set(['dad@family.example']) }],
    ['Lookup returned clean (null)', { senderName: 'News', senderEmail: 'news@site.example', subject: 'Read', body: 'An article you might like to read today.', links: [{ href: 'https://good.example/a', text: 'Read more' }] }, 'safe', T([['good.example', null]])],

    // ---------- email authentication ----------
    ['Real PayPal address, DMARC pass', { senderName: 'PayPal', senderEmail: 'service@paypal.com', subject: 'Action required: confirm your details',
      body: 'Please confirm your details within 48 hours to avoid any interruption to your account.', links: [{ href: 'https://www.paypal.com/myaccount', text: 'Log in' }],
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dkimDomains: ['paypal.com'] } }, 'safe'],
    ['Real PayPal address, DMARC FAIL (forged From)', { senderName: 'PayPal', senderEmail: 'service@paypal.com', subject: 'Your account is limited',
      body: 'Your account has been limited. Confirm your password within 24 hours to restore access.', links: [{ href: 'https://www.paypal.com/myaccount', text: 'Log in' }],
      auth: { spf: 'fail', dkim: 'none', dmarc: 'fail', dkimDomains: [] } }, 'suspicious'],
    ['Small business, SPF softfail only, no ask', { senderName: 'Rosa', senderEmail: 'rosa@bakery.example', subject: 'Order ready', body: 'Your cake order is ready for pickup on Saturday morning.', links: [],
      auth: { spf: 'softfail', dkim: 'none', dmarc: 'none', dkimDomains: [] } }, 'safe'],
    ['Trusted sender, but DMARC fail', { senderName: 'Dad', senderEmail: 'dad@family.example', subject: 'Send money', body: 'Please wire transfer the money today for the house payment, it is urgent.', links: [],
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', dkimDomains: [] } }, 'suspicious', { trusted: new Set(['dad@family.example']) }],

    // ---------- attachments ----------
    ['Double-extension HTML attachment', { senderName: 'Accounts', senderEmail: 'accounts@supplier.example', subject: 'Invoice 4471', body: 'Please find the invoice attached.', links: [],
      attachments: [{ name: 'Invoice_4471.pdf.html' }] }, 'suspicious'],
    ['HTML attachment with login form', { senderName: 'Accounts', senderEmail: 'accounts@supplier.example', subject: 'Remittance', body: 'See attached remittance advice.', links: [],
      attachments: [{ name: 'remittance.htm', html: { password: true, form: true } }] }, 'suspicious'],
    ['Executable attachment', { senderName: 'HR', senderEmail: 'hr@company.example', subject: 'Payroll update', body: 'Run the attached file to update your payroll details.', links: [],
      attachments: [{ name: 'PayrollUpdate.exe' }] }, 'suspicious'],
    ['Normal PDF + photo attachments', { senderName: 'Sarah Kim', senderEmail: 'sarah@acme.example', subject: 'Slides', body: 'Slides and a photo from the offsite are attached.', links: [],
      attachments: [{ name: 'Q3 review.pdf' }, { name: 'IMG_2041.jpg' }] }, 'safe'],

    // ---------- QR codes ----------
    ['QR code to a lookalike login page', { senderName: 'IT Service Desk', senderEmail: 'it@company.example', subject: 'MFA re-enrolment required',
      body: 'Your multi-factor authentication must be renewed within 24 hours. Scan the QR code with your phone to keep access.', links: [],
      qrCodes: [{ data: 'https://micros0ft-login-verify.example/mfa' }] }, 'suspicious'],
    ['QR code on a real event ticket', { senderName: 'Eventbrite', senderEmail: 'orders@eventbrite.example', subject: 'Your tickets', body: 'Show this QR code at the door.', links: [],
      qrCodes: [{ data: 'TICKET-88213-AB' }] }, 'safe'],

    // ---------- sender history ----------
    ['Familiar name from a new address asking for gift cards', { senderName: 'Mark Davis', senderEmail: 'mark.davis.ceo@gmail.com', subject: 'Quick task',
      body: 'Can you pick up some gift cards for a client today? Keep this between us.', links: [],
      history: { seenBefore: false, mature: true, nameKnownElsewhere: true } }, 'suspicious'],
    ['First-time sender, harmless note', { senderName: 'New Neighbour', senderEmail: 'lee@neighbours.example', subject: 'Hello', body: 'Hi, we just moved in next door. Come over for coffee sometime!', links: [],
      history: { seenBefore: false, mature: true, nameKnownElsewhere: false } }, 'safe'],

    // ---------- shortened links ----------
    ['Short link that expands to a lookalike', { senderName: 'Netflix', senderEmail: 'info@account-netflix.example', subject: 'Payment declined', body: 'Your payment failed. Update your payment details to keep watching.',
      links: [{ href: 'https://bit.ly/nflx-pay', text: 'Update payment' }] }, 'suspicious', { expanded: new Map([['https://bit.ly/nflx-pay', 'https://netflix-billing-update.example/pay']]) }],

    // ---------- on-device AI hints ----------
    ['Non-English credential scam (AI flags it)', { senderName: 'Servicio al cliente', senderEmail: 'avisos@banco-avisos.example', subject: 'Su cuenta',
      body: 'Estimado cliente, su cuenta será bloqueada hoy. Ingrese su clave en el siguiente enlace para evitarlo.', links: [{ href: 'https://banco-avisos.example/acceso', text: 'Acceder' }],
      ai: { risk: 'high', asks: ['credentials', 'click_link'], reasons: ['Threatens to block the account and asks for a password.'] } }, 'suspicious'],
  ];

  // ---------- payment changes & reply-chain hijack ----------
  const VALID_IBAN = 'GB82 WEST 1234 5698 7654 32';
  EMAILS.push(['Supplier says bank details changed', { senderName: 'Accounts', senderEmail: 'accounts@northwind-supplies.example', subject: 'Updated remittance details',
    body: `Hello, please note our bank details have changed. Kindly remit the outstanding invoice to the new account below. IBAN: ${VALID_IBAN}. Thank you.`, links: [] }, 'suspicious']);
  EMAILS.push(['Hijacked thread: look-alike reply changes the account', { senderName: 'Dana Reyes', senderEmail: 'dana@northwlnd-supplies.example', subject: 'Re: Invoice 4471',
    body: `Hi, quick update before you pay: we have changed banks. Please send the payment to the new account: ${VALID_IBAN}.`, links: [],
    thread: { senders: ['dana@northwind-supplies.example', 'me@mycompany.example'] } }, 'suspicious']);
  EMAILS.push(['Known supplier, same bank details as always', { senderName: 'Accounts', senderEmail: 'accounts@northwind-supplies.example', subject: 'Invoice 4502',
    body: `Please find invoice 4502 attached. Payment to our usual account ${VALID_IBAN} within 30 days.`, links: [],
    history: { seenBefore: true, mature: true, knownDomain: true } }, 'safe']);
  EMAILS.push(['Known supplier, but different bank details than before', { senderName: 'Accounts', senderEmail: 'accounts@northwind-supplies.example', subject: 'Invoice 4503',
    body: `Please find invoice 4503 attached. Payment to ${VALID_IBAN} within 30 days.`, links: [],
    history: { seenBefore: true, mature: true, knownDomain: true, bankChanged: true, bankChangedDomain: 'northwind-supplies.example' } }, 'suspicious']);
  EMAILS.push(['Imitates a supplier you correspond with (hashed history match)', { senderName: 'Northwind Accounts', senderEmail: 'billing@northwind-supplies.co', subject: 'Invoice overdue',
    body: 'Your invoice is overdue. Please arrange payment today.', links: [],
    history: { seenBefore: false, mature: true, lookalikeOf: 'northwind-supplies.example' } }, 'suspicious']);
  EMAILS.push(['New company joins a thread, harmless note', { senderName: 'Sam Lee', senderEmail: 'sam@partner-agency.example', subject: 'Re: Launch plan',
    body: 'Thanks for looping me in, happy to help with the launch next week.', links: [],
    thread: { senders: ['priya@mycompany.example'] } }, 'safe']);

  // Community reports are yellow, never red.
  EMAILS.push(['Link to a community-reported domain', { senderName: 'Shop', senderEmail: 'deals@shop.example', subject: 'Sale', body: 'Our autumn sale is on now.',
    links: [{ href: 'https://reported-by-users.example/sale', text: 'Shop now' }] }, 'suspicious',
    T([['reported-by-users.example', { cat: 'community', source: 'Tripwire community reports', threshold: 3, matched: 'reported-by-users.example' }]])]);
  EMAILS.push(['Sender domain reported by the community', { senderName: 'Accounts', senderEmail: 'billing@reported-sender.example', subject: 'Invoice', body: 'Please see the invoice for this month.', links: [] },
    'suspicious', T([['reported-sender.example', { cat: 'community', source: 'Tripwire community reports', threshold: 3, matched: 'reported-sender.example' }]])]);

  // [url, expected to have any warning]
  const URLS = [['https://paypal.com.secure-login.ru/x', true], ['https://www.paypal.com/signin', false], ['https://micros0ft.com', true],
    ['https://amazon-billing-update.com', true], ['https://goggle.com', true], ['https://linkedin.com/in/x', false], ['https://zoominfo.com', false],
    ['https://purchase.example', false], ['https://amazon.es/dp/1', true], ['http://user@evil.example/', true]];

  // [name, input, lists, expected threat category]: a known-threat match must be red with score 0.
  const THREATS = [
    ['Malware link (URLhaus)', { links: [{ href: 'http://dl.badfiles.example/invoice.exe', text: 'Download invoice' }] },
      T([['dl.badfiles.example', { cat: 'malware', source: 'URLhaus (abuse.ch) online malware sites', matched: 'badfiles.example' }]]), 'malware'],
    ['C2 server IP link (Feodo)', { links: [{ href: 'http://203.0.113.50:8080/gate.php', text: 'View document' }] },
      T([['203.0.113.50', { cat: 'c2', source: 'Feodo Tracker (abuse.ch) botnet C2 servers', matched: '203.0.113.50' }]]), 'c2'],
    ['C2 domain with label (C2IntelFeeds)', { links: [{ href: 'https://cdn-update.c2.example/x', text: 'Update' }] },
      T([['cdn-update.c2.example', { cat: 'c2', source: 'C2IntelFeeds', label: 'Possible Cobalt Strike C2 Domain', matched: 'cdn-update.c2.example' }]]), 'c2'],
    ['Exact phishing URL on a shared host', { links: [{ href: 'https://sites.google.com/view/fake-login-page', text: 'Sign in' }] },
      T([['url:sites.google.com/view/fake-login-page', { cat: 'phishing', source: 'OpenPhish', matched: 'sites.google.com/view/fake-login-page' }]]), 'phishing'],
    ['Sender domain on phishing list', { senderEmail: 'alerts@bank-verify.example' },
      T([['bank-verify.example', { cat: 'phishing', source: 'CERT Polska warning list', matched: 'bank-verify.example' }]]), 'phishing'],
    ['QR code to a listed phishing site', { qrCodes: [{ data: 'https://qr-phish.example/login' }] },
      T([['qr-phish.example', { cat: 'phishing', source: 'Phishing Filter', matched: 'qr-phish.example' }]]), 'phishing'],
  ];
  const THREAT_BASE = { context: 'open', senderName: 'News', senderEmail: 'news@site.example', subject: 'Hello', body: 'An update for you to read today.' };

  // Authentication-Results parsing: [raw headers, expected fields, expected verdict for the sender domain]
  const AUTH_HEADERS = [
    ['Authentication-Results: mx.google.com;\r\n       dkim=pass header.i=@paypal.com header.s=pp-dkim1 header.b=abc;\r\n       spf=pass (google.com: domain of service@paypal.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=service@paypal.com;\r\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com\r\nFrom: PayPal <service@paypal.com>\r\n\r\nbody',
      { spf: 'pass', dkim: 'pass', dmarc: 'pass', fromDomain: 'paypal.com' }, 'paypal.com', 'pass'],
    ['Authentication-Results: mx.google.com;\n       spf=softfail (google.com: domain of transitioning x@paypal.com does not designate 5.6.7.8 as permitted sender) smtp.mailfrom=x@paypal.com;\n       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=paypal.com\nAuthentication-Results: evil.example; dmarc=pass header.from=paypal.com\n\n',
      { spf: 'softfail', dmarc: 'fail' }, 'paypal.com', 'fail'],
    ['Authentication-Results: mx.example; dkim=pass header.d=mail.shop.example; spf=neutral\n\n', { dkim: 'pass', dmarc: '' }, 'shop.example', 'pass'],
    ['Subject: no auth header here\n\n', null, 'x.example', 'unknown'],
  ];

  root.TW_CASES = { EMAILS, URLS, THREATS, THREAT_BASE, AUTH_HEADERS };
  if (typeof module === 'object' && module.exports) module.exports = root.TW_CASES;
})(typeof globalThis !== 'undefined' ? globalThis : this);
