// Made-up practice emails. `extra` feeds the analyzer the same data it gets from a real inbox
// (authentication results, attachments, QR codes, sender history, expanded short links).
(function (root) {
  'use strict';
  root.TW_LESSONS = [
    { id: 'lookalike', email: { senderName: 'PayPal', senderEmail: 'service@paypa1-support.com', subject: 'Receipt for your payment to Steam',
      body: 'You sent a payment of $249.99 to Steam Games. If you did not authorise this payment, sign in to cancel it.',
      links: [{ href: 'https://paypa1-support.com/cancel', text: 'Cancel this payment' }] } },
    { id: 'freemail', email: { senderName: 'Microsoft 365 Security', senderEmail: 'ms365.security.team@gmail.com', subject: 'Unusual sign-in activity',
      body: 'We detected an unusual sign-in to your account from Russia. Review the activity now.',
      links: [{ href: 'https://account-review.example/ms', text: 'Review activity' }] } },
    { id: 'mismatch', email: { senderName: 'Chase', senderEmail: 'alerts@chase-notify.example', subject: 'Your statement is ready',
      body: 'Your monthly statement is available. View it online at the link below.',
      links: [{ href: 'https://statements-portal.example/view', text: 'https://www.chase.com/statements' }] } },
    { id: 'forged', email: { senderName: 'Netflix', senderEmail: 'info@netflix.com', subject: 'Your membership is on hold',
      body: 'We couldn\'t process your last payment. Update your payment details within 24 hours to keep watching.',
      links: [{ href: 'https://www.netflix.com/youraccount', text: 'Update payment' }] },
      extra: { auth: { spf: 'fail', dkim: 'none', dmarc: 'fail', dkimDomains: [] } },
      note: 'Behind the scenes: the email failed DMARC, the anti-forgery check Netflix uses. Your email provider records this in the message headers.' },
    { id: 'qr', email: { senderName: 'IT Service Desk', senderEmail: 'servicedesk@yourcompany.example', subject: 'Action required: renew your MFA',
      body: 'Your multi-factor authentication expires today. Scan the QR code below with your phone to renew it, or you will lose access to email.', links: [] },
      extra: { qrCodes: [{ data: 'https://mfa-renew-login.example/auth' }] }, qr: true },
    { id: 'double-ext', email: { senderName: 'Accounts Payable', senderEmail: 'ap@supplier-invoices.example', subject: 'Overdue invoice #20931',
      body: 'Please find the overdue invoice attached. Payment is required by Friday.', links: [] },
      extra: { attachments: [{ name: 'Invoice_20931.pdf.html' }] } },
    { id: 'ceo', email: { senderName: 'Daniel Okafor', senderEmail: 'daniel.okafor.office@gmail.com', subject: 'Are you available?',
      body: 'Are you available? I need a favour. I\'m in a meeting all afternoon. Please buy four $100 gift cards for a client and send me the codes. Keep this between us for now.', links: [] },
      extra: { history: { seenBefore: false, mature: true, nameKnownElsewhere: true } },
      note: 'Behind the scenes: you\'ve had emails from "Daniel Okafor" before, but always from a different address.' },
    { id: 'shortlink', email: { senderName: 'DHL Express', senderEmail: 'tracking@dhl-parcel-info.example', subject: 'Delivery attempt failed',
      body: 'We tried to deliver your parcel today. Reschedule your delivery and pay the $1.50 redelivery fee.', links: [{ href: 'https://bit.ly/dhl-redeliver', text: 'Reschedule delivery' }] },
      extra: { expanded: [['https://bit.ly/dhl-redeliver', 'https://dhl-redelivery-fee.example/pay']] } },
    { id: 'safe-amazon', email: { senderName: 'Amazon.com', senderEmail: 'shipment-tracking@amazon.com', subject: 'Your package was delivered',
      body: 'Hello Sam, your package was delivered to your front door at 2:14 PM. Track your orders anytime from Your Orders.',
      links: [{ href: 'https://www.amazon.com/gp/your-account/order-history', text: 'Your Orders' }] },
      extra: { auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dkimDomains: ['amazon.com'] } } },
    { id: 'safe-colleague', email: { senderName: 'Priya Shah', senderEmail: 'priya.shah@yourcompany.example', subject: 'Slides for Thursday',
      body: 'Hi! Here are the slides for Thursday\'s review. Let me know if anything needs changing before then.', links: [] },
      extra: { attachments: [{ name: 'Q3 review.pptx' }], history: { seenBefore: true, mature: true, nameKnownElsewhere: false } } },
  ];

  // Plausible-sounding answers that are NOT warning signs, used as wrong options.
  root.TW_DISTRACTORS = ['The email has a company logo', 'It was sent on a weekday', 'It starts with "Hello"', 'It includes an unsubscribe link',
    'The subject line is short', 'It mentions a date', 'The email is in English', 'It has a signature at the bottom'];
})(typeof globalThis !== 'undefined' ? globalThis : this);
