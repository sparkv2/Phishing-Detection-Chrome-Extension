// =====================================================================================================================
// Fake webmail pages for the browser tests. Each copies the page structure Tripwire's adapters read on the real site
// (the same selectors as data/selectors.json), with made-up emails. Every scenario returns:
//   { url, hosts, routes(url) }  the address to open, the hosts to intercept, and how to answer each request.
// All addresses and domains are fake (.example).
// =====================================================================================================================

const html = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}</body></html>`;
// Webmail apps redraw constantly; this keeps the page "alive" so Tripwire's scan-on-change logic runs as on the real site.
const TICKER = '<div id="ticker" hidden></div><script>setInterval(() => { document.getElementById("ticker").textContent = Date.now(); }, 700);</script>';
const VALID_IBAN = 'GB82 WEST 1234 5698 7654 32';

// ---------- Gmail ----------
// Inbox with three rows, and an open conversation where the latest reply comes from a look-alike domain, asks to
// change bank details, has a lying link, and carries an HTML "PDF" attachment containing a login form.
function gmailRow(name, email, subject, snippet) {
  return `<tr class="zA zE"><td><span class="yP" email="${email}" name="${name}">${name}</span></td>
    <td><span class="bog">${subject}</span> <span class="y2"> - ${snippet}</span></td></tr>`;
}
const GMAIL_ROWS = [
  gmailRow('PayPal', 'service@paypa1-security.com', 'Your account has been limited', 'We noticed unusual activity. Verify your account within 24 hours.'),
  gmailRow('Dana Reyes', 'dana@northwlnd-supplies.example', 'Re: Invoice 4471', 'Before you pay, please note our bank details have changed.'),
  gmailRow('Amazon.com', 'shipment-tracking@amazon.com', 'Your order has shipped', 'Your package should arrive on Thursday.'),
].join('');

function gmailPage({ rows = GMAIL_ROWS, rowClass = 'zA', withMessage = true } = {}) {
  const thread = !withMessage ? '' : `
  <div class="nH if"><h2 class="hP">Re: Invoice 4471</h2>
   <div role="list">
    <div role="listitem" class="kv"><span class="gD" email="dana@northwind-supplies.example" name="Dana Reyes">Dana Reyes</span> Invoice 4471 attached.</div>
    <div role="listitem" class="adn ads" data-message-id="#msg-f:1789000000000000001" data-legacy-message-id="18d4c6e8a0b1c2d3">
     <div class="gs"><!-- as on live Gmail (Nov 2026): the id is on .adn, one level above .gs -->
      <h3 class="iw"><span class="gD" email="dana@northwlnd-supplies.example" name="Dana Reyes">Dana Reyes</span></h3>
      <div class="a3s aiL" id="body">
        <p>Hi, thanks for confirming the order.</p>
        <p>Before you pay invoice 4471, please note our bank details have changed because our old account is under audit.</p>
        <p>Please send the payment to the new account: IBAN ${VALID_IBAN}</p>
        <p>You can also pay online at <a id="lying-link" href="http://198.51.100.7/pay">https://www.northwind-supplies.example/pay</a>.</p>
        <p>Dana</p>
      </div>
      <div class="aQH"><span class="aZo" download_url="text/html:Remittance.pdf.html:https://mail.google.com/mail/u/0/?ui=2&amp;ik=a1b2c3d4e5&amp;attid=0.1&amp;view=att&amp;th=18d4c6e8a0b1c2d3">
        <span class="aV3">Remittance.pdf.html</span></span></div>
     </div>
    </div>
   </div>
   <div class="M9" role="dialog" aria-label="New Message"><div class="Am" g_editable="true" contenteditable="true" role="textbox" aria-label="Message Body">
     <div class="a3s">Draft: please verify your account and send the payment urgently.</div></div></div>
  </div>`;
  return html('Inbox (3) - tester@gmail.example - Gmail', `
  <script>var GLOBALS=[null,null,1,"x","y",null,0,"z",null,"a1b2c3d4e5",null];</script>
  <div role="main"><table><tbody>${rowClass === 'zA' ? rows : rows.replaceAll('class="zA zE"', `class="${rowClass}"`)}</tbody></table>${thread}</div>${TICKER}`);
}

// Gmail's "Show original": raw headers. The top Authentication-Results says the look-alike domain failed DMARC.
const GMAIL_ORIGINAL = html('Original Message', `<pre class="raw_message_text" id="raw_message_text">Delivered-To: tester@gmail.example
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning dana@northwlnd-supplies.example does not designate 203.0.113.9 as permitted sender) smtp.mailfrom=dana@northwlnd-supplies.example;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=northwlnd-supplies.example
From: Dana Reyes &lt;dana@northwlnd-supplies.example&gt;
Subject: Re: Invoice 4471

body</pre>`);
// The HTML attachment's contents: a fake sign-in form.
const PHISHING_ATTACHMENT = html('Remittance', '<form action="https://collect.example/login"><input name="email"><input type="password" name="pw"><button>View PDF</button></form>');

function gmailRoutes(page) {
  return (url) => {
    const u = new URL(url);
    if (u.searchParams.get('view') === 'om') return { body: GMAIL_ORIGINAL };
    if (u.searchParams.get('view') === 'att') return { body: PHISHING_ATTACHMENT };
    if (u.pathname.startsWith('/mail/')) return { body: page };
    return null;
  };
}

export const gmail = {
  url: 'https://mail.google.com/mail/u/0/#inbox/FMfcgzQXJbHnTbqVwLkMnPqRsTuVwXyZ',
  hosts: ['mail.google.com'],
  routes: gmailRoutes(gmailPage()),
};

// The same inbox after an imagined Gmail redesign: rows have a new class, so the built-in rules find nothing.
export const gmailRedesigned = {
  url: 'https://mail.google.com/mail/u/0/#inbox',
  hosts: ['mail.google.com'],
  routes: gmailRoutes(gmailPage({ rowClass: 'qX9 newRow', withMessage: false })),
};

// ---------- Outlook ----------
// A reading pane with a phishing email, plus an open compose box that is also labelled "Message body"
// (the case that used to get a banner by mistake).
export const outlook = {
  url: 'https://outlook.live.com/mail/0/id/AQMkADAwATM0MDAAMS1iZDQ',
  hosts: ['outlook.live.com'],
  routes: (url) => (new URL(url).pathname.startsWith('/mail/') ? { body: html('Mail - Tester - Outlook', `
  <div role="main">
    <div role="listbox" aria-label="Message list">
      <div role="option"><span title="it.helpdesk.office365@gmail.com">Microsoft 365 Support</span> <span class="subject">Password expires today</span> Failure to verify will disable your mailbox.</div>
      <div role="option"><span title="sarah@acme-design.example">Sarah Kim</span> <span class="subject">Notes from today</span> Thanks for a great meeting.</div>
      <div role="option"><span title="news@shop.example">Shop</span> <span class="subject">Autumn sale</span> Our sale is on now.</div>
    </div>
    <div id="reading">
      <div class="header"><span title="it.helpdesk.office365@gmail.com">Microsoft 365 Support</span></div>
      <div role="heading" aria-level="2">ACTION REQUIRED: Password expires today</div>
      <div aria-label="Message body" id="read-body"><p>Dear user, your Office 365 password expires today. Failure to verify will result in your mailbox being disabled.</p>
        <p>Click below and enter your password to confirm. <a href="https://office365-keep-password.example/login">Keep my password</a></p></div>
    </div>
    <div id="compose"><div aria-label="Message body" contenteditable="true" id="compose-body">Hi team, please verify your account and confirm your password urgently. This is my draft.</div></div>
  </div>${TICKER}`) } : null),
};

// ---------- Yahoo ----------
export const yahoo = {
  url: 'https://mail.yahoo.com/d/folders/1/messages/42',
  hosts: ['mail.yahoo.com'],
  routes: (url) => (new URL(url).pathname.startsWith('/d/') ? { body: html('Yahoo Mail', `
  <div role="main"><ul>
    <li data-test-id="message-list-item"><span data-test-id="senders"><span title="noreply@dhl-delivery-notice.top">DHL Express</span></span>
      <span data-test-id="message-subject">Package on hold: delivery fee unpaid</span><span data-test-id="snippet">Pay the processing fee within 48 hours.</span></li>
    <li data-test-id="message-list-item"><span data-test-id="senders"><span title="mom@family.example">Mom</span></span>
      <span data-test-id="message-subject">Sunday dinner</span><span data-test-id="snippet">Are you coming on Sunday?</span></li>
  </ul>
  <div data-test-id="message-view">
    <span data-test-id="message-group-subject-text">Package on hold: delivery fee unpaid</span>
    <div data-test-id="message-from" title="DHL Express &lt;noreply@dhl-delivery-notice.top&gt;"><span data-test-id="email-pill-name">DHL Express</span></div>
    <div data-test-id="message-view-body-content"><p>Dear Customer, your package could not be delivered because a processing fee of $1.99 is unpaid.</p>
      <p>Pay the fee within 48 hours or your package will be returned. <a href="https://dhl.com.redelivery-fee.top/pay">Pay now</a></p></div>
  </div></div>${TICKER}`) } : null),
};
