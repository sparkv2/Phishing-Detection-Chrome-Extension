#!/usr/bin/env node
// Admin tool for community reports. Run on the server as the service user:
//   sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs check paypa1-login.example
//   sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs suppress good-bakery.example "false reports, site is legitimate"
//   sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs unsuppress good-bakery.example
//   sudo -u tripwire node /opt/tripwire/server/tripwire-admin.mjs stats
// The server only stores fingerprints, so you look domains up by name: the tool fingerprints the name for you.
// Suppressing a domain deletes its reports, removes it from the published list (within 10 minutes) and refuses new ones.
import { openDb, fingerprint, publishable, today, THRESHOLD, MIN_AGE_DAYS } from './db.mjs';

const [cmd, domainArg, ...noteParts] = process.argv.slice(2);
const { q } = openDb();
const domain = (domainArg || '').toLowerCase().trim();
const need = () => { if (!domain) { console.error(`usage: tripwire-admin ${cmd} <domain>`); process.exit(2); } return fingerprint(domain); };

switch (cmd) {
  case 'check': {
    const h = need();
    const s = q.stats.get(h, h);
    const sup = q.isSuppressed.get(h);
    const published = publishable(q).includes(h);
    console.log(`${domain}\n  fingerprint: ${h}\n  reporting networks: ${s.networks}\n  first reported: ${s.seen != null ? new Date(s.seen * 86400000).toISOString().slice(0, 10) : '-'}` +
      `\n  published: ${published ? 'yes' : 'no'} (needs ${THRESHOLD} networks and ${MIN_AGE_DAYS} day(s))\n  suppressed: ${sup ? `yes (${sup.note || 'no note'})` : 'no'}`);
    break;
  }
  case 'suppress': {
    const h = need();
    q.suppress.run(h, today(), noteParts.join(' ').slice(0, 200));
    q.dropReports.run(h);
    console.log(`Suppressed ${domain}: its reports were deleted and new ones will be refused. The public list updates within 10 minutes.`);
    break;
  }
  case 'unsuppress': {
    const h = need();
    q.unsuppress.run(h);
    console.log(`${domain} can be reported again.`);
    break;
  }
  case 'stats': {
    console.log(`stored reports: ${q.rows.get().n}\npublished domains: ${publishable(q).length}`);
    break;
  }
  default:
    console.error('commands: check <domain> | suppress <domain> [note] | unsuppress <domain> | stats');
    process.exit(2);
}
