#!/usr/bin/env node
// Signs the threat list so the extension and the server can prove it came from the project, not from whoever
// controls the server or the Cloudflare account. The private key never goes on the server.
//
//   node tools/sign-intel.mjs --generate-key DIR     create DIR/signing-key.pem (keep secret) and print the public key
//   node tools/sign-intel.mjs DIR                     sign DIR/threat-intel.meta.json -> DIR/threat-intel.meta.json.sig
//                                                     (key from the TRIPWIRE_SIGNING_KEY environment variable, PEM text)
// The signature covers the exact bytes of meta.json, which records the SHA-256 of threat-intel.bin and the build date.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
if (args[0] === '--generate-key') {
  const dir = args[1];
  if (!dir) { console.error('usage: sign-intel.mjs --generate-key DIR'); process.exit(2); }
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'signing-key.pem');
  if (existsSync(file)) { console.error(`${file} already exists; not overwriting it.`); process.exit(1); }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  console.log(`Private key: ${file}  (store it as the GitHub secret TRIPWIRE_SIGNING_KEY; never commit it)`);
  console.log(`Public key (put in src/intel.js SIGNING_PUBLIC_KEY): ${raw.toString('base64')}`);
  process.exit(0);
}

const pem = process.env.TRIPWIRE_SIGNING_KEY;
// --file PATH: sign any file (used for data/selectors.json, the webmail layout rules) -> PATH.sig
if (args[0] === '--file') {
  const file = args[1];
  if (!file || !pem) { console.error('usage: TRIPWIRE_SIGNING_KEY="<pem>" sign-intel.mjs --file PATH'); process.exit(2); }
  writeFileSync(file + '.sig', sign(null, readFileSync(file), createPrivateKey(pem)).toString('base64') + '\n');
  console.log(`Signed ${file}`);
  process.exit(0);
}

const dir = args[0];
if (!dir || !pem) { console.error('usage: TRIPWIRE_SIGNING_KEY="<pem>" sign-intel.mjs DIR'); process.exit(2); }
const key = createPrivateKey(pem);
const meta = readFileSync(join(dir, 'threat-intel.meta.json'));
const sig = sign(null, meta, key);
writeFileSync(join(dir, 'threat-intel.meta.json.sig'), sig.toString('base64') + '\n');
const pub = createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
console.log(`Signed ${join(dir, 'threat-intel.meta.json')} with key ${pub}`);
