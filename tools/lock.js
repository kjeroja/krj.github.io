#!/usr/bin/env node
// Encrypts the password-protected part of a page, or decrypts it for editing.
//
//   Decrypt to a file you can edit:
//     node tools/lock.js unlock index.html K2 > content.html
//   Encrypt it back into the page:
//     node tools/lock.js lock index.html content.html K2
//
// Don't commit content.html: the repo is public, so it would reveal the content.
// The password is not case-sensitive (k2 and K2 both work).

const fs = require('fs');
const crypto = require('crypto');

const ITERATIONS = 310000;
const SLOT = /(<script id="locked" type="application\/json">)([\s\S]*?)(<\/script>)/;
const normalize = (pw) => pw.trim().toUpperCase();

const [cmd, page, ...rest] = process.argv.slice(2);
if (!page || !['lock', 'unlock'].includes(cmd)) {
  console.error('Usage: lock <page.html> <content.html> <password> | unlock <page.html> <password>');
  process.exit(1);
}
const html = fs.readFileSync(page, 'utf8');
if (!SLOT.test(html)) throw new Error(page + ' has no <script id="locked"> slot');

if (cmd === 'lock') {
  const [contentFile, password] = rest;
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(normalize(password), salt, ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(fs.readFileSync(contentFile)), cipher.final(), cipher.getAuthTag()]);
  const payload = JSON.stringify({
    iter: ITERATIONS,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
  });
  fs.writeFileSync(page, html.replace(SLOT, (m, open, old, close) => open + payload + close));
  console.error('Locked ' + page);
} else {
  const [password] = rest;
  const p = JSON.parse(html.match(SLOT)[2]);
  const data = Buffer.from(p.ct, 'base64');
  const key = crypto.pbkdf2Sync(normalize(password), Buffer.from(p.salt, 'base64'), p.iter, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(p.iv, 'base64'));
  decipher.setAuthTag(data.subarray(data.length - 16));
  process.stdout.write(Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]));
}
