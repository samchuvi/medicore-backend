// Restore a backup. SAFE BY DEFAULT: without --apply it only decrypts the file
// and shows what is inside. Nothing is written anywhere.
//
//   Look inside the newest B2 backup:   node restore.js latest
//   Look inside a local file:           node restore.js backups/hms-2026-....bak
//   Restore into a DATABASE YOU NAME:   node restore.js latest --target "mongodb+srv://.../hms_restore_test" --apply
//
// --target is REQUIRED with --apply, so you can never overwrite the live database
// by accident. Each collection in the target is emptied and refilled from the backup.
// Needs BACKUP_PASSPHRASE (same one used when the backup was made).
require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');
const lib = require('./backup-lib');

async function main() {
  const src = process.argv[2];
  const apply = process.argv.includes('--apply');
  const ti = process.argv.indexOf('--target');
  const target = ti > -1 ? process.argv[ti + 1] : null;
  if (!src) throw new Error('Usage: node restore.js <latest | B2 key | local file> [--target <mongo uri> --apply]');
  if (!process.env.BACKUP_PASSPHRASE) throw new Error('BACKUP_PASSPHRASE is not set');

  let buf;
  if (fs.existsSync(src)) buf = fs.readFileSync(src);
  else {
    if (!lib.b2Configured()) throw new Error('B2 is not configured in .env and no such local file');
    let key = src;
    if (src === 'latest') { const f = await lib.b2List(); if (!f.length) throw new Error('No backups in B2'); key = f[f.length - 1].key; }
    console.log('Downloading', key);
    buf = await lib.b2Download(key);
  }
  const data = lib.unpack(lib.decrypt(buf, process.env.BACKUP_PASSPHRASE));
  console.log(`Backup made ${data.createdAt} from database "${data.database}":`);
  Object.entries(data.collections).forEach(([n, docs]) => console.log(`  ${n.padEnd(28)} ${docs.length}`));

  if (!apply) { console.log('\nPreview only — nothing was restored. To restore add: --target "<mongo uri>" --apply'); return; }
  if (!target) throw new Error('--apply needs --target "<mongo uri>" (a database you choose, to avoid overwriting the live one by accident)');
  await mongoose.connect(target);
  const db = mongoose.connection.db;
  console.log(`\nRestoring into database "${db.databaseName}" ...`);
  for (const [n, docs] of Object.entries(data.collections)) {
    await db.collection(n).deleteMany({});
    if (docs.length) await db.collection(n).insertMany(docs);
    console.log(`  ${n}: ${docs.length} restored`);
  }
  await mongoose.disconnect();
  console.log('✅ Restore finished.');
}
main().catch(e => { console.error('❌', e.message); process.exit(1); });
