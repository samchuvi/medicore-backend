// Nightly database backup.
//   Run now:   npm run backup
//   Check:     npm run backup:list
// Exports every collection, compresses, ENCRYPTS, then uploads to Backblaze B2
// (or saves in ./backups if B2 isn't configured yet). Old backups beyond
// BACKUP_KEEP_DAYS (default 30) are removed from B2.
// Needs in .env: MONGO_URI, BACKUP_PASSPHRASE   (+ B2_ENDPOINT, B2_KEY_ID, B2_APP_KEY, B2_BUCKET for cloud)
require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const lib = require('./backup-lib');

async function main() {
  if (process.argv.includes('--list')) {
    if (!lib.b2Configured()) { console.log('B2 is not configured in .env'); return; }
    const files = await lib.b2List();
    if (!files.length) console.log('No backups in B2 yet.');
    files.forEach(f => console.log(f.modified.toISOString(), String(f.size).padStart(10), f.key));
    return;
  }
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is not set');
  if (!process.env.BACKUP_PASSPHRASE) throw new Error('BACKUP_PASSPHRASE is not set');

  await mongoose.connect(process.env.MONGO_URI);
  const db = mongoose.connection.db;
  const names = (await db.listCollections().toArray()).map(c => c.name).filter(n => !n.startsWith('system.')).sort();
  const data = { createdAt: new Date().toISOString(), database: db.databaseName, collections: {} };
  const counts = {};
  for (const n of names) { data.collections[n] = await db.collection(n).find({}).toArray(); counts[n] = data.collections[n].length; }
  await mongoose.disconnect();

  const file = lib.encrypt(lib.pack(data), process.env.BACKUP_PASSPHRASE);
  const stamp = data.createdAt.replace(/[:.]/g, '-');
  const name = `hms-${stamp}.bak`;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  console.log(`Exported ${names.length} collections, ${total} records, ${(file.length / 1024).toFixed(1)} KB encrypted.`);

  if (lib.b2Configured()) {
    await lib.b2Upload(name, file);
    console.log(`Uploaded to Backblaze B2: ${lib.PREFIX}${name}`);
    const keepDays = parseInt(process.env.BACKUP_KEEP_DAYS, 10) || 30;
    const cutoff = Date.now() - keepDays * 86400000;
    const files = await lib.b2List();
    const old = files.filter(f => f.modified.getTime() < cutoff);
    // Never delete everything: always keep at least the 3 newest files.
    const deletable = old.filter(f => files.slice(-3).every(k => k.key !== f.key));
    for (const f of deletable) { await lib.b2Delete(f.key); console.log('Removed old backup', f.key); }
  } else {
    const dir = path.join(__dirname, 'backups');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, name), file);
    console.log(`B2 not configured — saved locally: backups/${name}`);
  }
  console.log('✅ Backup finished.');
}
main().catch(e => { console.error('❌ Backup failed:', e.message); process.exit(1); });
