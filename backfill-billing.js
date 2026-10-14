// One-time catch-up for records made BEFORE lab orders raised bills and pharmacy
// sales recorded payments:
//   - every pharmacy sale without a payment gets a Transaction (Cash, dated like the sale)
//   - every open or completed lab order without a bill gets a Bill (cancelled orders are skipped;
//     lab bills only for hospitals that have the Billing feature switched on)
// Safe to run more than once: records that already have a payment/bill are never touched.
// Nothing is deleted or changed except adding the missing payment/bill and linking it.
//
// Preview:  node backfill-billing.js
// Apply:    node backfill-billing.js --apply
// One hospital only: add --slug=byarwanga
//
// Tip: run cleanup-test-data.js / cleanup-test-sales.js FIRST, so test sales are not turned into revenue.

require('dotenv').config();
const mongoose = require('mongoose');
const { randomUUID } = require('crypto');

const APPLY = process.argv.includes('--apply');
const SLUG = (process.argv.find(a => a.startsWith('--slug=')) || '').slice(7).toLowerCase();

async function nextSeq(db, key) {
  const r = await db.collection('counters').findOneAndUpdate({ key }, { $inc: { seq: 1 } }, { upsert: true, returnDocument: 'after' });
  const doc = r && Object.prototype.hasOwnProperty.call(r, 'value') ? r.value : r;
  return doc.seq;
}
const pad = n => String(n).padStart(6, '0');

async function main() {
  if (!process.env.MONGO_URI) { console.error('❌ MONGO_URI is not set in .env'); process.exit(1); }
  await mongoose.connect(process.env.MONGO_URI);
  const db = mongoose.connection.db;

  const hospitals = await db.collection('hospitals').find(SLUG ? { slug: SLUG } : {}).toArray();
  if (SLUG && !hospitals.length) { console.error(`❌ No hospital with slug "${SLUG}"`); process.exit(1); }
  console.log(APPLY ? '── APPLY MODE ──' : '── PREVIEW (nothing will be changed) ──');

  let tx = 0, bills = 0, txTotal = 0, billTotal = 0;
  for (const h of hospitals) {
    const hid = h.id;

    // Pharmacy sales -> payments
    const sales = await db.collection('pharmacysales').find({ hospitalId: hid, transactionId: { $in: [null, ''] }, totalAmount: { $gt: 0 } }).toArray();
    for (const s of sales) {
      tx++; txTotal += Number(s.totalAmount) || 0;
      console.log(`  [${h.slug}] sale ${s.saleRef} (${s.totalAmount}) -> payment`);
      if (!APPLY) continue;
      const id = randomUUID();
      await db.collection('transactions').insertOne({
        id, hospitalId: hid, txRef: `TXN-${pad(await nextSeq(db, `tx:${hid}`))}`, pharmacySaleId: s.id,
        patientId: s.patientId, patientName: s.patientName, amount: Number(s.totalAmount),
        tenderedCurrency: h.currency, tenderedAmount: Number(s.totalAmount), exchangeRate: 1,
        method: 'Cash', note: `Pharmacy sale ${s.saleRef}`, recordedBy: s.soldByName || 'Backfill',
        createdAt: s.createdAt || new Date().toISOString(),
      });
      await db.collection('pharmacysales').updateOne({ id: s.id }, { $set: { transactionId: id } });
    }

    // Lab orders -> bills (only where billing is on)
    if (!h.features || h.features.billing === false) continue;
    const orders = await db.collection('laborders').find({ hospitalId: hid, billId: { $in: [null, ''] }, status: { $ne: 'cancelled' }, totalAmount: { $gt: 0 } }).toArray();
    for (const o of orders) {
      bills++; billTotal += Number(o.totalAmount) || 0;
      console.log(`  [${h.slug}] lab order ${o.orderRef} (${o.totalAmount}) -> bill`);
      if (!APPLY) continue;
      const id = randomUUID();
      const number = `BILL-${pad(await nextSeq(db, `bill:${hid}`))}`;
      const items = (o.tests || []).filter(t => Number(t.price) > 0).map(t => ({ description: `Lab: ${t.name}`, quantity: 1, unitPrice: Number(t.price), amount: Number(t.price) }));
      await db.collection('bills').insertOne({
        _id: `lab:${o.id}`, id, hospitalId: hid, billNumber: number, labOrderId: o.id, patientId: o.patientId, patientName: o.patientName,
        items, totalAmount: Number(o.totalAmount), paidAmount: 0, remainingAmount: Number(o.totalAmount), status: 'pending',
        notes: `Laboratory order ${o.orderRef}`, createdAt: o.createdAt || new Date().toISOString(),
      });
      await db.collection('laborders').updateOne({ id: o.id }, { $set: { billId: id, billNumber: number } });
    }
  }

  console.log(`\nPharmacy sales without a payment: ${tx} (total ${txTotal})`);
  console.log(`Lab orders without a bill:        ${bills} (total ${billTotal})`);
  console.log(APPLY ? '\n✅ Done.' : '\nThis was a preview. Run again with --apply to create them.');
  await mongoose.disconnect();
}

main().catch(e => { console.error('❌', e.message); process.exit(1); });
