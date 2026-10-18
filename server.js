require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { connect } = require('./db');

const app = express();

// The signing key MUST come from the environment. Refusing to start without it
// prevents anyone from forging tokens against a well-known default secret.
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error('❌ JWT_SECRET is missing or too short. Set a long random value in the environment before starting.');
  process.exit(1);
}

const SUPERADMIN = 'superadmin';
const ADMIN = 'admin';
const DOCTOR = 'doctor';
const RECEPTIONIST = 'receptionist';
const PHARMACIST = 'pharmacist';
const LAB_STAFF = 'labstaff';

// Never leak internals (stack traces, driver messages) to the browser: log the
// detail server-side, return a short safe message with a machine-readable code.
function serverError(res, err) {
  console.error('❌', err && err.stack ? err.stack : err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Something went wrong on the server. Please try again in a moment.', code: 'SERVER_ERROR' });
}

// Currencies a hospital can choose (shown everywhere money appears).
const CURRENCIES = {
  UGX: { symbol: 'UGX', name: 'Ugandan Shilling', decimals: 0 },
  CDF: { symbol: 'FC', name: 'Congolese Franc', decimals: 0 },
  USD: { symbol: '$', name: 'US Dollar', decimals: 2 },
  KES: { symbol: 'KSh', name: 'Kenyan Shilling', decimals: 0 },
  TZS: { symbol: 'TSh', name: 'Tanzanian Shilling', decimals: 0 },
  RWF: { symbol: 'FRw', name: 'Rwandan Franc', decimals: 0 },
  BIF: { symbol: 'FBu', name: 'Burundian Franc', decimals: 0 },
  EUR: { symbol: '€', name: 'Euro', decimals: 2 },
};
const COUNTRIES = ['UG', 'CD', 'KE', 'TZ', 'RW', 'BI', 'SS', 'OTHER'];
const DEFAULT_DEPARTMENTS = ['General Medicine', 'Outpatient (OPD)', 'Maternity', 'Paediatrics', 'Surgery', 'Laboratory', 'Pharmacy', 'Radiology', 'Dental', 'Emergency', 'Administration'];
// Job titles for the staff register (the login role is separate: see ASSIGNABLE_ROLES).
const STAFF_ROLES = ['Nurse', 'Midwife', 'Clinical Officer', 'Lab Technician', 'Pharmacist', 'Pharmacy Assistant', 'Receptionist', 'Accountant', 'Cashier', 'Cleaner', 'Security', 'Driver', 'Records Officer', 'Administrator', 'Other'];
const QUALIFICATIONS = ['MBChB', 'MD', 'MBBS', 'MMed', 'MSc', 'PhD', 'Diploma in Clinical Medicine', 'Certificate in Clinical Medicine', 'BSc Nursing', 'Diploma in Nursing', 'Diploma in Midwifery', 'Diploma in Medical Laboratory Technology', 'BSc Pharmacy', 'Diploma in Pharmacy', 'Specialist (Fellowship)', 'Other'];

// ─── CORS ────────────────────────────────────────────────────────────────────
const rawOrigins = process.env.CORS_ORIGINS;
if (rawOrigins) {
  const allowed = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);
  app.use(cors({ origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)) }));
} else {
  console.warn('⚠️  CORS_ORIGINS not set — every origin is allowed. Set CORS_ORIGINS in production.');
  app.use(cors());
}

app.use(express.json({ limit: '300kb' })); // room for a small hospital logo sent as a data-URL
app.set('trust proxy', true);

// Basic safe headers on every response, plus a health check for uptime monitors.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ─── LOGIN RATE LIMIT ────────────────────────────────────────────────────────
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginHits = new Map();

setInterval(() => {
  const cutoff = Date.now() - LOGIN_WINDOW_MS;
  for (const [key, hit] of loginHits) if (hit.first < cutoff) loginHits.delete(key);
}, LOGIN_WINDOW_MS).unref();

// Two counters: per network address AND per account (hospital + username). The
// per-account one still protects an account if someone fakes their address header.
const ACCOUNT_MAX_ATTEMPTS = 20;
function hitLimiter(key, max, now) {
  const hit = loginHits.get(key);
  if (!hit || now - hit.first > LOGIN_WINDOW_MS) { loginHits.set(key, { count: 1, first: now }); return null; }
  hit.count += 1;
  return hit.count > max ? Math.max(1, Math.ceil((hit.first + LOGIN_WINDOW_MS - now) / 1000)) : null;
}
function loginRateLimit(req, res, next) {
  const now = Date.now();
  const b = req.body || {};
  req.loginKeys = [`ip:${req.ip || 'unknown'}`, `acct:${String(b.hospitalSlug || '').toLowerCase().trim()}|${String(b.username || '').toLowerCase().trim()}`];
  const waits = [hitLimiter(req.loginKeys[0], LOGIN_MAX_ATTEMPTS, now), hitLimiter(req.loginKeys[1], ACCOUNT_MAX_ATTEMPTS, now)].filter(Boolean);
  if (waits.length) {
    const wait = Math.max(...waits);
    res.set('Retry-After', String(wait));
    return res.status(429).json({ error: `Too many login attempts. Please wait ${Math.ceil(wait / 60)} minute(s) and try again.`, code: 'RATE_LIMITED', retryAfter: wait });
  }
  next();
}

// ─── MONGOOSE SCHEMAS ────────────────────────────────────────────────────────

// The platform's tenants. A superadmin (platform owner) manages these; every
// other role belongs to exactly one hospital via hospitalId.
const HospitalSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  name: String,
  slug: { type: String, unique: true, lowercase: true, trim: true }, // used at login — e.g. "byarwanga"
  logo: String,
  theme: {
    primaryColor: { type: String, default: '#2E7D32' },
    secondaryColor: { type: String, default: '#1976D2' },
  },
  features: {
    pharmacy: { type: Boolean, default: true },
    laboratory: { type: Boolean, default: true },
    billing: { type: Boolean, default: true },
    insurance: { type: Boolean, default: false },
    theatre: { type: Boolean, default: false },
    treatmentPlans: { type: Boolean, default: true },
    referrals: { type: Boolean, default: true },
    inpatient: { type: Boolean, default: false },
  },
  // Each hospital's own preferences (the hospital admin can change these).
  settings: {
    // How pharmacy sales relate to patient records:
    //   off      – sales are never linked (name typed freely, as before)
    //   optional – walk-in customers allowed; a registered patient can be picked
    //   required – every sale must be linked to a registered patient
    pharmacyPatientLink: { type: String, enum: ['off', 'optional', 'required'], default: 'optional' },
    // Departments this hospital offers (staff and doctors pick from these).
    departments: { type: [String], default: undefined },
    // Extra currencies this hospital accepts for payments (the hospital's own `currency` is always accepted).
    // exchangeRates[code] = how many units of that currency equal ONE unit of the hospital's main currency
    // (e.g. main USD, exchangeRates.CDF = 2800 means 1 USD = 2,800 CDF).
    acceptedCurrencies: { type: [String], default: undefined },
    exchangeRates: { type: mongoose.Schema.Types.Mixed },
  },
  currency: { type: String, default: 'UGX' }, // ISO code from CURRENCIES
  country: { type: String, default: 'UG' },
  status: { type: String, default: 'active' }, // active | suspended | trial
  // Only hospitals marked as test hospitals can ever be deleted (see DELETE /api/hospitals/:id).
  isTest: { type: Boolean, default: false },
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Hospital = mongoose.model('Hospital', HospitalSchema);
// Hospitals created before settings existed simply get the defaults.
const PHARMACY_LINK_MODES = ['off', 'optional', 'required'];
// A money amount from a form: a number, zero or more, within reason. Anything else is rejected (null).
function cleanFee(v) {
  if (v === '' || v === null) return 0;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 && n <= 1e9 ? n : null;
}
const hospitalSettings = (h) => {
  const base = CURRENCIES[h?.currency] ? h.currency : 'UGX';
  const stored = h?.settings?.exchangeRates || {};
  const exchangeRates = {};
  for (const c of h?.settings?.acceptedCurrencies || []) {
    const r = Number(stored[c]);
    if (c !== base && CURRENCIES[c] && r > 0) exchangeRates[c] = r; // only usable with a valid rate
  }
  return {
    pharmacyPatientLink: h?.settings?.pharmacyPatientLink || 'optional',
    departments: h?.settings?.departments && h.settings.departments.length ? h.settings.departments : DEFAULT_DEPARTMENTS,
    acceptedCurrencies: [base, ...Object.keys(exchangeRates)],
    exchangeRates,
  };
};
// What the browser needs to format money for this hospital.
const hospitalPublic = (h) => ({
  id: h.id, name: h.name, logo: h.logo, theme: h.theme, features: h.features,
  settings: hospitalSettings(h),
  currency: CURRENCIES[h.currency] ? h.currency : 'UGX',
  country: h.country || 'UG',
});

// The platform owner's own settings (one document): the system name, colour and
// logo shown on the login page and in the platform owner's screens.
const PlatformSettingsSchema = new mongoose.Schema({
  key: { type: String, default: 'platform', unique: true },
  name: String,
  color: String, // #RRGGBB
  logo: String,  // small image as a data-URL
  updatedAt: String,
});
const PlatformSettings = mongoose.model('PlatformSettings', PlatformSettingsSchema);

const UserSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  // Absent/undefined for a superadmin (platform-level, belongs to no single
  // hospital). Present for every hospital-scoped user.
  hospitalId: { type: String },
  name: String,
  username: String,
  password: String,
  role: String,
  status: { type: String, default: 'active' },
  createdAt: { type: String, default: () => new Date().toISOString() },
});
// A username is unique WITHIN a hospital, so two hospitals can each have
// their own "admin". A superadmin (no hospitalId) is unique platform-wide.
UserSchema.index({ hospitalId: 1, username: 1 }, { unique: true, partialFilterExpression: { hospitalId: { $type: 'string' } } });
UserSchema.index({ username: 1 }, { unique: true, partialFilterExpression: { hospitalId: { $exists: false } } });
const User = mongoose.model('User', UserSchema);

const PatientSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  patientNumber: String, // human-friendly MRN, unique per hospital, e.g. P-000123
  name: String,
  age: Number,
  gender: String,
  phone: String,
  email: String,
  address: String,
  bloodGroup: String,
  emergencyContact: String,
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
PatientSchema.index({ hospitalId: 1, patientNumber: 1 });
PatientSchema.index({ hospitalId: 1, name: 1 });
const Patient = mongoose.model('Patient', PatientSchema);

// Atomic per-hospital counters (patient numbers) — two simultaneous registrations can never get the same number.
const CounterSchema = new mongoose.Schema({ key: { type: String, unique: true }, seq: { type: Number, default: 0 } });
const Counter = mongoose.model('Counter', CounterSchema);
async function nextSeq(key) {
  for (let attempt = 0; ; attempt++) {
    try { return (await Counter.findOneAndUpdate({ key }, { $inc: { seq: 1 } }, { new: true, upsert: true })).seq; }
    catch (e) { if (e && e.code === 11000 && attempt < 5) continue; throw e; }
  }
}
async function nextPatientNumber(hospitalId) {
  // The very first concurrent upserts can race on the unique key; retry resolves it.
  for (let attempt = 0; ; attempt++) {
    try {
      const c = await Counter.findOneAndUpdate({ key: `patient:${hospitalId}` }, { $inc: { seq: 1 } }, { new: true, upsert: true });
      return `P-${String(c.seq).padStart(6, '0')}`;
    } catch (e) {
      if (e && e.code === 11000 && attempt < 5) continue;
      throw e;
    }
  }
}
// Give existing patients a number (oldest first). Safe to run on every start.
async function backfillPatientNumbers() {
  const missing = await Patient.find({ $or: [{ patientNumber: { $exists: false } }, { patientNumber: null }, { patientNumber: '' }] }).sort({ createdAt: 1 });
  for (const p of missing) {
    if (!p.hospitalId) continue;
    p.patientNumber = await nextPatientNumber(p.hospitalId);
    await p.save();
  }
  if (missing.length) console.log(`✅ Patient numbers assigned to ${missing.length} existing patient(s)`);
}

const DoctorSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  name: String,
  specialization: String,
  qualification: String,
  department: String,
  phone: String,
  email: String,
  status: String,
  consultationFee: { type: Number, default: 0 }, // billed (in the hospital's main currency) when an appointment with this doctor is completed
  linkedUserId: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Doctor = mongoose.model('Doctor', DoctorSchema);

const StaffSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  name: String,
  role: String,
  phone: String,
  email: String,
  department: String,
  salary: Number,
  status: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Staff = mongoose.model('Staff', StaffSchema);

const AppointmentSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  patientId: String,
  patientName: String,
  doctorId: String,
  doctorName: String,
  date: String,
  time: String,
  status: { type: String, default: 'scheduled' },
  billId: String,        // the consultation bill raised when the appointment was completed
  reason: String,
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Appointment = mongoose.model('Appointment', AppointmentSchema);

const MedicalRecordSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  patientId: String,
  patientName: String,
  doctorId: String,
  doctorName: String,
  diagnosis: String,
  treatment: String,
  prescription: String,
  medicines: Array,
  medicinesUsed: Array,
  notes: String,
  createdBy: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const MedicalRecord = mongoose.model('MedicalRecord', MedicalRecordSchema);

// A treatment plan is the doctor's ongoing plan for a patient — separate from
// a single visit's medical record, since a plan spans multiple visits (e.g.
// "6-week physiotherapy course", reviewed and adjusted as it goes).
const TreatmentPlanSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  patientId: String,
  patientName: String,
  doctorId: String,
  doctorName: String,
  diagnosis: String,
  goals: String,
  medications: Array, // [{ name, dosage, frequency, duration }]
  instructions: String,
  startDate: String,
  reviewDate: String,
  status: { type: String, default: 'active' }, // active | completed | discontinued
  notes: String,
  createdBy: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const TreatmentPlan = mongoose.model('TreatmentPlan', TreatmentPlanSchema);

// A referral moves a patient from one doctor/department to another WITHIN
// the same hospital (by design — see the note on requireHospitalContext:
// each hospital on this platform can't see or reach any other hospital, so a
// referral never crosses that boundary).
const ReferralSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  patientId: String,
  patientName: String,
  fromDoctorId: String,
  fromDoctorName: String,
  toDoctorId: String,   // optional — a specific doctor, if known
  toDoctorName: String,
  toDepartment: String, // e.g. "Cardiology" — used when no specific doctor is picked yet
  reason: String,
  urgency: { type: String, default: 'routine' }, // routine | urgent
  status: { type: String, default: 'pending' }, // pending | accepted | completed | declined
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
  respondedAt: String,
  respondedBy: String,
});
const Referral = mongoose.model('Referral', ReferralSchema);

// A lab order is one request from a doctor for one or more tests on a
// patient. Lab staff work the order through pending -> in_progress ->
// completed, entering a result against each test. Prices are kept per test so
// the order carries its own total, ready to feed billing later.
const LabOrderSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  orderRef: String,
  patientId: String,
  patientName: String,
  orderedById: String,   // the user (doctor/admin) who requested the tests
  orderedByName: String,
  doctorId: String,      // linked Doctor record, when a doctor placed the order
  clinicalNotes: String, // why the tests are wanted — shown to lab staff
  priority: { type: String, default: 'routine' }, // routine | urgent
  tests: [{
    name: String,
    price: Number,
    result: String,
    unit: String,
    referenceRange: String,
    flag: String,        // optional: normal | high | low | abnormal
  }],
  status: { type: String, default: 'pending' }, // pending | in_progress | completed | cancelled
  totalAmount: { type: Number, default: 0 },
  billId: String,        // the bill raised for this order (when the hospital uses billing)
  billNumber: String,
  sampleCollectedAt: String,
  completedAt: String,
  processedById: String,
  processedByName: String,
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const LabOrder = mongoose.model('LabOrder', LabOrderSchema);

// ── Inpatient: wards (with their beds) and admissions ──────────────────────
// A bed is only ever claimed through an atomic update on its own ward document,
// so two receptionists can never admit two patients into the same bed.
const WardSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  name: String,
  type: { type: String, default: 'general' }, // general | private | icu | maternity | pediatric | other
  dailyRate: { type: Number, default: 0 },
  beds: [{
    number: String,
    status: { type: String, default: 'available' }, // available | occupied | maintenance
    admissionId: String,
  }],
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Ward = mongoose.model('Ward', WardSchema);

const AdmissionSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  admissionRef: String,
  patientId: String,
  patientName: String,
  wardId: String,
  wardName: String,
  bedNumber: String,
  dailyRate: { type: Number, default: 0 }, // snapshot — later rate changes don't alter this stay
  admittedById: String,
  admittedByName: String,
  reason: String,
  diagnosis: String,
  status: { type: String, default: 'admitted' }, // admitted | discharged
  admittedAt: { type: String, default: () => new Date().toISOString() },
  dischargedAt: String,
  dischargedByName: String,
  dischargeSummary: String,
  daysStayed: Number,
  bedCharge: Number,
  billId: String,
  notes: [{
    id: String,
    at: String,
    byId: String,
    byName: String,
    text: String,
  }],
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Admission = mongoose.model('Admission', AdmissionSchema);

const InventorySchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  name: String,
  category: String,
  quantity: Number,
  unit: String,
  unitPrice: Number,
  expiryDate: String,
  supplier: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Inventory = mongoose.model('Inventory', InventorySchema);

const BillSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  billNumber: String,
  labOrderId: String,    // set when the bill was raised from a laboratory order
  appointmentId: String, // set when the bill is a consultation fee for a completed appointment
  patientId: String,
  patientName: String,
  items: Array,
  totalAmount: { type: Number, default: 0 },
  paidAmount: { type: Number, default: 0 },
  remainingAmount: { type: Number, default: 0 },
  status: { type: String, default: 'pending' },
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Bill = mongoose.model('Bill', BillSchema);
// One bill per appointment and one per lab order, enforced by the database itself: such a bill gets a
// fixed _id ("consult:<appointment id>" / "lab:<order id>"), so a second insert for the same thing
// is refused (E11000) even when two requests arrive at the same moment.
async function insertOnceBill(fixedId, fields) {
  const doc = new Bill(fields).toObject();
  doc._id = fixedId;
  await Bill.collection.insertOne(doc);
  return doc;
}

const TransactionSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  txRef: String,
  billId: String,
  pharmacySaleId: String,                      // set when the payment was taken at the pharmacy counter
  patientId: String,
  patientName: String,
  amount: { type: Number, default: 0 },       // always in the hospital's MAIN currency (so totals stay correct)
  tenderedCurrency: String,                    // what the patient actually paid in (e.g. CDF)
  tenderedAmount: Number,                      // …and how much of it
  exchangeRate: Number,                        // units of tenderedCurrency per 1 main-currency unit, fixed at payment time
  recordedBy: String,
  method: String,
  note: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// A pharmacy sale records exactly what was sold, at what price, and takes the
// stock straight out of Inventory in the same request — no separate
// "remember to update stock" step for the pharmacist to forget.
const PharmacySaleSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  saleRef: String,
  patientId: String,
  patientName: String,
  items: [{
    inventoryId: String,
    name: String,
    quantity: Number,
    unitPrice: Number,
    subtotal: Number,
  }],
  totalAmount: { type: Number, default: 0 },
  transactionId: String,  // the payment recorded for this sale
  soldById: String,
  soldByName: String,
  notes: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const PharmacySale = mongoose.model('PharmacySale', PharmacySaleSchema);

const AuditLogSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String }, // absent for platform-level (superadmin) actions
  timestamp: { type: String, default: () => new Date().toISOString() },
  actorId: String,
  actorName: String,
  actorRole: String,
  action: String,
  entity: String,
  entityId: String,
  method: String,
  path: String,
  status: Number,
  description: String,
  ip: String,
  meta: mongoose.Schema.Types.Mixed,
});
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

async function writeAudit(entry) {
  try { await new AuditLog({ id: uuidv4(), ...entry }).save(); }
  catch (e) { console.error('⚠️  audit write failed:', e.message); }
}

// ─── TENANT SCOPING HELPERS ──────────────────────────────────────────────────
// scope(req) returns {} for a superadmin (so they see across every hospital —
// useful for platform support) and { hospitalId } for everyone else. Every
// find/count in this file is filtered through this, so the backend — not the
// frontend — is what actually enforces hospital isolation.
const scope = (req) => (req.user.hospitalId ? { hospitalId: req.user.hospitalId } : {});

// Hospital-scoped writes (creating a patient, bill, etc.) need a real
// hospitalId to attach the record to. A superadmin acting outside any
// hospital has none, so those routes are blocked for them — superadmin
// manages the platform and hospitals, not day-to-day clinical data.
function requireHospitalContext(req, res, next) {
  if (!req.user.hospitalId) return res.status(400).json({ error: 'This action must be performed as a hospital user, not the platform super admin.' });
  next();
}

// Blocks a route when the hospital hasn't enabled that feature, and re-checks
// hospital status on every request — a suspended hospital is locked out
// immediately, without users needing to log out/in. Superadmin bypasses, same
// as requireRole below.
function requireFeature(featureKey) {
  return async (req, res, next) => {
    if (req.user.role === SUPERADMIN) return next();
    const hospital = await Hospital.findOne({ id: req.user.hospitalId });
    if (!hospital || hospital.status !== 'active')
      return res.status(403).json({ error: 'Access denied' });
    if (!hospital.features?.[featureKey])
      return res.status(403).json({ error: 'Module not enabled' });
    next();
  };
}

// ─── DUPLICATE-SUBMISSION GUARD ──────────────────────────────────────────────
// The browser sends one Idempotency-Key per user action. If the same key arrives
// again (double click, impatient retry, flaky network resend) we never run the
// action twice: a finished request replays its first answer, a running one is refused.
const crypto = require('crypto');
const idem = new Map(); // hash -> { state: 'running'|'done', status, body, at }
setInterval(() => { const cut = Date.now() - 10 * 60 * 1000; for (const [k, v] of idem) if (v.at < cut) idem.delete(k); }, 60 * 1000).unref();
// Offline-capable actions also send X-Durable: 1. Those are remembered in the database (not just in
// memory), so a request replayed hours later, or after a server restart, still can't run twice.
const durableCol = () => mongoose.connection.collection('idempotency');
setInterval(() => { try { durableCol().deleteMany({ at: { $lt: new Date(Date.now() - 30 * 24 * 3600 * 1000) } }).catch(() => {}); } catch { /* not connected yet */ } }, 6 * 3600 * 1000).unref();
const callerOf = (req) => { try { const t = String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''); const p = JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); return `${p.hospitalId || ''}:${p.id || ''}`; } catch { return req.ip; } };
app.use(async (req, res, next) => {
  const key = req.method === 'POST' && req.headers['idempotency-key'];
  if (!key || typeof key !== 'string' || key.length > 100) return next();
  const durable = req.headers['x-durable'] === '1';
  const h = crypto.createHash('sha256').update(`${durable ? callerOf(req) : (req.headers.authorization || req.ip)}|${req.path}|${key}`).digest('hex');
  const prev = idem.get(h);
  if (prev) {
    if (prev.state === 'running') return res.status(409).json({ error: 'This request is already being processed.', code: 'DUPLICATE_REQUEST' });
    res.set('Idempotent-Replay', 'true');
    return res.status(prev.status).json(prev.body);
  }
  if (durable) {
    try {
      try { await durableCol().insertOne({ _id: h, state: 'running', at: new Date() }); }
      catch (e) {
        if (e && e.code !== 11000) throw e;
        const doc = await durableCol().findOne({ _id: h });
        if (doc && doc.state === 'done') { res.set('Idempotent-Replay', 'true'); return res.status(doc.status).json(doc.body); }
        if (doc && Date.now() - new Date(doc.at).getTime() < 2 * 60 * 1000) return res.status(409).json({ error: 'This request is already being processed.', code: 'DUPLICATE_REQUEST' });
        await durableCol().deleteOne({ _id: h, state: 'running' }); // a crashed attempt: let this one run
        await durableCol().insertOne({ _id: h, state: 'running', at: new Date() });
      }
    } catch (e) { return res.status(503).json({ error: 'The server is busy. Please try again.', code: 'SERVER_DOWN' }); }
  }
  idem.set(h, { state: 'running', at: Date.now() });
  const orig = res.json.bind(res);
  res.json = (body) => {
    // Failed attempts may be retried with the same key; only successes are replayed.
    if (res.statusCode < 400) {
      idem.set(h, { state: 'done', status: res.statusCode, body, at: Date.now() });
      if (durable) durableCol().updateOne({ _id: h }, { $set: { state: 'done', status: res.statusCode, body, at: new Date() } }).catch(() => {});
    } else {
      idem.delete(h);
      if (durable) durableCol().deleteOne({ _id: h }).catch(() => {});
    }
    return orig(body);
  };
  res.on('close', () => { const cur = idem.get(h); if (cur && cur.state === 'running') { idem.delete(h); if (durable) durableCol().deleteOne({ _id: h, state: 'running' }).catch(() => {}); } });
  next();
});

// ─── AUDIT TRAIL ─────────────────────────────────────────────────────────────
const AUDITED_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function deriveAction(req, statusCode) {
  if (req.path === '/api/login') return statusCode < 400 ? 'LOGIN' : 'LOGIN_FAILED';
  if (/\/password$/.test(req.path)) return 'PASSWORD_RESET';
  if (/\/suspend$/.test(req.path)) return 'HOSPITAL_SUSPENDED';
  if (/\/resume$/.test(req.path)) return 'HOSPITAL_RESUMED';
  if (req.method === 'POST') return 'CREATE';
  if (req.method === 'DELETE') return 'DELETE';
  if ((req.method === 'PUT' || req.method === 'PATCH')) {
    const s = req.body && req.body.status;
    if (s === 'inactive') return 'ACCOUNT_DISABLED';
    if (s === 'active') return 'ACCOUNT_ENABLED';
    return 'UPDATE';
  }
  return req.method;
}

app.use((req, res, next) => {
  if (!AUDITED_METHODS.has(req.method) || !req.path.startsWith('/api/')) return next();

  // Never write secrets or bulky blobs into the audit trail.
  const safeBody = req.body && typeof req.body === 'object' ? { ...req.body } : {};
  for (const k of Object.keys(safeBody)) {
    if (/pass(word|phrase)?|token|secret/i.test(k)) safeBody[k] = '***';
    else if (k === 'logo') safeBody[k] = '[image]';
    else if (typeof safeBody[k] === 'string' && safeBody[k].length > 500) safeBody[k] = safeBody[k].slice(0, 500) + '…';
  }

  const originalJson = res.json.bind(res);
  res.json = (data) => { res.locals.responseBody = data; return originalJson(data); };

  res.on('finish', () => {
    const seg = req.path.split('/').filter(Boolean);
    const isAuth = req.path === '/api/login';
    const entity = isAuth ? 'auth' : (seg[1] || 'unknown');
    const entityId = seg[2] || res.locals.responseBody?.id || undefined;
    writeAudit({
      hospitalId: req.user?.hospitalId || res.locals.auditHospitalId,
      actorId: req.user?.id,
      actorName: req.user?.name || safeBody.username || 'anonymous',
      actorRole: req.user?.role || 'guest',
      action: deriveAction(req, res.statusCode),
      entity,
      entityId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      description: `${req.method} ${req.path} → ${res.statusCode}`,
      ip: req.ip,
      meta: safeBody,
    });
  });

  next();
});

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────

async function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, SECRET); }
  catch { return res.status(401).json({ error: 'Your session has expired. Please sign in again.', code: 'SESSION_EXPIRED' }); }

  // The account must still exist and be active, and its CURRENT role (not the
  // one baked into the token) is what counts — so disabling a user or changing
  // their role takes effect immediately.
  try {
    const live = await User.findOne({ id: req.user.id }, { role: 1, status: 1, hospitalId: 1, name: 1 });
    if (!live || live.status === 'inactive' || (live.hospitalId || undefined) !== (req.user.hospitalId || undefined))
      return res.status(401).json({ error: 'Your session has expired. Please sign in again.', code: 'SESSION_EXPIRED' });
    req.user.role = live.role; req.user.name = live.name;
  } catch (err) { return serverError(res, err); }

  // A hospital that gets suspended (e.g. for non-payment) is locked out of
  // every route immediately — including staff who are already logged in with
  // a token that hasn't expired yet. They don't have to wait out the token.
  if (req.user.hospitalId) {
    try {
      const hospital = await Hospital.findOne({ id: req.user.hospitalId });
      if (!hospital || hospital.status !== 'active') {
        return res.status(403).json({ error: 'This hospital\'s access has been suspended. Please contact your platform administrator.', code: 'SUSPENDED' });
      }
    } catch (err) { return serverError(res, err); }
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    // The super admin can reach every endpoint.
    if (req.user.role === SUPERADMIN) return next();
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: 'You do not have permission to do this.', code: 'FORBIDDEN' });
    next();
  };
}

// Only a super admin may touch another super admin's account.
async function protectSuperAdmin(req, res, next) {
  try {
    const target = await User.findOne({ id: req.params.id, ...scope(req) });
    if (target && target.role === SUPERADMIN && req.user.role !== SUPERADMIN)
      return res.status(403).json({ error: 'Only a super admin can modify a super admin account' });
    next();
  } catch (err) { serverError(res, err); }
}

// Guard the `role` field on user create / update so an ordinary admin cannot
// mint (or promote themselves to) a super admin, and cannot set a bogus role.
const ASSIGNABLE_ROLES = new Set([ADMIN, DOCTOR, RECEPTIONIST, PHARMACIST, LAB_STAFF]);
async function sanitizeUserRole(req, res, next) {
  const { role } = req.body;
  if (role === undefined || role === null || role === '') return next();
  if (role === SUPERADMIN) {
    if (req.user.role !== SUPERADMIN)
      return res.status(403).json({ error: 'Only a super admin can assign the super admin role' });
    return next();
  }
  if (!ASSIGNABLE_ROLES.has(role))
    return res.status(400).json({ error: 'Please choose a valid role.', code: 'INVALID_ROLE' });
  // Administrator rights are powerful: only the platform owner hands them out.
  if (role === ADMIN && req.user.role !== SUPERADMIN) {
    // Editing an account that is ALREADY an administrator (name, status…) is fine; creating or promoting is not.
    let alreadyAdmin = false;
    if (req.method !== 'POST' && req.params.id) {
      try { const t = await User.findOne({ id: req.params.id, ...scope(req) }, { role: 1 }); alreadyAdmin = !!t && t.role === ADMIN; }
      catch (e) { return serverError(res, e); }
    }
    if (!alreadyAdmin)
      return res.status(403).json({ error: 'Only the platform owner can create or promote an administrator.', code: 'FORBIDDEN' });
  }
  next();
}

// ─── LOGIN ───────────────────────────────────────────────────────────────────
// Every hospital shares this one login page. A hospital user supplies
// hospitalSlug + username + password; the super admin (platform owner) logs
// in with no hospitalSlug at all. Same error either way credentials fail, so
// a bad guess never reveals whether a given hospital slug exists.

// One message for every credential failure, so the response never reveals whether
// the hospital code, the username or the password was the wrong part.
const BAD_LOGIN = 'Incorrect hospital code, username or password. Please check and try again.';
app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const { hospitalSlug, username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password)
      return res.status(400).json({ error: 'Enter your username and password.', code: 'MISSING_FIELDS' });
    let hospital = null;
    let userQuery;

    if (hospitalSlug) {
      hospital = await Hospital.findOne({ slug: String(hospitalSlug).toLowerCase().trim() });
      if (!hospital || hospital.status !== 'active')
        return res.status(401).json({ error: BAD_LOGIN, code: 'INVALID_CREDENTIALS' });
      res.locals.auditHospitalId = hospital.id; // so login attempts show under that hospital in the audit trail
      userQuery = { username: String(username).trim(), hospitalId: hospital.id, status: { $ne: 'inactive' } };
    } else {
      // No hospital selected — only the platform super admin can log in this way.
      userQuery = { username: String(username).trim(), hospitalId: { $exists: false }, role: SUPERADMIN, status: { $ne: 'inactive' } };
    }

    const user = await User.findOne(userQuery);
    if (!user || !user.password || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: BAD_LOGIN, code: 'INVALID_CREDENTIALS' });
    for (const k of req.loginKeys || []) loginHits.delete(k);
    const token = jwt.sign({ id: user.id, hospitalId: user.hospitalId, role: user.role, name: user.name }, SECRET, { expiresIn: '8h' });
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, username: user.username },
      hospital: hospital ? hospitalPublic(hospital) : null,
    });
  } catch (err) { serverError(res, err); }
});

// PUBLIC (no login): just the look of one hospital — name, logo and colour — so
// its login page can show them before anyone has signed in. Nothing else about the
// hospital is exposed. Light per-IP limit so it can't be hammered.
const brandingHits = new Map();
app.get('/api/public/branding', async (req, res) => {
  try {
    const ip = req.ip || 'unknown', now = Date.now();
    const recent = (brandingHits.get(ip) || []).filter(t => now - t < 60000);
    if (recent.length >= 60) return res.status(429).json({ error: 'Too many requests' });
    recent.push(now); brandingHits.set(ip, recent);
    if (brandingHits.size > 5000) brandingHits.clear();

    const slug = String(req.query.hospital || '').toLowerCase().trim();
    if (!slug) return res.status(400).json({ error: 'hospital is required' });
    const h = await Hospital.findOne({ slug });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json({ name: h.name, logo: h.logo || '', primaryColor: h.theme?.primaryColor || '' });
  } catch (err) { serverError(res, err); }
});

// PUBLIC (no login): the platform's name, colour and logo, so the login page can
// show them before anyone signs in. Nothing else is exposed.
app.get('/api/public/platform', async (req, res) => {
  try {
    const p = await PlatformSettings.findOne({ key: 'platform' });
    res.set('Cache-Control', 'no-cache');
    res.json({ name: p?.name || '', color: p?.color || '', logo: p?.logo || '' });
  } catch (err) { serverError(res, err); }
});

// Platform owner only: change the system name, login/platform colour and logo.
app.put('/api/platform', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const { name, color, logo } = req.body;
    const set = { updatedAt: new Date().toISOString() };
    if (name !== undefined) {
      const n = String(name).trim();
      if (n.length > 60) return res.status(400).json({ error: 'Name is too long (max 60 characters)' });
      set.name = n;
    }
    if (color !== undefined) {
      if (color !== '' && !/^#[0-9a-fA-F]{6}$/.test(color)) return res.status(400).json({ error: 'Colour must look like #1565C0' });
      set.color = color.toUpperCase();
    }
    if (logo !== undefined) {
      if (logo !== '' && !/^data:image\/(png|jpeg|webp|gif);base64,/.test(logo)) return res.status(400).json({ error: 'Logo must be an image' });
      if (logo.length > 200000) return res.status(400).json({ error: 'Logo is too large' });
      set.logo = logo;
    }
    const p = await PlatformSettings.findOneAndUpdate({ key: 'platform' }, { $set: set, $setOnInsert: { key: 'platform' } }, { new: true, upsert: true });
    res.json({ name: p.name || '', color: p.color || '', logo: p.logo || '' });
  } catch (err) { serverError(res, err); }
});

// The signed-in user's own hospital (name, logo, theme, enabled features), so the
// app can refresh what it shows without a new login. The auth middleware has
// already refused suspended hospitals before this runs. Superadmin has none.
app.get('/api/session', auth, async (req, res) => {
  try {
    if (!req.user.hospitalId) return res.json({ hospital: null });
    const h = await Hospital.findOne({ id: req.user.hospitalId });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json({ hospital: hospitalPublic(h) });
  } catch (err) { serverError(res, err); }
});

// A hospital's own admin changes that hospital's preferences.
app.put('/api/hospital/settings', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    const { pharmacyPatientLink, currency, departments, acceptedCurrencies, exchangeRates } = req.body || {};
    const update = {};
    const current = await Hospital.findOne({ id: req.user.hospitalId });
    if (!current) return res.status(404).json({ error: 'Not found' });
    const newBase = currency !== undefined ? currency : (CURRENCIES[current.currency] ? current.currency : 'UGX');
    if (currency !== undefined) {
      if (!CURRENCIES[currency]) return res.status(400).json({ error: 'Choose a supported currency.' });
      update.currency = currency;
      // Rates are relative to the main currency, so changing it clears the extra currencies unless new rates are sent.
      if (currency !== (current.currency || 'UGX') && acceptedCurrencies === undefined) { update['settings.acceptedCurrencies'] = []; update['settings.exchangeRates'] = {}; }
    }
    if (acceptedCurrencies !== undefined) {
      if (!Array.isArray(acceptedCurrencies)) return res.status(400).json({ error: 'Accepted currencies must be a list.' });
      const list = [...new Set(acceptedCurrencies.filter(c => c !== newBase))];
      const rates = {};
      for (const c of list) {
        const r = Number(exchangeRates && exchangeRates[c]);
        if (!CURRENCIES[c]) return res.status(400).json({ error: 'Choose supported currencies only.' });
        if (!(r > 0) || r > 1e9) return res.status(400).json({ error: `Enter the exchange rate for ${c} (how many ${c} equal 1 ${newBase}).` });
        rates[c] = r;
      }
      update['settings.acceptedCurrencies'] = list;
      update['settings.exchangeRates'] = rates;
    }
    if (departments !== undefined) {
      if (!Array.isArray(departments) || departments.length > 60) return res.status(400).json({ error: 'Departments must be a list.' });
      const clean = [...new Set(departments.map((d) => String(d || '').trim()).filter(Boolean))];
      if (clean.some((d) => d.length > 60)) return res.status(400).json({ error: 'A department name is too long.' });
      update['settings.departments'] = clean;
    }
    if (pharmacyPatientLink !== undefined) {
      if (!PHARMACY_LINK_MODES.includes(pharmacyPatientLink)) return res.status(400).json({ error: 'Invalid option' });
      update['settings.pharmacyPatientLink'] = pharmacyPatientLink;
    }
    const h = await Hospital.findOneAndUpdate({ id: req.user.hospitalId }, update, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json({ settings: hospitalSettings(h), currency: CURRENCIES[h.currency] ? h.currency : 'UGX' });
  } catch (err) { serverError(res, err); }
});

// ─── HOSPITALS (super admin only) ────────────────────────────────────────────
// Onboarding a new hospital is now configuration, not a new deployment.

app.get('/api/hospitals', auth, requireRole(SUPERADMIN), async (req, res) => {
  try { res.json(await Hospital.find()); }
  catch (err) { serverError(res, err); }
});

app.post('/api/hospitals', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const slug = String(req.body.slug || '').toLowerCase().trim();
    if (!slug) return res.status(400).json({ error: 'A hospital slug is required' });
    const exists = await Hospital.findOne({ slug });
    if (exists) return res.status(400).json({ error: 'That hospital slug is already taken' });
    if (req.body.currency !== undefined && !CURRENCIES[req.body.currency]) return res.status(400).json({ error: 'Choose a supported currency.' });
    if (req.body.country !== undefined && !COUNTRIES.includes(req.body.country)) return res.status(400).json({ error: 'Choose a supported country.' });
    const h = new Hospital({ ...req.body, id: uuidv4(), slug, status: req.body.status || 'active' });
    await h.save(); res.json(h);
  } catch (err) { serverError(res, err); }
});

app.put('/api/hospitals/:id', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const update = { ...req.body };
    delete update.id; delete update._id;
    if (update.slug) update.slug = String(update.slug).toLowerCase().trim();
    if (update.currency !== undefined && !CURRENCIES[update.currency]) return res.status(400).json({ error: 'Choose a supported currency.' });
    if (update.country !== undefined && !COUNTRIES.includes(update.country)) return res.status(400).json({ error: 'Choose a supported country.' });
    // Changing one feature switch (or one theme colour) must not reset the
    // others. Sent as a nested object, Mongo would replace the whole block, so
    // flatten it to "features.laboratory": true style updates instead.
    for (const group of ['features', 'theme', 'settings']) {
      if (update[group] && typeof update[group] === 'object') {
        for (const [key, value] of Object.entries(update[group])) update[`${group}.${key}`] = value;
        delete update[group];
      }
    }
    const h = await Hospital.findOneAndUpdate({ id: req.params.id }, update, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json(h);
  } catch (err) { serverError(res, err); }
});

// Suspend a hospital (e.g. non-payment) — every one of its staff is locked
// out immediately, even if already logged in, because `auth` rechecks
// hospital status on every request.
app.post('/api/hospitals/:id/suspend', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const h = await Hospital.findOneAndUpdate({ id: req.params.id }, { status: 'suspended' }, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json(h);
  } catch (err) { serverError(res, err); }
});

// Resume a previously suspended hospital (e.g. payment received) — staff can
// log in and use the system again right away.
app.post('/api/hospitals/:id/resume', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const h = await Hospital.findOneAndUpdate({ id: req.params.id }, { status: 'active' }, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json(h);
  } catch (err) { serverError(res, err); }
});

// Permanently delete a TEST hospital and everything in it. Guarded three ways:
// the hospital must be marked as a test hospital, it must already be suspended,
// and the caller must type its code. A copy of its data is saved first (in the
// "hospital_archive" collection, which the nightly backup also covers); if that
// copy fails, nothing is deleted. Real hospitals can never be deleted here.
app.delete('/api/hospitals/:id', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const h = await Hospital.findOne({ id: req.params.id });
    if (!h) return res.status(404).json({ error: 'Not found' });
    if (!h.isTest) return res.status(403).json({ error: 'Only hospitals marked as test hospitals can be deleted. Suspend a real hospital instead.', code: 'NOT_TEST' });
    if (h.status !== 'suspended') return res.status(400).json({ error: 'Suspend the hospital first, then delete it.', code: 'NOT_SUSPENDED' });
    if (String((req.body || {}).confirm || '').toLowerCase().trim() !== h.slug)
      return res.status(400).json({ error: 'Type the hospital code exactly to confirm.', code: 'CONFIRM_MISMATCH' });

    const models = { users: User, patients: Patient, doctors: Doctor, staff: Staff, appointments: Appointment, medicalrecords: MedicalRecord,
      treatmentplans: TreatmentPlan, referrals: Referral, laborders: LabOrder, wards: Ward, admissions: Admission,
      inventories: Inventory, bills: Bill, transactions: Transaction, pharmacysales: PharmacySale };
    const archive = mongoose.connection.collection('hospital_archive');
    const deletedAt = new Date().toISOString();
    const counts = {};
    // 1) save a copy of everything (password hashes are left out) — abort if this fails
    for (const [name, M] of Object.entries(models)) {
      const docs = await M.find({ hospitalId: h.id }).lean();
      counts[name] = docs.length;
      if (!docs.length) continue;
      if (name === 'users') docs.forEach(d => { delete d.password; });
      await archive.insertOne({ hospitalId: h.id, slug: h.slug, name: h.name, collection: name, deletedAt, deletedBy: req.user.id, docs });
    }
    await archive.insertOne({ hospitalId: h.id, slug: h.slug, name: h.name, collection: 'hospital', deletedAt, deletedBy: req.user.id, docs: [h.toObject()] });
    // 2) delete the data, then the hospital record last (so a retry is possible if something fails midway)
    for (const M of Object.values(models)) await M.deleteMany({ hospitalId: h.id });
    await Counter.deleteMany({ key: { $in: [`patient:${h.id}`, `bill:${h.id}`, `tx:${h.id}`] } });
    await Hospital.deleteOne({ id: h.id });
    res.json({ ok: true, removed: counts });
  } catch (err) { serverError(res, err); }
});

// Convenience: create a hospital together with its first admin user in one
// call, so onboarding a new customer is a single action.
app.post('/api/hospitals/:id/admin', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const hospital = await Hospital.findOne({ id: req.params.id });
    if (!hospital) return res.status(404).json({ error: 'Hospital not found' });
    if (!/^[A-Za-z0-9._-]{3,40}$/.test(String(req.body.username || ''))) return res.status(400).json({ error: 'Username must be 3–40 letters, numbers, dots, dashes or underscores.', code: 'VALIDATION' });
    if (!req.body.password || String(req.body.password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.', code: 'VALIDATION' });
    const exists = await User.findOne({ username: req.body.username, hospitalId: hospital.id });
    if (exists) return res.status(400).json({ error: 'Username already exists for this hospital' });
    const user = new User({
      id: uuidv4(),
      hospitalId: hospital.id,
      name: req.body.name || 'Administrator',
      username: req.body.username,
      password: await bcrypt.hash(req.body.password, 10),
      role: ADMIN,
      status: 'active',
    });
    await user.save();
    const result = user.toObject(); delete result.password;
    res.json(result);
  } catch (err) { serverError(res, err); }
});

// The superadmin's dashboard: one row per hospital, so the platform owner can
// compare every hospital at a glance — activity, revenue, staffing, low
// stock — without switching context into each one individually.
app.get('/api/hospitals/overview', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const hospitals = await Hospital.find();
    const overview = await Promise.all(hospitals.map(async (h) => {
      const hScope = { hospitalId: h.id };
      const [patients, doctors, staff, users, appointmentsToday, bills, transactions, pharmacySales, inventory] = await Promise.all([
        Patient.countDocuments(hScope),
        Doctor.countDocuments(hScope),
        Staff.countDocuments(hScope),
        User.countDocuments(hScope),
        Appointment.countDocuments({ ...hScope, date: today }),
        Bill.find(hScope),
        Transaction.find(hScope),
        PharmacySale.find(hScope),
        Inventory.find(hScope),
      ]);
      return {
        id: h.id,
        name: h.name,
        slug: h.slug,
        status: h.status,
        isTest: !!h.isTest,
        logo: h.logo,
        theme: h.theme,
        features: h.features,
        createdAt: h.createdAt,
        totalPatients: patients,
        totalDoctors: doctors,
        totalStaff: staff,
        totalUsers: users,
        todayAppointments: appointmentsToday,
        pendingBills: bills.filter(b => b.status === 'pending').length,
        currency: CURRENCIES[h.currency] ? h.currency : 'UGX',
        totalRevenue: transactions.reduce((s, t) => s + (Number(t.amount) || 0), 0),
        pharmacySalesCount: pharmacySales.length,
        pharmacyRevenue: pharmacySales.reduce((s, sale) => s + (Number(sale.totalAmount) || 0), 0),
        lowStockItems: inventory.filter(i => Number(i.quantity) < 10).length,
      };
    }));
    res.json(overview);
  } catch (err) { serverError(res, err); }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const users = await User.find(scope(req), { password: 0 });
    res.json(users);
  } catch (err) { serverError(res, err); }
});

app.post('/api/users', auth, requireRole(ADMIN), requireHospitalContext, sanitizeUserRole, async (req, res) => {
  try {
    const { name, username, password, role } = req.body || {};
    if (!String(name || '').trim()) return res.status(400).json({ error: 'Enter the person\'s full name.', code: 'VALIDATION' });
    if (!/^[A-Za-z0-9._-]{3,40}$/.test(String(username || ''))) return res.status(400).json({ error: 'Username must be 3–40 letters, numbers, dots, dashes or underscores (no spaces).', code: 'VALIDATION' });
    if (!password || String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.', code: 'VALIDATION' });
    if (!role) return res.status(400).json({ error: 'Please choose a role.', code: 'INVALID_ROLE' });
    const exists = await User.findOne({ username, hospitalId: req.user.hospitalId });
    if (exists) return res.status(409).json({ error: 'That username is already taken in this hospital.', code: 'DUPLICATE' });
    const user = new User({
      name: String(name).trim(), username, role,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      password: await bcrypt.hash(req.body.password, 10),
      status: 'active',
    });
    await user.save();
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) { serverError(res, err); }
});

app.put('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, sanitizeUserRole, async (req, res) => {
  try {
    const update = { ...req.body };
    delete update.id; delete update._id; delete update.hospitalId; // never let a client move a user between hospitals
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);
    else delete update.password;
    const found = await User.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!found) return res.status(404).json({ error: 'Not found' });
    const user = found.toObject(); delete user.password;
    res.json(user);
  } catch (err) { serverError(res, err); }
});

app.put('/api/users/:id/password', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    const target = await User.findOne({ id: req.params.id, ...scope(req) });
    if (!target) return res.status(404).json({ error: 'Not found' });
    const generated = !req.body.password;
    const newPassword = req.body.password
      || `Hms-${Math.random().toString(36).slice(-8)}${Math.floor(Math.random() * 90 + 10)}`;
    target.password = await bcrypt.hash(newPassword, 10);
    await target.save();
    res.json({ success: true, generated, password: generated ? newPassword : undefined });
  } catch (err) { serverError(res, err); }
});

app.delete('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await User.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── AUDIT LOGS (super admin only) ───────────────────────────────────────────

// hospitalId query value: a hospital id, "platform" (platform-level entries with
// no hospital), or empty/"all" (everything).
function auditHospitalFilter(v) {
  if (!v || v === 'all') return {};
  if (v === 'platform') return { hospitalId: { $exists: false } };
  return { hospitalId: String(v) };
}

app.get('/api/audit-logs/meta', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const base = auditHospitalFilter(req.query.hospitalId);
    const [actions, entities, actors] = await Promise.all([
      AuditLog.distinct('action', base),
      AuditLog.distinct('entity', base),
      AuditLog.aggregate([
        { $match: base },
        { $group: { _id: '$actorId', name: { $last: '$actorName' }, role: { $last: '$actorRole' } } },
        { $sort: { name: 1 } },
      ]),
    ]);
    res.json({
      actions: actions.filter(Boolean).sort(),
      entities: entities.filter(Boolean).sort(),
      actors: actors.map(a => ({ id: a._id, name: a.name, role: a.role })),
    });
  } catch (err) { serverError(res, err); }
});

function auditRangeFilter(from, to) {
  const r = {};
  if (from) { const d = new Date(from); if (!isNaN(d)) r.$gte = d.toISOString(); }
  if (to) { const d = new Date(to); if (!isNaN(d)) { d.setHours(23, 59, 59, 999); r.$lte = d.toISOString(); } }
  return Object.keys(r).length ? { timestamp: r } : {};
}

app.get('/api/audit-logs', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const { action, actor, entity, from, to, hospitalId, q: text } = req.query;
    const q = { ...auditHospitalFilter(hospitalId), ...auditRangeFilter(from, to) };
    if (action && action !== 'all') q.action = action;
    if (entity && entity !== 'all') q.entity = entity;
    if (actor && actor !== 'all') q.actorId = actor;
    if (text && String(text).trim()) {
      const rx = new RegExp(String(text).trim().slice(0, 60).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      q.$or = [{ actorName: rx }, { description: rx }, { entity: rx }];
    }
    const limit = Math.min(parseInt(req.query.limit, 10) || 1000, 5000);
    const [logs, total] = await Promise.all([
      AuditLog.find(q).sort({ timestamp: -1 }).limit(limit),
      AuditLog.countDocuments(q),
    ]);
    res.setHeader('X-Total-Count', String(total));
    res.json(logs);
  } catch (err) { serverError(res, err); }
});

// Clear audit history (super admin only). Deletes ONLY audit entries, never
// patient or hospital data. Narrow by hospital and/or "older than a date";
// with no narrowing it clears everything. Requires confirm:"DELETE".
// The clearing itself is recorded afterwards, so there is always a trace.
app.delete('/api/audit-logs', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const { hospitalId, before, confirm } = req.body || {};
    if (confirm !== 'DELETE') return res.status(400).json({ error: 'Type DELETE to confirm' });
    const q = { ...auditHospitalFilter(hospitalId) };
    if (before) {
      const d = new Date(before);
      if (isNaN(d)) return res.status(400).json({ error: 'Invalid date' });
      d.setHours(23, 59, 59, 999);
      q.timestamp = { $lte: d.toISOString() };
    }
    const r = await AuditLog.deleteMany(q);
    res.json({ deleted: r.deletedCount });
  } catch (err) { serverError(res, err); }
});

// ─── PATIENTS ────────────────────────────────────────────────────────────────

// A plain q= search across name, phone, and email — receptionists in a busy
// clinic rarely know a patient's exact spelling, so this matches anywhere in
// any of those three fields, not just from the start.
app.get('/api/patients', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const filter = scope(req);
    const q = req.query.q && String(req.query.q).trim();
    if (q) {
      const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // escape regex special characters
      const regex = new RegExp(safe, 'i');
      filter.$or = [{ name: regex }, { phone: regex }, { email: regex }, { patientNumber: regex }];
    }
    // limit: used by the type-ahead pickers so they never download every patient.
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 0, 0), 200);
    let cursor = Patient.find(filter);
    if (limit) cursor = cursor.sort({ name: 1 }).limit(limit);
    res.json(await cursor);
  } catch (err) { serverError(res, err); }
});

app.post('/api/patients', auth, requireRole(ADMIN, RECEPTIONIST), requireHospitalContext, async (req, res) => {
  try {
    const body = { ...req.body }; delete body.patientNumber; delete body._id;
    if (!String(body.name || '').trim()) return res.status(400).json({ error: 'Enter the patient\'s name.', code: 'VALIDATION' });
    body.name = String(body.name).trim();
    const p = new Patient({ ...body, id: uuidv4(), hospitalId: req.user.hospitalId, patientNumber: await nextPatientNumber(req.user.hospitalId) });
    await p.save(); res.json(p);
  } catch (err) { serverError(res, err); }
});

app.put('/api/patients/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId; delete update.patientNumber; delete update.id; delete update._id;
    const p = await Patient.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/patients/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Patient.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// One patient's full history in a single call — every past appointment,
// medical record, bill, payment, and pharmacy sale, plus a running money
// summary — so staff aren't hunting across four separate screens to answer
// "what happened last time this patient came in, and what do they owe?"
// Deliberately not filtered to one doctor's own patients (unlike the plain
// appointments/records lists) — any doctor at the hospital needs the full
// picture for continuity of care once they've opened a specific patient.
app.get('/api/patients/:id/history', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), async (req, res) => {
  try {
    const patient = await Patient.findOne({ id: req.params.id, ...scope(req) });
    if (!patient) return res.status(404).json({ error: 'Not found' });

    const pScope = { patientId: patient.id, ...scope(req) };
    const [appointments, records, treatmentPlans, referrals, labOrders, bills, transactions, pharmacySales, admissions] = await Promise.all([
      Appointment.find(pScope).sort({ date: -1, time: -1 }),
      MedicalRecord.find(pScope).sort({ createdAt: -1 }),
      TreatmentPlan.find(pScope).sort({ createdAt: -1 }),
      Referral.find(pScope).sort({ createdAt: -1 }),
      LabOrder.find(pScope).sort({ createdAt: -1 }),
      Bill.find(pScope).sort({ createdAt: -1 }),
      Transaction.find(pScope).sort({ createdAt: -1 }),
      PharmacySale.find(pScope).sort({ createdAt: -1 }),
      Admission.find(pScope).sort({ admittedAt: -1 }),
    ]);

    const totalBilled = bills.reduce((s, b) => s + (Number(b.totalAmount) || 0), 0);
    const totalPaid = transactions.reduce((s, t) => s + (Number(t.amount) || 0), 0);
    const outstanding = bills.reduce((s, b) => s + (Number(b.remainingAmount) || 0), 0);
    const pharmacyTotal = pharmacySales.reduce((s, sale) => s + (Number(sale.totalAmount) || 0), 0);

    res.json({
      patient,
      appointments,
      records,
      treatmentPlans,
      referrals,
      // Lab results are clinical detail the front desk doesn't need.
      labOrders: req.user.role === RECEPTIONIST ? [] : labOrders,
      bills,
      transactions,
      pharmacySales,
      admissions,
      summary: {
        totalVisits: appointments.length,
        activeTreatmentPlans: treatmentPlans.filter(p => p.status === 'active').length,
        totalBilled,
        totalPaid,
        outstanding,
        pharmacyTotal,
      },
    });
  } catch (err) { serverError(res, err); }
});

// Older rows were saved without the patient's/doctor's name: fill them in on the way out.
async function withNames(rows, req) {
  const list = rows.map(r => (r.toObject ? r.toObject() : r));
  const need = (k, nk) => [...new Set(list.filter(r => r[k] && !r[nk]).map(r => r[k]))];
  const pIds = need('patientId', 'patientName'), dIds = need('doctorId', 'doctorName');
  const [ps, ds] = await Promise.all([
    pIds.length ? Patient.find({ id: { $in: pIds }, ...scope(req) }, { id: 1, name: 1 }) : [],
    dIds.length ? Doctor.find({ id: { $in: dIds }, ...scope(req) }, { id: 1, name: 1 }) : [],
  ]);
  const pm = Object.fromEntries(ps.map(p => [p.id, p.name])), dm = Object.fromEntries(ds.map(d => [d.id, d.name]));
  return list.map(r => ({ ...r, patientName: r.patientName || pm[r.patientId], doctorName: r.doctorName || dm[r.doctorId] }));
}

// ─── DROPDOWN OPTIONS ────────────────────────────────────────────────────────
// One call gives the browser every list it needs for dropdowns. Departments come
// from the signed-in hospital's own settings; the rest are platform-wide lists.
app.get('/api/meta/options', auth, async (req, res) => {
  try {
    let departments = DEFAULT_DEPARTMENTS;
    if (req.user.hospitalId) {
      const h = await Hospital.findOne({ id: req.user.hospitalId });
      if (h) departments = hospitalSettings(h).departments;
    }
    res.json({
      departments,
      qualifications: QUALIFICATIONS,
      staffRoles: STAFF_ROLES,
      currencies: Object.entries(CURRENCIES).map(([code, c]) => ({ code, ...c })),
      countries: COUNTRIES,
      // Roles the signed-in user may hand out to others.
      assignableRoles: req.user.role === SUPERADMIN ? [...ASSIGNABLE_ROLES] : [...ASSIGNABLE_ROLES].filter(r => r !== ADMIN),
    });
  } catch (err) { serverError(res, err); }
});

// Department and qualification must be a real choice (departments: from THIS hospital).
async function checkChoices(req, { department, qualification, staffRole }, existing) {
  // On edit, a value the record already had (maybe typed freely before this list existed) is left alone.
  if (existing) {
    if (department === existing.department) department = undefined;
    if (qualification === existing.qualification) qualification = undefined;
    if (staffRole === existing.role) staffRole = undefined;
  }
  if (department) {
    const h = await Hospital.findOne({ id: req.user.hospitalId });
    if (!hospitalSettings(h).departments.includes(department)) return 'Please choose a department from the list.';
  }
  if (qualification && !QUALIFICATIONS.includes(qualification)) return 'Please choose a qualification from the list.';
  if (staffRole && !STAFF_ROLES.includes(staffRole)) return 'Please choose a valid staff role.';
  return null;
}

// ─── DOCTORS ─────────────────────────────────────────────────────────────────

app.get('/api/doctors', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try { res.json(await Doctor.find(scope(req))); }
  catch (err) { serverError(res, err); }
});

app.post('/api/doctors', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    if (!String(req.body.name || '').trim()) return res.status(400).json({ error: 'Enter the doctor\'s name.', code: 'VALIDATION' });
    const bad = await checkChoices(req, req.body); if (bad) return res.status(400).json({ error: bad, code: 'VALIDATION' });
    if (req.body.linkedUserId) {
      const u = await User.findOne({ id: req.body.linkedUserId, hospitalId: req.user.hospitalId, role: DOCTOR });
      if (!u) return res.status(400).json({ error: 'The linked login account must be a doctor account of this hospital.', code: 'VALIDATION' });
    }
    const body = { ...req.body }; delete body._id;
    if (body.consultationFee !== undefined) { const fee = cleanFee(body.consultationFee); if (fee === null) return res.status(400).json({ error: 'The consultation fee must be a number, zero or more.', code: 'VALIDATION' }); body.consultationFee = fee; }
    const d = new Doctor({ ...body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await d.save(); res.json(d);
  } catch (err) { serverError(res, err); }
});

app.put('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId; delete update.id; delete update._id;
    const before = await Doctor.findOne({ id: req.params.id, ...scope(req) });
    if (!before) return res.status(404).json({ error: 'Not found' });
    if (update.consultationFee !== undefined) { const fee = cleanFee(update.consultationFee); if (fee === null) return res.status(400).json({ error: 'The consultation fee must be a number, zero or more.', code: 'VALIDATION' }); update.consultationFee = fee; }
    const bad = await checkChoices(req, update, before); if (bad) return res.status(400).json({ error: bad, code: 'VALIDATION' });
    if (update.linkedUserId && update.linkedUserId !== before.linkedUserId) {
      const u = await User.findOne({ id: update.linkedUserId, ...scope(req), role: DOCTOR });
      if (!u) return res.status(400).json({ error: 'The linked login account must be a doctor account of this hospital.', code: 'VALIDATION' });
    }
    const d = await Doctor.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!d) return res.status(404).json({ error: 'Not found' });
    res.json(d);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Doctor.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── STAFF ───────────────────────────────────────────────────────────────────

app.get('/api/staff', auth, requireRole(ADMIN), async (req, res) => {
  try { res.json(await Staff.find(scope(req))); }
  catch (err) { serverError(res, err); }
});

app.post('/api/staff', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    if (!String(req.body.name || '').trim()) return res.status(400).json({ error: 'Enter the staff member\'s name.', code: 'VALIDATION' });
    if (!req.body.role) return res.status(400).json({ error: 'Please choose a role.', code: 'INVALID_ROLE' });
    const bad = await checkChoices(req, { department: req.body.department, staffRole: req.body.role }); if (bad) return res.status(400).json({ error: bad, code: 'VALIDATION' });
    const body = { ...req.body }; delete body._id;
    if (body.salary !== undefined && body.salary !== '' && !(Number(body.salary) >= 0)) return res.status(400).json({ error: 'Salary must be a positive number.', code: 'VALIDATION' });
    const s = new Staff({ ...body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await s.save(); res.json(s);
  } catch (err) { serverError(res, err); }
});

app.put('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId; delete update.id; delete update._id;
    const before = await Staff.findOne({ id: req.params.id, ...scope(req) });
    if (!before) return res.status(404).json({ error: 'Not found' });
    const bad = await checkChoices(req, { department: update.department, staffRole: update.role }, before); if (bad) return res.status(400).json({ error: bad, code: 'VALIDATION' });
    const s = await Staff.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Staff.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── APPOINTMENTS ─────────────────────────────────────────────────────────────

app.get('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const filter = scope(req);
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      filter.doctorId = doc ? doc.id : '__no_linked_doctor__';
    }
    res.json(await withNames(await Appointment.find(filter), req));
  } catch (err) { serverError(res, err); }
});

app.post('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST), requireHospitalContext, async (req, res) => {
  try {
    const { patientId, doctorId, date, time } = req.body || {};
    if (!patientId) return res.status(400).json({ error: 'Please choose a patient from the list.', code: 'VALIDATION' });
    if (!date) return res.status(400).json({ error: 'Choose the appointment date.', code: 'VALIDATION' });
    // The patient (and doctor) must really belong to THIS hospital; names are copied from the database, not trusted from the browser.
    const patient = await Patient.findOne({ id: patientId, hospitalId: req.user.hospitalId });
    if (!patient) return res.status(400).json({ error: 'That patient was not found in this hospital.', code: 'VALIDATION' });
    let doctor = null;
    if (doctorId) {
      doctor = await Doctor.findOne({ id: doctorId, hospitalId: req.user.hospitalId });
      if (!doctor) return res.status(400).json({ error: 'That doctor was not found in this hospital.', code: 'VALIDATION' });
    }
    const dup = await Appointment.findOne({ hospitalId: req.user.hospitalId, patientId, doctorId: doctorId || null, date, time: time || null, status: { $ne: 'cancelled' } });
    if (dup) return res.status(409).json({ error: 'This patient already has an appointment at that date and time.', code: 'DUPLICATE' });
    const body = { ...req.body }; delete body._id;
    const a = new Appointment({ ...body, doctorId: doctor ? doctor.id : undefined, id: uuidv4(), hospitalId: req.user.hospitalId, patientName: patient.name, doctorName: doctor ? doctor.name : undefined, status: 'scheduled' });
    await a.save(); res.json(a);
  } catch (err) { serverError(res, err); }
});

app.put('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId; delete update.id; delete update._id;
    if (update.patientId) {
      const pt = await Patient.findOne({ id: update.patientId, ...scope(req) });
      if (!pt) return res.status(400).json({ error: 'That patient was not found in this hospital.', code: 'VALIDATION' });
      update.patientName = pt.name;
    }
    if (update.doctorId) {
      const dc = await Doctor.findOne({ id: update.doctorId, ...scope(req) });
      if (!dc) return res.status(400).json({ error: 'That doctor was not found in this hospital.', code: 'VALIDATION' });
      update.doctorName = dc.name;
    }
    // A bill is raised by the server only; it can never be set or cleared from the request.
    delete update.billId;
    const a = await Appointment.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!a) return res.status(404).json({ error: 'Not found' });

    // Completing an appointment bills the doctor's consultation fee, once.
    try {
      if (a.status === 'completed' && !a.billId && a.doctorId && a.patientId) {
        const doc = await Doctor.findOne({ id: a.doctorId, hospitalId: a.hospitalId });
        const fee = Number(doc?.consultationFee) || 0;
        const hospital = fee > 0 ? await Hospital.findOne({ id: a.hospitalId }) : null;
        if (fee > 0 && hospital?.features?.billing) {
          const bill = await insertOnceBill(`consult:${a.id}`, {
            id: uuidv4(),
            hospitalId: a.hospitalId,
            billNumber: `BILL-${String(await nextSeq(`bill:${a.hospitalId}`)).padStart(6, '0')}`,
            appointmentId: a.id,
            patientId: a.patientId,
            patientName: a.patientName,
            items: [{ description: `Consultation — ${doc.name}`, quantity: 1, unitPrice: fee, amount: fee }],
            totalAmount: fee, paidAmount: 0, remainingAmount: fee, status: 'pending',
            notes: `Appointment ${a.date || ''} ${a.time || ''}`.trim(),
          });
          await Appointment.updateOne({ id: a.id, hospitalId: a.hospitalId }, { $set: { billId: bill.id } });
          a.billId = bill.id;
        }
      }
    } catch (billErr) {
      // E11000: a parallel request already billed this appointment — nothing more to do.
      if (!(billErr && billErr.code === 11000)) console.error('Could not raise the consultation bill for appointment', a.id, billErr.message);
      else { const fresh = await Appointment.findOne({ id: a.id, hospitalId: a.hospitalId }); if (fresh?.billId) a.billId = fresh.billId; }
    }
    res.json(a);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    await Appointment.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── MEDICAL RECORDS ──────────────────────────────────────────────────────────

app.get('/api/records', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), async (req, res) => {
  try {
    const { patientId } = req.query;
    const filter = scope(req);
    if (patientId) filter.patientId = patientId;
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      filter.doctorId = doc ? doc.id : '__no_linked_doctor__';
    }
    res.json(await withNames(await MedicalRecord.find(filter), req));
  } catch (err) { serverError(res, err); }
});

app.post('/api/records', auth, requireRole(ADMIN, DOCTOR), requireHospitalContext, async (req, res) => {
  try {
    const { patientId } = req.body || {};
    if (!patientId) return res.status(400).json({ error: 'Please choose a patient from the list.', code: 'VALIDATION' });
    const patient = await Patient.findOne({ id: patientId, hospitalId: req.user.hospitalId });
    if (!patient) return res.status(400).json({ error: 'That patient was not found in this hospital.', code: 'VALIDATION' });
    let doctorId = req.body.doctorId;
    if (req.user.role === DOCTOR) { const mine = await Doctor.findOne({ linkedUserId: req.user.id, hospitalId: req.user.hospitalId }); if (mine) doctorId = mine.id; }
    let doctor = null;
    if (doctorId) {
      doctor = await Doctor.findOne({ id: doctorId, hospitalId: req.user.hospitalId });
      if (!doctor) return res.status(400).json({ error: 'That doctor was not found in this hospital.', code: 'VALIDATION' });
    }
    const body = { ...req.body }; delete body._id;
    const r = new MedicalRecord({ ...body, doctorId: doctor ? doctor.id : undefined, patientName: patient.name, doctorName: doctor ? doctor.name : undefined, id: uuidv4(), hospitalId: req.user.hospitalId, createdBy: req.user.id });
    await r.save(); res.json(r);
  } catch (err) { serverError(res, err); }
});

app.put('/api/records/:id', auth, requireRole(ADMIN, DOCTOR), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId; delete update.id; delete update._id; delete update.createdBy; delete update.patientId;
    const r = await MedicalRecord.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json(r);
  } catch (err) { serverError(res, err); }
});

// ─── TREATMENT PLANS ──────────────────────────────────────────────────────────

app.get('/api/treatment-plans', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('treatmentPlans'), async (req, res) => {
  try {
    const { patientId, status } = req.query;
    const filter = scope(req);
    if (patientId) filter.patientId = patientId;
    if (status) filter.status = status;
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      filter.doctorId = doc ? doc.id : '__no_linked_doctor__';
    }
    res.json(await TreatmentPlan.find(filter).sort({ createdAt: -1 }));
  } catch (err) { serverError(res, err); }
});

app.post('/api/treatment-plans', auth, requireRole(ADMIN, DOCTOR), requireFeature('treatmentPlans'), requireHospitalContext, async (req, res) => {
  try {
    const p = new TreatmentPlan({
      ...req.body,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      createdBy: req.user.id,
      status: req.body.status || 'active',
    });
    await p.save(); res.json(p);
  } catch (err) { serverError(res, err); }
});

app.put('/api/treatment-plans/:id', auth, requireRole(ADMIN, DOCTOR), requireFeature('treatmentPlans'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const p = await TreatmentPlan.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { serverError(res, err); }
});

// ─── REFERRALS (within one hospital only) ────────────────────────────────────

app.get('/api/referrals', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('referrals'), async (req, res) => {
  try {
    const { patientId, status } = req.query;
    const filter = scope(req);
    if (patientId) filter.patientId = patientId;
    if (status) filter.status = status;
    // A doctor sees referrals they sent AND ones sent to them — both
    // directions of their own referral traffic, not every referral at the
    // hospital.
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      const docId = doc ? doc.id : '__no_linked_doctor__';
      filter.$or = [{ fromDoctorId: docId }, { toDoctorId: docId }];
    }
    res.json(await Referral.find(filter).sort({ createdAt: -1 }));
  } catch (err) { serverError(res, err); }
});

app.post('/api/referrals', auth, requireRole(ADMIN, DOCTOR), requireFeature('referrals'), requireHospitalContext, async (req, res) => {
  try {
    let fromDoctorId = req.body.fromDoctorId;
    let fromDoctorName = req.body.fromDoctorName;
    if (req.user.role === DOCTOR) {
      // A doctor always refers as themselves — can't be spoofed via the body.
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      if (doc) { fromDoctorId = doc.id; fromDoctorName = doc.name; }
    }
    const r = new Referral({
      ...req.body,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      fromDoctorId,
      fromDoctorName,
      status: 'pending',
    });
    await r.save(); res.json(r);
  } catch (err) { serverError(res, err); }
});

// Accept, decline, or complete a referral, or edit its notes/department.
app.put('/api/referrals/:id', auth, requireRole(ADMIN, DOCTOR), requireFeature('referrals'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    if (update.status && update.status !== 'pending') {
      update.respondedAt = new Date().toISOString();
      update.respondedBy = req.user.name;
    }
    const r = await Referral.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json(r);
  } catch (err) { serverError(res, err); }
});

// ─── LABORATORY (feature-gated: laboratory) ──────────────────────────────────
// Doctors (and admins) order tests; lab staff run them and enter results.

const LAB_STATUSES = new Set(['pending', 'in_progress', 'completed', 'cancelled']);

app.get('/api/lab-orders', auth, requireRole(ADMIN, DOCTOR, LAB_STAFF), requireFeature('laboratory'), async (req, res) => {
  try {
    const { patientId, status } = req.query;
    const filter = scope(req);
    if (patientId) filter.patientId = patientId;
    if (status) filter.status = status;
    // A doctor sees the orders they placed, not every order at the hospital.
    if (req.user.role === DOCTOR) filter.orderedById = req.user.id;
    res.json(await LabOrder.find(filter).sort({ createdAt: -1 }));
  } catch (err) { serverError(res, err); }
});

app.post('/api/lab-orders', auth, requireRole(ADMIN, DOCTOR), requireFeature('laboratory'), requireHospitalContext, async (req, res) => {
  try {
    const { patientId, clinicalNotes, priority } = req.body;
    if (!patientId) return res.status(400).json({ error: 'patientId is required' });

    // The patient must belong to THIS hospital — never trust an id from the body.
    const patient = await Patient.findOne({ id: patientId, ...scope(req) });
    if (!patient) return res.status(404).json({ error: 'Patient not found' });

    // Each test can be a plain name ("Malaria RDT") or { name, price, unit, referenceRange }.
    const tests = (Array.isArray(req.body.tests) ? req.body.tests : [])
      .map(t => (typeof t === 'string' ? { name: t } : (t || {})))
      .map(t => ({
        name: String(t.name || '').trim(),
        price: Number(t.price) || 0,
        unit: t.unit ? String(t.unit) : undefined,
        referenceRange: t.referenceRange ? String(t.referenceRange) : undefined,
      }))
      .filter(t => t.name);
    if (tests.length === 0) return res.status(400).json({ error: 'At least one test is required' });

    let doctorId;
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      if (doc) doctorId = doc.id;
    }

    const order = new LabOrder({
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      orderRef: `LAB-${Date.now()}`,
      patientId: patient.id,
      patientName: patient.name,
      orderedById: req.user.id,
      orderedByName: req.user.name,
      doctorId,
      clinicalNotes,
      priority: priority === 'urgent' ? 'urgent' : 'routine',
      tests,
      totalAmount: tests.reduce((s, t) => s + t.price, 0),
      status: 'pending',
    });
    await order.save();

    // Raise a bill for the priced tests so the money shows up in Billing and can be
    // paid in Transactions. A billing hiccup must never lose the doctor's order.
    try {
      const hospital = await Hospital.findOne({ id: req.user.hospitalId });
      if (hospital?.features?.billing && order.totalAmount > 0) {
        const items = order.tests.filter(t => t.price > 0).map(t => ({ description: `Lab: ${t.name}`, quantity: 1, unitPrice: t.price, amount: t.price }));
        const bill = await insertOnceBill(`lab:${order.id}`, {
          id: uuidv4(),
          hospitalId: req.user.hospitalId,
          billNumber: `BILL-${String(await nextSeq(`bill:${req.user.hospitalId}`)).padStart(6, '0')}`,
          labOrderId: order.id,
          patientId: patient.id,
          patientName: patient.name,
          items,
          totalAmount: order.totalAmount,
          paidAmount: 0,
          remainingAmount: order.totalAmount,
          status: 'pending',
          notes: `Laboratory order ${order.orderRef}`,
        });
        order.billId = bill.id; order.billNumber = bill.billNumber;
        await order.save();
      }
    } catch (billErr) { console.error('Could not raise a bill for lab order', order.orderRef, billErr.message); }
    res.json(order);
  } catch (err) { serverError(res, err); }
});

// Lab staff update an order: move it along, and enter results. Only the
// result fields of each test can change here — never which tests were ordered,
// their prices, or who the patient is.
app.put('/api/lab-orders/:id', auth, requireRole(ADMIN, LAB_STAFF), requireFeature('laboratory'), async (req, res) => {
  try {
    const order = await LabOrder.findOne({ id: req.params.id, ...scope(req) });
    if (!order) return res.status(404).json({ error: 'Not found' });

    // Once released, results shouldn't be quietly reworked by the tech who
    // entered them — corrections go through an administrator.
    const canOverride = req.user.role === ADMIN || req.user.role === SUPERADMIN;
    if ((order.status === 'completed' || order.status === 'cancelled') && !canOverride)
      return res.status(409).json({ error: `This order is already ${order.status} and can only be changed by an administrator` });

    const { status, tests, notes, sampleCollectedAt } = req.body;
    if (status !== undefined && !LAB_STATUSES.has(status))
      return res.status(400).json({ error: `Invalid status: ${status}` });

    if (tests !== undefined) {
      if (!Array.isArray(tests) || tests.length !== order.tests.length)
        return res.status(400).json({ error: `Send one entry per ordered test (${order.tests.length}), in the same order they were ordered` });
      tests.forEach((t, i) => {
        for (const field of ['result', 'unit', 'referenceRange', 'flag']) {
          if (t && t[field] !== undefined) order.tests[i][field] = String(t[field]);
        }
      });
    }
    if (notes !== undefined) order.notes = notes;
    if (sampleCollectedAt !== undefined) order.sampleCollectedAt = sampleCollectedAt;

    if (status !== undefined && status !== order.status) {
      if (status === 'completed' && order.tests.some(t => !t.result || !String(t.result).trim()))
        return res.status(400).json({ error: 'Enter a result for every test before completing the order' });
      order.status = status;
      if (status === 'in_progress' && !order.sampleCollectedAt) order.sampleCollectedAt = new Date().toISOString();
      if (status === 'completed') {
        order.completedAt = new Date().toISOString();
        order.processedById = req.user.id;
        order.processedByName = req.user.name;
      }
    }

    await order.save();

    // A cancelled order that nobody has paid for should not leave an open bill behind.
    if (order.status === 'cancelled' && order.billId) {
      try {
        await Bill.updateOne({ id: order.billId, hospitalId: order.hospitalId, paidAmount: { $lte: 0 }, status: 'pending' }, { $set: { status: 'cancelled', remainingAmount: 0 } });
      } catch (e) { console.error('Could not cancel the bill of lab order', order.orderRef, e.message); }
    }
    res.json(order);
  } catch (err) { serverError(res, err); }
});

// ─── INPATIENT (feature-gated: inpatient) ────────────────────────────────────
// Wards hold beds. Admitting claims a bed atomically; discharging frees it and
// (when billing is enabled) raises a bill for the bed days automatically.

const BED_STATUSES = new Set(['available', 'maintenance']); // 'occupied' is only ever set by admitting

app.get('/api/wards', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try { res.json(await Ward.find(scope(req)).sort({ name: 1 })); }
  catch (err) { serverError(res, err); }
});

app.post('/api/wards', auth, requireRole(ADMIN), requireFeature('inpatient'), requireHospitalContext, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Ward name is required' });
    const bedCount = Math.floor(Number(req.body.bedCount));
    if (!(bedCount >= 1 && bedCount <= 200)) return res.status(400).json({ error: 'bedCount must be between 1 and 200' });
    if (await Ward.findOne({ hospitalId: req.user.hospitalId, name }))
      return res.status(409).json({ error: 'A ward with this name already exists' });
    const ward = new Ward({
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      name,
      type: req.body.type || 'general',
      dailyRate: Math.max(0, Number(req.body.dailyRate) || 0),
      beds: Array.from({ length: bedCount }, (_, i) => ({ number: String(i + 1), status: 'available' })),
    });
    await ward.save(); res.json(ward);
  } catch (err) { serverError(res, err); }
});

// Rename / re-rate a ward, add beds, or put a free bed in/out of maintenance.
// Rate changes only affect FUTURE admissions (each admission keeps its own rate).
app.put('/api/wards/:id', auth, requireRole(ADMIN), requireFeature('inpatient'), async (req, res) => {
  try {
    const ward = await Ward.findOne({ id: req.params.id, ...scope(req) });
    if (!ward) return res.status(404).json({ error: 'Not found' });

    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: 'Ward name cannot be empty' });
      if (name !== ward.name && await Ward.findOne({ hospitalId: ward.hospitalId, name }))
        return res.status(409).json({ error: 'A ward with this name already exists' });
      ward.name = name;
    }
    if (req.body.type !== undefined) ward.type = req.body.type;
    if (req.body.dailyRate !== undefined) ward.dailyRate = Math.max(0, Number(req.body.dailyRate) || 0);

    if (req.body.addBeds !== undefined) {
      const n = Math.floor(Number(req.body.addBeds));
      if (!(n >= 1 && ward.beds.length + n <= 200)) return res.status(400).json({ error: 'Invalid number of beds to add' });
      let next = ward.beds.reduce((m, b) => Math.max(m, parseInt(b.number) || 0), 0);
      for (let i = 0; i < n; i++) ward.beds.push({ number: String(++next), status: 'available' });
    }
    if (req.body.bedStatus) {
      const { number, status } = req.body.bedStatus;
      const bed = ward.beds.find(b => b.number === String(number));
      if (!bed) return res.status(404).json({ error: 'Bed not found' });
      if (!BED_STATUSES.has(status)) return res.status(400).json({ error: 'Bed status must be available or maintenance' });
      if (bed.status === 'occupied') return res.status(409).json({ error: 'That bed is occupied — discharge the patient first' });
      bed.status = status;
    }
    await ward.save(); res.json(ward);
  } catch (err) { serverError(res, err); }
});

app.get('/api/admissions', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try {
    const { status, patientId, wardId } = req.query;
    const filter = scope(req);
    if (status) filter.status = status;
    if (patientId) filter.patientId = patientId;
    if (wardId) filter.wardId = wardId;
    res.json(await Admission.find(filter).sort({ admittedAt: -1 }));
  } catch (err) { serverError(res, err); }
});

app.get('/api/admissions/:id', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try {
    const a = await Admission.findOne({ id: req.params.id, ...scope(req) });
    if (!a) return res.status(404).json({ error: 'Not found' });
    res.json(a);
  } catch (err) { serverError(res, err); }
});

app.post('/api/admissions', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), requireHospitalContext, async (req, res) => {
  try {
    const { patientId, wardId, bedNumber, reason, diagnosis } = req.body;
    if (!patientId || !wardId || bedNumber === undefined)
      return res.status(400).json({ error: 'patientId, wardId and bedNumber are required' });

    const patient = await Patient.findOne({ id: patientId, ...scope(req) });
    if (!patient) return res.status(404).json({ error: 'Patient not found' });
    const ward = await Ward.findOne({ id: wardId, ...scope(req) });
    if (!ward) return res.status(404).json({ error: 'Ward not found' });

    if (await Admission.findOne({ patientId: patient.id, status: 'admitted', ...scope(req) }))
      return res.status(409).json({ error: `${patient.name} is already admitted — discharge first` });

    const admissionId = uuidv4();
    // Atomically claim the bed: only succeeds if it is still available.
    const claimed = await Ward.findOneAndUpdate(
      { id: ward.id, hospitalId: req.user.hospitalId, beds: { $elemMatch: { number: String(bedNumber), status: 'available' } } },
      { $set: { 'beds.$.status': 'occupied', 'beds.$.admissionId': admissionId } },
      { new: true },
    );
    if (!claimed) return res.status(409).json({ error: `Bed ${bedNumber} in ${ward.name} is not available` });

    try {
      const admission = new Admission({
        id: admissionId,
        hospitalId: req.user.hospitalId,
        admissionRef: `ADM-${Date.now()}`,
        patientId: patient.id,
        patientName: patient.name,
        wardId: ward.id,
        wardName: ward.name,
        bedNumber: String(bedNumber),
        dailyRate: ward.dailyRate || 0,
        admittedById: req.user.id,
        admittedByName: req.user.name,
        reason,
        diagnosis,
        status: 'admitted',
      });
      await admission.save(); res.json(admission);
    } catch (e) {
      // Don't leave a bed stuck "occupied" by a failed admission.
      await Ward.updateOne(
        { id: ward.id, hospitalId: req.user.hospitalId, 'beds.number': String(bedNumber) },
        { $set: { 'beds.$.status': 'available' }, $unset: { 'beds.$.admissionId': '' } },
      );
      throw e;
    }
  } catch (err) { serverError(res, err); }
});

// Daily progress notes on an inpatient.
app.post('/api/admissions/:id/notes', auth, requireRole(ADMIN, DOCTOR), requireFeature('inpatient'), requireHospitalContext, async (req, res) => {
  try {
    const text = String(req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Note text is required' });
    const note = { id: uuidv4(), at: new Date().toISOString(), byId: req.user.id, byName: req.user.name, text };
    const a = await Admission.findOneAndUpdate(
      { id: req.params.id, status: 'admitted', ...scope(req) },
      { $push: { notes: note } },
      { new: true },
    );
    if (!a) return res.status(404).json({ error: 'No current admission found with that id (already discharged?)' });
    res.json(a);
  } catch (err) { serverError(res, err); }
});

// Discharge: closes the stay, frees the bed, and — if the hospital has billing
// on — raises a bill for the bed days (plus any extra charges sent along).
app.post('/api/admissions/:id/discharge', auth, requireRole(ADMIN, DOCTOR), requireFeature('inpatient'), requireHospitalContext, async (req, res) => {
  try {
    const existing = await Admission.findOne({ id: req.params.id, ...scope(req) });
    if (!existing) return res.status(404).json({ error: 'Not found' });
    if (existing.status !== 'admitted') return res.status(409).json({ error: 'This patient is already discharged' });

    const now = new Date();
    const hours = (now - new Date(existing.admittedAt)) / 3600000;
    const daysStayed = Math.max(1, Math.ceil(hours / 24)); // every started 24h counts, minimum one day
    const bedCharge = daysStayed * (Number(existing.dailyRate) || 0);

    const extras = (Array.isArray(req.body.extraCharges) ? req.body.extraCharges : [])
      .map(c => ({ description: String(c?.description || '').trim(), amount: Number(c?.amount) || 0 }))
      .filter(c => c.description && c.amount > 0);

    // Atomic guard: only one request can flip admitted → discharged.
    const a = await Admission.findOneAndUpdate(
      { id: existing.id, status: 'admitted', ...scope(req) },
      { $set: {
        status: 'discharged',
        dischargedAt: now.toISOString(),
        dischargedByName: req.user.name,
        dischargeSummary: req.body.dischargeSummary,
        daysStayed,
        bedCharge,
      } },
      { new: true },
    );
    if (!a) return res.status(409).json({ error: 'This patient is already discharged' });

    await Ward.updateOne(
      { id: a.wardId, hospitalId: a.hospitalId, 'beds.number': a.bedNumber },
      { $set: { 'beds.$.status': 'available' }, $unset: { 'beds.$.admissionId': '' } },
    );

    let bill = null, billError;
    const hospital = await Hospital.findOne({ id: a.hospitalId });
    const items = [];
    if (bedCharge > 0) items.push({
      description: `Bed — ${a.wardName}, bed ${a.bedNumber} (${daysStayed} day${daysStayed > 1 ? 's' : ''} × ${a.dailyRate})`,
      quantity: daysStayed, unitPrice: a.dailyRate, amount: bedCharge,
    });
    extras.forEach(c => items.push({ description: c.description, quantity: 1, unitPrice: c.amount, amount: c.amount }));
    const total = items.reduce((s, i) => s + i.amount, 0);

    if (hospital?.features?.billing && total > 0) {
      try {
        bill = await new Bill({
          id: uuidv4(),
          hospitalId: a.hospitalId,
          billNumber: `BILL-${Date.now()}`,
          patientId: a.patientId,
          patientName: a.patientName,
          items,
          totalAmount: total,
          paidAmount: 0,
          remainingAmount: total,
          status: 'pending',
          notes: `Inpatient stay ${a.admissionRef}`,
        }).save();
        a.billId = bill.id; await a.save();
      } catch (e) { billError = e.message; }
    }

    res.json({ admission: a, bill, ...(billError ? { billError } : {}) });
  } catch (err) { serverError(res, err); }
});

// ─── INVENTORY (feature-gated: pharmacy) ──────────────────────────────────────

app.get('/api/inventory', auth, requireRole(ADMIN, PHARMACIST, DOCTOR), requireFeature('pharmacy'), async (req, res) => {
  try { res.json(await Inventory.find(scope(req))); }
  catch (err) { serverError(res, err); }
});

app.post('/api/inventory', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), requireHospitalContext, async (req, res) => {
  try {
    const i = new Inventory({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await i.save(); res.json(i);
  } catch (err) { serverError(res, err); }
});

app.put('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const i = await Inventory.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!i) return res.status(404).json({ error: 'Not found' });
    res.json(i);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), async (req, res) => {
  try {
    await Inventory.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── PHARMACY SALES (feature-gated: pharmacy) ────────────────────────────────
// Selling a medicine and reducing its stock happen together, atomically per
// item, so stock can never go negative even under two pharmacists selling the
// same drug at the same moment.

app.post('/api/pharmacy-sales', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), requireHospitalContext, async (req, res) => {
  try {
    const { items, patientId, patientName, notes } = req.body;
    if (!Array.isArray(items) || items.length === 0)
      return res.status(400).json({ error: 'At least one item is required' });

    // The hospital's preference decides how a sale relates to a patient record.
    const hosp = await Hospital.findOne({ id: req.user.hospitalId });
    const mode = hospitalSettings(hosp).pharmacyPatientLink;
    let linkedPatient = null;
    if (mode !== 'off' && patientId) {
      linkedPatient = await Patient.findOne({ id: String(patientId), ...scope(req) });
      if (!linkedPatient) return res.status(400).json({ error: 'Patient not found' });
    }
    if (mode === 'required' && !linkedPatient)
      return res.status(400).json({ error: 'This hospital requires every sale to be linked to a registered patient' });

    // Validate every line against live stock before touching anything.
    const resolved = [];
    for (const line of items) {
      const qty = Number(line.quantity);
      if (!line.inventoryId || !qty || qty <= 0)
        return res.status(400).json({ error: 'Each item needs a valid inventoryId and a positive quantity' });
      const stockItem = await Inventory.findOne({ id: line.inventoryId, ...scope(req) });
      if (!stockItem)
        return res.status(404).json({ error: `Medicine not found: ${line.inventoryId}` });
      if (Number(stockItem.quantity) < qty)
        return res.status(400).json({ error: `Not enough stock for "${stockItem.name}" — only ${stockItem.quantity} left` });
      resolved.push({ stockItem, qty });
    }

    // Deduct stock one item at a time, each guarded by quantity >= qty so a
    // concurrent sale can never push it below zero. If a later item in this
    // same sale fails that guard (stock changed between check and deduct),
    // roll back everything already deducted so the sale doesn't half-happen.
    const deducted = [];
    let saleFailed = null;
    for (const { stockItem, qty } of resolved) {
      const updated = await Inventory.findOneAndUpdate(
        { id: stockItem.id, ...scope(req), quantity: { $gte: qty } },
        { $inc: { quantity: -qty } },
        { new: true }
      );
      if (!updated) { saleFailed = stockItem.name; break; }
      deducted.push({ inventoryId: stockItem.id, name: stockItem.name, quantity: qty, unitPrice: Number(stockItem.unitPrice) || 0 });
    }

    if (saleFailed) {
      for (const done of deducted) {
        await Inventory.findOneAndUpdate({ id: done.inventoryId, ...scope(req) }, { $inc: { quantity: done.quantity } });
      }
      return res.status(409).json({ error: `Stock for "${saleFailed}" changed — please retry the sale` });
    }

    const saleItems = deducted.map(i => ({ ...i, subtotal: i.unitPrice * i.quantity }));
    const totalAmount = saleItems.reduce((s, i) => s + i.subtotal, 0);

    const sale = new PharmacySale({
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      saleRef: `RX-${Date.now()}`,
      patientId: linkedPatient ? linkedPatient.id : undefined,
      // A linked sale takes the registered name; otherwise whatever was typed (walk-in).
      patientName: linkedPatient ? linkedPatient.name : (patientName ? String(patientName).slice(0, 120) : undefined),
      notes,
      items: saleItems,
      totalAmount,
      soldById: req.user.id,
      soldByName: req.user.name,
    });
    await sale.save();

    // The customer pays at the counter, so record the payment: it then shows in
    // Transactions and in the hospital's revenue like every other payment.
    try {
      if (totalAmount > 0) {
        const method = String(req.body.method || 'Cash').slice(0, 40) || 'Cash';
        const tx = await new Transaction({
          id: uuidv4(),
          hospitalId: req.user.hospitalId,
          txRef: `TXN-${String(await nextSeq(`tx:${req.user.hospitalId}`)).padStart(6, '0')}`,
          pharmacySaleId: sale.id,
          patientId: sale.patientId,
          patientName: sale.patientName,
          amount: totalAmount,
          tenderedCurrency: hosp && CURRENCIES[hosp.currency] ? hosp.currency : undefined,
          tenderedAmount: totalAmount,
          exchangeRate: 1,
          method,
          note: `Pharmacy sale ${sale.saleRef}`,
          recordedBy: req.user.name,
        }).save();
        sale.transactionId = tx.id; await sale.save();
      }
    } catch (txErr) { console.error('Could not record the payment of pharmacy sale', sale.saleRef, txErr.message); }
    res.json(sale);
  } catch (err) { serverError(res, err); }
});

// Lets the pharmacy find a registered patient to attach a sale to. Pharmacists
// can't list patients, so this returns only the minimum: name, phone, age, gender.
app.get('/api/pharmacy-sales/patient-search', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), requireHospitalContext, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) return res.json([]);
    const rx = new RegExp(q.slice(0, 60).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    const found = await Patient.find({ ...scope(req), $or: [{ name: rx }, { phone: rx }] }).limit(10);
    res.json(found.map(p => ({ id: p.id, name: p.name, phone: p.phone, age: p.age, gender: p.gender })));
  } catch (err) { serverError(res, err); }
});

app.get('/api/pharmacy-sales', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), async (req, res) => {
  try {
    const { from, to } = req.query;
    const q = scope(req);
    if (from || to) {
      q.createdAt = {};
      if (from) q.createdAt.$gte = new Date(from).toISOString();
      if (to) { const d = new Date(to); d.setHours(23, 59, 59, 999); q.createdAt.$lte = d.toISOString(); }
    }
    const sales = await PharmacySale.find(q).sort({ createdAt: -1 });
    res.json(sales);
  } catch (err) { serverError(res, err); }
});

// ─── BILLING (feature-gated: billing) ─────────────────────────────────────────

app.get('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try { res.json(await withNames(await Bill.find(scope(req)), req)); }
  catch (err) { serverError(res, err); }
});

app.post('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), requireHospitalContext, async (req, res) => {
  try {
    const { total, totalAmount: bodyTotal, ...rest } = req.body;
    delete rest._id; delete rest.paidAmount; delete rest.remainingAmount; delete rest.status;
    const totalAmount = Number(bodyTotal ?? total) || 0;
    if (!(totalAmount > 0)) return res.status(400).json({ error: 'A bill needs at least one item with an amount greater than zero.', code: 'VALIDATION' });
    if (!rest.patientId) return res.status(400).json({ error: 'Please choose a patient.', code: 'VALIDATION' });
    const patient = await Patient.findOne({ id: rest.patientId, hospitalId: req.user.hospitalId });
    if (!patient) return res.status(400).json({ error: 'That patient was not found in this hospital.', code: 'VALIDATION' });
    const b = new Bill({
      ...rest,
      patientName: patient.name,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      billNumber: `BILL-${String(await nextSeq(`bill:${req.user.hospitalId}`)).padStart(6, '0')}`,
      status: 'pending',
      paidAmount: 0,
      totalAmount,
      remainingAmount: totalAmount,
    });
    await b.save(); res.json(b);
  } catch (err) { serverError(res, err); }
});

app.put('/api/bills/:id', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try {
    // Money fields are only ever changed by recording payments, never by a direct edit.
    const update = {}; if (req.body.notes !== undefined) update.notes = String(req.body.notes).slice(0, 1000);
    const b = await Bill.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!b) return res.status(404).json({ error: 'Not found' });
    res.json(b);
  } catch (err) { serverError(res, err); }
});

// ─── TRANSACTIONS (feature-gated: billing) ────────────────────────────────────

app.get('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try { res.json(await withNames(await Transaction.find(scope(req)), req)); }
  catch (err) { serverError(res, err); }
});

app.post('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), requireHospitalContext, async (req, res) => {
  try {
    // The patient may pay in any currency this hospital accepts. We keep the amount in the MAIN
    // currency (so bills and totals stay correct) and remember what was really handed over.
    const hosp = await Hospital.findOne({ id: req.user.hospitalId });
    const base = CURRENCIES[hosp?.currency] ? hosp.currency : 'UGX';
    const hs = hospitalSettings(hosp);
    const payCur = req.body.currency || base;
    if (!hs.acceptedCurrencies.includes(payCur)) return res.status(400).json({ error: 'This hospital does not accept that currency. Choose one from the list.', code: 'VALIDATION' });
    const rate = payCur === base ? 1 : hs.exchangeRates[payCur];
    const tendered = Number(req.body.amount) || 0;
    if (!(tendered > 0)) return res.status(400).json({ error: 'Enter an amount greater than zero.', code: 'VALIDATION' });
    const dec = CURRENCIES[base].decimals;
    const round = (n) => Math.round(n * 10 ** dec) / 10 ** dec;
    let amount = round(tendered / rate);
    if (!(amount > 0)) return res.status(400).json({ error: 'That amount is too small to record.', code: 'VALIDATION' });
    let bill = null;
    if (req.body.billId) {
      bill = await Bill.findOne({ id: req.body.billId, hospitalId: req.user.hospitalId });
      if (!bill) return res.status(400).json({ error: 'That bill was not found in this hospital.', code: 'VALIDATION' });
      if (bill.status === 'paid' || Number(bill.remainingAmount) <= 0) return res.status(409).json({ error: 'This bill is already fully paid.', code: 'DUPLICATE' });
      const owed = Number(bill.remainingAmount);
      // Converting between currencies rounds a little; allow up to half a percent (or one smallest unit) over and settle exactly.
      const tolerance = payCur === base ? 0.0001 : Math.max(10 ** -dec, owed * 0.005);
      if (amount > owed + tolerance) return res.status(400).json({ error: 'The payment is more than the amount still owed on this bill.', code: 'VALIDATION' });
      if (amount > owed) amount = owed;
    }
    const patientId = req.body.patientId || (bill && bill.patientId);
    let patientName;
    if (patientId) {
      const p = await Patient.findOne({ id: patientId, hospitalId: req.user.hospitalId });
      if (!p) return res.status(400).json({ error: 'That patient was not found in this hospital.', code: 'VALIDATION' });
      patientName = p.name;
    }
    const { _id, currency: _c, tenderedCurrency: _tc, tenderedAmount: _ta, exchangeRate: _er, ...txBody } = req.body;
    const tx = new Transaction({
      ...txBody,
      patientId,
      amount,
      tenderedCurrency: payCur,
      tenderedAmount: payCur === base ? amount : tendered,
      exchangeRate: rate,
      patientName,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      txRef: `TXN-${String(await nextSeq(`tx:${req.user.hospitalId}`)).padStart(6, '0')}`,
      recordedBy: req.user.name,
    });
    await tx.save();

    // ── Instalment-aware bill update ─────────────────────────────────────────
    if (req.body.billId) {
      const bill = await Bill.findOne({ id: req.body.billId, ...scope(req) });
      if (bill) {
        const allTx = await Transaction.find({ billId: req.body.billId, ...scope(req) });
        const totalPaid = allTx.reduce((s, t) => s + (Number(t.amount) || 0), 0);
        const totalAmount = Number(bill.totalAmount) || 0;
        const remaining = totalAmount - totalPaid;
        await Bill.findOneAndUpdate({ id: req.body.billId, ...scope(req) }, {
          paidAmount: totalPaid,
          remainingAmount: Math.max(0, remaining),
          status: remaining <= 0 ? 'paid' : 'partial',
        });
      }
    }
    // ─────────────────────────────────────────────────────────────────────────

    res.json(tx);
  } catch (err) { serverError(res, err); }
});

app.delete('/api/transactions/:id', auth, requireRole(ADMIN), requireFeature('billing'), async (req, res) => {
  try {
    await Transaction.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ─── DASHBOARD STATS ──────────────────────────────────────────────────────────

app.get('/api/stats', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const role = req.user.role;
    const hScope = scope(req);
    const stats = { role };

    if (role === ADMIN || role === SUPERADMIN) {
      const [patients, doctors, staff, users, appointments, bills, transactions, inventory] = await Promise.all([
        Patient.countDocuments(hScope),
        Doctor.countDocuments(hScope),
        Staff.countDocuments(hScope),
        User.countDocuments(hScope),
        Appointment.countDocuments({ ...hScope, date: today }),
        Bill.find(hScope),
        Transaction.find(hScope),
        Inventory.find(hScope),
      ]);
      const recentPatients = await Patient.find(hScope).sort({ createdAt: -1 }).limit(5);
      Object.assign(stats, {
        totalPatients: patients,
        totalDoctors: doctors,
        totalStaff: staff,
        totalUsers: users,
        todayAppointments: appointments,
        pendingBills: bills.filter(b => b.status === 'pending').length,
        partialBills: bills.filter(b => b.status === 'partial').length,
        partialBillsAmount: bills.filter(b => b.status === 'partial').reduce((s, b) => s + (parseFloat(b.remainingAmount) || 0), 0),
        totalRevenue: transactions.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0),
        lowStockItems: inventory.filter(i => parseInt(i.quantity) < 10).length,
        recentPatients,
      });

      if (role === SUPERADMIN) {
        const [totalHospitals, activeHospitals] = await Promise.all([
          Hospital.countDocuments(),
          Hospital.countDocuments({ status: 'active' }),
        ]);
        const allUsers = await User.find({}, { password: 0 });
        const usersByRole = allUsers.reduce((acc, u) => { acc[u.role] = (acc[u.role] || 0) + 1; return acc; }, {});
        const [auditTotal, auditToday, recentAudit] = await Promise.all([
          AuditLog.countDocuments(),
          AuditLog.countDocuments({ timestamp: { $gte: today } }),
          AuditLog.find().sort({ timestamp: -1 }).limit(8),
        ]);
        const allPharmacySales = await PharmacySale.find();
        // Money in different currencies must never be added together.
        const hospCur = Object.fromEntries((await Hospital.find({}, { id: 1, currency: 1 })).map(h => [h.id, CURRENCIES[h.currency] ? h.currency : 'UGX']));
        const allTx = await Transaction.find({}, { amount: 1, hospitalId: 1 });
        const revenueByCurrency = {};
        for (const t of allTx) { const c = hospCur[t.hospitalId] || 'UGX'; revenueByCurrency[c] = (revenueByCurrency[c] || 0) + (Number(t.amount) || 0); }
        Object.assign(stats, {
          revenueByCurrency,
          totalHospitals,
          activeHospitals,
          usersByRole,
          activeUsers: allUsers.filter(u => u.status !== 'inactive').length,
          disabledUsers: allUsers.filter(u => u.status === 'inactive').length,
          auditTotal,
          auditToday,
          recentAudit,
          totalAppointments: await Appointment.countDocuments(),
          totalRecords: await MedicalRecord.countDocuments(),
          totalPharmacySales: allPharmacySales.length,
          totalPharmacyRevenue: allPharmacySales.reduce((s, sale) => s + (Number(sale.totalAmount) || 0), 0),
        });
      }

    } else if (role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...hScope });
      const recentPatients = await Patient.find(hScope).sort({ createdAt: -1 }).limit(5);
      const inventory = await Inventory.find(hScope);
      Object.assign(stats, {
        totalPatients: await Patient.countDocuments(hScope),
        myAppointments: doc ? await Appointment.countDocuments({ doctorId: doc.id, ...hScope }) : 0,
        todayAppointments: doc ? await Appointment.countDocuments({ doctorId: doc.id, ...hScope, date: today }) : 0,
        myRecords: doc ? await MedicalRecord.countDocuments({ doctorId: doc.id, ...hScope }) : 0,
        lowStockItems: inventory.filter(i => parseInt(i.quantity) < 10).length,
        recentPatients,
      });

    } else if (role === RECEPTIONIST) {
      const [bills, transactions, recentPatients] = await Promise.all([
        Bill.find(hScope),
        Transaction.find(hScope),
        Patient.find(hScope).sort({ createdAt: -1 }).limit(5),
      ]);
      Object.assign(stats, {
        totalPatients: await Patient.countDocuments(hScope),
        todayAppointments: await Appointment.countDocuments({ ...hScope, date: today }),
        pendingBills: bills.filter(b => b.status === 'pending').length,
        partialBills: bills.filter(b => b.status === 'partial').length,
        partialBillsAmount: bills.filter(b => b.status === 'partial').reduce((s, b) => s + (parseFloat(b.remainingAmount) || 0), 0),
        totalRevenue: transactions.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0),
        recentPatients,
      });

    } else if (role === PHARMACIST) {
      const inventory = await Inventory.find(hScope);
      const todaySales = await PharmacySale.find({ ...hScope, createdAt: { $gte: today } });
      Object.assign(stats, {
        totalItems: inventory.length,
        lowStockItems: inventory.filter(i => parseInt(i.quantity) < 10).length,
        expiringSoon: inventory.filter(i => {
          if (!i.expiryDate) return false;
          const diff = (new Date(i.expiryDate) - new Date()) / 86400000;
          return diff < 30 && diff > 0;
        }).length,
        outOfStock: inventory.filter(i => parseInt(i.quantity) === 0).length,
        todaySalesCount: todaySales.length,
        todaySalesRevenue: todaySales.reduce((s, sale) => s + (Number(sale.totalAmount) || 0), 0),
      });

    } else if (role === LAB_STAFF) {
      const orders = await LabOrder.find(hScope);
      const open = o => o.status === 'pending' || o.status === 'in_progress';
      Object.assign(stats, {
        pendingOrders: orders.filter(o => o.status === 'pending').length,
        inProgressOrders: orders.filter(o => o.status === 'in_progress').length,
        urgentOpenOrders: orders.filter(o => o.priority === 'urgent' && open(o)).length,
        completedToday: orders.filter(o => o.status === 'completed' && o.completedAt >= today).length,
      });
    }

    res.json(stats);
  } catch (err) { serverError(res, err); }
});

// ─── SEED ADMIN (dev convenience — only on a completely empty database) ─────
// Guarded behind zero users so this never touches or conflicts with a real,
// migrated hospital's accounts. It only ever fires on a brand-new empty DB.

async function seedAdmin() {
  const totalUsers = await User.countDocuments();
  if (totalUsers > 0) return;

  let hospital = await Hospital.findOne({ slug: 'demo' });
  if (!hospital) {
    hospital = await new Hospital({ id: uuidv4(), name: 'Demo Hospital', slug: 'demo', status: 'active' }).save();
    console.log('✅ Default hospital created — slug: demo');
  }
  await new User({
    id: uuidv4(),
    hospitalId: hospital.id,
    name: 'Administrator',
    username: 'admin',
    password: await bcrypt.hash('password', 10),
    role: 'admin',
    status: 'active',
  }).save();
  console.log('✅ Default admin created — hospital: demo / username: admin / password: password');
  console.warn('⚠️  Change the default admin password immediately after first login.');
}

// ─── SEED SUPER ADMIN ───────────────────────────────────────────────────────
// Credentials come from the environment. Set SUPERADMIN_USERNAME and
// SUPERADMIN_PASSWORD on the host (Render → Environment). The fallbacks below
// are for local development only — change them before going live.
async function seedSuperAdmin() {
  const username = process.env.SUPERADMIN_USERNAME || 'superadmin';
  const password = process.env.SUPERADMIN_PASSWORD;
  const name = process.env.SUPERADMIN_NAME || 'Super Administrator';

  const existing = await User.findOne({ username, hospitalId: { $exists: false } });
  if (!existing && (!password || password.length < 10)) {
    // No built-in default password: a forgotten setting must never leave a known login behind.
    console.error('❌ Super admin not created: set SUPERADMIN_PASSWORD (at least 10 characters) in the environment.');
    return;
  }
  if (!existing) {
    await new User({
      id: uuidv4(),
      name,
      username,
      password: await bcrypt.hash(password, 10),
      role: SUPERADMIN,
      status: 'active',
    }).save();
    console.log(`✅ Super admin created — username: ${username}`);
  } else {
    if (existing.role !== SUPERADMIN) {
      existing.role = SUPERADMIN;
      console.log(`✅ Existing user "${username}" promoted to super admin`);
    }
    if (process.env.SUPERADMIN_RESET_PASSWORD === 'true' && password && password.length >= 10) {
      existing.password = await bcrypt.hash(password, 10);
      console.log(`✅ Super admin "${username}" password reset from environment`);
    }
    if (existing.isModified()) await existing.save();
  }
}

// ─── START SERVER ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4000;

connect().then(async () => {
  await seedAdmin();
  await seedSuperAdmin();
  await backfillPatientNumbers().catch(e => console.error('⚠️  patient number backfill failed:', e.message));
  app.listen(PORT, () => console.log(`🏥 HMS Backend running on http://localhost:${PORT}`));
});
