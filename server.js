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

function loginRateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const hit = loginHits.get(key);
  if (!hit || now - hit.first > LOGIN_WINDOW_MS) {
    loginHits.set(key, { count: 1, first: now });
    return next();
  }
  hit.count += 1;
  if (hit.count > LOGIN_MAX_ATTEMPTS)
    return res.status(429).json({ error: 'Too many login attempts. Please wait a few minutes and try again.' });
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
    laboratory: { type: Boolean, default: false },
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
  },
  status: { type: String, default: 'active' }, // active | suspended | trial
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Hospital = mongoose.model('Hospital', HospitalSchema);
// Hospitals created before settings existed simply get the defaults.
const PHARMACY_LINK_MODES = ['off', 'optional', 'required'];
const hospitalSettings = (h) => ({ pharmacyPatientLink: h?.settings?.pharmacyPatientLink || 'optional' });

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
const Patient = mongoose.model('Patient', PatientSchema);

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

const TransactionSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  hospitalId: { type: String },
  txRef: String,
  billId: String,
  patientId: String,
  patientName: String,
  amount: { type: Number, default: 0 },
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

  const safeBody = req.body && typeof req.body === 'object' ? { ...req.body } : {};
  if ('password' in safeBody) safeBody.password = '***';

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
  catch { return res.status(401).json({ error: 'Invalid token' }); }

  // A hospital that gets suspended (e.g. for non-payment) is locked out of
  // every route immediately — including staff who are already logged in with
  // a token that hasn't expired yet. They don't have to wait out the token.
  if (req.user.hospitalId) {
    try {
      const hospital = await Hospital.findOne({ id: req.user.hospitalId });
      if (!hospital || hospital.status !== 'active') {
        return res.status(403).json({ error: 'This hospital\'s access has been suspended. Please contact your platform administrator.' });
      }
    } catch (err) { return res.status(500).json({ error: err.message }); }
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    // The super admin can reach every endpoint.
    if (req.user.role === SUPERADMIN) return next();
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: 'Access denied' });
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
  } catch (err) { res.status(500).json({ error: err.message }); }
}

// Guard the `role` field on user create / update so an ordinary admin cannot
// mint (or promote themselves to) a super admin, and cannot set a bogus role.
const ASSIGNABLE_ROLES = new Set([ADMIN, DOCTOR, RECEPTIONIST, PHARMACIST, LAB_STAFF]);
function sanitizeUserRole(req, res, next) {
  const { role } = req.body;
  if (role === undefined || role === null || role === '') return next();
  if (role === SUPERADMIN) {
    if (req.user.role !== SUPERADMIN)
      return res.status(403).json({ error: 'Only a super admin can assign the super admin role' });
    return next();
  }
  if (!ASSIGNABLE_ROLES.has(role))
    return res.status(400).json({ error: `Invalid role: ${role}` });
  next();
}

// ─── LOGIN ───────────────────────────────────────────────────────────────────
// Every hospital shares this one login page. A hospital user supplies
// hospitalSlug + username + password; the super admin (platform owner) logs
// in with no hospitalSlug at all. Same error either way credentials fail, so
// a bad guess never reveals whether a given hospital slug exists.

app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const { hospitalSlug, username, password } = req.body;
    let hospital = null;
    let userQuery;

    if (hospitalSlug) {
      hospital = await Hospital.findOne({ slug: String(hospitalSlug).toLowerCase().trim() });
      if (!hospital || hospital.status !== 'active')
        return res.status(401).json({ error: 'Invalid credentials' });
      res.locals.auditHospitalId = hospital.id; // so login attempts show under that hospital in the audit trail
      userQuery = { username, hospitalId: hospital.id, status: { $ne: 'inactive' } };
    } else {
      // No hospital selected — only the platform super admin can log in this way.
      userQuery = { username, hospitalId: { $exists: false }, role: SUPERADMIN, status: { $ne: 'inactive' } };
    }

    const user = await User.findOne(userQuery);
    if (!user || !user.password || !(await bcrypt.compare(password || '', user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });
    loginHits.delete(req.ip || 'unknown');
    const token = jwt.sign({ id: user.id, hospitalId: user.hospitalId, role: user.role, name: user.name }, SECRET, { expiresIn: '8h' });
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, username: user.username },
      hospital: hospital ? { id: hospital.id, name: hospital.name, logo: hospital.logo, theme: hospital.theme, features: hospital.features, settings: hospitalSettings(hospital) } : null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUBLIC (no login): the platform's name, colour and logo, so the login page can
// show them before anyone signs in. Nothing else is exposed.
app.get('/api/public/platform', async (req, res) => {
  try {
    const p = await PlatformSettings.findOne({ key: 'platform' });
    res.set('Cache-Control', 'no-cache');
    res.json({ name: p?.name || '', color: p?.color || '', logo: p?.logo || '' });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// The signed-in user's own hospital (name, logo, theme, enabled features), so the
// app can refresh what it shows without a new login. The auth middleware has
// already refused suspended hospitals before this runs. Superadmin has none.
app.get('/api/session', auth, async (req, res) => {
  try {
    if (!req.user.hospitalId) return res.json({ hospital: null });
    const h = await Hospital.findOne({ id: req.user.hospitalId });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json({ hospital: { id: h.id, name: h.name, logo: h.logo, theme: h.theme, features: h.features, settings: hospitalSettings(h) } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// A hospital's own admin changes that hospital's preferences.
app.put('/api/hospital/settings', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    const { pharmacyPatientLink } = req.body || {};
    const update = {};
    if (pharmacyPatientLink !== undefined) {
      if (!PHARMACY_LINK_MODES.includes(pharmacyPatientLink)) return res.status(400).json({ error: 'Invalid option' });
      update['settings.pharmacyPatientLink'] = pharmacyPatientLink;
    }
    const h = await Hospital.findOneAndUpdate({ id: req.user.hospitalId }, update, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json({ settings: hospitalSettings(h) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── HOSPITALS (super admin only) ────────────────────────────────────────────
// Onboarding a new hospital is now configuration, not a new deployment.

app.get('/api/hospitals', auth, requireRole(SUPERADMIN), async (req, res) => {
  try { res.json(await Hospital.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/hospitals', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const slug = String(req.body.slug || '').toLowerCase().trim();
    if (!slug) return res.status(400).json({ error: 'A hospital slug is required' });
    const exists = await Hospital.findOne({ slug });
    if (exists) return res.status(400).json({ error: 'That hospital slug is already taken' });
    const h = new Hospital({ ...req.body, id: uuidv4(), slug, status: req.body.status || 'active' });
    await h.save(); res.json(h);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/hospitals/:id', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const update = { ...req.body };
    delete update.id; delete update._id;
    if (update.slug) update.slug = String(update.slug).toLowerCase().trim();
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Suspend a hospital (e.g. non-payment) — every one of its staff is locked
// out immediately, even if already logged in, because `auth` rechecks
// hospital status on every request.
app.post('/api/hospitals/:id/suspend', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const h = await Hospital.findOneAndUpdate({ id: req.params.id }, { status: 'suspended' }, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json(h);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Resume a previously suspended hospital (e.g. payment received) — staff can
// log in and use the system again right away.
app.post('/api/hospitals/:id/resume', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const h = await Hospital.findOneAndUpdate({ id: req.params.id }, { status: 'active' }, { new: true });
    if (!h) return res.status(404).json({ error: 'Not found' });
    res.json(h);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Convenience: create a hospital together with its first admin user in one
// call, so onboarding a new customer is a single action.
app.post('/api/hospitals/:id/admin', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const hospital = await Hospital.findOne({ id: req.params.id });
    if (!hospital) return res.status(404).json({ error: 'Hospital not found' });
    if (!req.body.username || !req.body.password) return res.status(400).json({ error: 'username and password are required' });
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
        totalRevenue: transactions.reduce((s, t) => s + (Number(t.amount) || 0), 0),
        pharmacySalesCount: pharmacySales.length,
        pharmacyRevenue: pharmacySales.reduce((s, sale) => s + (Number(sale.totalAmount) || 0), 0),
        lowStockItems: inventory.filter(i => Number(i.quantity) < 10).length,
      };
    }));
    res.json(overview);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const users = await User.find(scope(req), { password: 0 });
    res.json(users);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', auth, requireRole(ADMIN), requireHospitalContext, sanitizeUserRole, async (req, res) => {
  try {
    if (!req.body.password) return res.status(400).json({ error: 'A password is required' });
    const exists = await User.findOne({ username: req.body.username, hospitalId: req.user.hospitalId });
    if (exists) return res.status(400).json({ error: 'Username already exists' });
    const user = new User({
      ...req.body,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      password: await bcrypt.hash(req.body.password, 10),
      status: 'active',
    });
    await user.save();
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, sanitizeUserRole, async (req, res) => {
  try {
    const update = { ...req.body };
    delete update.id; delete update._id; delete update.hospitalId; // never let a client move a user between hospitals
    if (req.body.password) update.password = await bcrypt.hash(req.body.password, 10);
    else delete update.password;
    const user = await User.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true, projection: { password: 0 } });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await User.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
      filter.$or = [{ name: regex }, { phone: regex }, { email: regex }];
    }
    res.json(await Patient.find(filter));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patients', auth, requireRole(ADMIN, RECEPTIONIST), requireHospitalContext, async (req, res) => {
  try {
    const p = new Patient({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await p.save(); res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/patients/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const p = await Patient.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/patients/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Patient.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DOCTORS ─────────────────────────────────────────────────────────────────

app.get('/api/doctors', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try { res.json(await Doctor.find(scope(req))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/doctors', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    const d = new Doctor({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await d.save(); res.json(d);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const d = await Doctor.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!d) return res.status(404).json({ error: 'Not found' });
    res.json(d);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Doctor.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── STAFF ───────────────────────────────────────────────────────────────────

app.get('/api/staff', auth, requireRole(ADMIN), async (req, res) => {
  try { res.json(await Staff.find(scope(req))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/staff', auth, requireRole(ADMIN), requireHospitalContext, async (req, res) => {
  try {
    const s = new Staff({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await s.save(); res.json(s);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const s = await Staff.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Staff.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── APPOINTMENTS ─────────────────────────────────────────────────────────────

app.get('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const filter = scope(req);
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id, ...scope(req) });
      filter.doctorId = doc ? doc.id : '__no_linked_doctor__';
    }
    res.json(await Appointment.find(filter));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST), requireHospitalContext, async (req, res) => {
  try {
    const a = new Appointment({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId, status: 'scheduled' });
    await a.save(); res.json(a);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const a = await Appointment.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!a) return res.status(404).json({ error: 'Not found' });
    res.json(a);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    await Appointment.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    res.json(await MedicalRecord.find(filter));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/records', auth, requireRole(ADMIN, DOCTOR), requireHospitalContext, async (req, res) => {
  try {
    const r = new MedicalRecord({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId, createdBy: req.user.id });
    await r.save(); res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/records/:id', auth, requireRole(ADMIN, DOCTOR), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const r = await MedicalRecord.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/treatment-plans/:id', auth, requireRole(ADMIN, DOCTOR), requireFeature('treatmentPlans'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const p = await TreatmentPlan.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    await order.save(); res.json(order);
  } catch (err) { res.status(500).json({ error: err.message }); }
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

    await order.save(); res.json(order);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── INPATIENT (feature-gated: inpatient) ────────────────────────────────────
// Wards hold beds. Admitting claims a bed atomically; discharging frees it and
// (when billing is enabled) raises a bill for the bed days automatically.

const BED_STATUSES = new Set(['available', 'maintenance']); // 'occupied' is only ever set by admitting

app.get('/api/wards', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try { res.json(await Ward.find(scope(req)).sort({ name: 1 })); }
  catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admissions', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try {
    const { status, patientId, wardId } = req.query;
    const filter = scope(req);
    if (status) filter.status = status;
    if (patientId) filter.patientId = patientId;
    if (wardId) filter.wardId = wardId;
    res.json(await Admission.find(filter).sort({ admittedAt: -1 }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admissions/:id', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), requireFeature('inpatient'), async (req, res) => {
  try {
    const a = await Admission.findOne({ id: req.params.id, ...scope(req) });
    if (!a) return res.status(404).json({ error: 'Not found' });
    res.json(a);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── INVENTORY (feature-gated: pharmacy) ──────────────────────────────────────

app.get('/api/inventory', auth, requireRole(ADMIN, PHARMACIST, DOCTOR), requireFeature('pharmacy'), async (req, res) => {
  try { res.json(await Inventory.find(scope(req))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), requireHospitalContext, async (req, res) => {
  try {
    const i = new Inventory({ ...req.body, id: uuidv4(), hospitalId: req.user.hospitalId });
    await i.save(); res.json(i);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const i = await Inventory.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!i) return res.status(404).json({ error: 'Not found' });
    res.json(i);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), requireFeature('pharmacy'), async (req, res) => {
  try {
    await Inventory.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    res.json(sale);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── BILLING (feature-gated: billing) ─────────────────────────────────────────

app.get('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try { res.json(await Bill.find(scope(req))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), requireHospitalContext, async (req, res) => {
  try {
    const { total, totalAmount: bodyTotal, ...rest } = req.body;
    const totalAmount = Number(bodyTotal ?? total) || 0;
    const b = new Bill({
      ...rest,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      billNumber: `BILL-${Date.now()}`,
      status: 'pending',
      paidAmount: 0,
      totalAmount,
      remainingAmount: totalAmount,
    });
    await b.save(); res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/bills/:id', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try {
    const update = { ...req.body }; delete update.hospitalId;
    const b = await Bill.findOneAndUpdate({ id: req.params.id, ...scope(req) }, update, { new: true });
    if (!b) return res.status(404).json({ error: 'Not found' });
    res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── TRANSACTIONS (feature-gated: billing) ────────────────────────────────────

app.get('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), async (req, res) => {
  try { res.json(await Transaction.find(scope(req))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), requireFeature('billing'), requireHospitalContext, async (req, res) => {
  try {
    const amount = Number(req.body.amount) || 0;
    let patientName = req.body.patientName;
    if (!patientName && req.body.patientId) {
      const p = await Patient.findOne({ id: req.body.patientId, ...scope(req) });
      patientName = p?.name;
    }
    const tx = new Transaction({
      ...req.body,
      amount,
      patientName,
      id: uuidv4(),
      hospitalId: req.user.hospitalId,
      txRef: `TXN-${Date.now()}`,
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
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/transactions/:id', auth, requireRole(ADMIN), requireFeature('billing'), async (req, res) => {
  try {
    await Transaction.findOneAndDelete({ id: req.params.id, ...scope(req) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
        Object.assign(stats, {
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
  } catch (err) { res.status(500).json({ error: err.message }); }
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
  app.listen(PORT, () => console.log(`🏥 HMS Backend running on http://localhost:${PORT}`));
});
