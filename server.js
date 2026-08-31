require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const { connect } = require('./db');

const app = express();
const SECRET = process.env.JWT_SECRET || 'medicore_hms_super_secret_2024';
const SUPERADMIN = 'superadmin';
const ADMIN = 'admin';
const DOCTOR = 'doctor';
const RECEPTIONIST = 'receptionist';
const PHARMACIST = 'pharmacist';

app.use(cors());
app.use(express.json());
app.set('trust proxy', true);

// ─── MONGOOSE SCHEMAS ────────────────────────────────────────────────────────

const UserSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  name: String,
  username: { type: String, unique: true },
  password: String,
  role: String,
  status: { type: String, default: 'active' },
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const User = mongoose.model('User', UserSchema);

const PatientSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  name: String,
  age: String,
  gender: String,
  phone: String,
  address: String,
  bloodGroup: String,
  emergencyContact: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Patient = mongoose.model('Patient', PatientSchema);

const DoctorSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
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
  name: String,
  role: String,
  phone: String,
  email: String,
  department: String,
  salary: String,
  status: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Staff = mongoose.model('Staff', StaffSchema);

const AppointmentSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
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

const InventorySchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  name: String,
  category: String,
  quantity: String,
  unit: String,
  price: String,
  expiryDate: String,
  supplier: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Inventory = mongoose.model('Inventory', InventorySchema);

const BillSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  billNumber: String,
  patientId: String,
  patientName: String,
  items: Array,
  totalAmount: String,
  paidAmount: { type: Number, default: 0 },
  remainingAmount: Number,
  status: { type: String, default: 'pending' },
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Bill = mongoose.model('Bill', BillSchema);

const TransactionSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  txRef: String,
  billId: String,
  patientName: String,
  amount: String,
  paymentMethod: String,
  recordedBy: String,
  method: String,
  note: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

const AuditLogSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  timestamp: { type: String, default: () => new Date().toISOString() },
  actorId: String,
  actorName: String,
  actorRole: String,
  action: String,          // CREATE | UPDATE | DELETE | LOGIN | LOGIN_FAILED | PASSWORD_RESET | ACCOUNT_DISABLED | ACCOUNT_ENABLED
  entity: String,          // patients | users | appointments | auth | ...
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

// ─── AUDIT TRAIL ─────────────────────────────────────────────────────────────
// Every state-changing request (and every login attempt) is recorded, including
// the ones made by the super admin.

const AUDITED_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function deriveAction(req, statusCode) {
  if (req.path === '/api/login') return statusCode < 400 ? 'LOGIN' : 'LOGIN_FAILED';
  if (/\/password$/.test(req.path)) return 'PASSWORD_RESET';
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
    const seg = req.path.split('/').filter(Boolean);      // ['api', 'patients', ':id']
    const isAuth = req.path === '/api/login';
    const entity = isAuth ? 'auth' : (seg[1] || 'unknown');
    const entityId = seg[2] || res.locals.responseBody?.id || undefined;
    writeAudit({
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

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
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
    const target = await User.findOne({ id: req.params.id });
    if (target && target.role === SUPERADMIN && req.user.role !== SUPERADMIN)
      return res.status(403).json({ error: 'Only a super admin can modify a super admin account' });
    next();
  } catch (err) { res.status(500).json({ error: err.message }); }
}

// ─── LOGIN ───────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username, status: { $ne: 'inactive' } });
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role, username: user.username } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const exists = await User.findOne({ username: req.body.username });
    if (exists) return res.status(400).json({ error: 'Username already exists' });
    const user = new User({
      ...req.body,
      id: uuidv4(),
      password: bcrypt.hashSync(req.body.password, 10),
      status: 'active',
    });
    await user.save();
    const result = user.toObject();
    delete result.password;
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    const update = { ...req.body };
    if (req.body.password) update.password = bcrypt.hashSync(req.body.password, 10);
    const user = await User.findOneAndUpdate({ id: req.params.id }, update, { new: true, projection: { password: 0 } });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Reset a user's password. If no password is supplied a temporary one is
// generated and returned once so the super admin can hand it over.
app.put('/api/users/:id/password', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    const target = await User.findOne({ id: req.params.id });
    if (!target) return res.status(404).json({ error: 'Not found' });
    const generated = !req.body.password;
    const newPassword = req.body.password
      || `Hms-${Math.random().toString(36).slice(-8)}${Math.floor(Math.random() * 90 + 10)}`;
    target.password = bcrypt.hashSync(newPassword, 10);
    await target.save();
    res.json({ success: true, generated, password: generated ? newPassword : undefined });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', auth, requireRole(ADMIN), protectSuperAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await User.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── AUDIT LOGS (super admin only) ───────────────────────────────────────────

// Distinct values, for building the filter dropdowns on the client.
app.get('/api/audit-logs/meta', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const [actions, entities, actors] = await Promise.all([
      AuditLog.distinct('action'),
      AuditLog.distinct('entity'),
      AuditLog.aggregate([
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

// Full log with optional filters — action, actor, entity and a date range.
// Any filter that is omitted (or "all") is not applied.
app.get('/api/audit-logs', auth, requireRole(SUPERADMIN), async (req, res) => {
  try {
    const { action, actor, entity, from, to } = req.query;
    const q = {};
    if (action && action !== 'all') q.action = action;
    if (entity && entity !== 'all') q.entity = entity;
    if (actor && actor !== 'all') q.actorId = actor;
    if (from || to) {
      q.timestamp = {};
      if (from) q.timestamp.$gte = new Date(from).toISOString();
      if (to) { const d = new Date(to); d.setHours(23, 59, 59, 999); q.timestamp.$lte = d.toISOString(); }
    }
    const limit = Math.min(parseInt(req.query.limit, 10) || 1000, 5000);
    const logs = await AuditLog.find(q).sort({ timestamp: -1 }).limit(limit);
    res.json(logs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PATIENTS ────────────────────────────────────────────────────────────────

app.get('/api/patients', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try { res.json(await Patient.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patients', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const p = new Patient({ ...req.body, id: uuidv4() });
    await p.save(); res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/patients/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const p = await Patient.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/patients/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Patient.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── DOCTORS ─────────────────────────────────────────────────────────────────

app.get('/api/doctors', auth, async (req, res) => {
  try { res.json(await Doctor.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/doctors', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const d = new Doctor({ ...req.body, id: uuidv4() });
    await d.save(); res.json(d);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const d = await Doctor.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!d) return res.status(404).json({ error: 'Not found' });
    res.json(d);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/doctors/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Doctor.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── STAFF ───────────────────────────────────────────────────────────────────

app.get('/api/staff', auth, requireRole(ADMIN), async (req, res) => {
  try { res.json(await Staff.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/staff', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const s = new Staff({ ...req.body, id: uuidv4() });
    await s.save(); res.json(s);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    const s = await Staff.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/staff/:id', auth, requireRole(ADMIN), async (req, res) => {
  try {
    await Staff.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── APPOINTMENTS ─────────────────────────────────────────────────────────────

app.get('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id });
      return res.json(doc ? await Appointment.find({ doctorId: doc.id }) : await Appointment.find());
    }
    res.json(await Appointment.find());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/appointments', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const a = new Appointment({ ...req.body, id: uuidv4(), status: 'scheduled' });
    await a.save(); res.json(a);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST, DOCTOR), async (req, res) => {
  try {
    const a = await Appointment.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!a) return res.status(404).json({ error: 'Not found' });
    res.json(a);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/appointments/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    await Appointment.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── MEDICAL RECORDS ──────────────────────────────────────────────────────────

app.get('/api/records', auth, requireRole(ADMIN, DOCTOR, RECEPTIONIST), async (req, res) => {
  try {
    const { patientId } = req.query;
    const filter = patientId ? { patientId } : {};
    if (req.user.role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id });
      if (doc) filter.doctorId = doc.id;
    }
    res.json(await MedicalRecord.find(filter));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/records', auth, requireRole(ADMIN, DOCTOR), async (req, res) => {
  try {
    const r = new MedicalRecord({ ...req.body, id: uuidv4(), createdBy: req.user.id });
    await r.save(); res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/records/:id', auth, requireRole(ADMIN, DOCTOR), async (req, res) => {
  try {
    const r = await MedicalRecord.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!r) return res.status(404).json({ error: 'Not found' });
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── INVENTORY ────────────────────────────────────────────────────────────────

app.get('/api/inventory', auth, requireRole(ADMIN, PHARMACIST, DOCTOR), async (req, res) => {
  try { res.json(await Inventory.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory', auth, requireRole(ADMIN, PHARMACIST), async (req, res) => {
  try {
    const i = new Inventory({ ...req.body, id: uuidv4() });
    await i.save(); res.json(i);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), async (req, res) => {
  try {
    const i = await Inventory.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!i) return res.status(404).json({ error: 'Not found' });
    res.json(i);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/inventory/:id', auth, requireRole(ADMIN, PHARMACIST), async (req, res) => {
  try {
    await Inventory.findOneAndDelete({ id: req.params.id });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── BILLING ──────────────────────────────────────────────────────────────────

app.get('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try { res.json(await Bill.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/bills', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const totalAmount = parseFloat(req.body.totalAmount) || 0;
    const b = new Bill({
      ...req.body,
      id: uuidv4(),
      billNumber: `BILL-${Date.now()}`,
      status: 'pending',
      paidAmount: 0,
      remainingAmount: totalAmount,
    });
    await b.save(); res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/bills/:id', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const b = await Bill.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!b) return res.status(404).json({ error: 'Not found' });
    res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── TRANSACTIONS ─────────────────────────────────────────────────────────────

app.get('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try { res.json(await Transaction.find()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/transactions', auth, requireRole(ADMIN, RECEPTIONIST), async (req, res) => {
  try {
    const tx = new Transaction({
      ...req.body,
      id: uuidv4(),
      txRef: `TXN-${Date.now()}`,
      recordedBy: req.user.name,
    });
    await tx.save();

    // ── Instalment-aware bill update ─────────────────────────────────────────
    if (req.body.billId) {
      const bill = await Bill.findOne({ id: req.body.billId });
      if (bill) {
        const allTx = await Transaction.find({ billId: req.body.billId });
        const totalPaid = allTx.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
        const totalAmount = parseFloat(bill.totalAmount) || 0;
        const remaining = totalAmount - totalPaid;
        await Bill.findOneAndUpdate({ id: req.body.billId }, {
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

app.delete('/api/transactions/:id',auth,requireRole(ADMIN),async(req,res)=>{try{await Transaction.findOneAndDelete({id:req.params.id});res.json({success:true});}catch(err){res.status(500).json({error:err.message});}});

// ─── DASHBOARD STATS ──────────────────────────────────────────────────────────

app.get('/api/stats', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const role = req.user.role;
    const stats = { role };

    if (role === ADMIN || role === SUPERADMIN) {
      const [patients, doctors, staff, users, appointments, bills, transactions, inventory] = await Promise.all([
        Patient.countDocuments(),
        Doctor.countDocuments(),
        Staff.countDocuments(),
        User.countDocuments(),
        Appointment.countDocuments({ date: today }),
        Bill.find(),
        Transaction.find(),
        Inventory.find(),
      ]);
      const recentPatients = await Patient.find().sort({ createdAt: -1 }).limit(5);
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
        const allUsers = await User.find({}, { password: 0 });
        const usersByRole = allUsers.reduce((acc, u) => { acc[u.role] = (acc[u.role] || 0) + 1; return acc; }, {});
        const [auditTotal, auditToday, recentAudit] = await Promise.all([
          AuditLog.countDocuments(),
          AuditLog.countDocuments({ timestamp: { $gte: today } }),
          AuditLog.find().sort({ timestamp: -1 }).limit(8),
        ]);
        Object.assign(stats, {
          usersByRole,
          activeUsers: allUsers.filter(u => u.status !== 'inactive').length,
          disabledUsers: allUsers.filter(u => u.status === 'inactive').length,
          auditTotal,
          auditToday,
          recentAudit,
          totalAppointments: await Appointment.countDocuments(),
          totalRecords: await MedicalRecord.countDocuments(),
        });
      }

    } else if (role === DOCTOR) {
      const doc = await Doctor.findOne({ linkedUserId: req.user.id });
      const recentPatients = await Patient.find().sort({ createdAt: -1 }).limit(5);
      const inventory = await Inventory.find();
      Object.assign(stats, {
        totalPatients: await Patient.countDocuments(),
        myAppointments: doc ? await Appointment.countDocuments({ doctorId: doc.id }) : 0,
        todayAppointments: doc ? await Appointment.countDocuments({ doctorId: doc.id, date: today }) : 0,
        myRecords: doc ? await MedicalRecord.countDocuments({ doctorId: doc.id }) : 0,
        lowStockItems: inventory.filter(i => parseInt(i.quantity) < 10).length,
        recentPatients,
      });

    } else if (role === RECEPTIONIST) {
      const [bills, transactions, recentPatients] = await Promise.all([
        Bill.find(),
        Transaction.find(),
        Patient.find().sort({ createdAt: -1 }).limit(5),
      ]);
      Object.assign(stats, {
        totalPatients: await Patient.countDocuments(),
        todayAppointments: await Appointment.countDocuments({ date: today }),
        pendingBills: bills.filter(b => b.status === 'pending').length,
        partialBills: bills.filter(b => b.status === 'partial').length,
        partialBillsAmount: bills.filter(b => b.status === 'partial').reduce((s, b) => s + (parseFloat(b.remainingAmount) || 0), 0),
        totalRevenue: transactions.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0),
        recentPatients,
      });

    } else if (role === PHARMACIST) {
      const inventory = await Inventory.find();
      Object.assign(stats, {
        totalItems: inventory.length,
        lowStockItems: inventory.filter(i => parseInt(i.quantity) < 10).length,
        expiringSoon: inventory.filter(i => {
          if (!i.expiryDate) return false;
          const diff = (new Date(i.expiryDate) - new Date()) / 86400000;
          return diff < 30 && diff > 0;
        }).length,
        outOfStock: inventory.filter(i => parseInt(i.quantity) === 0).length,
      });
    }

    res.json(stats);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── SEED ADMIN (first run only) ─────────────────────────────────────────────

async function seedAdmin() {
  const exists = await User.findOne({ username: 'admin' });
  if (!exists) {
    await new User({
      id: uuidv4(),
      name: 'Administrator',
      username: 'admin',
      password: bcrypt.hashSync('password', 10),
      role: 'admin',
      status: 'active',
    }).save();
    console.log('✅ Default admin created — username: admin / password: password');
  }
}

// ─── SEED SUPER ADMIN ───────────────────────────────────────────────────────
// Credentials come from the environment. Set SUPERADMIN_USERNAME and
// SUPERADMIN_PASSWORD on the host (Render → Environment). The fallbacks below
// are for local development only — change them before going live.
async function seedSuperAdmin() {
  const username = process.env.SUPERADMIN_USERNAME || 'superadmin';
  const password = process.env.SUPERADMIN_PASSWORD || 'ChangeMe_SuperAdmin_2024';
  const name = process.env.SUPERADMIN_NAME || 'Super Administrator';

  const existing = await User.findOne({ username });
  if (!existing) {
    await new User({
      id: uuidv4(),
      name,
      username,
      password: bcrypt.hashSync(password, 10),
      role: SUPERADMIN,
      status: 'active',
    }).save();
    console.log(`✅ Super admin created — username: ${username}`);
  } else if (existing.role !== SUPERADMIN) {
    existing.role = SUPERADMIN;
    await existing.save();
    console.log(`✅ Existing user "${username}" promoted to super admin`);
  }
}

// ─── START SERVER ─────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4000;

connect().then(async () => {
  await seedAdmin();
  await seedSuperAdmin();
  app.listen(PORT, () => console.log(`🏥 HMS Backend running on http://localhost:${PORT}`));
});