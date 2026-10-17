# MediCore HMS — Architecture & Developer Guide

> "MediCore HMS" is the working name. The product name is a single setting (see §9), so a buyer can rebrand it in minutes.

This guide is for a developer who has never seen the system. Read §1–§4 for the big picture (15 minutes), then jump to the recipe you need in §10.

---

## 1. What it is

A **multi-hospital Hospital Management System delivered as SaaS**. One deployment serves many hospitals ("tenants"). Each hospital gets its own logo, colour, staff, patients, billing and enabled features, and can never see another hospital's data. A platform owner (the **superadmin**) creates and suspends hospitals.

Designed for East/Central African conditions: unreliable internet, free/cheap hosting, mixed currencies, English/French/Arabic.

## 2. System at a glance

```
 Browser (React + Vite SPA)                 Render (Node/Express API)          MongoDB Atlas
 ┌───────────────────────────┐   HTTPS/JSON ┌──────────────────────────┐       ┌────────────┐
 │ App.jsx  shell + login    │ ───────────▶ │ server.js                │ ────▶ │ 19 colls.  │
 │ modules/*  feature screens│  Bearer JWT  │  auth → role → feature   │       │ (tenant    │
 │ shared.jsx api(), UI kit  │ ◀─────────── │  → hospital scope → data │ ◀──── │  = hospitalId)
 │ offline.js IndexedDB queue│              └──────────────────────────┘       └────────────┘
 │ sw.js app-shell cache     │                         │ nightly
 └───────────────────────────┘                         ▼
   hosted on Vercel                    GitHub Actions → backup.js → AES-256-GCM → Backblaze B2
```

| Layer | Tech | Where |
|---|---|---|
| Frontend | React + Vite, plain CSS, no UI framework | Vercel |
| Backend | Node.js, Express 5, Mongoose 9, JWT, bcryptjs | Render |
| Database | MongoDB Atlas | Atlas |
| Backups | Node script, AES-256-GCM, S3 API to Backblaze B2 | GitHub Actions (01:00 UTC) |

Two repositories: `medicore-backend` (API, scripts, tests, backup workflow) and `medicore-frontend` (SPA).

## 3. Multi-tenancy — the single most important idea

* Every business document carries a `hospitalId`.
* The JWT holds `{ id, hospitalId, role, name }`. The superadmin has **no** `hospitalId`.
* `scope(req)` returns `{}` for the superadmin (sees all) and `{ hospitalId }` for everyone else. **Every query goes through it**, so isolation is enforced on the server, never trusted from the client.
* `requireHospitalContext` blocks hospital-scoped *writes* by the superadmin (there is no hospital to attach to).
* Patient numbers, bill numbers and transaction refs are per-hospital sequences (`Counter` collection + `nextSeq(key)`, e.g. `bill:<hospitalId>`) so they never collide.

**Rule for new code:** any new collection gets a `hospitalId` field and every find/update uses `scope(req)`.

## 4. Request pipeline (backend)

Each route is a chain, read left to right:

```
app.post('/api/lab-orders', auth, requireRole(ADMIN, DOCTOR), requireFeature('laboratory'), requireHospitalContext, handler)
```

1. **Global middleware**: safe headers, CORS (`CORS_ORIGINS`), JSON body limit 300 kb, idempotency guard, audit trail.
2. **`auth`**: verifies the JWT, then **re-reads the user, role and hospital status from the database on every request**. Disabling a user or suspending a hospital takes effect immediately, even with a valid token.
3. **`requireRole(...)`**: roles are `superadmin, admin, doctor, receptionist, pharmacist, labstaff`.
4. **`requireFeature(key)`**: per-hospital feature flag (`pharmacy, laboratory, billing, insurance, theatre, treatmentPlans, referrals, inpatient`); also re-checks the hospital is active.
5. **`requireHospitalContext`**: see §3.
6. **Handler**: validates input, runs the query with `scope(req)`, and catches errors through `serverError(res, err)` (never leaks internals).

## 5. Data model (19 collections, all in `server.js`)

| Group | Collections |
|---|---|
| Platform | `Hospital`, `PlatformSettings`, `User`, `AuditLog`, `Counter` |
| Clinical | `Patient`, `Doctor`, `Staff`, `Appointment`, `MedicalRecord`, `TreatmentPlan`, `Referral`, `LabOrder`, `Ward`, `Admission` |
| Money & stock | `Inventory`, `Bill`, `Transaction`, `PharmacySale` |

`Hospital` holds `features` (the flags above) and `settings`: `pharmacyPatientLink` (off / optional / required), `departments`, `acceptedCurrencies`, `exchangeRates`. Supported currencies: UGX, CDF, USD, KES, TZS, RWF, BIF, EUR.

Records use a string `id` (uuid) as the public identifier alongside Mongo's `_id`.

## 6. Money & automation

* **Mixed-currency payments.** A `Transaction.amount` is always the hospital's **main-currency equivalent**; the currency actually handed over is stored as `tenderedCurrency`, `tenderedAmount`, `exchangeRate`. Reports therefore sum cleanly. Front-end helpers: `rateView` / `rateToStored`.
* **Automatic bills.** A lab order creates a bill; a completed consultation creates a consultation-fee bill. `insertOnceBill` uses a fixed `_id` (`lab:<orderId>`, `consult:<appointmentId>`), so the same event can never bill twice, even if it fires twice.
* **Pharmacy sale** decrements stock and writes a `Transaction`. If stock is insufficient the sale is refused (HTTP 4xx), never negative.
* `backfill-billing.js` is a **preview-first** catch-up script for events that happened before automation existed. Do not run `--apply` casually.

## 7. Security model

| Concern | Mechanism |
|---|---|
| Passwords | bcrypt hashes; login messages never reveal which part was wrong |
| Sessions | JWT, 8 h expiry, `JWT_SECRET` must be ≥ 16 chars or the server refuses to start |
| Brute force | login limit: 10 per IP and 20 per account per 15 min |
| Privilege escalation | `ASSIGNABLE_ROLES`, `sanitizeUserRole`, `protectSuperAdmin` (an admin cannot create/modify a superadmin) |
| Tenant isolation | `scope(req)` on every query (§3) |
| Instant revocation | `auth` re-reads live user and hospital status per request |
| Audit trail | every mutating request logged with secrets redacted; superadmin-only viewer |
| Errors | sanitised through `serverError`; no stack traces to clients |
| Backups | encrypted at rest (AES-256-GCM, key from a passphrase via scrypt) before leaving the server; nightly; 30-day retention; restore proven in CI |

## 8. Reliability features built for poor connectivity

### 8.1 Cold-start handling (free hosting sleeps)
Render's free tier sleeps. `login` and public requests retry (12 tries, 5 s apart) and show a "waking the server" notice; `warmUp()` pings early. An UptimeRobot monitor (or a paid plan) removes the delay entirely.

### 8.2 Offline mode (browser only, `offline.js` + `shared.jsx`)
* **Saved copies**: lists the user viewed are stored in IndexedDB, scoped per user, and shown when the network is down.
* **Queue**: while offline, these POSTs are queued instead of failing: `/patients`, `/bills`, `/transactions`, `/pharmacy-sales`, `/appointments`, `/records`. Queued items appear immediately in lists (an "overlay") with a temporary id `offline-<uuid>`.
* **Sync**: on reconnect, every 30 s, and at start-up, the queue is replayed in order. Temporary ids are rewritten to real ids in later items (`remap`). A server *refusal* (e.g. out of stock) marks the item **failed** for the user to review or discard; network/5xx/401 errors just retry later.
* **Service worker** (`public/sw.js`) caches the app shell so the page itself loads offline. Saved data is wiped on sign-out (the queue is kept).

### 8.3 Duplicate protection
Every POST carries an `Idempotency-Key`. Normal requests use a 10-minute in-memory guard. Queued offline requests also send `X-Durable: 1`, which switches to a **database-backed** guard (`idempotency` collection, insert-first, unique key): it survives server restarts and re-login, replays the original response with `Idempotent-Replay: true`, and returns 409 `DUPLICATE_REQUEST` if the first attempt is still running. This is what makes "a payment recorded twice because the Wi-Fi flickered" impossible.

## 9. Frontend structure

```
src/
  main.jsx           entry, service-worker registration
  App.jsx            shell: login, menu, built-in screens (patients, appointments, billing…), offline bar
  shared.jsx         api() client, UI kit (Modal, tables, icons), translation helpers, offline integration
  modules/           ONE FILE PER OPTIONAL FEATURE  ← where new features go
    index.js         the module registry (one line per module)
    foundation.js    shared translations and base setup
    hospitals.jsx, platformSettings.jsx           superadmin tools
    lab.jsx, inpatient.jsx, carePlans.jsx, pharmacySales.jsx, patientHistory.jsx, hospitalSettings.jsx
    offlineBar.jsx   connection/queue status bar
  offline.js         IndexedDB cache + queue + sync engine
  i18n.js, extraText.js   translations: English, French, Arabic (RTL)
  theme.js, platform.js, config.js   branding and colours
public/sw.js         service worker
```

* **Module registry** (`modules/index.js`): a module is `{ key, navKey, icon, Component, roles, feature }`. The menu is built from it, filtered by the user's role and the hospital's enabled features. Adding a screen = one file + one line.
* **`api(path, options)`** in `shared.jsx` is the only place that talks HTTP: it adds the token, retries cold starts, attaches idempotency headers, falls back to saved copies/queue when offline, and signs the user out on 401.
* **Translations**: all visible text is a key (`t("lab.title")`), with en/fr/ar values, plural forms included. Arabic switches the layout to right-to-left.
* **Branding**: `config.js` holds platform defaults; each hospital's own name/logo/colour is stored in the database and applied at login (`/api/public/branding`). `node rebrand.mjs --name "…" --color "#RRGGBB"` rewrites the defaults.

## 10. Recipes

### Add a new feature module (e.g. "Radiology")
1. **Backend**: add a Mongoose schema with `hospitalId`; add routes with the standard chain `auth, requireRole(...), requireFeature('radiology'), requireHospitalContext`; use `scope(req)` on all queries.
2. Add `'radiology'` to the hospital `features` schema and to the feature list the superadmin sees when creating/editing a hospital.
3. **Frontend**: create `modules/radiology.jsx` exporting a component that receives `{ token, user, hospital }`; add its text with `addTranslations({ en, fr, ar })`.
4. Register it with one line in `modules/index.js`.
5. If staff should be able to create records offline, add its path to `OFFLINE_POSTS` in `shared.jsx` (and a list overlay in `offlineRead` if it appears in a list).
6. Add API tests to `tests/api.test.js`.

### Add a role
Add the constant, include it in `ASSIGNABLE_ROLES`, add it to relevant `requireRole(...)` calls, add a translation in `roles.*`, and add it to the `roles` array of the modules it should see.

### Add a currency
Add the code to the currency list in `server.js` and the front-end currency list; hospitals then enable it in Hospital settings.

### Add a language
Add a new language block to `i18n.js` and `extraText.js` (and mark it RTL if needed).

## 11. Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `MONGO_URI` | Atlas connection string |
| `JWT_SECRET` | token signing key, ≥ 16 chars (generate a 48-byte random) |
| `PORT` | listen port |
| `CORS_ORIGINS` | comma-separated allowed frontend URLs |
| `SUPERADMIN_NAME / _USERNAME / _PASSWORD` | platform owner seeded on first boot |
| `SUPERADMIN_RESET_PASSWORD=true` | one-boot password reset; remove afterwards |
| `BACKUP_PASSPHRASE` | encrypts backups (≥ 12 chars). **Lose it and backups are unreadable** |
| `B2_ENDPOINT, B2_KEY_ID, B2_APP_KEY, B2_BUCKET` | Backblaze B2 target (blank = save to `./backups`) |
| `BACKUP_KEEP_DAYS` | retention (default 30, never fewer than 3 kept) |
| Frontend: `VITE_API_URL` | backend URL, set at build time |

Never commit `.env`; `.env.example` lists every variable.

## 12. Running, testing, deploying

```
# backend
npm install
npm run dev            # node --watch server.js
node tests/api.test.js # integration tests (API=http://localhost:4100/api against a running server)
npm run backup         # manual backup;  npm run backup:list
node restore.js        # preview a restore; --apply --target <uri> to restore

# frontend
npm install
npm run dev
npm run build          # VITE_API_URL must be set
```

**Deploy**: push to `main` on each repo; Vercel (frontend) and Render (backend) redeploy automatically. The nightly backup workflow is `.github/workflows/nightly-backup.yml`; it needs six repository secrets (`MONGO_URI`, `BACKUP_PASSPHRASE`, `B2_ENDPOINT`, `B2_KEY_ID`, `B2_APP_KEY`, `B2_BUCKET`).

**Restore drill** (do this once a quarter): run `node restore.js` against the newest backup — it previews counts per collection without changing anything.

## 13. Operational scripts (backend root)

| Script | Purpose |
|---|---|
| `backup.js`, `restore.js`, `backup-lib.js` | encrypted backup / safe restore |
| `migrate-to-multitenant.js` | one-time conversion of the original single-hospital data |
| `backfill-billing.js` | preview-first billing catch-up |
| `cleanup-test-data.js`, `cleanup-test-sales.js` | remove test records (preview first; **back up before deleting**) |
| `check-inventory.js`, `fix-inventory-number-types.js` | stock diagnostics/repairs |
| `server.legacy.js`, `data.json` | the original single-tenant prototype, kept for reference only |

## 14. Known limits & recommended next steps

Honest list — a buyer will ask.

1. **`server.js` is one ~2,500-line file.** It is organised in clearly labelled sections (models → middleware → routes by area), but a growing team should split it into `models/`, `middleware/`, `routes/`. This is mechanical, not architectural.
2. **Database tier**: Atlas M0 is for development. Move to M10+ (continuous backups, no connection caps) before real patient data at scale.
3. **Hosting**: Render free tier sleeps and has limited CPU; use a paid plan for production.
4. **Offline mode** covers six write types in the browser. It is not a full offline-first database; reports and search need a connection for data not previously viewed.
5. **Compliance**: no formal certification (HIPAA / GDPR / local data-protection law) yet. Encryption in transit (HTTPS) and for backups is in place; encryption of individual fields at rest and a data-protection policy are next steps.
6. **Mobile money / insurance claims**: the `insurance` flag exists, but payer integrations and mobile-money gateways are not built.
7. **Tests** are API integration tests; there are no front-end automated tests yet.
