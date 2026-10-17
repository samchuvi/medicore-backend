# MediCore HMS — Pitch Guide

Use this together with `EXTENDING.md`. Read the one-minute pitch aloud until it feels natural, then use the rest as reference for questions. (Replace "MediCore" with the final product name.)

---

## 1. The 30-second pitch

"Most hospital software in our region is either expensive foreign software built for stable internet, or a local desktop system that can't scale. **MediCore is a cloud hospital management system built for Africa**: one platform that serves many hospitals, each with its own branding, staff and data. It works through internet drops, handles several currencies in one till, speaks English, French and Arabic, and a new hospital can be live in a day, with no servers to buy. It is already running at a live hospital, Byarwanga Medical Centre."

## 2. The problem

* Small and mid-size hospitals still run on paper registers or spreadsheets: lost records, unbilled services, drugs that disappear.
* Existing systems are costly, need on-site servers and IT staff, and **stop working when the internet drops**.
* Cash arrives in several currencies (USD, local currency), and tills don't reconcile.
* Owners can't see revenue, stock or activity without being in the building.

## 3. The solution

| Need | What MediCore does |
|---|---|
| Patient flow | Registration, appointments, doctors, medical records, history search |
| Clinical | Lab orders and results, inpatient wards/admissions/discharge, referrals, treatment plans |
| Money | Bills, payments, mixed-currency receipts, automatic lab and consultation billing |
| Pharmacy | Stock, sales that deduct stock, optional patient link |
| Control | Roles for six staff types, audit trail, per-hospital feature switches |
| Owner view | Platform dashboard across all hospitals; suspend or resume a hospital instantly |

## 4. Why it is different (the five talking points)

1. **Multi-tenant SaaS, not a single install.** One deployment, many hospitals, isolated by design; each hospital gets its own look and chosen modules.
2. **Built for bad internet.** Offline mode queues registrations, bills, payments, sales, appointments and records, then syncs automatically with duplicate protection, so nothing is lost and nothing is charged twice.
3. **Mixed-currency till.** A payment in USD or CDF is stored with the exchange rate and the main-currency equivalent, so reports always add up.
4. **Automation that prevents revenue leakage.** Lab orders and consultations create bills automatically, and exactly once.
5. **Production-grade safety.** Encrypted nightly off-site backups with a proven restore, instant account/hospital shutdown, audit trail, rate-limited login.

## 5. Technology (for developers in the room)

* React + Vite single-page app on Vercel; Node.js / Express 5 / Mongoose API on Render; MongoDB Atlas; GitHub Actions for backups; Backblaze B2 storage.
* Tenant isolation is enforced on the server in one place (`scope(req)`), on every query.
* Auth: JWT (8 h) re-validated against the database on each request, so revoking access is immediate.
* Idempotency-Key on every write, with a database-backed guard for offline replays.
* Feature flags per hospital, module registry on the front end: a new module is one file plus one line.
* i18n with full plural rules in English, French and Arabic (right-to-left).
* Integration test suite (126 checks at last run) covering auth, roles, tenant isolation, billing and idempotency.

## 6. Security answers (have these ready)

* **"How do you stop one hospital seeing another's data?"** Every document has a `hospitalId`; the server derives it from the signed token, never from client input, and every query is scoped. Tests verify cross-tenant requests are refused.
* **"What if an employee leaves?"** Disable the account: the next request fails, even if they hold a valid token.
* **"What about backups?"** Nightly, compressed, AES-256-GCM encrypted with a passphrase-derived key, stored off-site, 30-day retention; CI also proves the newest backup can be decrypted.
* **"What if the passphrase is lost?"** Backups become unreadable. That's why it's kept in a password manager.
* **"Passwords?"** bcrypt-hashed; login throttled per IP and per account.

## 7. Business model (adapt to your plans)

* **SaaS subscription per hospital**, tiered by enabled modules (core / +lab+pharmacy / +inpatient).
* One-time onboarding and staff-training fee.
* Optional extras: data migration from paper, custom reports, integrations (mobile money, insurers).
* Low marginal cost: new hospital = a database record, not a server.

## 8. Traction & honesty slide

* **Live** at Byarwanga Medical Centre.
* Roadmap: mobile-money payments, insurer claims, SMS reminders, deeper reports, mobile app wrapper, formal compliance review.

## 9. Demo script (5 minutes)

1. Log in as platform owner → show the hospitals list; create or open a hospital; toggle a feature.
2. Log in as the hospital admin (branding appears) → register a patient, book an appointment.
3. Doctor adds a lab order → bill appears automatically.
4. Pharmacist sells a drug → stock drops; take a payment in USD while the main currency is local → show the receipt equivalent.
5. **Wow moment:** switch the browser to offline (DevTools → Network → Offline), register a patient and record a payment, show the "waiting to sync" bar, go back online, show it syncing with no duplicates.
6. Show the audit trail and switch the language to French/Arabic.

## 10. Hard questions & good answers

| Question | Answer |
|---|---|
| Why not an existing HMS (OpenMRS, Bahmni, DHIS2)? | Those are powerful but heavy to deploy and customise. MediCore is lightweight SaaS with offline-tolerant billing and multi-currency tills out of the box. We can interoperate later. |
| Is it HIPAA/GDPR compliant? | Not certified yet. Transport encryption, access control, audit trail and encrypted backups are done; a compliance review is on the roadmap before large-scale rollout. |
| Does it scale? | Stateless API, MongoDB Atlas; scale by upgrading tiers. Production move to M10+ and a paid host is planned with the first paying hospital. |
| Single 2,500-line server file? | Deliberately organised and fully tested; splitting into routes/models is a mechanical refactor scheduled with team growth. |
| What if the internet is down for days? | Staff keep working; the queue holds changes and syncs on return. Items the server refuses (e.g. out of stock) are flagged for review, not lost. |
| Can others take your code? | The value is also in the live deployment, hospital relationships, data model and domain workflow; plus license terms (decide before sale). |
| What if you leave? | `EXTENDING.md` documents architecture, recipes, deployment and restore; configuration lives in environment variables. |
| Who owns the data? | The hospital. Backups are encrypted under a key the operator controls. |

## 11. Closing line

"We're not selling software to a hospital; we're giving every clinic in the region the reliability of a big-hospital system, without the servers, the IT team, or the need for perfect internet."
