---
name: mongodb-document-model
description: Use when changing MongoDB collections, document shapes, indexes, ownership or embedded investigation data.
---

# MongoDB document model

Files: `backend/trustlens/models.py` (document factories), `backend/trustlens/db.py` (client, dedicated database, indexes).

Model:

- `investigations` embeds `checks`, `indicators` and `reports`, so the normal read path is one document.
- `jobs`, `users`, `sessions`, `automation_settings`, `feedback`, `audit_events`, `rule_versions` and `worker_heartbeats` are separate collections.
- IDs are string UUIDs stored as `_id`; timestamps are UTC-aware BSON datetimes.
- Ownership stays `owner_kind` + `owner_id` on investigations and is checked server-side.

Rules:

- `MONGODB_DB` must stay dedicated even on a shared cluster; only `MONGODB_URL` should need to change per environment.
- Declare indexes in `db.init_db()`; there are no SQL migrations. Keep startup idempotent.
- Do not use multi-document transactions for the local-first path; use atomic single-document updates and idempotency.
- Update document factories, API serialisers, `frontend/lib/types.ts` and tests together.
- Never trust a client-supplied owner or risk class.

Verify: `python backend/run.py -m pytest` and a smoke run against local MongoDB (`MONGODB_URL=mongodb://127.0.0.1:27017`, scratch `MONGODB_DB`).
