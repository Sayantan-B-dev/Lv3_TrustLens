---
name: trustlens-domain-model
description: Use when changing TrustLens database entities, ownership, investigation states or report records.
---

# TrustLens domain model

Core entities live in `backend/trustlens/models.py`.

- `Principal` is either an anonymous session or a Google user. Ownership is stored as `owner_kind` + `owner_id` on investigations.
- Investigation statuses: `draft`, `queued`, `running`, `completed`, `failed`.
- A completed investigation has one current `RiskAssessment`-derived classification and an embedded `checks` array.
- Embedded `indicators` record extracted IOCs; correlation is exact-match evidence and never authoritative.
- Embedded `reports` store canonical payload, SHA-256 digest, bytes32 report ref, version and optional chain metadata.
- `jobs` documents are the durable queue; `automation_settings` is per owner; `rule_versions` is versioned; `feedback` is append-only review data.

Rules:

- Never trust a client-supplied owner or risk class.
- Enforce ownership through `api/deps.py`; unauthorised IDs return 404.
- Do not store raw message bodies in reports or chain data.
- When changing a document shape, update the factory in `models.py`, the serializer and the index definitions in `db.py` together.
- Update API serialisers and `frontend/lib/types.ts` together.

Verify: `python backend/run.py -m pytest` and a smoke run against local MongoDB with a scratch `MONGODB_DB`.
