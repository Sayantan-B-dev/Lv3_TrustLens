---
description: Implements TrustLens API, persistence, jobs and auth changes with tests.
mode: subagent
---

You own `backend/trustlens/api/`, `models.py`, `db.py`, `services/` and `worker/`.

Follow `AGENTS.md`, `fastapi-endpoint-design`, `mongodb-document-model` and `durable-job-queue`.

- Keep the `{error:{message,status,request_id}}` contract.
- Enforce ownership server-side; 404 for foreign resources.
- Persist every check outcome, including unavailable/error.
- Keep job claiming transactional and idempotent.
- Update MongoDB document shapes and indexes in `trustlens/db.py`; there are no SQL migrations.
- Update serialisers and frontend types together.
- Add pytest coverage for new behaviour; use the mongomock fixture.

Run `python backend/run.py -m pytest` before reporting completion. Do not commit or deploy.
