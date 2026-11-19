# TrustLens

**AI-powered web threat detection and digital trust intelligence.** TrustLens investigates suspicious links, domains, TLS trust, website security configuration and scam messages, then explains every finding with traceable evidence. Risk classification is deterministic; AI is optional and can only explain, never decide. Completed reports can be committed to a local EVM registry and verified independently.

> Evidence first. AI second. Transparency always.

---

## What works

- URL/domain investigation with SSRF-safe fetching, DNS pinning, redirect revalidation and IDN/typosquatting heuristics.
- TLS handshake, certificate-chain and Certificate Transparency intelligence, plus passive header and mixed-content review.
- Scam-message analysis with URL/email/phone/IP IOC extraction and cross-investigation correlation.
- Deterministic, versioned risk engine with exactly five outcomes: `Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, `Inconclusive`.
- Optional AI explanation with strict evidence-ID validation, prompt-injection defences and a deterministic fallback when no key is present.
- Persistent investigation history, ownership isolation, feedback, export, automation pause/resume and automatic/manual modes.
- Durable database-backed job queue with leases, retries, exponential backoff and expired-lease recovery.
- Sanitised report export, canonical JSON + SHA-256 digest, Solidity `ReportRegistry`, local commit and independent verification.
- Single-page Next.js dashboard with anime.js motion; responsive dark interface; every visible control calls the real API.
- Backend, contract and frontend test suites plus CI and free-tier deployment configuration.

**Blockchain limitation:** the registry proves that a report's canonical bytes have not changed. It does not prove that the report's claims are true.

---

## Architecture

```text
Browser
  │
  ▼
Next.js 16 dashboard (frontend)
  │  /api/* rewrite (BACKEND_URL) or direct NEXT_PUBLIC_API_BASE_URL
  ▼
FastAPI API + embedded worker (backend)
  ├── Intelligence pipeline ── URL · DNS · HTTP · TLS · headers · messages · correlation
  ├── Deterministic risk engine (trustlens-rules-v1)
  ├── Optional AI explainer (evidence-bound, validated, fallback)
  ├── MongoDB (PyMongo) ── local mongod or a shared cluster, dedicated database
  └── EVM JSON-RPC client ── Solidity ReportRegistry (digest + report ref only)
```

The API and worker share one process for the free-tier MVP. The job queue lives in the database, so no Redis, Docker or Kubernetes is required.

---

## Stack

| Layer | Technology |
| --- | --- |
| Frontend | Next.js 16.4 App Router, React 19.3, strict TypeScript, Tailwind CSS 4, anime.js 4 |
| Backend | Python 3.13, FastAPI, Pydantic v2, PyMongo |
| Database | MongoDB 8 via `MONGODB_URL`; dedicated `MONGODB_DB` (default `trustlens`) |
| Intelligence | Python `ssl`, `cryptography`, `dnspython`, `httpx`, certifi roots |
| AI | Provider abstraction (`auto`, `none`, `mock`, `openai`, `deterministic`) |
| Web3 | Solidity 0.8.28, Hardhat 3, raw JSON-RPC + `eth-account` |
| Tests | pytest, Vitest, Hardhat/Mocha/Chai |

---

## Repository layout

```text
frontend/                Pure Next.js dashboard, API client, Vitest tests
backend/                 FastAPI app, intelligence engine, AI, worker, MongoDB document layer, pytest
backend/contracts/       Optional Solidity ReportRegistry, Hardhat config and tests
backend/run.py             Start the API or run backend commands with the venv
docs/                    SRS copy, architecture, security, testing, deployment, AI, learning
.agents/skills/          Project-specific engineering skills
.opencode/agents/        Specialist project agents
AGENTS.md                Repository rules for AI agents
README.md                This file
```

---

## Prerequisites

- **Node.js 24** and **pnpm 11** (`corepack enable` if pnpm is unavailable).
- **Python 3.13** with `venv`.
- **MongoDB 8** running locally (`mongod` or the MongoDB service on `127.0.0.1:27017`).
- Git Bash on Windows is assumed below. macOS/Linux users replace `.venv/Scripts/python.exe` with `.venv/bin/python`.
- Optional: Google OAuth credentials, an OpenAI-compatible key, a local Hardhat chain.
- No cloud account, API key or Docker is required; the core product uses a local MongoDB.

---

## Run locally

Two terminals, nothing else.

### Backend — terminal 1

First time only:

```bash
python -m venv backend/.venv
backend/.venv/Scripts/python -m pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
```

Start the API:

```bash
python backend/run.py
```

- API: <http://127.0.0.1:8000>
- Docs: <http://127.0.0.1:8000/docs>
- Health: <http://127.0.0.1:8000/health>

`backend/run.py` uses `backend/.venv` automatically. MongoDB indexes are created at startup. The default URL is `mongodb://127.0.0.1:27017` and the dedicated database is `trustlens`; set `MONGODB_URL` in `backend/.env` to use another cluster.

macOS/Linux use `backend/.venv/bin/python` instead of `backend/.venv/Scripts/python`.

### Frontend — terminal 2

```bash
cd frontend
pnpm install
cp .env.example .env.local
pnpm dev
```

Open <http://localhost:3000>.

### Environment and CORS

- **`backend/.env`** — API, database, sessions, AI, threat intel, chain.
- **`frontend/.env.local`** — backend URL and optional direct API mode.

By default the frontend calls `/api/v1/*` and Next.js proxies it to `BACKEND_URL`, so no CORS setup is needed. For direct cross-origin calls, set `NEXT_PUBLIC_API_BASE_URL` in `frontend/.env.local` and add the frontend origin to `CORS_ORIGINS` (or `FRONTEND_URL`) in `backend/.env`.

Never commit either env file.

### 5. Use it

1. Choose **URL / domain** or **Scam message**.
2. Paste a target and submit. Automatic mode queues it immediately; Manual mode saves a draft you can run.
3. Watch the progress panel, then review the risk class, coverage, evidence, TLS, headers, indicators and remediation.
4. Pause/resume automation or toggle modules from the control panels; changes persist through the API.
5. Open a completed investigation, create a sanitised report, and verify its digest. Commit on-chain only when a registry is configured.

> Try benign `https://example.com` and suspicious `https://paypa1.com`. TrustLens never fabricates findings: if a network source is unavailable, the check is reported as unavailable and can make the overall result `Inconclusive`.

---

## Database configuration

TrustLens uses MongoDB documents rather than relational tables. An investigation embeds its checks, indicators and reports, so the normal read path is one document.

### Local MongoDB (default)

Start MongoDB locally, then use the committed default:

```env
MONGODB_URL=mongodb://127.0.0.1:27017
MONGODB_DB=trustlens
```

`MONGODB_DB` is always a dedicated database name. On a shared cluster, change only `MONGODB_URL` (and optionally `MONGODB_DB` to your assigned namespace).

### Shared or hosted cluster

```env
MONGODB_URL=mongodb+srv://USER:PASSWORD@cluster.example.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=trustlens_yourname
```

Indexes are created automatically on startup when `AUTO_CREATE_SCHEMA=true`. No migration command is required. Never put credentials in Git or chat.

---

## Tests and checks

Run from the repository root. The helper scripts use `backend/.venv` automatically.

```bash
# Backend: 66 tests — SSRF/netguard, normalisation, domain, messages, risk, canonical JSON,
# API ownership, pause/manual mode, reports, worker retries/leases, AI validation fallback
python backend/run.py -m pytest

# Frontend typecheck, unit tests and production build
cd frontend && pnpm typecheck
cd frontend && pnpm test
cd frontend && pnpm build

# Solidity: compile + 8 contract tests
cd backend/contracts && pnpm build
cd backend/contracts && pnpm test

# Optional browser smoke flow (requires Google Chrome)
cd frontend && pnpm test:e2e
```

For database changes, update the document access code and index definitions in `backend/trustlens/db.py`; indexes are applied at startup.

---

## Optional: local blockchain verification

The application works without a chain. To exercise the Web3 path locally:

```bash
# Terminal 3 — local Hardhat node (chain ID 31337)
cd backend/contracts && pnpm node

# Terminal 4 — deploy once per node session
cd backend/contracts && pnpm deploy:local
```

Copy the printed address into your `backend/.env`:

```env
CHAIN_RPC_URL=http://127.0.0.1:8545
CHAIN_ID=31337
CHAIN_CONTRACT_ADDRESS=0x...
CHAIN_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

`CHAIN_PRIVATE_KEY` above is Hardhat's **public, well-known local account #0 key**. It must only ever be used against a disposable local chain. Never fund it or use it on a testnet/mainnet.

Restart the backend. In the dashboard, create a report → **Commit on-chain** → **Verify independently**. Verification should report `verified` with a matching on-chain digest. The chain stores only the report reference and SHA-256 digest — never raw URLs, message bodies, emails or PII.

---

## Optional integrations

| Integration | Required? | Configure |
| --- | --- | --- |
| AI explanation | No | `AI_PROVIDER=auto` + `AI_API_KEY`; without a key the deterministic explainer is used |
| Google OAuth | No | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`; redirect URI must match exactly |
| URLhaus | No key | `THREAT_INTEL_ENABLED=true`; optional `URLHAUS_AUTH_KEY` for higher limits |
| crt.sh | No key | `CT_LOOKUP_ENABLED=true` |
| MongoDB | Yes (local default) | `MONGODB_URL` + dedicated `MONGODB_DB` |
| EVM registry | No | local Hardhat address + local dev key |

Production must change `SESSION_SECRET`, set `COOKIE_SECURE=true`, and use `ENVIRONMENT=production`.

---

## Deployment

Detailed beginner-friendly steps are in [`docs/deployment/free-tier.md`](docs/deployment/free-tier.md). The intended free topology:

- **Vercel** — Next.js in `frontend`; set `BACKEND_URL` to the Render URL.
- **Render** — one Python web service from `backend`; `backend/render.yaml` is included.
- **MongoDB Atlas** — shared cluster; set `MONGODB_URL` and a dedicated `MONGODB_DB`.
- **GitHub Actions** — optional CI only; no workflow is bundled in this trimmed repository.

Free tiers sleep, have instance-hour and usage limits, and are not an uptime guarantee. Local development never requires these accounts.

---

## Security, privacy and honest limits

- **SSRF defence:** only `http`/`https`, only ports 80/443, credentials rejected, every resolved IP checked against private/special-use ranges, DNS pinned per hop, redirects revalidated (max 5), response capped at 64 KiB.
- **Passive only:** TrustLens fetches public pages, headers and TLS metadata. It does not exploit, brute-force, log in, execute JavaScript or download malware.
- **TLS:** certificate chains are verified with certifi's public roots; the system does not silently disable verification. Revocation and full CT coverage have limitations and are labelled as such.
- **AI:** schema-validated output; every claim must cite an existing evidence ID; unknown IDs trigger deterministic fallback; AI never sets or overrides risk. Message text is untrusted data, never instructions.
- **Privacy:** raw messages are redacted for display/logging; reports mask emails/phones and store only indicator digests and values where needed; retention defaults are 7 days anonymous / 90 days signed-in.
- **Web3:** only `report_ref` + `digest` go on-chain; verification proves byte integrity, not truthfulness.
- **No secrets in the repo.** Env files are ignored; the committed `.env.example` files contain only documented local defaults.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Dashboard shows “Cannot reach the TrustLens API” | Start uvicorn on port 8000; check `BACKEND_URL`; ensure only one process owns the port. |
| `unable to get local issuer certificate` | TrustLens already uses certifi roots. Check system proxy/VPN or corporate interception; never disable TLS verification. |
| Worker shows idle | Set `WORKER_ENABLED=true`, restart the API, check `/api/v1/system/status`. |
| Queue item stays queued | Worker disabled, automation paused, or the job is backing off after a retry. |
| MongoDB connection refused | Start `mongod` (or the MongoDB service) and check `MONGODB_URL` reaches port 27017. |
| Wrong database / missing history | Confirm `MONGODB_DB` is the dedicated TrustLens database for this environment. |
| Google sign-in redirects fail | Register the exact `GOOGLE_REDIRECT_URI`, including scheme/host/port. |
| Commit says registry not configured | Set `CHAIN_CONTRACT_ADDRESS`, restart, and ensure the Hardhat node is running. |
| Port already in use | `pnpm --dir frontend dev -- -p 3001` or change the uvicorn port and `BACKEND_URL`. |

---

## Documentation

- [SRS (verbatim source)](docs/source/SRS.md)
- [Requirements traceability](docs/traceability.md)
- [Architecture](docs/architecture/overview.md)
- [Security model](docs/security/threat-model.md)
- [Testing strategy](docs/testing/strategy.md)
- [Free-tier deployment](docs/deployment/free-tier.md)
- [AI context and prompt contract](docs/ai/README.md)
- [Demo script](docs/demo.md)
- [Learning and interview guide](docs/learning/guide.md)
- [Repository agent rules](AGENTS.md)

---

## Status

Built and validated locally on Windows/Git Bash: backend test suite, frontend typecheck/tests/production build, Solidity compile and contract tests, a live two-service proxy flow, the Playwright browser smoke flow, and a live local Hardhat report commit + verification. Optional cloud deployment and Google OAuth require your own accounts and were not deployed automatically.
