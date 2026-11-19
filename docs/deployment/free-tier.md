# Free-tier deployment: Vercel + Render + MongoDB Atlas

This guide deploys the existing code. The agent did **not** create accounts, deploy, or spend testnet funds. Do not commit secrets. Free tiers change; verify current limits before relying on them.

## 1. Database — MongoDB Atlas

1. Create a free MongoDB Atlas cluster in the closest available region.
2. Create a database user and allow the Render egress address.
3. Copy the driver connection string into `MONGODB_URL`.
4. Choose a dedicated database name (for example `trustlens` or `trustlens_yourname`) for `MONGODB_DB`. Do not reuse another app's database name on a shared cluster.
5. Local alternative: MongoDB 8 on `mongodb://127.0.0.1:27017` with the same `MONGODB_DB`.

## 2. Backend — Render

The repository includes [`backend/render.yaml`](../../backend/render.yaml). Either use the blueprint or create a Web Service manually:

- **Repository:** this repo.
- **Root directory:** `backend`.
- **Runtime:** Python 3.13.
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `uvicorn trustlens.main:app --host 0.0.0.0 --port $PORT`
- **Health check path:** `/ready`
- **Plan:** Free (note: sleeps after inactivity).

Environment variables:

```env
ENVIRONMENT=production
MONGODB_URL=mongodb+srv://USER:PASSWORD@cluster.example.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=trustlens
SESSION_SECRET=<generate a long random value>
COOKIE_SECURE=true
FRONTEND_URL=https://your-app.vercel.app
CORS_ORIGINS=https://your-app.vercel.app
WORKER_ENABLED=true
AI_PROVIDER=auto
AI_API_KEY=<optional>
THREAT_INTEL_ENABLED=true
CT_LOOKUP_ENABLED=true
```

Optional: Google OAuth (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI=https://your-app.vercel.app/api/v1/auth/google/callback`), chain variables only if you intentionally run a registry.

Do not set `CHAIN_PRIVATE_KEY` on Render unless you have a deliberate signer design. The local Hardhat key is public.

After deploy, check:

```bash
curl https://YOUR-SERVICE.onrender.com/health
curl https://YOUR-SERVICE.onrender.com/ready
```

If startup fails, confirm `MONGODB_URL` is reachable from Render and that the Atlas user can read/write `MONGODB_DB`. Indexes are created on startup.

## 3. Frontend — Vercel

1. Import the repository into Vercel.
2. **Root Directory:** `frontend`.
3. Framework preset: Next.js. Build command `pnpm build` (default), install at repo root via the workspace.
4. Environment variable:

```env
BACKEND_URL=https://YOUR-SERVICE.onrender.com
```

5. Deploy. Open the Vercel URL. The `/api/*` rewrite proxies to Render, so cookies stay on the Vercel origin.

If Vercel's build cannot see workspace dependencies, set the project root to the repository root and the output/app directory to `frontend`; the included `pnpm-workspace.yaml` is the source of truth.

Update Render's `CORS_ORIGINS`/`FRONTEND_URL` to the final Vercel domain after the first deploy, then restart the service.

## 4. Google OAuth (optional)

In Google Cloud Console:

- Authorised JavaScript origin: `https://your-app.vercel.app`
- Authorised redirect URI: `https://your-app.vercel.app/api/v1/auth/google/callback`

Set the same values in Render. A mismatch produces `redirect_uri_mismatch`. Without OAuth, anonymous demo sessions still work.

## 5. Blockchain (optional, not required for hosting)

Local only by default. A public testnet would require explicit approval, a funded deployer, and a deliberate key-management decision. Never use the documented Hardhat key on a public network. If no registry is configured, the UI clearly shows “Registry offline” and still verifies the canonical digest locally.

## 6. CI

This trimmed repository does not bundle a CI workflow. If you add one, run:

- `python backend/run.py -m pytest`
- `cd frontend && pnpm typecheck && pnpm test && pnpm build`
- `cd backend/contracts && pnpm test`

No secrets are required for those checks, and none of them deploy.

## Free-tier limitations (be honest with judges/users)

- Render Free services sleep after inactivity; the first request may be slow. Monthly instance-hour limits apply.
- MongoDB Atlas Free has storage and connection limits; shared clusters have noisy-neighbour effects.
- Vercel Hobby has usage and commercial-eligibility restrictions.
- No SLA, no guaranteed uptime, no managed backups on free plans.
- The embedded worker stops when the web service sleeps; queued jobs resume after wake.
- AI/URLhaus/crt.sh/Google are external dependencies with their own quotas and outages.
- In-process rate limiting is per instance; it is not a distributed control.

## Production hardening checklist

- Strong `SESSION_SECRET`; secure cookies; HTTPS everywhere.
- Restrict CORS/frontend URLs to the real origin.
- Rotate any key that was ever exposed; never commit `.env`.
- Use a dedicated DB role with least privilege.
- Monitor `/ready`, worker heartbeat and queue depth.
- Add a shared rate limiter and an egress-restricted fetch proxy if scaling beyond a demo.
- Review retention and privacy requirements for your jurisdiction.
