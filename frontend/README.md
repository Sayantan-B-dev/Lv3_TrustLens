# TrustLens dashboard

Pure Next.js 16 App Router single-page client for TrustLens. By default the dashboard calls `/api/v1/*` on its own origin; Next.js rewrites those requests to the FastAPI service configured by `BACKEND_URL` (default `http://127.0.0.1:8000`). Set `NEXT_PUBLIC_API_BASE_URL` to call the backend directly with CORS instead.

```bash
# From this directory, with the backend running:
pnpm dev
```

Open http://localhost:3000. Copy `.env.example` to `.env.local` to override `BACKEND_URL` or enable direct API mode.

See the repository [README](../README.md) for the full setup, tests and environment options.

```bash
pnpm typecheck
pnpm test
pnpm build
```

All visible controls are wired to the real API. The client never assigns a risk class; it renders the server's deterministic result and evidence.
