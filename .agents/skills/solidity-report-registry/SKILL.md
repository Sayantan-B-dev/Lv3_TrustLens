---
name: solidity-report-registry
description: Use when changing ReportRegistry.sol, deploy scripts, contract tests or chain verification.
---

# Solidity report registry

Files: `backend/contracts/contracts/ReportRegistry.sol`, `backend/contracts/test/`, `backend/contracts/scripts/deploy.ts`, `backend/trustlens/services/chain.py`.

Contract rules:

- Store only `bytes32 reportRef → bytes32 digest` plus submitter/revision metadata.
- `register` is owner-only; reject zero digest and duplicate report refs.
- Emit an event for auditability.
- `getDigest` returns zero for unknown refs; `getReport` exposes metadata.
- Ownership transfer is explicit and emits an event.
- Never store URLs, message text, emails or PII.

Local workflow:

```bash
cd backend/contracts && pnpm node
cd backend/contracts && pnpm deploy:local
# set CHAIN_CONTRACT_ADDRESS, restart API
```

Use only Hardhat's public dev key against a disposable local chain. Never testnet/mainnet without explicit approval and a real key-management plan.

Verification proves integrity of committed bytes, not truthfulness. Tests: 8 Hardhat cases.
