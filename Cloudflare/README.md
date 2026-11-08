# Guardian Cloud Worker

Deploy `worker.js` to the existing `guardian-cloud-api` Cloudflare Worker.

## Required Worker secrets

- `ANTHROPIC_API_KEY`
- `GUARDIAN_ACCESS_TOKEN`

Keep both as **Secret** bindings in Cloudflare. Never commit either value to this repository or place them in the desktop executable.

## Endpoints

- `GET /health`
- `POST /api/analyze` (requires `Authorization: Bearer <GUARDIAN_ACCESS_TOKEN>`)

## Version 0.4.0 changes

- Adds a small official-domain registry for known brand domains.
- Uses hostname-boundary matching (`host === domain` or `host.endsWith('.' + domain)`).
- Returns `analysis.domainAssessment` separately from Claude's confidence score.
- Treats registry matches as a positive consistency signal, not a guarantee of safety.
- Explicitly tells Claude not to flag OCR fragments as URL mismatches.
- Keeps confidence as model-reported assessment confidence; it is never forced to 100% by a whitelist match.

The registry is intentionally small and must be maintained. Absence from the registry is not evidence of phishing. A match does not prove that a page, account, script or session is safe.

## Privacy and deployment

The desktop client sends the authoritative browser URL, OCR text and local heuristic findings only. It does not upload screenshots. Cloud analysis is user-initiated.

The current shared bearer token is suitable only for a private developer build. Do not distribute a public executable containing this shared token. Before inviting additional users, add per-user/device credentials, server-side rate limiting and usage quotas.
