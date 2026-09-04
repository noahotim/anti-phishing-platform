# Testing

The suite lives in `backend/tests/` and runs with pytest against FastAPI’s
TestClient on a **temporary database** (`conftest.py` points `DATABASE_PATH`
into a per-session temp dir and initialises + seeds before any test). Your real
`backend/data/antiphishing.db` is never touched.

## Running

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest            # normal detail
..\.venv\Scripts\python.exe -m pytest -q         # quiet
..\.venv\Scripts\python.exe -m pytest -k email   # single area
```

On Windows consoles, fixtures containing Cyrillic/IDN samples may trip the
cp1252 codec — set `$env:PYTHONIOENCODING='utf-8'` first.

## What is covered (134 tests)

| File                    | Verifies                                                       |
|-------------------------|----------------------------------------------------------------|
| `test_url_parser.py`    | host/decomposition, ports, credentials, `split_registered_domain` with real public suffixes |
| `test_homoglyph.py`     | confusable folding, circled letters, mixed-script detection    |
| `test_similarity.py`    | fold-match, edit distance, misleading subdomains, suffix embedding, brand prefixes |
| `test_risk_scorer.py`   | weight aggregation, classification bands, one-char typosquat → MALICIOUS |
| `test_analyzer.py`      | end-to-end dataset (SAFE/SUSPICIOUS/MALICIOUS + matched domain), reasons, trusted green |
| `test_ssrf.py`          | SSRF guard rejects non-allow-listed targets; metadata URLs are never fetched |
| `test_auth.py`          | login, wrong password, disabled account, `/me`, logout, RBAC    |
| `test_api.py`           | full HTTP layer: thresholds validation, trusted domains CRUD, reports, audit, email impersonation via API |
| `test_rate_limit.py`    | standalone app: 429 enforcement and per-route-group buckets     |
| `test_email.py`         | sender impersonation, safe mail, link display-text/href mismatch, keywords, attachments, Reply-To |
| `test_ti_sync.py`       | URLhaus hostfile parsing (dedupe/caps), feed upsert idempotency, eviction, stub-fetcher sync, failure tolerance |
| `test_content_policy.py`| blocked-site CRUD + CSV import, per-category enforcement in the scanner, lifting a category lifts the block, content-policy settings validation, uncategorized entries stay malware |
| `test_precheck.py`      | anonymous `precheck` (blocked verdicts, no scan/audit rows, policy lift respected, validation), anonymous `guard/rules` feed (active-category filtering, labels) |

## Culture / tips

- **Fixture dependencies matter:** `analyzer` and other DB-backed fixtures
  depend on the authenticated `client` fixture precisely so `init_db` + `seed`
  have already run. If you add a test that builds a service directly, give it a
  `client` parameter too — otherwise you’ll hit `sqlite3.OperationalError: no
  such table`.
- **Rate-limit tests** build their own bare FastAPI app with the middleware;
  they never depend on the full app.
- **Deterministic datasets:** classification expectations in
  `test_analyzer.py::DATASET` are pinned to the current weights. If you change
  a weight in `risk_scorer.py`, re-run that test and update expectations
  deliberately (they encode product behaviour, not just code).
- Anonymous scans resolve to org 1 — tests that need attribution should log in
  first.
- Stress critical thinking in reviews rather than coverage: for this product
  the interesting assertions are “did it match the *right* trusted domain” and
  “was the verdict safety-first (unapproved never SAFE)”.

## Adding an integration smoke test

```powershell
# quick end-to-end against a running dev server
$tok = (curl.exe -s -X POST http://127.0.0.1:8000/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"email":"admin@company-example.com","password":"<your .env password>"}' | ConvertFrom-Json).token
curl.exe -s -X POST http://127.0.0.1:8000/api/analyze/url `
  -H "Authorization: Bearer $tok" -H "Content-Type: application/json" `
  -d '{"url":"https://paypa1-secure.com/login"}'
```