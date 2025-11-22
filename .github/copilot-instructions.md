## Lamprell — Copilot instructions (concise)

These notes make an AI coding assistant productive quickly. Read this before editing core behaviour (prompts, parsing, DB schema, or auth).

### Big picture (single paragraph)
- Single-process Node backend (`server.js`) that serves a static frontend (`index.html`, `script.js`) and implements the AI/document pipeline: text extraction (PDF.js on client + Mammoth via `/api/extract-word-text`), requirement/resume parsing (OpenRouter calls in `server.js`), and final scoring (`/api/analyze`). PostgreSQL stores users; SendGrid is optional for email.

### Key files to inspect first
- `server.js` — everything server-side: DB init (`initializeDatabase()`), OpenRouter helper `makeOpenRouterRequest()`, JSON recovery `parseJSONFromResponse()`, auth + user endpoints, rate-limit middleware (`requireApiKey`, MAX_CONCURRENT_REQUESTS, MIN_REQUEST_INTERVAL).
- `script.js` — client flow, DOM IDs (e.g. `analyzeBtn`, `jobFile`, `resumeFiles`, `saveCriteriaBtn`) and batching/rate limits used before calling server endpoints.
- `index.html` / `login.html` — UI skeleton and IDs used by `script.js`.
- `Dockerfile` / `docker-compose.yml` — development / container run commands; note `wait-on tcp:db:5432 && npm start` in `Dockerfile`.

### Developer workflows & useful commands
- Local (quick):
	- npm install
	- set env vars (PowerShell):
		$env:OPENROUTER_API_KEY = "sk-or-..."
		$env:DATABASE_URL = "postgresql://user:pass@localhost:5432/resume_analyzer_db"
	- npm start (or node server.js)
- Docker: docker compose up --build (or docker compose up -d --build). To follow logs: `docker compose logs -f app`.

### Environment & runtime gotchas (explicit)
- Required: `OPENROUTER_API_KEY` (must start with `sk-or-`). Optional: `SENDGRID_API_KEY` (starts with `SG.`) — remove if you don't use emails.
- `DATABASE_URL` must match DB: for local docker Postgres use `postgresql://user:password@db:5432/resume_analyzer_db` (or append `?sslmode=disable` to avoid SSL negotiation errors in some setups).
- DB init creates a `users` table and seeds `hradmin` / `hradmin@2025` on first run (`initializeDatabase()`). Server enforces max 5 non-admin users.

### Project-specific conventions & constraints
- Admin checks are hard-coded to `hradmin` in many endpoints (see `/api/users` checks). Changing this requires coordinated client+server updates.
- File support: PDF and DOCX only. Max single file 10MB; frontend recommends batches <200 (supports up to 500).
- Rate limits: server enforces MAX_CONCURRENT_REQUESTS = 3 and MIN_REQUEST_INTERVAL = 1000ms; client uses 1.5s API delays — adjust in `server.js` and `script.js` together.

### AI contracts & parsing rules (exact shapes you must preserve)
- `/api/extract-job-requirements` — returns a JSON object with keys: `technical_skills`, `experience_requirements`, `education_requirements`, `soft_skills`, `industry_experience`, `certifications`, `additional_requirements`.
- `/api/extract-resume-data` — returns object: `name`, `technical_skills`, `experience_years`, `work_experience`, `education`, `certifications`, `soft_skills`, `industry_experience`, `key_achievements`, `tools_technologies`.
- `/api/analyze` — expects `jobRequirements` + `resumeDataList`; returns an array of { name, score (0-100), reasoning, strengths[], weaknesses[] } sorted by score. Keep these exact keys; `parseJSONFromResponse()` tries to salvage malformed LLM output.

### Common editing pitfalls and fixes
- Native modules in Docker: do NOT copy host `node_modules` into the image. Use `.dockerignore` (added) and avoid mounting host `node_modules`. If you see bcrypt Exec format errors, rebuild image after ensuring `.dockerignore` excludes `node_modules`, or add a volume mapping for `/app/node_modules` in `docker-compose.yml`.
- When changing an API contract, edit `server.js` validation/parsing and update `script.js` UI code (DOM ids and request/response handling) together.

### Quick debugging checklist
- Tail server logs: `docker compose logs -f app` or run `node server.js` locally and watch console.
- DB issues: `docker compose exec db psql -U user -d resume_analyzer_db -c '\l'` to inspect DB.
- OpenRouter/key errors: server responds with clear messages — check `OPENROUTER_API_KEY` format and runtime logs for model fetch attempts.

If anything here is ambiguous or you want the file to include CI steps, an `.env.example`, or small tests for `parseJSONFromResponse()`, tell me which and I'll add it.

