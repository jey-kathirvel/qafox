# QAFox 🦊

QAFox is an open-source, AI-first quality-engineering workspace for discovering, configuring, generating, approving, executing, and reporting API tests. It is designed to work across uploaded projects—not for one specific application or framework.

> Developed by [ads-ai.in](https://ads-ai.in) — an AI-powered company.

## Product direction

QAFox starts with API testing and is intended to expand into manual, automation, security, performance, mobile, and accessibility testing. Its core principle is to reduce manual intervention while keeping every inferred value editable and every state-changing action explicitly controlled.

## Current capabilities

- Private signup, login, email verification, recovery, password/passcode support, MFA, and one-time recovery codes
- Account-isolated projects, uploads, reports, configurations, execution plans, and audit history
- Secure ZIP, TAR, TAR.GZ, TGZ, OpenAPI, and Postman Collection uploads
- Archive traversal, symlink, device-file, and compression-bomb protection
- Static API discovery and inventory with JSON/CSV export
- Framework-aware route composition and API-prefix inference
- Editable smart environment configuration with confidence and evidence
- Encrypted authentication values and custom headers
- AI-focused positive, negative, authorization, validation, boundary, path-parameter, and content-type test-case generation
- Smart test-data inference from schemas and source evidence
- Human review, enable/disable controls, and explicit approval for state-changing requests
- Immutable execution plans with SHA-256 fingerprints and one-run approval
- Hardened execution controls including TLS validation, SSRF defenses, redirect restrictions, secret masking, runtime limits, live results, and stop requests
- PWA manifest, service worker, offline page, Android icons, and Apple home-screen icon

## Project-agnostic smart-data architecture

Uploaded projects are evidence sources, not special cases. Do not hardcode project names, domains, routes, model fields, credentials, or test values.

The smart-data pipeline should:

1. Inspect OpenAPI/Postman definitions and supported source frameworks.
2. Compose mounted routers, blueprints, or controller prefixes into complete endpoints.
3. Infer parameters, schemas, validation rules, authentication, prerequisites, and data relationships.
4. Generate deterministic candidate data with confidence scores and evidence.
5. Keep all inferred inputs editable before approval.
6. Resolve prerequisites during execution without executing uploaded source code.
7. Record provenance, masking decisions, approval identity, and results.

FastAPI and Flask are the first source adapters. Planned adapters include Django/DRF, Express/NestJS, Spring Boot, Laravel, and ASP.NET Core. OpenAPI and Postman remain framework-neutral sources.

## Safety model

- Uploaded source code is inspected statically and is never executed.
- Every database query and filesystem path must be scoped to the authenticated owner.
- Secrets are encrypted at rest and masked in screens, logs, and reports.
- Public HTTPS targets are required; private, loopback, metadata, and unsafe redirect targets are blocked.
- TLS verification remains enabled.
- Safe read-only cases may be included automatically.
- State-changing cases require explicit, one-run approval.
- Destructive endpoints remain blocked unless a future policy explicitly and safely permits them.
- Execution uses immutable configuration and test-case snapshots.

## Technology

- Python 3.12+
- FastAPI / Uvicorn
- PostgreSQL 16+
- Server-rendered UI and static assets
- Apache reverse proxy with TLS in production
- systemd service management

## Repository layout

```text
app/
  main.py                  Application bootstrap and shared web routes
  recovery.py              Account recovery
  mfa.py                   Authenticator MFA and recovery codes
  projects.py              Private project upload and ownership isolation
  api_discovery.py         API discovery and inventory
  smart_data_review.py     Field-level adapter contract review
  smart_configuration.py   Project-derived configuration suggestions
  test_configuration.py    Encrypted test environments
  test_case_generation.py  Test-case and smart-data generation
  execution_planning.py    Review, approval, and immutable plans
  automated_runner.py      Hardened automated execution
  smart_data/              Project-agnostic contracts, adapters, persistence
static/                     Styles, scripts, icons, and PWA assets
data/                       Private runtime project data (not committed)
migrations/                 Numbered SQL patches (start with 004B1A-6)
```

The exact layout may evolve; keep domain logic separated from framework-specific adapters.

## Local setup

### 1. Prerequisites

- Linux or macOS
- Python 3.12+
- PostgreSQL 16+
- A dedicated database and database user

### 2. Create the environment

```bash
git clone <your-qafox-repository-url> qafox
cd qafox
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

At minimum, configure values equivalent to:

```dotenv
DATABASE_URL=postgresql://qafox_user:change-me@127.0.0.1:5432/qafox_db
QAFOX_SECRET_KEY=generate-a-long-random-secret
TEST_VAULT_KEY=generate-a-dedicated-encryption-key
QAFOX_DOMAIN=http://127.0.0.1:8091

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=no-reply@example.com
SMTP_FROM_EMAIL=no-reply@example.com
SMTP_FROM_NAME=QAFox
SMTP_PASSWORD_B64=base64-encoded-smtp-password
```

Never commit `.env`, encryption keys, SMTP credentials, uploaded projects, database exports, or generated reports.

### 4. Prepare the database

Apply the repository's current schema or migration procedure using a least-privileged PostgreSQL role.

The first numbered patch is `PATCH-QAFOX-004B1A-6` (smart-data contract persistence). Live discovery compatibility is `PATCH-QAFOX-004B1A-7`. Runtime orchestration is `PATCH-QAFOX-004B1A-8`. Response assertions are `PATCH-QAFOX-004B1A-9`: plans snapshot status, schema-field, secret/stack-trace, and duration checks; the runner evaluates them after each hardened HTTPS call. See `migrations/README.md` for backup, forward, rollback, and historical-count commands. Do not apply 004B1A-6 as a rewrite of existing API, plan, run, or result tables.

### 5. Run locally

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8091 --reload
```

Then open `http://127.0.0.1:8091` and verify:

```bash
curl --fail http://127.0.0.1:8091/health
```

## Production deployment

Run QAFox as a non-root system user behind a TLS-terminating reverse proxy. Bind Uvicorn only to loopback; do not expose it directly to the internet.

Recommended request path:

```text
Internet → Apache HTTPS → 127.0.0.1:8091 → QAFox → PostgreSQL
```

Production hardening should include:

- A systemd service with automatic restart and restricted permissions
- Apache `ProxyPass`/`ProxyPassReverse` and security headers
- A valid automatically renewed TLS certificate
- Secure cookies, CSRF protection, rate limiting, and trusted-host validation
- Restricted permissions for `.env`, private project storage, and backups
- Monitored database backups and restore tests
- Log rotation without secret leakage

## Development rules

- Keep QAFox project-agnostic. A sample project is a regression fixture, never a product-specific branch.
- Prefer adapter interfaces over framework conditions spread through business logic.
- Store confidence, evidence, and provenance for every inferred value.
- Require review for low-confidence or state-changing actions.
- Do not execute uploaded source code or install its dependencies.
- Add regression fixtures for each supported framework and upload format.
- Preserve ownership isolation in every query, route, download, and filesystem operation.

Before deployment, run the available automated tests and at least:

```bash
python -m compileall app
```

Also verify application import, registered routes, database connectivity, `/health`, ownership isolation, CSRF enforcement, and runner safety gates.

## Roadmap

- Generic smart-data intermediate representation
- Adapter registry with capability and confidence reporting
- Dependency-aware prerequisite planning and runtime value capture
- Contract, schema, security, and performance assertions
- Framework fixture matrix and golden-result regression suite
- Manual test management and reusable automation suites
- Security, performance, mobile, and accessibility modules
- Rich reports, trends, integrations, and team workflows

## Privacy

Project files, credentials, configurations, generated tests, results, and reports belong to their account owner. They must not be exposed to other users or used for advertising or external model training. Deployment operators must document retention, deletion, backup, incident-response, and any AI-provider processing that actually applies to their installation.

## Contributing

Contributions are welcome. Please open an issue describing the problem, affected adapter or module, security impact, expected behavior, and a minimal reproducible fixture. Security vulnerabilities should be reported privately rather than posted publicly.

## License

QAFox is intended to be completely open source. Add an OSI-approved `LICENSE` file before public release and update this section with the selected license. Until that file is added, no specific license grant should be assumed.

