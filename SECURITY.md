# Security Policy

MORI SOC is an **alpha** audit-evidence platform. It ships with intentionally simple
demo defaults; do not run it as-is in production.

## Supported versions

| Version | Supported |
|---|---|
| `0.6.x-alpha` (current) | security fixes |
| `< 0.6` | |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Email: **qorwlsdk1996@gmail.com** (subject: `MORI SECURITY`), or
- Use GitHub **Security → Report a vulnerability** (private advisory) on `saranf/mori-soc`.

Include: affected component/endpoint, reproduction steps, impact, and (if possible) a fix
suggestion. We aim to acknowledge within a few days.

## Scope

In scope: the MORI API (`src/mori_soc`), auth/RBAC, ingest endpoints, deployment scripts,
and the Docker Compose stack wiring.
Out of scope: vulnerabilities in bundled third-party tools (Zabbix, Wazuh, FleetDM, Trivy,
Grafana, PostgreSQL) — report those upstream.

## Demo credentials & hardening

- Demo accounts (`admin` / `security` / `monitor`, password `1234`) and default service
  passwords are **for isolated demo use only** and contain **seeded sample data only**.
- For any non-demo deployment you **must**:
  - Change `MORI_ADMIN_PASSWORD` and all service passwords (`.env`), set `MORI_DEMO_MODE=false`.
  - **Set `MORI_AUTH_ENABLED=true`.** If it is empty and LDAP is off, session auth is **disabled**
    and every API/dashboard is publicly readable — MORI now logs a loud `[security] AUTH DISABLED`
    warning at boot and surfaces it on `/health`, but the safe default is still your responsibility.
  - Serve over HTTPS behind a reverse proxy **and set `MORI_COOKIE_SECURE=true`** (session cookie
    `Secure` flag; it is off by default so HTTP demos keep working).
  - Restrict RBAC and network exposure; rotate `MORI_INGEST_TOKEN` and Zabbix/Wazuh/Fleet secrets.
- MORI connects to source tools **read-only**; it does not modify their configuration.

## Security posture (current, honest)

| Area | State |
|---|---|
| **RBAC** | `admin`·`security` only for privacy flow, evidence, and code-review findings export (code paths/snippets). Enforced when auth is on; covered by unauthenticated **and** authenticated-non-privileged tests. |
| **Session cookie** | `HttpOnly` + `SameSite=Lax` always; `Secure` when `MORI_COOKIE_SECURE=true`. |
| **OIDC** | GitHub Actions provenance verified (issuer/audience/expiry/kid/`alg=none`/repo allowlist) — failure paths tested. |
| **XSS** | Dashboard renders ingest/user data through `escapeHtml` consistently; titles/copy via `textContent`. |
| **CSRF** | Mitigated by `SameSite=Lax` (blocks cross-site POST). A dedicated CSRF token would need a frontend change and is tracked as future work. |
| **Ingest** | Bearer `MORI_INGEST_TOKEN` or GitHub OIDC. **Replay protection (nonce/timestamp) is not yet implemented** for the static-token path — treat the token as a secret and prefer OIDC. |
| **Public endpoints** | `/privacy/pii-rules.yml`, `/privacy/flow-scanner.py`, `/code-review/fullscan.py`, `/code-review/scanners/manifest.json` are intentionally unauthenticated (CI fetches them). They expose **detection patterns/admin PII terms/checksums**, not credentials — acceptable low-sensitivity disclosure by design. |
| **Audit log** | Action audit log is **hash-chained** (each entry links to the previous); `GET /admin/audit-log/verify` recomputes the chain and reports tampering/deletion. Append-only in practice (no update/delete API). Persistence to DB + external forwarding + signed export are backlog. |
| **Evidence provenance** | Every promoted control-evidence record carries `content_hash` (sha256 of its meaningful content) + `version` + `source_event_id` + `generated_at`. Re-promotion with identical content yields the same hash (provably unchanged); any change is detectable. Full append-only snapshot history per promotion is backlog. |
| **Abuse / rate limiting** | IP sliding-window limits on `/ingest/*` and `/auth/login` (429). Login lockout per (username, ip). Single-instance in-memory. |

> Known hardening not yet defaulted (needs a deployment decision, not a silent flip):
> **fail-closed auth default** (auth currently defaults *off* when unset). Set `MORI_AUTH_ENABLED=true`.
