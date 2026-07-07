# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this is an alpha project so
versions are `x.y.z-alpha.n`.

## [v0.7.0-alpha.1] — 2026-07-07 — CSOP Evidence Ingest + Brownfield Mode

### Added
- **CSOP evidence ingest** (`POST /ingest/evidence`): remote scanners/agents push a
  "before/after" diff envelope (`delta_type` new/fixed/reopened) — persisted verbatim as
  JSONB in `ui_evidence_events` (`schema/006`) with extracted `host_id`/`artifact_name`/
  `delta_type`/`cve`/`summary` for filtering. Accepts a single envelope or `{"events":[…]}`.
- **Evidence read API** (`GET /evidence`): newest-first list with `host`/`delta` filters,
  gated to **admin·security** roles (same visibility policy as the risk register).
- **Trivy ingest host↔image mapping**: `POST /ingest/trivy` now accepts a hostname via
  `?hostname=` / `X-MORI-Hostname` header / body `hostname`, so image scans
  (`ArtifactName=alpine:3.19`) bind to the real Zabbix/Fleet host instead of the artifact
  name. Backward-compatible (omit → previous ArtifactName derivation).
- **Brownfield mode**: bundled Zabbix/Fleet/Wazuh stacks moved behind compose profiles
  (`bundled`, and per-source `zabbix`/`fleet`/`wazuh`). `docker compose up` now starts
  **MORI core only** (api + worker + postgres + dashboards) and connects to existing
  infrastructure via `.env`. `docs/BROWNFIELD_CONNECT.md` guide added; `.env.example`
  gains a brownfield source-connection block + Fleet/Wazuh API scaffolding vars.

### Changed
- `MORI_INGEST_TOKEN` and `MORI_ADMIN_PASSWORD` are now passed through to the `mori-api`
  container (were defined but never wired) — token-based ingest works without a login
  session, and the admin password is configurable from `.env`.
- Session-auth middleware bypasses `/ingest/*` so the endpoints' own token-or-session auth
  governs remote pushes (previously the middleware blocked token pushes when auth was on).
- `mori-worker` / `mori-poller-zabbix` no longer hard-depend on the bundled `zabbix-web`
  (they retry the source each cycle) — required for pointing at an external Zabbix.

### Security
- Default `MORI_ADMIN_PASSWORD` replaced in `.env` with a strong value; `/health`
  `insecure_defaults` no longer flags it.

## [v0.6.0-alpha.1] — 2026-07-07 — Zabbix Evidence Flow + Risk Register

### Added
- **Zabbix evidence flow (verified end-to-end against the real Zabbix API)**: problem →
  `mori-worker` `problem.get` polling → PostgreSQL `alerts` → Alert Triage (`source=zabbix`)
  → Incident → CSV/PDF evidence → **resolve** (Zabbix recovery → `alert.resolved_at`).
- **Risk assessment (R-series)**: per-CVE 3×3 impact × likelihood matrix, treatment
  decision (mitigate/accept/transfer/avoid), residual risk, admin-only provenance panel,
  role-gated (admin/security). Persisted in `ui_risk_register` (`schema/004`).
  Risk Register CSV/PDF report (6th audit-evidence report).
- **Role-aware dashboard**: security hero + 24h/12h infra status with Zabbix/Wazuh deep
  links; panel editing (per-user widget on/off + drag-resize, persisted).
- **Compliance PDCA** on real ISMS-P criteria (2.x controls); weakness-rate summary.
- **Trivy HTTP ingest** (`POST /ingest/trivy`) for remote endpoints; token auth.
- **Onboarding**: `mori-endpoint-onboard.sh` (Zabbix Agent 2 + Trivy, one-command/curl),
  `mori-zabbix-template.sh` (MORI Zabbix template with LLD + macros; exported YAML),
  `mori-community-pr.sh` (assemble a zabbix/community-templates PR).
- **CI**: GitHub Actions `tests` workflow (ruff + unittest); deploy workflow hardened to
  skip gracefully when deploy secrets are absent.
- **Docs**: Zabbix agent, deploy SSH, Fleet, Wazuh, community-template PR guides;
  `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- Alert `resolved_at` (`schema/005`), Zabbix ↔ Alert Triage bidirectional URL links.

### Changed
- Dashboard reads PostgreSQL **live per request** (postgres backend) — worker-ingested
  data surfaces with no API restart.
- READMEs (KO/EN) reworked: 30-second Status table; demo security notice; Zabbix marked
  **verified**, Fleet/Wazuh **Next**, Trivy **partial**.

### Removed
- Removed the public demo-server URL/credentials block and internal "resume prompt" from
  the README.

## [v0.5.0-alpha.2] — Core Structure Stabilization
- `server.py` modularized into `routes/` (16 domain modules) + `RouteContext`.
- Prepared Phase 2 PostgreSQL persistence (M2-1) foundation.

## [v0.4.0-alpha.1]
- Initial audit-ready operations UI, seed data, compliance/reporting scaffolding.
