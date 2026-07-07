# MORI SOC — Audit-Ready Security Operations

[🇰🇷 한국어 README](./README.md) · **🇬🇧 English (this page)**

[![tests](https://github.com/saranf/mori-soc/actions/workflows/test.yml/badge.svg)](https://github.com/saranf/mori-soc/actions/workflows/test.yml)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Phase](https://img.shields.io/badge/phase-2%20(audit--ready)-yellow)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey)

## TL;DR

A one-line (`docker compose up -d`) **ISMS-P / ISO 27001 audit-evidence accumulation platform**. Integrates Zabbix · FleetDM · Wazuh · Trivy · Loki to operate assets / vulnerabilities / alerts / incidents + control checks on a single screen (`/ui`), automatically accumulating every change with *who / when / what* metadata.

- 🎯 **Target audience** — Small to mid-sized organizations with 1–2 security staff + IT helpdesk preparing for ISMS-P / ISO 27001
- 🚀 **One-line start** — `./scripts/mori-start-demo.sh` → `http://localhost:18000/ui` (`admin / 1234`, demo only)
- 📊 **Screens** — Unified dashboard · Alert Triage · Incidents · Assets / Vulnerabilities · **Risk Assessment Matrix** · Compliance PDCA · 6 audit-evidence CSV/PDF reports
- 🎯 **Risk Assessment (R-series)** — Per-CVE **Risk = Impact (asset importance H/M/L) × Likelihood (severity)** scored on a 3×3 matrix, with treatment decision (mitigate/accept/transfer/avoid) · residual risk · review date. **Admin-only assessment-basis (provenance)** panel. Based on ISMS-P risk management / ISO 27001 6.1.2·8.8
- 🔐 **Role-aware screens** — Risk assessment is **admin·security only**; infra/helpdesk see only **their servers' vulnerabilities & remediation rate**. The dashboard is a **role-aware security hero + 24h/12h infra status (Zabbix/Wazuh deep links)**, with **panel editing** for per-user widget selection (persisted)
- 🌐 **Multi-language UI** — Korean / English toggle on every page (login, dashboard, admin console); moved from a fixed top-right widget into the **account menu (👤)**, persisted in a cookie + localStorage and switches instantly without a reload
- 👤 **User profile + My Servers** — Save name · department · assigned servers to your account, and view only your assets in a dedicated **⭐ My Servers** view (profile-menu shortcut)
- 🧾 **Automatic evidence** — Asset owner/importance, host/CVE-level remediation plans & exceptions, **per-CVE risk assessment**, Triage & Incident state changes
- ✅ **Persistence (M2-1 + R-2 done)** — UI operational state stores (asset owners · audit log · vuln actions · Triage · Incidents · profiles + the **risk register `ui_risk_register`**) are **write-through persisted** to PostgreSQL and survive restarts.
- 🔌 **Live data integration** — **Zabbix real-time polling is verified against the real API** (problem→Triage→Incident→evidence→resolve). **Trivy/CSOP integrate via remote token push** (`/ingest/trivy`·`/ingest/evidence`). **Fleet / Wazuh live integration is Next**.
- 🧩 **Brownfield** — for existing Zabbix/Wazuh/Fleet, run **MORI core only and connect via `.env`** (no bundled sources). `docker compose up` = core only, `--profile bundled` = bundled demo. → [guide](docs/BROWNFIELD_CONNECT.md)

> ⚠️ **Alpha / Work in Progress** — Day-to-day security operations + audit-evidence accumulation work, and **UI operational state is persisted to PostgreSQL (M2-1 · R-2)** across restarts. **Zabbix real-time polling is verified against the real API**, so problem→alert→Triage flows live with no restart (other seed data is for demo). **Fleet / Wazuh live integration is the next step.**

## ⚡ Status — 30-second overview

| ✅ Works now | 🧪 Partially integrated | 🚧 Next |
|---|---|---|
| **✅ Zabbix real-time polling → alerts (verified)** | Trivy collector local polling (ingest done) | **FleetDM live API poller** |
| **✅ Trivy/CSOP remote push + evidence ingest** (`/ingest/trivy`·`/ingest/evidence`, token) | Source freshness / Worker cycle | **Wazuh live API poller** |
| **✅ Brownfield connect** — existing Zabbix/Trivy via `.env` config only (no bundled sources) | | LDAP/AD production integration |
| Alert triage / Incident workflow · per-CVE **risk assessment** | | Slack / Email notifications |
| Login / RBAC · PostgreSQL-backed UI state · CSV/PDF evidence export | | Live-read caching (perf) |

> ✅ **Zabbix** is **verified end-to-end** against the real API (*problem → collect → Triage → Incident → evidence → resolve*, see [🎬 scenario](#-end-to-end-scenario--zabbix-operational-problem--audit-evidence-verified-against-the-live-api)). **Fleet / Wazuh** collectors/parsers are ready but **live integration is the next step**.

> 🔒 **Demo credentials notice** — Demo credentials (`admin` / `security` / `monitor`, password `1234`) are **intentionally simple for isolated demo use only**. The demo instance contains **seeded sample data only**; **no production secrets or real customer data are stored.** For any non-demo deployment, **change credentials and RBAC settings immediately** (`.env`: `MORI_ADMIN_PASSWORD`, `MORI_DEMO_MODE=false`).

## 🎬 End-to-end scenario — Zabbix operational problem → audit evidence (verified against the live API)

MORI's core value: **turn the operational data Zabbix already produces into ISMS-P / ISO 27001 audit evidence.** The pipeline below works **end-to-end against the real Zabbix API** (no API restart — the API reads PostgreSQL live on every request).

> 💡 This scenario needs the bundled Zabbix. The brownfield default (`docker compose up`) starts core only, so bring up the demo Zabbix with `docker compose --profile zabbix up -d` (or `--profile bundled`). With an existing Zabbix, just repoint `MORI_ZABBIX_API_URL` in `.env` → [brownfield guide](docs/BROWNFIELD_CONNECT.md).

1. **A Zabbix problem occurs** — demo: `./scripts/mori-zabbix-demo-problem.sh` (fires a trigger on the Zabbix server → a real problem event)
2. **MORI worker collects** — `mori-worker` polls `problem.get` every 30s → normalizes (severity/host/timestamp) → upserts into PostgreSQL `alerts` + records source freshness
3. **Surfaces in Alert Triage** — `/ui` → 🚨 Alert Triage shows it **immediately** with `source=zabbix`
4. **Triage** — 3-tier state (🔴🟡🟢) + analyst · actor · change history
5. **Incident** — promote the alert into an incident with owner / status / notes
6. **Evidence export** — incidents / monthly / **risk register** as CSV·PDF

> In other words, MORI is not "another security tool" — it is a **read-only layer that turns Zabbix operational data into ISMS-P / ISO 27001 audit evidence (who · when · what · on what basis).**

A lightweight SOC platform built by integrating open-source security tools so that **evidence, control checks, and remediation history required for ISMS-P / ISO 27001 audits** can be collected, managed, and exported in one place.

> **Goal:** A "Compliance-Evidence Platform" that lets IT helpdesk + 1 designated owner at a small/mid-sized organization deploy with a single `docker compose` command, running ISMS-P / ISO 27001 preparation alongside daily security operations.

> 🔌 **A read-only evidence layer on top of your existing tools** — **MORI-SOC is designed to sit on top of existing monitoring and security tools, not replace them.** It connects to your running Zabbix / Wazuh / FleetDM / Trivy in **read-only mode via configuration only** (no agent installation, no change to existing tool configuration) and organizes operational evidence, incident history, vulnerability actions, and compliance views.

### Product positioning — not the "viewing layer", the "evidence layer"

MORI is **not a unified monitoring dashboard.** Time-series, log exploration, and real-time visualization are delegated to the tools that already do them well (**Grafana/Loki**); MORI sits one layer above and owns **"judge, record, prove."**

| Layer | Owns | Tool |
|---|---|---|
| **Viewing layer** | time-series · logs · real-time visualization | Grafana · Loki *(delegated via deep links)* |
| **Evidence layer (MORI's place)** | triage → remediation workflow → control mapping → evidence PDF → audit log | **MORI API** (`/ui`) |

> Core thesis: the product is **not "unified monitoring" — it's "monitoring that becomes ISMS-P / ISO 27001 evidence as you look at it."**

### Why these five — per-source ISMS-P coverage

Each source owns a **non-overlapping set of certification controls.** This mapping is both the rationale for the stack and the basis for poller ordering ("fill the largest evidence gap first").

| Data source | ISMS-P controls (representative) | ISO 27001 Annex A | Evidence form | MORI status |
|---|---|---|---|---|
| **Fleet** (osquery) | 1.2.1 asset ID · 2.1.3 asset mgmt · 2.10.6 endpoint | A.5.9 · A.8.9 | Asset inventory / config state | 🔲 Phase 3 |
| **Zabbix** | 2.9.x operations/monitoring · availability | A.8.6 · A.8.16 | Uptime · threshold alerts + handling history | ✅ Live (verified) |
| **Trivy** | 2.10.8 patch mgmt · 2.11.2 vuln check/remediate | A.8.8 | Scan history · remediation plans · exception approvals | ✅ Remote push |
| **Wazuh** | 2.9.4~5 log mgmt · 2.10.9 malware · 2.11.3 anomaly | A.8.7 · A.8.15 · A.8.16 | Detection events · rule matches · response records | 🔲 Phase 3 |
| **Loki** | 2.9.4 log retention (statutory access-log retention) | A.8.15 | Retention policy + storage proof | 🟡 Collect |
| **MORI itself** | 1.x management system · 2.11.4~5 incident response | A.5.24~27 | Incident tickets · audit log · PDCA | ✅ Core |

> 🧭 **Fleet = foundation work**: an ISMS-P audit **starts with asset identification.** A weak asset list cascades into "unclear scope" defects across vulnerability management, access control, and logging. The Zabbix×Fleet×Trivy **reconciliation** is the strongest asset evidence there is — and something most orgs can't do.
>
> 💡 Once the control catalog (Phase 2) lands, this mapping auto-derives **"lite = N% control coverage / full = M%"**.

---

## 🗺️ Architecture Diagram

```mermaid
flowchart LR
    subgraph SRC["Data Sources"]
        Z[Zabbix]
        F[FleetDM]
        W[Wazuh]
        T[Trivy]
        L["Loki + Fluent Bit"]
        D["LDAP / AD"]
    end

    subgraph COL["Collection layer (src/mori_soc/collectors, pollers)"]
        C1[zabbix_collector]
        C2[fleet_collector]
        C3[wazuh_collector]
        C4[trivy_collector]
        C5[ldap_collector]
        WK["worker.py<br/>(periodic polling)"]
    end

    subgraph SVC["Service layer (services)"]
        N[normalization<br/>EnvelopeEntityMapper]
        I[ingestion]
        R[risk_score]
        AC[asset_classifier<br/>importance scoring]
        QC[query_catalog<br/>12 intents]
        QS[query_service<br/>_INTENT_HANDLERS]
        V[views<br/>latest/risk/timeline]
        RP[reports<br/>5 CSV types]
    end

    subgraph REPO["Repositories"]
        PG["PostgreSQL<br/>normalized seed data<br/>(hosts/alerts/vulns/observations…)"]
        MEM["InMemoryRepository<br/>(query cache — current)"]
        STR["UI operational state<br/>PostgreSQL-backed cache<br/>asset_owners / asset_audit_log / vuln_actions<br/>triage_store / incident_store / user_profiles"]
    end

    subgraph API["MORI API (api/)"]
        SRV["server.py<br/>orchestrator (888 lines)<br/>builds RouteContext + registers modules"]
        RT["routes/ package (16 domain modules)<br/>auth · assets · alerts · vulnerabilities<br/>incidents · compliance · query · pages<br/>rbac · audit · plans · guides · sources<br/>webhooks · dashboard_prefs"]
        UI["Unified ops UI (/ui)<br/>Overview · Assets · Trivy · Triage<br/>Incidents · Compliance · Reports"]
    end

    subgraph OUT["Outputs / Evidence"]
        G[Grafana dashboards]
        CSV["Audit-evidence CSV<br/>5 types + PDCA pending"]
        AUD["Change history<br/>(host·CVE·Triage·Incident)"]
    end

    Z --> C1
    F --> C2
    W --> C3
    T --> C4
    D --> C5
    L --> G

    C1 & C2 & C3 & C4 & C5 --> WK
    WK --> N --> I
    I --> AC & R
    AC & R --> MEM

    MEM --> V & QS & RP
    QC --> QS
    SRV --> RT
    STR <-->|RouteContext| RT

    V & QS & RP --> RT
    RT --> UI
    RT --> CSV
    UI --> AUD

    PG --> MEM
    STR -- M2-1 write-through persistence --> PG
```

> Solid lines = current operating flow. With `MORI_QUERY_BACKEND=postgres`, the **API reads a fresh PostgreSQL snapshot on every request** (materialized into an InMemoryQueryStore per request) — i.e. a **live read, not a boot snapshot**. So data ingested by `mori-worker` (e.g. **real Zabbix problems → alerts**) surfaces on the **next request with no API restart**. UI operational state (triage / incidents / asset owners / vuln actions / asset audit log / user profiles + risk register) is persisted to PostgreSQL via **cache-aside + write-through** (M2-1 · R-2). ✅ **Zabbix real-time polling is verified working** (see [🎬 end-to-end scenario](#-end-to-end-scenario--zabbix-operational-problem--audit-evidence-verified-against-the-live-api)); Fleet/Wazuh live integration is the next step.
>
> **API structure (Task J done):** `server.py` is now a **thin orchestrator (888 lines)** that assembles in-memory state and helper closures into a `RouteContext`, then registers 16 domain modules. Each endpoint is owned by `register_<domain>(ctx)` in `routes/<domain>.py`, and the 6 in-memory stores are shared across modules via the `RouteContext`.

---

## 🎯 Core Concept — Audit-Ready

The "who, when, with what data, made what decision" trail that audits frequently require is automatically accumulated across every compliance-sensitive area.

| Area | Recorded change | Storage |
|---|---|---|
| Asset owner / team / category / **importance** | `field`, `old_value`, `new_value`, `changed_by`, `changed_at` | `asset_audit_log` (per host) |
| Host-level remediation plan / exception | Same (plan text, target date, exception expiry, reason) | `asset_audit_log` |
| **CVE-level remediation plan / exception** | Labels like `vuln_plan_text [CVE-…]` / `vuln_exception_until [CVE-…]` consolidated into the same host history | `asset_audit_log` (viewed per-host via 📋 history modal) |
| Alert Triage state change (🔴🟡🟢) | `status`, `note`, `analyst`, `changed_by`, `changed_at` | `triage_store` + history |
| Incident change history | State / assignee / impact / note changes + author/time | Incident history (`/incidents/{id}/history`) |

### Host-level vs CVE-level — UX consistency

A guidance modal automatically surfaces so that host-level bulk plans don't conflict with CVE-level detailed plans.

- If a host has **any CVE-level remediation plan/exception**, host-level edits trigger a *"Detailed plans are configured. Please check the totals tab."* modal that directs the user to the totals tab (CVE-level edit screen).
- Change history is consolidated chronologically — host-level + CVE-level changes appear together in a single 📋 history modal per host.

---


## 🗺️ Current Status at a Glance

### ✅ What works now — Seed security data + PostgreSQL-backed UI operational state

| Category | Feature | Notes |
|---|---|---|
| **Auth/RBAC** | Login / session / RBAC (per-role tab on·off) / signup request & approval | Demo accounts `admin` / `security` / `monitor` (password `1234`) — **seeded sample data only · demo only. Must be changed for production** |
| **Overview** | Asset/alert/vuln summary cards + Critical vulnerability detail modal exposing **plan / exception** columns | Per-host progress visible right on the dashboard |
| **Assets (Server / PC / Trivy)** | Per-host owner/team/category edits + **manual override of server asset importance** | Takes priority over auto-classification (asset_classifier). Audit log records every change |
| **Vulnerability management (Trivy)** | Host-level remediation plan / exception + **per-CVE detailed plan / exception** | Author / target date / expiry / reason recorded. Conflict guidance modal |
| **📥 Remote ingest (v0.7)** | `POST /ingest/trivy` (raw report, `?hostname=` host mapping) · `POST /ingest/evidence` (CSOP before/after diff envelope) — **session-less push** via `MORI_INGEST_TOKEN` | Evidence in `ui_evidence_events` (`schema/006`). `GET /evidence` admin·security only |
| **🧩 Brownfield mode (v0.7)** | `docker compose up` = MORI core only → connect to existing Zabbix/Trivy via `.env`. Bundled sources behind `--profile bundled`/`zabbix`/`fleet`/`wazuh` | [docs/BROWNFIELD_CONNECT.md](docs/BROWNFIELD_CONNECT.md) |
| **🎯 Risk Assessment (R-series)** | Per-CVE **3×3 risk matrix** (impact × likelihood) + treatment decision (mitigate/accept/transfer/avoid) · approver · residual risk · review date. Click a matrix cell/level → drill-down. **Admin-only assessment basis** | ISMS-P risk mgmt / ISO 27001 6.1.2·8.8. **admin·security only**. Persisted in `ui_risk_register` |
| **🔐 Role-aware dashboard** | Role-aware security hero (risk KPIs/TOP ↔ my-servers remediation) + **24h/12h infra status** (Zabbix/Wazuh deep links) + **panel editing** (per-user widget on/off, persisted) | Responsive grid. Infra/helpdesk see remediation rate, not risk grades |
| **🚨 Alert Triage** | 3-tier state (🔴🟡🟢) change, analyst·**actor** separation, history display | If actor is omitted on UI, falls back to session user → "unknown" |
| **📋 Incident management** | Create / state change / note / date filter / text search / CSV download + change history | CSV download triggers "history not included" guidance modal |
| **✅ Compliance PDCA** | Plan/Do/Check/Act 4-stage cards, per-category Pass/Fail/Warning table | **Click Do card → unified pending items modal** (controls + Trivy + Alerts) |
| **Pending / overdue** | Control checks (fail/warning) + Trivy critical/high + Alerts critical/high (7-day) unified view | **📥 CSV download** (`/compliance/pdca/pending.csv`) |
| **📥 Audit-evidence reports** | 6 types (asset/account/log/vuln/risk_register/monthly) CSV + **PDF** (NanumGothic embedded) | **🔍 Preview modal** (top 50 rows + CSV/PDF download buttons) |
| **📡 Source Freshness · Collector Lag** | Per-collector last-success timestamp · lag · SLA threshold visualization (`/dashboard` `source_coverage`) | Card/table shown on Admin Overview + user dashboard |
| **🔀 Cross-validation** | Zabbix × Fleet × Trivy host mapping diff / unmapped asset detection | source_coverage / orphan check |
| **💬 Natural language queries (FAB)** | 12-intent dispatch (alert_summary, offline_hosts, top_vulnerable_hosts, host_timeline, …) | `/interpret` + `/query` |
| **📚 Guide system** | 7 guide types with admin on/off + direct editing | ISMS-P / ISO 27001 operations guides |
| **🌐 Multi-language (KO/EN)** | **In-account-menu** toggle on login, dashboard, and admin pages + `data-i18n` static substitution + `window.t()` dynamic messages | Persisted in cookie / localStorage; active tab re-renders instantly on toggle |
| **👤 User profile / ⭐ My Servers** | Account menu → profile edit (name · department · assigned servers) + **My Servers** sub-tab in Assets | Filters Fleet+Zabbix hosts where `assigned_servers` matches or `owner == display_name` |
| **API docs** | Swagger `/docs` | Auto-generated by FastAPI |

> ✅ **Storage persistence notice (M2-1 + R-2 done)** — PostgreSQL holds **normalized seed security data** (hosts/alerts/vulnerabilities/observations etc.), loaded into InMemoryRepository at boot for queries. The **UI operational state stores** (triage / incidents / asset owners / vuln actions / asset audit log / user profiles + the **risk register**) are persisted via `schema/003_*` · `schema/004_risk_register.sql` + `repositories/state_*.py` (the StateRepository layer) using **cache-aside + write-through**, so they **survive restarts**. (Falls back to in-memory when `MORI_QUERY_BACKEND=memory` or `MORI_DATABASE_URL` is unset.)

### 🟡 In progress / Next steps (next milestone)

| Item | Status | Priority |
|---|---|---|
| **UI operational state → PostgreSQL persistence (M2-1)** | ✅ Done — `schema/003_*` + `repositories/state_*.py` (StateRepository) cache-aside + write-through. The 6 stores survive restarts, verified by an integration test (`tests/test_state_persistence.py`) | ✅ Done |
| **Zabbix API polling** | ✅ **Verified** — real Zabbix API, problem→collect→Triage→Incident→evidence→resolve end-to-end (`collectors/zabbix_events.py`, `tests/test_zabbix_events.py`) | ✅ Done |
| **Control catalog (Phase 2)** | ISMS-P/ISO N:M mapping + common defects + control-tree screen — **the product-identity pivot; comes before pollers** | 🔴 Top |
| **Trivy ingest** | ✅ Remote token push (`/ingest/trivy`·`/ingest/evidence`) done · only local scheduled scan automation remains | 🟡 Medium |
| **Fleet / Wazuh API poller** | Parser·Collector ready, REST poller not yet connected — **Phase 3** (after the control catalog). Done = wired into MORI workflow, not just data arriving | 🔴 High |

### 🔲 Planned / Future work

| Item | Status | Priority |
|---|---|---|
| LDAP authentication operational adoption | Code ready, activates when `LDAP_URL` is set | 🟡 Medium |
| Slack / Email webhook notifications | Not connected (`SLACK_WEBHOOK_URL` slot exists only) | 🟡 Medium |

---

## 🚀 Quick Start

### Demo mode (sample data)

```bash
# One line: generate .env → start API → schema/seed → demo incidents → worker
./scripts/mori-start-demo.sh
```

→ Log in at `http://localhost:18000/ui` with `admin / 1234`.

### Brownfield mode — sit on top of existing Zabbix/Wazuh/Fleet

If you already run Zabbix·Wazuh·FleetDM·Trivy, start **MORI core only and connect via `.env`** (no bundled sources needed). Full guide: [docs/BROWNFIELD_CONNECT.md](docs/BROWNFIELD_CONNECT.md).

```bash
# 1) Start MORI core only (api + worker + postgres; bundled sources excluded)
docker compose up -d

# 2) Point .env at your existing infra (e.g. Zabbix)
#    MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
#    MORI_ZABBIX_API_TOKEN=<token>   (or MORI_ZABBIX_USER/PASSWORD)
docker compose up -d mori-worker      # re-apply

# 3) Trivy/CSOP connect via token push (set MORI_INGEST_TOKEN)
#    POST /ingest/trivy  ·  POST /ingest/evidence
```

> Connectivity today: **Zabbix** (live REST) and **Trivy/CSOP** (token push) work by config alone. **Fleet/Wazuh** live API pollers are Phase 3 (`.env` slots reserved for now).

To also bring up the bundled demo sources:

```bash
docker compose --profile bundled up -d          # full stack (Zabbix+Fleet+Wazuh demo)
# individual: --profile zabbix / --profile fleet / --profile wazuh
```

### Stop demo

```bash
./scripts/mori-stop-demo.sh             # Delete seed data + stop containers (preserve real poller data)
./scripts/mori-stop-demo.sh --keep      # Delete seed only, keep containers
./scripts/mori-stop-demo.sh --purge     # Remove containers + volumes entirely
```

### Demo screen preview

When demo mode is started, the platform behaves as follows.

#### 1) Unified dashboard — Asset / alert / vuln status at a glance

![Dashboard](docs/images/demo-dashboard.png)

- Top cards: Total Hosts / Offline Hosts / High Alerts 24h / Critical Vulns
- Latest Host Status: prioritizes offline / unknown hosts for immediate attention
- **Source Freshness · Collector Lag** card: Fleet/Wazuh/Zabbix/Trivy collector last_sync + lag + SLA
- User dashboard tabs: **Dashboard / Alert Triage / Incidents / Asset status / Compliance PDCA / Guides & Standards** (RBAC per-role on·off)
- **Admin console (/admin) 8 tabs** (Phase 2 reorg): Overview · Compliance · Triage & Incidents · Remediation · Assets / Owners · Access Control · Audit & Logs · Settings (per-role exposed tabs auto-restricted)

#### 2) Natural language queries (NLQ) — `interpret` → `query`

![NLQ Modal](docs/images/demo-nlq.png)

- Enter a Korean question like "오프라인 호스트 보여줘" (Show offline hosts) and it maps to the matching intent out of 12
- **Interpret** → intent shown (`offline_hosts`) / **Run Query** → results + summary text / **Download CSV** → evidence-purpose download
- Result table: Source / Summary / Record ID

#### 3) Vulnerabilities (Trivy) — Per-CVE remediation plans & exceptions

![Trivy Vulnerabilities](docs/images/demo-trivy.png)

- Per-host Critical / High / Medium / Low totals + recent CVEs / detection date
- **Plan** / **Exception** columns: `+ Add plan` / `+ Set exception` buttons or current value display
- When a host has host-level plan/exception set, "📋 Per-CVE detailed plans" / expiry surfaces immediately, and within the **CVE detail modal (N items ↗ button)** a host-level plan/exception banner + per-CVE row marker ("host-level applied") confirms scope
- **📋 History** button shows unified per-host change history (asset · plan · exception · CVE-level actions)

### Individual scripts

```bash
./scripts/mori-seed-sample-data.sh        # (Re)insert sample data only
./scripts/mori-run-workers.sh start       # Start workers
./scripts/mori-run-workers.sh status      # Status
./scripts/mori-run-workers.sh cycle       # Manual single collection cycle
./scripts/mori-run-workers.sh logs        # Logs
./scripts/mori-run-workers.sh stop        # Stop workers
./scripts/mori-backup.sh                  # pg_dump → backups/mori-soc-<ts>.dump
./scripts/mori-restore.sh backups/<file>.dump  # pg_restore (confirmation prompt, --force to skip)
./scripts/trivy-fs-scan.sh .              # Filesystem vulnerability scan
./scripts/trivy-image-scan.sh <image>     # Image vulnerability scan
```

---


## 🧱 Architecture / Module Layout

```text
src/mori_soc/
├── api/
│   ├── server.py          ← thin orchestrator (888 lines): builds RouteContext + registers modules
│   ├── routes/            ← 16 domain route modules (register_<domain>(ctx))
│   │   ├── context.py     ← RouteContext (stores + helper closures, ~35 fields)
│   │   ├── auth.py · assets.py · alerts.py · vulnerabilities.py
│   │   ├── incidents.py · compliance.py · query.py · pages.py
│   │   ├── rbac.py · audit.py · plans.py · guides.py · sources.py
│   │   └── webhooks.py · dashboard_prefs.py
│   ├── templates.py       ← /ui · /login · dashboard · console HTML/JS renderers
│   ├── payloads.py        ← dashboard/pdca/query payload builders
│   ├── i18n.py            ← UI localization strings
│   ├── auth.py            ← session middleware · credential verify · default role perms
│   └── contracts.py       ← QueryRequest/Response, EvidenceRef, QueryScope
├── collectors/            ← Fleet · Wazuh · Zabbix · Trivy · LDAP collectors
├── pollers/               ← Per-source periodic pollers (worker.py orchestrates)
├── services/
│   ├── normalization.py   ← EnvelopeEntityMapper (host auto-creation, alias registration)
│   ├── ingestion.py       ← Collection ingestion pipeline
│   ├── risk_score.py      ← Risk score calculation
│   ├── query_catalog.py   ← 12 intent definitions (TemplateQuery)
│   ├── query_service.py   ← Intent dispatch (_INTENT_HANDLERS registry)
│   ├── views.py           ← Logical view aggregation (latest_host_status / risk_summary / timeline)
│   ├── reports.py         ← 6-type audit-evidence report builder (+ risk register) + report_to_csv
│   └── asset_classifier.py← Asset auto-classification + importance scoring (manual override supported)
├── repositories/
│   ├── memory.py          ← InMemoryRepository / InMemoryQueryStore (loaded from seed, used for queries)
│   ├── postgres.py        ← Postgres repository (holds normalized seed → query snapshot)
│   ├── state_base.py      ← StateRepository ABC (interface for the 6 UI operational stores)
│   ├── state_memory.py    ← InMemoryStateRepository (default for tests/demo, pure dicts)
│   └── state_postgres.py  ← PostgresStateRepository (write-through for the 6 stores, schema/003)
├── models/entities.py     ← Host, HostAlias, Alert, Vulnerability, ControlCheckResult …
└── worker.py              ← Poller orchestrator
```

### Storage separation

| Storage area | Current status | Location |
|---|---|---|
| **Normalized security data** (hosts / alerts / vulnerabilities / observations / fleet_query_results / control_checks / directory_accounts / source_syncs …) | PostgreSQL **seed schema + seed data** loaded. Boot-time load into InMemoryRepository for queries | `schema/001_phase1_initial.sql`, `repositories/postgres.py`, `repositories/memory.py` |
| **UI operational state — 6 stores** (survive restarts) | Persisted to PostgreSQL via cache-aside + write-through. Warm-loaded DB→memory at boot, written through to the DB on every mutation | `schema/003_*`, `repositories/state_*.py`, `api/server.py` → `api/routes/context.py` |
| Phase 2 persistence (6 stores → Postgres) | ✅ M2-1 done — StateRepository layer + `schema/003`. Round-trip verified by an integration test | `tests/test_state_persistence.py` |

#### Persisted 6-store detail (cache-aside + write-through)

| Variable | Content |
|---|---|
| `asset_owners` | hostname → {owner, team, importance, category, …} |
| `asset_audit_log` | hostname → list of {field, old_value, new_value, changed_by, changed_at} |
| `vuln_actions` | vuln_id → {plan_text, plan_target_date, plan_updated_by, exception_until, exception_reason, exception_updated_by} |
| `triage_store` | alert_id → {status, analyst, note, changed_by, changed_at, history[]} |
| `incident_store` | incident_id → {…, history[]} |
| `user_profiles` | username → {display_name, department, assigned_servers[], updated_at} |

→ The 6 stores above are warm-loaded from PostgreSQL into memory at boot, and every mutation is written through to the DB immediately (M2-1 done). State survives restarts.

### 12 natural language query intents

| # | intent | Description |
|---|---|---|
| 1 | `alert_summary` | High/critical alert summary for last N hours |
| 2 | `offline_hosts` | Currently offline/unknown hosts |
| 3 | `fleet_checkin_gap` | Hosts missing Fleet check-ins |
| 4 | `top_vulnerable_hosts` | Top N hosts by vulnerability count |
| 5 | `host_timeline` | Host timeline (alert+query+obs merged) |
| 6 | `host_wazuh_alerts` | Wazuh alerts for a specific host |
| 7 | `host_fleet_queries` | Fleet query results for a specific host |
| 8 | `new_high_vulns` | Recent newly-detected high+ vulnerabilities |
| 9 | `risky_hosts` | Hosts with many alerts + offline/unknown |
| 10 | `unmapped_assets` | Assets unmapped across Fleet/Wazuh/Zabbix |
| 11 | `login_failure_spike` | Hosts with login failure spikes |
| 12 | `collection_errors` | Hosts with repeated collection errors |

#### Adding a new intent

`QueryService._INTENT_HANDLERS` is a dict that dispatches intent → handler method. Adding a new intent is 3 steps.

1. `services/query_catalog.py` — Add `TemplateQuery` to `PHASE1_QUERY_CATALOG`
2. `services/query_service.py` — Add `"my_new_intent": "_my_new_intent"` to `_INTENT_HANDLERS` + implement handler method
3. `tests/test_query_service.py` — Add behavior test

`execute()` requires no modification — auto-routes.

---

## 🔌 Key API Endpoints

| Category | Method / Path | Description |
|---|---|---|
| Health / Catalog | `GET /health`, `GET /catalog` | Health check (DB ping + freshness + insecure defaults), query catalog |
| Auth / Profile | `POST /auth/login`, `GET /auth/logout`, `GET /auth/me`, `GET/POST /auth/profile` | Login/session + user profile (name·department·assigned servers) get·upsert. `/auth/me` merges profile |
| Query | `POST /query`, `POST /interpret` | Structured query / NL interpretation |
| Dashboard | `GET /dashboard/summary` | Overview cards + Critical vulnerability detail (plan/exception included) |
| Assets | `GET /assets`, `POST /assets/owners` | Asset list / owner·importance change (audit log) |
| Alert Triage | `PATCH /alerts/{id}/triage` | State/analyst/note change + actor recording |
| Vulnerability Actions | `PUT/DELETE /vulnerabilities/{id}/plan`, `/exception` | Per-CVE plan·exception + audit log |
| **Risk Assessment (R-series)** | `GET/PUT /vulnerabilities/{id}/risk`, `GET /vulnerabilities/risk-summary` | Per-CVE risk assessment (impact × likelihood) read/write (auto-suggestion + provenance) / full 3×3 matrix aggregation |
| Incidents | `GET /incidents`, `POST /incidents`, `PATCH /incidents/{id}`, `GET /incidents/{id}/history`, `GET /incidents?format=csv` | Incident CRUD + history + CSV |
| Compliance | `GET /compliance/pdca`, `GET /compliance/crosscheck` | PDCA aggregation / cross-validation |
| **Compliance CSV** | `GET /compliance/pdca/pending.csv` | Pending/overdue CSV (source/control_id/target/state/owner/due_date/overdue/note) |
| Reports | `GET /compliance/reports`, `GET /compliance/reports/{type}?format=csv\|pdf` | 6-type audit-evidence reports (asset/account/log/vuln/**risk_register**/monthly). PDF embeds NanumGothic |

Full spec at Swagger `/docs`.

---


## 🧪 Tests

### Unit tests (Docker)

```bash
# Fastest: run all tests in the running container
docker compose cp tests/test_api_server.py mori-api:/app/tests/test_api_server.py
docker compose exec mori-api python -m unittest tests.test_api_server

# Specific test class only
docker compose exec mori-api python -m unittest tests.test_api_server.FastAPIAppTests

# One-shot when container is not running
docker compose run --rm \
  -v "$(pwd)/tests:/app/tests:ro" \
  mori-api \
  python -m unittest discover -s /app/tests
```

### Test file list

| File | Target |
|---|---|
| `tests/test_api_server.py` | FastAPI endpoints, PDCA payload, Triage actor, Compliance integration |
| `tests/test_query_service.py` | 12 query intents + view aggregation |
| `tests/test_fleet_logs.py` | Fleet osquery log collector |
| `tests/test_wazuh_alerts.py` | Wazuh alert collector |
| `tests/test_zabbix_events.py` | Zabbix trigger/item collector |
| `tests/test_trivy_collector.py` | Trivy vulnerability collector |
| `tests/test_ingestion.py` | Ingestion pipeline |
| `tests/test_intent_parser.py` | NL → intent parser |
| `tests/test_postgres_repository.py` | Postgres repository (requires DB) |

### Manual API tests

```bash
curl http://localhost:18000/health
curl http://localhost:18000/dashboard/summary
curl http://localhost:18000/compliance/pdca
curl -OJ http://localhost:18000/compliance/pdca/pending.csv
curl http://localhost:18000/compliance/crosscheck
curl http://localhost:18000/compliance/reports
curl -OJ "http://localhost:18000/compliance/reports/asset_inspection?format=csv"

curl -X POST http://localhost:18000/interpret \
  -H 'Content-Type: application/json' \
  -d '{"text":"Show offline hosts"}'

curl -X POST http://localhost:18000/query \
  -H 'Content-Type: application/json' \
  -d '{"intent":"offline_hosts","scope":{"time_range":"24h"}}'

# PDF audit-evidence report (NanumGothic embedded)
curl -OJ "http://localhost:18000/compliance/reports/monthly_operations?format=pdf"
```

### Backup / restore

```bash
./scripts/mori-backup.sh                          # Creates backups/mori-soc-<timestamp>.dump
./scripts/mori-restore.sh backups/<file>.dump     # Restore after confirmation
./scripts/mori-restore.sh backups/<file>.dump --force   # Skip confirmation
docker compose restart mori-api                   # Reload snapshot after restore
```

### Code validation (when editing routes / templates)

Task J split routes into `api/routes/` and HTML/JS renderers into `api/templates.py`. To guarantee a lossless refactor, run the **3-gate check** after changes:

```bash
# 1) OpenAPI route diff — registered paths/methods/schema match the baseline
#    compare _routes_snapshot.py output against _routes_baseline.json → must be IDENTICAL
# 2) Rendered-template SHA — 6 hashes (login/signup/dashboard/console) match baseline
#    python /app/_verify_templates.py
# 3) Full unit-test suite
docker compose run --rm --no-deps -e MORI_DEMO_SEED=0 \
  -v "$(pwd)/tests:/app/tests" -v "$(pwd)/src:/app/src" \
  mori-api python -m unittest discover -s tests   # → 115 OK (skipped=2)
```

Each domain's routes are owned by `register_<domain>(ctx)` in `routes/<domain>.py`; shared state/helpers are injected via the `RouteContext` in `routes/context.py`.

---

## 📦 Deployment / Infrastructure

### Public entry points

| Port | Service |
|---|---|
| `37854` | Main Portal (Grafana / Zabbix / Fleet / MORI link hub) |
| `18000` | MORI API + unified ops UI |
| `13000` | Grafana |
| `18081` | Zabbix Web |
| `1337` | FleetDM |
| `127.0.0.1:8443` | Wazuh Dashboard (internal) |

### Service ports

`10051` Zabbix Server · `1514` Wazuh agent · `1515` Wazuh registration · `514/udp` Syslog · `55000` Wazuh API.

### Deployment flow

The GitHub Actions workflow runs in this order:

1. Repo checkout
2. Create/verify `/backup/rmstudio/mori` on the server
3. `rsync` the code
4. Upload `.env` from GitHub Secrets
5. Prepare Wazuh certificates directory (first-run certificate generation)
6. `docker compose pull` → `docker compose up -d --remove-orphans`

**Required GitHub Secrets**: `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, `DEPLOY_ENV_FILE`, `DEPLOY_KNOWN_HOSTS` (optional).

### Required environment variables (`.env`)

Run `cp .env.example .env` and **change the following values** before deploying:

- `GRAFANA_ADMIN_PASSWORD`
- `ZABBIX_DB_PASSWORD`
- `FLEET_DB_ROOT_PASSWORD`
- `FLEET_DB_PASSWORD`
- `FLEET_SERVER_PRIVATE_KEY`
- `MORI_DB_PASSWORD`
- `MORI_API_PORT` (default 18000), `MORI_DB_NAME` (default mori_soc), `MORI_DB_USER` (default mori)

### Server prerequisites

- Docker Engine + Compose plugin
- Deployment directory: `/backup/rmstudio/mori`
- Wazuh Indexer kernel parameter: `vm.max_map_count=262144`

### Rebuild without cache (preserve data volumes)

```bash
docker builder prune -f
docker compose build --no-cache mori-api
docker compose up -d mori-api
```

---


## 🌱 Seeded sample data

The seed script (`mori-seed-sample-data.sh`) **loads into PostgreSQL** (then loaded into InMemoryRepository at boot for queries):

| Item | Count | Description |
|---|---|---|
| Hosts | 10 | Servers, PCs, firewall, VPN — mixed asset types |
| Host Aliases | 13 | Per-source (Zabbix/Fleet/Trivy) mapping |
| Alerts | 8 | Wazuh/Zabbix — SSH brute force, rootkit, disk/CPU alerts, etc. |
| Vulnerabilities | 8 | Trivy 6 + Fleet 2 — CVE-based critical to medium |
| Observations | 9 | Zabbix/Fleet — CPU, Disk, Memory, encryption status |
| Fleet Query Results | 8 | osquery — installed apps, disk encryption, startup programs, etc. |
| Control Checks | 12 | ISO 27001 / ISMS-P control check results |
| Directory Accounts | 7 | LDAP users (admin, developer, DBA, etc.) |
| Privilege Bindings | 6 | sudo, domain_admin, db_admin permissions |
| Group Memberships | 8 | Domain Admins, Developers, DBA, etc. |
| Source Syncs | 4 | Zabbix/Fleet/Trivy/Wazuh collection state |

Operational state generated by demo seed / during operation (the 6 UI operational stores are write-through persisted to PostgreSQL — survive restart):

| Item | Count | Generated when |
|---|---|---|
| Incidents | 3 | `mori-start-demo.sh` calls `POST /incidents` after seeding |
| Triage / asset owners / user profiles | Seeded when `MORI_DEMO_SEED=1` | Injected in-memory at app startup (see below) |
| Vulnerability actions / incident changes | 0 | Accumulate as you edit in the UI |

> 🌱 **`MORI_DEMO_SEED`** — When `1/true`, the app injects demo data in-memory at startup: `triage_store` (4 entries across reviewing/resolved/pending), `asset_owners` (web-server-01·02 / db-primary / app-server-01), and `user_profiles` (`admin`=System Admin / `security`=Security Officer with assigned-server mappings). Hostnames/alert IDs match the SQL seed so the **⭐ My Servers** view lines up with real assets. Default `1` in `docker-compose.yml`; **set to `0` for production deployments**.

---

## 📖 Reference documents

| Document | Content |
|---|---|
| `docs/FUNCTIONAL_SPEC.md` | Original functional spec (Korean) |
| `docs/SECURITY_CONTROL_MAPPING.md` | Security controls mapping |
| `docs/IMPLEMENTATION_ROADMAP.md` | Implementation roadmap against the functional spec |
| `docs/SECURITY_DATA_QUERY_PLATFORM.md` | Data-centric security query platform design |
| `docs/MORI_IMPLEMENTATION_SUMMARY.md` | Implementation status / ops strategy / next steps |
| `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md` | Phase 1 input sources, schema, query specs |
| `docs/PHASE1_LOGICAL_SCHEMA.md` | Phase 1 logical schema, table relations |
| `docs/DEPLOYMENT.md` | Server deployment / ops / troubleshooting |
| `docs/ZABBIX_AGENT_ACTIVE_SETUP.md` | Zabbix Agent onboarding |
| `docs/TRIVY_USAGE.md` | Trivy filesystem / image scanning guide |
| `docs/FLEET_MACBOOK_ENROLLMENT_AND_TEST.md` | Fleet macOS enrollment + verification |
| `docs/FLEET_RESET_AND_REINSTALL_GUIDE.md` | Fleet reset / reinstall |
| `docs/collection-standards.md` | Collection standards |
| `schema/001_phase1_initial.sql` | Phase 1 Postgres initial DDL |
| `schema/002_phase2_compliance_identity.sql` | Phase 2 Compliance / Identity DDL |

> ℹ️ Most documents under `docs/` are currently in Korean. Translation is on the roadmap; see [`docs/MORI_IMPLEMENTATION_SUMMARY.md`](docs/MORI_IMPLEMENTATION_SUMMARY.md) for the implementation summary that has been kept up to date in English-friendly form.

---



## 🔌 Integrations & expansion roadmap

MORI SOC combines open-source security tools to provide a single ops screen, with the longer-term ambition to **distribute it as a Zabbix-ecosystem template / lightweight Agent package**. The goal is that organizations running Zabbix only can also partially adopt MORI's asset / control-check / evidence-accumulation concepts.

### Current integrations (Phase 1 / Phase 2 Alpha)

| Tool | Integration | Status |
|---|---|---|
| **Zabbix** | problem/trigger collector (`collectors/zabbix_events.py`) → ingestion → alert. problem→Triage→Incident→evidence→resolve | ✅ **Verified end-to-end against the real API** |
| **FleetDM** | osquery results + host registration normalization. Asset identification + unmapped (orphan) detection | 🟡 Parser/collector ready, REST poller not yet connected |
| **Wazuh** | alert ingestion → triage pipeline. SSH brute force / rootkit and other security event evidence | 🟡 Parser/collector ready, REST poller not yet connected |
| **Trivy** | JSON result ingest → per-CVE remediation plan / exception + host-level bulk apply | 🟡 Auto-ingestion packaging in progress |
| **Loki + Fluent Bit** | Log centralization (Grafana visualization downstream) | ✅ Operational |
| **LDAP / AD** | Directory account + privilege binding consistency checks (seed) | 🔲 Activates with `LDAP_URL` in production |
| **Grafana** | Operational dashboards that query Postgres / Loki directly | ✅ Operational |

## 🗺️ Roadmap (Phase 0 → 5)

> **The identity pivot**: today MORI is an "audit-ready ops UI." The goal is **"a platform where, centered on a control catalog, the monitoring of five sources becomes ISMS-P/ISO 27001 evidence as it happens."** Ordering matters — **the control catalog (Phase 2) comes before the pollers (Phase 3).** Each phase has a **done criterion** to prevent solo-dev drift.

> **3 core principles**: ① **delegate viewing to Grafana** — no time-series charts inside MORI (deep links only). ② **collection ≠ evidence** — a poller is done when it's wired into the MORI workflow (triage→remediate→record), not when "data arrives." ③ **lite/full packaging** — a lite profile (no Wazuh) for 1–2 person orgs alongside full.

> **5 read-only integration principles** — ① read-only token recommended ② no change to existing configuration ③ isolated source failure (won't break MORI) ④ source freshness shown ⑤ last sync time / failure reason stored

### Phase 0 — Foundations of trust · *in progress*
- 🟡 compose profile split — brownfield default (core only) + `bundled`/`zabbix`/`fleet`/`wazuh` **(done)** → rename to `lite`/`full`/`demo` **(planned)**
- 🟡 pass `MORI_ADMIN_PASSWORD`·`MORI_INGEST_TOKEN` into the container + `/health` insecure warning **(done)** → remove Wazuh hard-coded creds, `:?required` on weak defaults, `MORI_DEMO_SEED` default 0 **(planned)**
- 🔲 move root temp files (`_scan_*`, `_routes_*`) → `tools/`, README-code sync (route snapshot in CI)
- ✅ **Done when**: 0 plaintext passwords in the repo · `docker compose -f … lite up` boots in one line

### Phase 1 — Structure + persistence · ✅ *mostly done*
- ✅ **J**: `server.py` split into `routes/` (16 domains) + `RouteContext`, 2,962→888 lines (-70%), lossless-verified
- ✅ **M2-1 + R-2**: 6 UI operational stores + risk register → PostgreSQL cache-aside + write-through (`schema/003·004`)
- ✅ **Done when**: triage/incident/owner/plan survive a restart (round-trip test passes)

### Phase 2 — Control catalog (identity pivot) · 🟡 *started (skeleton) — the core next*
> **A parallel, independent track from the pollers (Phase 3).** The catalog is domain-knowledge work with no code dependency, so you can fill it on days when poller coding is blocked, and it's an independent asset publishable to the community the moment it's done. **It is a prerequisite for P3-5 (Control Mapping) and P4-3 (Evidence Pack)** — you need control data before you can map to it.
- 🟡 `controls/` open data — ISMS-P 101 + ISO 27001:2022 Annex A 93 as YAML + N:M crossmapping + `common_defects`. **Skeleton · JSON Schema · samples started** ([`controls/`](controls/)); v1 target: full skeleton + 60~70 mappings + 10~15 deep defect cases (no bulk mapping — solo dev drift)
- 🔲 JSON Schema validation CI (YAML validity) + `schema/007` control tables + YAML→DB sync on boot + evidence mapper
- 🔲 PDCA screen → **control-tree screen** (evidence-source status / last update / owner / evidence PDF button)
- 🟡 dashboard **GRC preset** — today's work queue (evidence gaps) card started (admin·security); audit D-day after catalog wiring
- ✅ **Done when**: NLQ "show me evidence for 2.11.2" → real-data answer · PDF in one click from the control screen

### Phase 3 — Complete collection, realize "see it all in one place" · 🟡 *partial*
- ✅ **M2-2** Zabbix poller verified against real API · ✅ Trivy/CSOP remote push (`/ingest/trivy`·`/ingest/evidence`)
- 🔲 Trivy auto-scan by default (`MORI_ENABLE_TRIVY` on + schedule)
- 🔲 **Wazuh poller (new)** — detection events → MORI alert queue → handling history as 2.11.3 evidence (compose service def first)
- 🔲 **Fleet poller (new) — asset ID = foundation work** — if the asset list is weak, every downstream control cascades into an "unclear scope" defect. **Done = the cycle closes as evidence, not data arriving**: new Fleet host → MORI asset auto-created → **surfaced in the work queue as unassigned** (discover→assign→manage). The existing intents (`fleet_checkin_gap`·`host_fleet_queries`·`unmapped_assets`) are the asset-management evidence generators. 1.2.1 asset ID · 2.1.3 currency · 2.10.6 endpoint
- 🔲 tie Loki retention to controls — statutory access-log retention (1yr default, 2yr for unique-ID data) surfaced as 2.9.4 evidence
- 🔲 ship 5 Grafana dashboard JSONs (1/source + 1 unified) — control screen → Grafana panel deep link
- ✅ **Done when**: in the full profile, all 5 sources map onto control screens

### Phase 4 — Complete audit readiness · 🔲
- Risk assessment UI (`schema/004`): asset importance × threat × real vuln → treatment decision + approval record
- **Evidence Gap Detector** (new intent `evidence_gaps`) — expired freshness / exceptions expiring / Critical without a plan
- SoA generator · **Evidence Pack** (P4-3): per-control evidence bundle PDF · defect tracker (finding → remediation → completion evidence)
- ✅ **Done when**: a "mock audit scenario" — every document an auditor asks for is exportable from the tool

### Phase 5 — Adoption · 🔲 *(can run in parallel)*
- onboarding wizard (scope → assets → owners, first value in 30 min) · Korean-first docs + "Top-N ISMS-P defects & fixes" content · 2–3 pilot orgs

> 🚫 **AI hard limits** (collection/investigation assistance only): no auto-patch / auto-exception-approval / auto-incident-close.

### Other backlog
- **Webhook integrations** — Slack / Teams / Email (`SLACK_WEBHOOK_URL` slot only)
- **CVE Lite collector** — JS/TS lockfile dependency vulnerabilities (`source=cve_lite`)
- **MORI → Zabbix export** — critical/high/pending/lag metrics → zabbix_sender (Zabbix-only adoption pack)
- **SQL-based read optimization** — gradually move snapshot reads to Postgres views

---

---

Try the full feature set (risk assessment · Zabbix end-to-end scenario included) with `./scripts/mori-start-demo.sh`. For production, apply changes with `docker compose down && docker compose up -d`. See the [⚡ Status](#-status--30-second-overview) table at the top for a summary.
