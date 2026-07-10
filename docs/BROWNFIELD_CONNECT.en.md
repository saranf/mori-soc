# Connect an existing stack — bring your Zabbix/Wazuh/Fleet data into MORI

[한국어](./BROWNFIELD_CONNECT.md) · **English**

> **This document is for you if** — *"I already run Zabbix (and maybe Wazuh/Fleet), and I want to feed
> that data into MORI to build up ISMS-P/ISO evidence."*
> MORI does **not replace** your existing tools; it sits on top of them read-only by **bringing up only the MORI core and configuring `.env`.**
> There's no need to spin up the bundled Zabbix/Fleet/Wazuh separately.
>
> If this is your first time installing MORI → read the [Getting Started guide](GETTING_STARTED.en.md) first.

---

## TL;DR (3 steps)

```bash
# 1) Create the config file (one time)
cp .env.example .env

# 2) In .env, swap the source URLs/credentials for your 'existing infrastructure' (see §3 below)

# 3) Start only the MORI core (without bundled sources)
docker compose up -d
```

`docker compose up -d` = **MORI core (api + worker + postgres) + dashboards (grafana/loki) + LDAP**.
The bundled source stack sits behind the `bundled` profile, so it only comes up when you explicitly ask for it.

---

## 1. Prerequisites

| Item | Details |
| --- | --- |
| MORI host | Docker 24+ / Compose v2, in a location that can **reach your existing infrastructure over the network** |
| Zabbix | Version 5.0+ (JSON-RPC API). Permission to issue a **read-only account or API token** |
| Firewall | Allow outbound from MORI → Zabbix API port (usually 443/80/8080) |
| (Optional) Trivy/CSOP | An outbound path for the scanner to **push** to MORI |

> MORI accesses sources **read-only**. It does not change your existing tools' configuration and does not deploy any new agents.
> If a source is briefly unreachable, MORI as a whole does not go down — it retries on the next cycle.

---

## 2. Compose profiles (what comes up)

| Command | What it starts |
|---|---|
| `docker compose up -d` | **MORI core only** (brownfield default) |
| `docker compose --profile bundled up -d` | Core + the full bundled Zabbix/Fleet/Wazuh demo |
| `docker compose --profile zabbix up -d` | Core + bundled Zabbix only |
| `docker compose --profile fleet up -d` | Core + bundled Fleet only |
| `docker compose --profile wazuh up -d` | Core + bundled Wazuh only |
| `docker compose --profile scanner run trivy …` | One-off Trivy scan |

Profiles can be combined: `docker compose --profile zabbix --profile fleet up -d`.
**When connecting to existing infrastructure, just use** `docker compose up -d` **without any profile.**

---

## 3. Connecting each source

| Source | Connection method | Status | Key .env |
|---|---|---|---|
| **Zabbix** | Live REST (JSON-RPC) polling | **Works with config only (verified)** | `MORI_ZABBIX_API_URL` + token **or** user/password |
| **Trivy / CSOP** | Remote token push | Just set the token | `MORI_INGEST_TOKEN` |
| **Fleet** | Live REST poller | **Planned for Phase 3 (not yet implemented)** | `MORI_FLEET_API_URL`, `…_TOKEN` (placeholder only) |
| **Wazuh** | Manager REST (55000) poller | **Planned for Phase 3 (not yet implemented)** | `MORI_WAZUH_API_URL`, `…_USER/PASSWORD` (placeholder only) |

### 3-1) Zabbix (existing instance) — step by step

**① Prepare read-only access in Zabbix**
- Recommended: issue an **API token** (Zabbix 5.4+): *Users → API tokens → Create*, linked to a read-permission user.
- Alternatively, create a **read-only user** (e.g. `mori-readonly`) and use user/password.

**② Configure `.env`**
```dotenv
MORI_ENABLE_ZABBIX=true
MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
# Auth — token recommended (when set, user/password are ignored)
MORI_ZABBIX_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx
#   (if you have no token, use the following)
# MORI_ZABBIX_USER=mori-readonly
# MORI_ZABBIX_PASSWORD=********
MORI_ZABBIX_TIMEOUT_SECONDS=10
MORI_ZABBIX_HOST_LIMIT=500
MORI_ZABBIX_PROBLEM_LIMIT=500
```

**③ Apply (restart the worker)**
```bash
docker compose up -d mori-worker
docker compose logs -f mori-worker   # Check the "zabbix … problems/hosts" collection logs
```
The worker periodically polls `problem.get`/`host.get` and loads them into PostgreSQL `alerts`/`hosts`.

**④ Verify in MORI**
- `/ui` → **Asset inventory → Server assets (Zabbix)** to see whether hosts appear
- **Alert Triage** to see whether `source=zabbix` alerts appear → handle status → promote to **Incident** → evidence export

> To fire a demo problem once and check the pipeline (when using bundled Zabbix):
> `./scripts/mori-zabbix-demo-problem.sh`

### 3-2) Trivy / CSOP (remote scanner → MORI push)

Rather than MORI polling the scanner, **the scanner/agent sends reports to MORI (push).**

**① Ingest token in `.env`**
```dotenv
MORI_INGEST_TOKEN=<value generated with openssl rand -hex 32>
```
> Once the token is set, `/ingest/*` accepts requests with the token alone, without a login session. If it's not set, a session is required
> and automation won't work.

**② Send from the scanner/CSOP**
```bash
# Raw vulnerability report (host mapping: ?hostname= or the X-MORI-Hostname header)
curl -X POST "https://mori.your-corp.com/ingest/trivy?hostname=server-db01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @trivy-report.json

# Before/after remediation evidence (delta_type: new/fixed/reopened) — query via GET /evidence (admin·security)
curl -X POST "https://mori.your-corp.com/ingest/evidence" \
  -H "X-MORI-Token: $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @evidence-envelope.json
```

**③ Verify in MORI** — `/ui` → **Asset inventory → Vulnerabilities (Trivy)** shows per-host aggregates,
where you can manage risk scores and remediation plans/exceptions.

### 3-3) Fleet / Wazuh (Phase 3 — no live poller yet)

Currently the Fleet/Wazuh **live API pollers are not implemented** (`build_collector()` in
`src/mori_soc/pollers/{fleet,wazuh}.py` returns `None`). The connection variables **have placeholders** in `.env`, but the code does not read them yet.
Once implemented, they will connect read-only to your existing FleetDM / Wazuh Manager **with just a URL + credentials**, exactly like Zabbix above.

Until then, to experience the screens with the bundled Fleet/Wazuh demo, use `--profile fleet` / `--profile wazuh`.

---

## 4. Point source-console deep-links at **your own URLs** (optional)

Connect the MORI UI's `Zabbix ↗ / Fleet ↗ / Wazuh ↗ / Grafana ↗` buttons to **your own consoles.**
The defaults point at MORI's demo server, so change them to your own URLs (leave empty to hide just that link).

```dotenv
MORI_ZABBIX_UI_URL=https://zabbix.your-corp.com    # Server assets → Zabbix host page
MORI_FLEET_UI_URL=https://fleet.your-corp.com      # PC assets → Fleet host page
MORI_WAZUH_UI_URL=https://wazuh.your-corp.com      # Alert tiles → Wazuh
MORI_GRAFANA_URL=https://grafana.your-corp.com     # Assigned-server detail → Grafana (Loki logs)
```

> Deep-links are shown only where they match the asset type — Zabbix for servers, Fleet for PCs, and Grafana everywhere.

---

## 5. Operational notes (brownfield deployment)

In `.env`, be sure to set:
```dotenv
MORI_ADMIN_PASSWORD=<strong value>   # Replace the demo default
MORI_AUTH_ENABLED=true               # Block unauthenticated access
MORI_DEMO_MODE=false                 # Turn off demo behavior
MORI_DEMO_SEED=0                     # Stop injecting sample data (real data only)
```
- The worker **retries** every cycle even if a source is temporarily unreachable (it does not depend on the bundled sources).
- A **read-only token** is recommended for MORI's access — it never touches your existing systems' configuration.

---

## 6. Troubleshooting

| Symptom | Check |
| --- | --- |
| Zabbix hosts/alerts don't appear | `docker compose logs mori-worker` → API URL/token, firewall (outbound), `MORI_ENABLE_ZABBIX=true` |
| Auth error | Token permissions (read), user/password typos. When a token is set, user/password are ignored |
| Trivy push returns 401 / "login" | Confirm `MORI_INGEST_TOKEN` is set and the request-header token matches |
| Host and image tracked separately | Specify the real host in the Trivy push with `?hostname=` or `X-MORI-Hostname` |
| Deep-links go to the MORI demo | Replace `.env`'s `MORI_*_UI_URL` with your own URLs (§4) |
| Bundled sources come up too | Run just `docker compose up -d` without any profile |

---

## Next steps

- Onboard Zabbix Agent + Trivy on endpoints → [ZABBIX_AGENT_ACTIVE_SETUP.md](ZABBIX_AGENT_ACTIVE_SETUP.md)
- Understanding & operating Wazuh → [WAZUH_SETUP_AND_OPERATIONS.md](WAZUH_SETUP_AND_OPERATIONS.md)
- Installing & operating Fleet → [FLEET_SETUP_AND_OPERATIONS.md](FLEET_SETUP_AND_OPERATIONS.md)
- Server deployment, HTTPS, operations → [DEPLOYMENT.md](DEPLOYMENT.md)
