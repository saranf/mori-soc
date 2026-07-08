# Getting Started — Install & Operate MORI (new users)

[🇰🇷 한국어](./GETTING_STARTED.md) · **🇬🇧 English**

> This single page walks you through the whole journey: installing MORI, learning it in demo mode, and moving to real operations.
> If you already run Zabbix/Wazuh/Fleet and **just want to feed their data into MORI** →
> see the [Connect an existing stack guide](BROWNFIELD_CONNECT.en.md).

---

## 0. What is MORI? (30 seconds)

MORI is an **"evidence layer" that automatically builds up your ISMS-P / ISO 27001 evidence.**
- It sits **read-only on top of** Zabbix, Wazuh, Fleet, Trivy, and Loki, letting you operate assets, vulnerabilities, alerts, incidents, and control implementation
  from a single screen (`/ui`), while recording every change as evidence with **who, when, and what.**
- The "viewing layer" (dashboard visualization) is delegated to Grafana, so MORI can focus on the **evidence you submit to auditors.**

---

## 1. Prerequisites

| Item | Required version | Check |
| --- | --- | --- |
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | v2 (`docker compose`) | `docker compose version` |
| Spare resources | 4 vCPU / 8GB RAM recommended | For the full demo stack |
| Ports | 18000 (MORI), etc. | Configurable in `.env` |

> To just try MORI on its own, all you need is Docker. To bring up the bundled demo (including Zabbix/Fleet/Wazuh),
> make sure you have plenty of memory.

---

## 2. Install & first run (one line)

```bash
git clone https://github.com/saranf/mori-soc.git
cd mori-soc
cp .env.example .env          # Create the config file (works as-is for the demo)
./scripts/mori-start-demo.sh  # Start MORI core + seed sample data
```

- Open **http://localhost:18000/ui** in your browser
- Log in: **`admin` / `1234`** (demo only — always change before production, see §6)

> `mori-start-demo.sh` brings up **only the MORI core (api, worker, postgres)** and loads sample data.
> To also see the bundled demo sources (Zabbix/Fleet/Wazuh):
> ```bash
> docker compose --profile bundled up -d   # Full demo stack
> # Or individually: --profile zabbix / --profile fleet / --profile wazuh
> ```

Stop / restart:
```bash
./scripts/mori-stop-demo.sh     # Stop
docker compose ps               # Check status
docker compose logs -f mori-api # Logs
```

---

## 3. Default accounts & permissions (RBAC)

The demo ships with role-based accounts (all passwords are `1234`, **demo only**).

| Account | Role | What they can see |
| --- | --- | --- |
| `admin` | Administrator | Everything + settings and scoring rationale |
| `security` | Security officer | Risk assessment, control catalog, all evidence |
| `monitor` | Server monitor | Monitoring, assets (mostly read) |
| `auditor` | Auditor | Monitoring, change history (read-only) |
| `helpdesk` | Help desk | **Only the remediation status of my assigned servers** |

> **Risk assessment / control catalog / evidence** are exclusive to admin and security. Infrastructure and help desk
> see only the remediation status of the servers they are responsible for. (Register your assigned servers in Profile to use the "⭐ My servers" filter.)

---

## 4. A full operational loop (audit scenario)

1. **Dashboard** — role-based security hero + 24h/12h infrastructure status (alert tiles → source deep-links)
2. **Asset inventory** — Fleet (PCs), Zabbix (servers), Trivy (vulnerabilities) tabs. Filter by team or "⭐ my assets only",
   and edit each host's owner and criticality (changes are logged automatically)
3. **Vulnerabilities → Risk assessment** — per-CVE **risk score (1–9)** = impact (criticality) × likelihood (severity).
   Record risk treatment (remediate/accept/transfer/avoid). When admin sets the **DoA (acceptable-risk threshold)** score,
   any risk at or below it is automatically classified as "default accepted".
4. **Compliance → Control catalog** — expand "Detailed analysis" for the **ISMS-P 101 × ISO 194-criteria**
   tree. Click an item to edit its **implementation status (implemented/partially implemented/not implemented/not applicable), owner, improvement plan, and deadline**;
   these **persist across restarts** and leave a change history. One-click **evidence-pack PDF** per control, too.
5. **My assigned servers** — **double-click** a row and the detail modal organizes open items into three buckets — **exception expired, remediation deadline overdue,
   and other risks** — and shows **Zabbix/Grafana/Fleet deep-links** appropriate to the asset type.
6. **Evidence export** — download assets, accounts, logs, vulnerabilities, monthly, and the **6 risk-assessment registers** as CSV/PDF.

---

## 5. Backup & restore

```bash
./scripts/mori-backup.sh    # Create a PostgreSQL logical backup
./scripts/mori-restore.sh   # Restore from a backup
```

- MORI's operational state (owners, remediations, triage, incidents, risk assessments, control implementation status, settings) is all
  **write-through persisted** to PostgreSQL, so it survives restarts and restores. (Schemas `001`–`009`)

---

## 6. Demo → production transition checklist

Be sure to change the following in `.env`.

```bash
# 1) Admin password (required)
MORI_ADMIN_PASSWORD=<strong value>

# 2) Turn on session auth (block unauthenticated access)
MORI_AUTH_ENABLED=true

# 3) DB/service passwords (replace all change_this_*)
MORI_DB_PASSWORD=...
ZABBIX_DB_PASSWORD=...   # Only if using bundled sources
FLEET_DB_PASSWORD=...    # Only if using bundled sources

# 4) Remote ingest token (if using Trivy/CSOP push)
MORI_INGEST_TOKEN=<generate with openssl rand -hex 32>

# 5) Turn off the demo seed (stop injecting sample data)
MORI_DEMO_MODE=false
MORI_DEMO_SEED=0
```

- For detailed server deployment, HTTPS, and operations, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 7. Point source-console deep-links at **your own URLs**

The `Zabbix ↗ / Fleet ↗ / Wazuh ↗ / Grafana ↗` buttons throughout the MORI UI link to each source's web console.
The defaults point at MORI's demo server, but you can **freely swap them for your own server URLs** in `.env`.

```bash
MORI_ZABBIX_UI_URL=https://zabbix.your-corp.com    # Leave empty to hide the Zabbix link
MORI_FLEET_UI_URL=https://fleet.your-corp.com      # Leave empty to hide the Fleet link
MORI_WAZUH_UI_URL=https://wazuh.your-corp.com      # Leave empty to hide the Wazuh link
MORI_GRAFANA_URL=https://grafana.your-corp.com     # Leave empty to hide the Grafana link
```

> Only the links matching the source type are shown — Zabbix for servers, Fleet for PCs, and Grafana everywhere.

---

## 8. Common issues

| Symptom | Check |
| --- | --- |
| `/ui` won't open | Whether `mori-api` is healthy via `docker compose ps`; `docker compose logs mori-api` |
| No data after login | Whether the seed ran — re-run `./scripts/mori-seed-sample-data.sh` |
| Deep-links go to the wrong server | Replace `.env`'s `MORI_*_UI_URL` with your own URLs (§7) |
| Port conflict | Change `.env`'s `MORI_API_PORT`, etc., then restart |
| Remote push returns 401/"login" | Confirm `MORI_INGEST_TOKEN` is set and the request-header token matches |

---

## Next steps

- **Already running Zabbix/Wazuh/Fleet** → [Connect an existing stack guide](BROWNFIELD_CONNECT.en.md)
- Attach Zabbix Agent + Trivy to endpoints → [ZABBIX_AGENT_ACTIVE_SETUP.md](ZABBIX_AGENT_ACTIVE_SETUP.md)
- Server deployment, HTTPS, troubleshooting → [DEPLOYMENT.md](DEPLOYMENT.md)
