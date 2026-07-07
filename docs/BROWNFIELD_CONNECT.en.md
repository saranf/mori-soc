# Brownfield connect — put MORI on top of existing Zabbix/Wazuh/Fleet

[🇰🇷 한국어](./BROWNFIELD_CONNECT.md) · **🇬🇧 English**

For environments that already run monitoring/security tools: start **MORI core only and connect via `.env`** — MORI does not need to bring up its own bundled Zabbix/Fleet/Wazuh.

## TL;DR

```bash
cp .env.example .env          # first time
# repoint the source URLs/credentials in .env to your existing infra (table below)
docker compose up -d          # MORI core only (api + worker + postgres)
```

`docker compose up` now starts **MORI core + dashboards (grafana/loki/fluent-bit) + LDAP** only. Bundled source stacks (Zabbix/Fleet/Wazuh + their DBs) sit behind the `bundled` profile.

## compose profiles

| Command | Starts |
|---|---|
| `docker compose up -d` | MORI core only (brownfield default) |
| `docker compose --profile bundled up -d` | core + the full bundled Zabbix·Fleet·Wazuh demo |
| `docker compose --profile zabbix up -d` | core + bundled Zabbix only |
| `docker compose --profile fleet up -d` | core + bundled Fleet only |
| `docker compose --profile wazuh up -d` | core + bundled Wazuh only |

Profiles combine: `docker compose --profile zabbix --profile fleet up -d`.

## Per-source connectivity

| Source | Method | Status | Required .env |
|---|---|---|---|
| **Zabbix** | live REST (JSON-RPC) polling | ✅ config only | `MORI_ENABLE_ZABBIX`, `MORI_ZABBIX_API_URL`, `MORI_ZABBIX_API_TOKEN` **or** `MORI_ZABBIX_USER`/`MORI_ZABBIX_PASSWORD` |
| **Trivy / CSOP** | remote token push (`POST /ingest/trivy`, `/ingest/evidence`) | ✅ token only | `MORI_INGEST_TOKEN` |
| **Fleet** | live REST poller | ⚠️ Phase 3 (not yet) | `MORI_FLEET_API_URL`, `MORI_FLEET_API_TOKEN` (slots reserved) |
| **Wazuh** | Manager REST (55000) poller | ⚠️ Phase 3 (not yet) | `MORI_WAZUH_API_URL`, `MORI_WAZUH_API_USER`, `MORI_WAZUH_API_PASSWORD` (slots reserved) |

### 1) Zabbix (existing instance)

```dotenv
MORI_ENABLE_ZABBIX=true
MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
MORI_ZABBIX_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx   # token preferred (ignores user/pass)
# or
MORI_ZABBIX_USER=mori-readonly
MORI_ZABBIX_PASSWORD=********
```

Apply: `docker compose up -d mori-worker`. A read-only account is sufficient.

### 2) Trivy / CSOP (remote scanner → MORI push)

```dotenv
MORI_INGEST_TOKEN=$(openssl rand -hex 32)
```

```bash
curl -X POST "https://mori.example.com/ingest/trivy?hostname=server-db01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @trivy-report.json
```

### 3) Fleet / Wazuh (planned)

Live API pollers are **not implemented yet** (`build_collector()` returns `None`). `.env` slots exist but code doesn't read them. Until then, use `--profile fleet` / `--profile wazuh` to try the bundled demo.

## Operational notes

- For brownfield deployments set `MORI_ADMIN_PASSWORD`, `MORI_DEMO_MODE=false`, `MORI_DEMO_SEED=0`.
- The worker retries each cycle even if a source is temporarily unreachable (no dependency on bundled sources).
