# Contributing to MORI SOC

Thanks for your interest! This is an alpha portfolio project; contributions, issues, and
suggestions are welcome.

## Dev setup

```bash
# Full stack (API + PostgreSQL + Zabbix/Wazuh/Fleet/Trivy/Grafana)
cp .env.example .env
docker compose up -d

# One-line demo (seeds sample data + arms the Zabbix scenario)
./scripts/mori-start-demo.sh     # → http://localhost:18000/ui  (admin / 1234)
```

The API is Python 3.12 / FastAPI. Source lives in `src/mori_soc` (`PYTHONPATH=src`).

## Tests & lint (must pass — same as CI)

```bash
# In the running api container (fastest):
docker exec -e PYTHONPATH=/app/src:/app -w /app mori-soc-mori-api-1 \
  python -m unittest discover -s tests -p "test_*.py"

# Lint (critical errors), matching .github/workflows/test.yml:
ruff check --select E9,F63,F7,F82 src tests
```

Postgres-backed tests self-skip when `MORI_DATABASE_URL` is unset, so the suite runs
green without a database in CI.

## Guidelines

- **Match the surrounding code** — comment density, naming, and idioms.
- **Add a test** for behavior changes (`tests/test_*.py`, `unittest`).
- Keep the API thin: endpoints live in `src/mori_soc/api/routes/<domain>.py`, shared state
  flows via `RouteContext` (see `routes/context.py`).
- Templates/i18n: UI strings go through `src/mori_soc/api/i18n.py` (KO + EN).
- **Route/template changes**: verify the app renders (`docker restart mori-soc-mori-api-1`
  picks up new code — the image bakes source, so a restart is required to see changes).

## Commit & PR

- Small, focused commits with a clear message (Korean or English both fine).
- Branch from `main`; open a PR describing what and why. Ensure tests + ruff pass.
- For the Zabbix community template, see [docs/COMMUNITY_TEMPLATE_PR.md](docs/COMMUNITY_TEMPLATE_PR.md).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.
