# Security Policy

MORI SOC is an **alpha** audit-evidence platform. It ships with intentionally simple
demo defaults; do not run it as-is in production.

## Supported versions

| Version | Supported |
|---|---|
| `0.6.x-alpha` (current) | ✅ security fixes |
| `< 0.6` | ❌ |

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
  - Serve over HTTPS behind a reverse proxy.
  - Restrict RBAC and network exposure; rotate `MORI_INGEST_TOKEN` and Zabbix/Wazuh/Fleet secrets.
- MORI connects to source tools **read-only**; it does not modify their configuration.
