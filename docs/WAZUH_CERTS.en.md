# Wazuh TLS certificates — what broke, and how it is automated now

> Written so that someone new to Wazuh (and to this repo) can read it and act.
> Korean: [WAZUH_CERTS.md](WAZUH_CERTS.md)

## 30-second summary

The three Wazuh services (indexer / manager / dashboard) **only talk to each other over TLS**, so the
certificate files **must exist before they start**. Those certificates used to be created **by hand**,
and when nobody created them the stack died silently (it was down from March 2026 for five months).

Now a single `docker compose --profile wazuh up -d` runs **generate certs -> fix filenames -> start
services**, in that order, automatically. There is nothing for you to do by hand.

```bash
docker compose --profile wazuh up -d          # that's it
```

---

## What went wrong (recorded so it can't happen again)

### 1. No service in compose created the certificates

`docker-compose.yml` mounts `config/wazuh_indexer_ssl_certs/` into the containers — but **nothing ever
filled that directory**, so it was empty.

That triggers a Docker trap:

> **If you ask Docker to bind-mount a file that does not exist, it does not fail — it silently creates
> an _empty directory_ with that name.**

So all eight `.pem` files **became directories**, and OpenSearch (the indexer) died at boot with:

```
root-ca.pem - is a directory
```

The container looped on `Restarting` and nobody noticed.

### 2. Even when generated, the filenames don't match

The generator (`wazuh/wazuh-certs-generator`) emits **one fixed naming scheme**, but the three services
expect **different names**. A single mismatched name kills the stack the same way.

| Service | Expects | Generator produces | Fix |
|---|---|---|---|
| indexer | `wazuh.indexer.pem` | `wazuh.indexer.pem` | none |
| indexer | **`wazuh.indexer.key`** | `wazuh.indexer-key.pem` | **copy** |
| dashboard | **`wazuh-dashboard.pem`** | `wazuh.dashboard.pem` | **copy** |
| dashboard | **`wazuh-dashboard-key.pem`** | `wazuh.dashboard-key.pem` | **copy** |
| manager | `root-ca-manager.pem` / `wazuh.manager.pem` / `wazuh.manager-key.pem` | same | none |

(The difference is only a dot `.` vs a hyphen `-` — nearly invisible. That is why this stayed unfixed.)

---

## How it works now

`docker-compose.yml` contains a **`generate-indexer-certs`** service. It is a one-shot job, and the three
Wazuh services only start **after it completes successfully**
(`depends_on: condition: service_completed_successfully`).

```
generate-indexer-certs  (runs once)
   1. certificates already present? -> do nothing (idempotent)
   2. otherwise                     -> read config/certs.yml, generate 12 files
   3. copy the 3 differently-named files to the aliases the services expect
   4. exit 0
        |
        v
wazuh.indexer / wazuh.manager / wazuh.dashboard  start
```

- **Input**: [`config/certs.yml`](../config/certs.yml) — which node gets which certificate.
- **Output**: `config/wazuh_indexer_ssl_certs/` — the real certificates (**never committed**; gitignored).
- **Idempotent**: re-running never overwrites existing certificates; it only creates missing ones.

### Why copies, not symlinks

Symlinks **can break inside a container** (the link target resolves differently under the container's
mount path). Certificates are a few KB of text, so copying costs nothing. We chose the safe option.

---

## The one rule to remember

> ### Mount certificates **as a directory**. Never bind-mount them **file by file**.
>
> ```yaml
> # Correct — the whole directory
> - ./config/wazuh_indexer_ssl_certs:/usr/share/wazuh-indexer/config/certs:ro
>
> # Forbidden — individual files
> - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/.../certs/root-ca.pem:ro
> ```
>
> With a file-level mount, **if the file is not there yet Docker creates an empty directory with that
> name**, and the service dies with `is a directory`. That is exactly what happened in March.

One more rule, in `config/certs.yml`: the **`ip:` field only accepts a dotted DNS name or an IP**. A short
name like `indexer` is rejected by the generator with `Invalid IP or DNS`. That's why we use
`wazuh.indexer` — and it must equal the compose service name / container hostname for TLS to verify.

---

## Verifying it works

```bash
# 1) all three containers must be Up, not Restarting
docker compose --profile wazuh ps

# 2) the cluster must be green
docker exec mori-soc-wazuh.indexer-1 \
  curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health
# -> {"cluster_name":"wazuh-cluster","status":"green", ...}
```

The `mori-soc-` prefix depends on your compose project name (the directory name). Check `docker ps` for
the actual container names.

## Recovery (when it is broken)

Symptom: containers stuck in `Restarting`; logs say `is a directory` or `no such file`.

```bash
# 1) inspect the cert directory — if the .pem entries are DIRECTORIES, that's the cause
ls -la config/wazuh_indexer_ssl_certs/

# 2) take down ONLY the three wazuh services (careful: a plain `docker compose down`
#    would also stop every other container in this project — mori-api, grafana, ...)
docker compose --profile wazuh rm -sf wazuh.indexer wazuh.manager wazuh.dashboard

# 3) throw the broken certs away (they are empty directories, not real certificates)
rm -rf config/wazuh_indexer_ssl_certs

# 4) bring it back up — generate-indexer-certs recreates everything
docker compose --profile wazuh up -d wazuh.indexer wazuh.manager wazuh.dashboard
```

Regenerating certificates does **not** touch indexer data — a certificate is an identity for the
connection, not your data.

---

## Related

- [Wazuh setup & operations](WAZUH_SETUP_AND_OPERATIONS.md)
- [Deployment](DEPLOYMENT.md)
