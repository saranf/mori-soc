# controls/ — Control catalog (ISMS-P × ISO 27001)

[🇰🇷 한국어](./README.md) · **🇬🇧 English**

The core asset of MORI's **identity pivot (Phase 2)**. It structures — machine-readably — **which certification criterion each of the five sources' operational data serves as evidence for** (Zabbix/Wazuh/Fleet/Trivy/Loki). It's an **independent track** with no code dependency, so it can be filled in parallel with poller work and published to the community as it completes.

> Status: 🟢 **live** — ISMS-P 2023 **101** + ISO 27001:2022 Annex A **93** = **194 controls** (all with KO/EN titles). 14 of them are `reviewed` (evidence sources wired); the rest are `draft` skeletons (titles need verification against the official standard). 61 mappings, 5 defects. Browsable and **editable in the Compliance tab tree**; control_status persists to `schema/009`. Coverage lite ~24% / full ~30% (honest ceiling). Next: grow to 10~15 defects.

## Layout

```
controls/
├── schema/*.json               # JSON Schema (draft-07) — control/mapping/defect (source of truth for shape)
├── isms-p/<id>.yaml            # ISMS-P 2023 (101)   e.g. 2.11.2.yaml
├── iso27001/<id>.yaml          # ISO 27001:2022 Annex A (93)   e.g. A.8.8.yaml
├── mappings/isms-p_to_iso.yaml # N:M crossmapping
├── common_defects/<id>.yaml    # frequent audit defects + link to a MORI evidence signal
├── validate.py                 # validation (schema + cross-refs). PyYAML only
├── _generate_skeleton.py       # full-catalog skeleton generator (ISO 93 + ISMS-P 101)
└── _build_catalog_json.py      # YAML → src/mori_soc/data/controls_catalog.json build
```

## Pipeline (YAML is the source of truth)

```
controls/*.yaml  ──_build_catalog_json.py──▶  src/mori_soc/data/controls_catalog.json
                                                     │ (runtime artifact, committed)
      on boot: services/control_catalog.sync_catalog_to_db() ──▶ schema/007 tables
                                                     │
                     GET /controls/tree  ──▶  Compliance tab tree (admin·security) — browse + edit, control_status → schema/009
```

The image copies only `src/` and has no PyYAML, so **runtime reads only the JSON artifact via stdlib.** After editing `controls/*.yaml`, always re-run `_build_catalog_json.py` to refresh and commit the JSON.

## Key design — evidence source · evidence signal linkage

- **control.evidence_sources**: the MORI sources that produce evidence for a control. This field auto-derives **lite (core+Zabbix+Trivy) / full (+Wazuh·Fleet·Loki) control coverage %** (shown atop the tree screen).
- **defect.mori_signal**: links a common defect to a dashboard **"today's work queue" (evidence-gaps)** tile key — `vuln_pending`·`exceptions_expiring`·`untriaged_alerts`·`overdue`·`control_pending`·`unmapped_assets`. The catalog's "defect" flows straight into the runtime "work queue".

## Add / validate

```bash
python controls/validate.py            # schema + id cross-refs + mori_signal validity
python controls/_build_catalog_json.py # rebuild the runtime JSON (commit it)
```

> `validate.py` runs in GitHub Actions CI (catalog validate job). Roadmap: **Phase 2 — Control catalog** in the README "🗺️ Roadmap (Phase 0 → 5)". It is a prerequisite for P3-5 (Control Mapping) and P4-3 (Evidence Pack).
