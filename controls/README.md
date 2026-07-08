# controls/ — 통제 카탈로그 (ISMS-P × ISO 27001)

**🇰🇷 한국어** · [🇬🇧 English](./README.en.md)

MORI의 **정체성 전환(Phase 2)** 핵심 자산. 다섯 소스(Zabbix/Wazuh/Fleet/Trivy/Loki)의 운영 데이터를 **어떤 인증기준의 증적으로 쓰는지** 기계가 읽을 수 있게 구조화한다. 코드 의존성이 없는 **독립 트랙**이라 폴러 개발과 병렬로 채우고, 완성되는 대로 커뮤니티에 공개 가능하다.

> 상태: 🟢 **라이브** — ISMS-P 2023 **101** + ISO 27001:2022 Annex A **93** = **194 통제**(모두 한/영 제목). 이 중 14건은 증적 소스가 연결된 `reviewed`, 나머지는 `draft` 골격(공식 고시 대비 검증 필요). 매핑 61·결함 5. **Compliance 탭 트리**에서 조회·편집 가능하며 통제 상태(control_status)는 `schema/009`에 영속화된다. 커버리지 lite ~24% / full ~30%(정직한 상한). 다음: 결함 10~15로 확장.

## 디렉터리 구조

```
controls/
├── schema/*.json               # JSON Schema(draft-07) — control/mapping/defect (정답지)
├── isms-p/<id>.yaml            # ISMS-P 2023 (101)  예: 2.11.2.yaml
├── iso27001/<id>.yaml          # ISO 27001:2022 Annex A (93)  예: A.8.8.yaml
├── mappings/isms-p_to_iso.yaml # N:M 크로스매핑
├── common_defects/<id>.yaml    # 심사 단골 결함 + MORI 증적 신호 연결
├── validate.py                 # 검증(스키마 + 상호참조). PyYAML만 필요
├── _generate_skeleton.py       # 전 항목 골격 생성기(ISO 93 + ISMS-P 101)
└── _build_catalog_json.py      # YAML → src/mori_soc/data/controls_catalog.json 빌드
```

## 파이프라인 (YAML = 정본)

```
controls/*.yaml  ──_build_catalog_json.py──▶  src/mori_soc/data/controls_catalog.json
                                                     │ (런타임 아티팩트, 커밋됨)
             기동 시 services/control_catalog.sync_catalog_to_db() ──▶ schema/007 테이블
                                                     │
                        GET /controls/tree  ──▶  Compliance 탭 트리(admin·security) — 조회·편집, 통제상태 → schema/009
```

이미지에는 `src/`만 복사되고 PyYAML이 없으므로, **런타임은 JSON 아티팩트만 stdlib로 읽는다.** `controls/*.yaml`을 수정하면 반드시 `_build_catalog_json.py`를 다시 실행해 JSON을 갱신·커밋한다.

## 핵심 설계 — 증적 소스 · 증적 신호 연결

- **control.evidence_sources**: 각 통제의 증적을 만드는 MORI 소스. 이 필드로 **lite(코어+Zabbix+Trivy) / full(+Wazuh·Fleet·Loki) 통제 커버리지 %**를 자동 산출한다(트리 화면 상단에 노출).
- **defect.mori_signal**: 공통 결함을 대시보드 **'오늘의 작업 큐'(evidence-gaps)** 타일 키와 연결 — `vuln_pending`·`exceptions_expiring`·`untriaged_alerts`·`overdue`·`control_pending`·`unmapped_assets`. 카탈로그의 "결함"이 런타임 "작업 큐"로 이어진다.

## 항목 추가 / 검증

```bash
# 1) isms-p/ 또는 iso27001/ 에 <id>.yaml 추가(또는 draft 골격의 intent/evidence 채우기)
# 2) 매핑/결함이면 mappings/ · common_defects/ 에 추가
python controls/validate.py            # 스키마 준수 + id 상호참조 + mori_signal 유효성
python controls/_build_catalog_json.py # 런타임 JSON 재빌드(커밋)
```

> `validate.py`는 GitHub Actions CI(catalog validate job)로 승격되어 있다. 로드맵 위치는 README "🗺️ 로드맵 (Phase 0 → 5)"의 **Phase 2 — 통제 카탈로그**. 전제조건: 이 카탈로그가 있어야 P3-5(Control Mapping)·P4-3(Evidence Pack)이 성립한다.
