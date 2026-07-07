# controls/ — 통제 카탈로그 (ISMS-P × ISO 27001)

MORI의 **정체성 전환(Phase 2)** 핵심 자산. 다섯 소스(Zabbix/Wazuh/Fleet/Trivy/Loki)가 만들어내는 운영 데이터를 **어떤 인증기준의 증적으로 쓰는지** 기계가 읽을 수 있게 구조화한다. 코드 의존성이 없는 **독립 트랙**이라 폴러 개발과 병렬로 채우고, 완성되는 대로 커뮤니티에 공개 가능하다.

> 상태: 🟡 **골격(skeleton)**. 전 항목 구조 + JSON Schema + 샘플이 들어와 있고, 1차 목표는 전 항목 골격 + 매핑 60~70건 + 결함사례 10~15건. (전량 매핑은 하지 않는다 — 혼자라 늘어짐.)

## 디렉터리 구조

```
controls/
├── schema/                     # JSON Schema (draft-07) — 데이터의 정답지
│   ├── control.schema.json     #   통제 1건
│   ├── mapping.schema.json     #   ISMS-P ↔ ISO N:M 매핑
│   └── defect.schema.json      #   공통 결함사례
├── isms-p/<id>.yaml            # ISMS-P(2023) 인증기준 (예: 2.11.2.yaml)
├── iso27001/<id>.yaml          # ISO 27001:2022 Annex A (예: A.8.8.yaml)
├── mappings/isms-p_to_iso.yaml # 크로스매핑
├── common_defects/<id>.yaml    # 심사 단골 결함 + MORI 증적 신호 연결
└── validate.py                 # 검증(스키마 준수 + 상호참조). PyYAML만 필요
```

## 핵심 설계 — 증적 소스 · 증적 신호 연결

- **control.evidence_sources**: 각 통제의 증적을 만드는 MORI 소스(`zabbix`/`wazuh`/`fleet`/`trivy`/`loki`/`mori`). 이 필드로 "lite(=코어+Zabbix+Trivy) 통제 커버리지 N% / full M%"를 자동 산출한다.
- **defect.mori_signal**: 공통 결함을 대시보드 **'오늘의 작업 큐'(evidence-gaps)** 타일 키와 연결한다 — `vuln_pending` · `exceptions_expiring` · `untriaged_alerts` · `overdue` · `control_pending` · `unmapped_assets`. 즉 카탈로그의 "결함"이 런타임의 "작업 큐"로 그대로 이어진다.

## 항목 추가하는 법

1. `isms-p/` 또는 `iso27001/`에 `<id>.yaml` 추가 (스키마의 `required` 필드 채우기).
2. 대응 관계가 있으면 `mappings/isms-p_to_iso.yaml`에 매핑 추가.
3. 심사 결함 패턴이면 `common_defects/`에 추가하고 가능하면 `mori_signal` 연결.
4. 검증: `python controls/validate.py` → `OK` 확인.

## 검증

```bash
python controls/validate.py     # 스키마 준수 + id 상호참조 + mori_signal 유효성
```

> Phase 2 정식 단계에서 이 검증을 GitHub Actions CI로 승격하고, 기동 시 `schema/007_controls.sql` 테이블로 YAML→DB 싱크한다.

## 로드맵 위치

README "🗺️ 로드맵 (Phase 0 → 5)"의 **Phase 2 — 통제 카탈로그**. 전제조건: 이 카탈로그가 있어야 P3-5(Control Mapping Assistant)·P4-3(Evidence Pack)이 성립한다.
