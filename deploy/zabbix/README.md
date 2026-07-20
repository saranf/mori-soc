# 번들 Zabbix 모리답게 꾸미기

MORI 에 번들된 Zabbix(`docker compose --profile bundled` / `--profile zabbix`)를 **모리답게** 바꾸는 자산.
**다른(외부) Zabbix 는 대상 아님** — 여긴 MORI 가 띄우는 번들 인스턴스 전용.

> ⚠️ **정직 표기**: 이 저장소 CI 환경엔 실행 중인 Zabbix 가 없어 **시각 검증을 못 했습니다.**
> 리브랜딩(로고·푸터·헬프)은 Zabbix 공식 기능이라 신뢰도 높음. **토스 색 테마(CSS)는
> best-effort** — 실인스턴스에서 눈으로 확인하고 선택자를 조정하세요.
> 재설치(볼륨·이미지 초기화) 시에도 아래 **마운트가 유지되면 리브랜딩도 유지**됩니다.

---

## 1) 리브랜딩 (기본 적용 · 확실함)

`docker-compose.yml` 의 `zabbix-web` 에 다음 파일들이 read-only 로 마운트되어 있습니다:

| 컨테이너 경로 | 파일 | 효과 |
|---|---|---|
| `/usr/share/zabbix/local/conf/brand.conf.php` | `brand.conf.php` | 로고·푸터·도움말 링크 교체 |
| `/usr/share/zabbix/local/conf/mori-logo.svg` | `mori-logo.svg` | 로그인/상단 로고 |
| `/usr/share/zabbix/local/conf/mori-logo-sidebar.svg` | `mori-logo-sidebar.svg` | 사이드바(펼침) |
| `/usr/share/zabbix/local/conf/mori-logo-compact.svg` | `mori-logo-compact.svg` | 사이드바(접힘) |

Zabbix 는 `local/conf/brand.conf.php` 존재를 자동 감지해 리브랜딩합니다. 푸터는
`MORI SOC — ISMS-P / ISO 27001 증적 층 · 모니터링은 Zabbix`, 도움말은 MORI 저장소로.

**적용**: `docker compose --profile bundled up -d zabbix-web` (재생성). 로고가 안 바뀌면
브라우저 캐시를 비우세요.

## 2) 라이트 / 다크 테마 (Zabbix 내장)

Zabbix 는 **라이트(Blue)·다크(Dark)** 테마가 내장돼 있습니다. 사용자별로:
**사용자 프로필(우상단) → Theme → Blue(라이트) / Dark(다크)**.
전역 기본값: **Administration → GUI → Default theme**.

## 3) 토스 색 테마 (옵트인 · best-effort)

`mori-accent.css` 가 내장 라이트(`blue-theme`)·다크(`dark-theme`) 위에 **토스 블루**를 얹습니다
(6색만). 레이아웃은 Zabbix 그대로, 색만 모리.

주입은 nginx `sub_filter` 로 모든 HTML `<head>` 에 CSS 링크를 넣는 방식이 가장 깔끔합니다.
**기본 스택엔 넣지 않았습니다**(검증 안 된 nginx 오버라이드로 부팅을 깨지 않기 위해). 쓰려면:

1. CSS 를 웹루트로 마운트 (`docker-compose.yml` zabbix-web `volumes` 에 추가):
   ```yaml
   - ./deploy/zabbix/mori-accent.css:/usr/share/zabbix/mori-accent.css:ro
   ```
2. nginx 에 sub_filter 추가 (이미지의 서버 설정에 반영 — 예: 커스텀 conf 마운트):
   ```nginx
   location / {
     sub_filter '</head>' '<link rel="stylesheet" href="/mori-accent.css"></head>';
     sub_filter_once on;
     sub_filter_types text/html;
   }
   ```
3. `zabbix-web` 재생성 후 브라우저에서 확인 → 안 먹는 선택자는 개발자도구로 실제 클래스명을
   잡아 `mori-accent.css` 수정.

> 대안(주입 없이): 위 CSS 내용을 Zabbix `assets/styles/` 의 커스텀 테마로 만드는 방법도
> 있으나 테마 등록이 버전마다 달라 유지보수가 번거롭습니다. sub_filter 주입을 권장.

---

## 팔레트 (모리다움 6색)
파랑 `#3182f6` · 진한 파랑 `#1b64da` · 위험 `#f04452` · 완료 `#15c47e` · 주의 `#f5a623` ·
잉크 `#191f28` · 보조 `#8b95a1` · 배경 라이트 `#f2f4f6` / 다크 `#131417`.
