# LDAP 통합 — 계정 하나로 MORI·Grafana·Zabbix·Fleet 로그인

**🇰🇷 한국어** · [🇬🇧 English](./LDAP_INTEGRATION.en.md)

> LDAP은 **선택**입니다. 기본 설치는 LDAP 없이 로컬 계정으로 동작하고, **원하는 사람만**
> `MORI_LDAP_ENABLED=true` 로 켜면 됩니다. 켜면 ① MORI 로그인이 LDAP으로 되고 ② **가입 승인 시
> 계정이 LDAP에 생성**되어 같은 LDAP을 보는 Grafana/Zabbix/Fleet 에서도 **같은 계정으로 로그인**됩니다.

---

## 0. 켤까 말까? (30초 판단)

| 상황 | 권장 |
| --- | --- |
| 계정을 MORI에서만 쓰고 사용자 수 적음 | **LDAP 끄고** 로컬 계정 (기본) |
| MORI + Grafana/Zabbix/Fleet를 **계정 하나로** 통합 로그인하고 싶음 | **LDAP 켜기** |
| 이미 사내 LDAP/AD가 있음 | **LDAP 켜서** 그 디렉터리를 가리키기 |

LDAP은 언제든 켜고 끌 수 있습니다(끄면 다시 로컬 계정만 사용).

---

## 1. LDAP 켜기 (번들 OpenLDAP)

`docker compose up` 은 번들 **OpenLDAP + phpLDAPadmin** 을 함께 띄웁니다.
`.env` 에서 아래만 켜고 `mori-api` 를 재기동하면 끝입니다.

```dotenv
MORI_LDAP_ENABLED=true                                   # ← 이 한 줄이 스위치 (기본 false)
MORI_LDAP_URL=ldap://openldap:389
MORI_LDAP_BIND_DN=cn=admin,dc=mori,dc=local
MORI_LDAP_BIND_PASSWORD=change_this_ldap_admin_password  # = LDAP_ADMIN_PASSWORD (쓰기 권한)
MORI_LDAP_BASE_DN=ou=users,dc=mori,dc=local              # 사용자 OU
MORI_LDAP_USER_ATTR=uid
```

```bash
docker compose up -d openldap mori-api
```

> phpLDAPadmin(웹 LDAP 관리)은 `http://localhost:18089` (계정 `cn=admin,dc=mori,dc=local`).

**기존(사내) LDAP/AD 를 쓰려면** 위 URL/DN/비밀번호를 그 디렉터리 값으로 바꾸면 됩니다.
바인드 계정은 **가입 승인 시 계정 생성**을 위해 사용자 OU에 쓰기 권한이 필요합니다(로그인만
검증하려면 읽기 권한으로 충분).

---

## 2. 로그인 & 가입 흐름 (승인제)

**로그인** — LDAP이 켜져 있으면 `LDAP → 로컬 계정` 순으로 검증합니다. 그래서 관리자(`admin`)
같은 로컬 계정도 그대로 로그인됩니다.

**가입(승인제)** — 아무나 계정이 생기지 않도록 **admin 승인**을 거칩니다.

1. 사용자: `/signup-request` 에서 **로그인 아이디·이름·이메일** 제출
2. admin: 어드민 콘솔 → **가입 요청 관리** → 요청 행에서 **역할** 선택 + **초기 비밀번호**
   입력(비우면 자동 생성) → **승인**
3. 승인 즉시 **LDAP에 계정 생성** + 초기 비밀번호 **1회 표시**(사용자에게 전달)
4. 사용자는 그 계정으로 **MORI + Grafana/Zabbix/Fleet(같은 LDAP)** 에 로그인

> 역할(role)은 `ui_settings`(`ldaprole:<uid>`)에 영속되어 **재시작 후에도 유지**됩니다.
> 비밀번호는 LDAP이 검증하므로 MORI가 저장하지 않습니다.

---

## 3. 사용자 직접 관리

### (A) MORI 어드민 UI (권장)

`admin` 으로 로그인 → **어드민 콘솔 → Access Control(접근 제어) → 🔑 LDAP 사용자 관리**.
LDAP이 켜져 있으면 상단에 `● 활성 · <url> · <base_dn>` 이 표시되고, 아래에서:

- **사용자 목록** — uid·이름·이메일·MORI 역할
- **추가** — uid·이름·이메일·초기 비밀번호·역할 입력 → **+ 추가**
- **비번 재설정 / 역할 변경 / 삭제** — 각 행에서 바로

가입 폼 없이 관리자가 즉시 계정을 만들고 관리할 수 있고, 여기서 만든 계정은 같은 LDAP을
보는 Grafana/Zabbix/Fleet 에서도 로그인됩니다. (LDAP이 꺼져 있으면 켜라는 안내만 표시)

> API: `GET /admin/ldap/status` · `GET/POST /admin/ldap/users` ·
> `POST /admin/ldap/users/{uid}/password` · `.../role` · `DELETE /admin/ldap/users/{uid}` (모두 admin 전용)

### (B) CLI 헬퍼 스크립트

서버 터미널에서 바로 만들 수도 있습니다.

```bash
# 번들 OpenLDAP 에 추가
./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'InitPassw0rd!' -m hong@corp.com

# 기존(외부) LDAP 에 추가
./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'pw' \
  --host ldap://ldap.corp.com:389 \
  --admin-dn 'cn=admin,dc=corp,dc=com' --admin-pw '***' \
  --base 'ou=users,dc=corp,dc=com'
```

스크립트는 사용자 OU가 없으면 만들고, `inetOrgPerson` 계정을 추가합니다. 추가된 계정은
같은 LDAP을 보는 모든 서비스에서 로그인됩니다.

---

## 4. 기존 Zabbix/Grafana 를 같은 LDAP에 붙이기

이 스택은 각 서비스의 LDAP 토글을 **이미 `.env` 로 노출**합니다. 켜면 세 서비스가 같은
디렉터리를 바라봐서 **계정 하나로 통합 로그인**됩니다.

### Grafana
```dotenv
GRAFANA_LDAP_ENABLED=true
```
- 매핑은 `config/grafana/ldap.toml` (compose가 `/etc/grafana/ldap.toml` 로 마운트).
- 신규 사용자 자동 생성 허용(`GF_AUTH_LDAP_ALLOW_SIGN_UP=true`)이 기본입니다.

### Zabbix (번들)
```dotenv
ZABBIX_LDAP_ENABLED=true
ZABBIX_LDAP_BASE_DN=ou=users,dc=mori,dc=local
ZABBIX_LDAP_SEARCH_ATTRIBUTE=uid
ZABBIX_LDAP_BIND_DN=cn=admin,dc=mori,dc=local
# 바인드 비밀번호는 LDAP_ADMIN_PASSWORD 를 사용
```
> 기존(외부) Zabbix라면 Zabbix 웹 UI → **관리 → 인증 → LDAP** 에서 위와 같은 값을 넣으면
> 됩니다(BASE DN·검색 속성·바인드 계정).

### 적용
```bash
docker compose up -d grafana zabbix-web    # 번들 서비스 재기동
```

이제 §2/§3 으로 만든 계정으로 **MORI·Grafana·Zabbix에 동일 로그인**됩니다.

---

## 5. 끄기 / 되돌리기

`.env` 에서 `MORI_LDAP_ENABLED=false` (+ 필요 시 `GRAFANA_LDAP_ENABLED`/`ZABBIX_LDAP_ENABLED=false`)
후 재기동하면 각 서비스는 다시 로컬 계정만 사용합니다. LDAP에 만든 계정은 디렉터리에 남습니다.

---

## 6. 트러블슈팅

| 증상 | 확인 |
| --- | --- |
| LDAP 로그인 실패 | `MORI_LDAP_ENABLED=true` 인지, `MORI_LDAP_URL/BASE_DN/USER_ATTR` 값, 바인드 계정 비밀번호 |
| 가입 승인 시 "LDAP 계정 생성 실패" | 바인드 계정의 **쓰기 권한**, 사용자 OU(`MORI_LDAP_BASE_DN`) 존재 여부 |
| 승인했는데 역할이 user로 보임 | 재시작 후 역할은 `ui_settings`(`ldaprole:<uid>`)에서 복원됨 — DB 연결(`MORI_DATABASE_URL`) 확인 |
| 비밀번호가 안 맞음 | 초기 비밀번호는 승인 시 **1회만 표시** — 분실 시 phpLDAPadmin/스크립트로 재설정 |
| ldap3 미설치 | 이미지에 포함(`ldap3==2.9.1`). 커스텀 환경이면 설치 필요 |

---

## 다음 단계

- 신규 설치·운영 → [GETTING_STARTED.md](GETTING_STARTED.md)
- 기존 Zabbix/Wazuh/Fleet 데이터 연결 → [BROWNFIELD_CONNECT.md](BROWNFIELD_CONNECT.md)
