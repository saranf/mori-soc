# 배포용 SSH 키 & GitHub Actions 시크릿 설정 가이드

`deploy-mori-soc` 워크플로우(`.github/workflows/deploy.yml`)가 GitHub → 배포 서버로
**SSH 접속하여 자동 배포**하려면 아래 시크릿이 필요합니다. 시크릿이 없으면
워크플로우는 **자동으로 스킵**(초록)되므로, 자동 배포를 쓸 때만 설정하면 됩니다.

| 시크릿 | 용도 | 필수 |
|---|---|---|
| `DEPLOY_HOST` | 배포 서버 호스트/IP | ✅ |
| `DEPLOY_PORT` | SSH 포트 (기본 22) | ✅ |
| `DEPLOY_USER` | SSH 로그인 계정 | ✅ |
| `DEPLOY_SSH_KEY` | **개인키**(private key) 전체 내용 | ✅ |
| `DEPLOY_ENV_FILE` | 서버에서 쓸 `.env` 전체 내용(멀티라인) | ✅ |
| `DEPLOY_KNOWN_HOSTS` | 서버의 known_hosts 라인 | 선택(없으면 ssh-keyscan 자동) |

---

## 1. 배포 전용 SSH 키쌍 생성 (로컬)

개인 계정 키를 재사용하지 말고 **배포 전용 키**를 새로 만드세요.

```bash
ssh-keygen -t ed25519 -C "mori-deploy" -f ~/.ssh/mori_deploy -N ""
# 생성물:
#   ~/.ssh/mori_deploy       ← 개인키 (GitHub Secret DEPLOY_SSH_KEY 에 넣을 것)
#   ~/.ssh/mori_deploy.pub   ← 공개키 (서버에 등록)
```

> `-N ""` = 패스프레이즈 없음. CI는 대화형 입력을 못 하므로 배포 키는 패스프레이즈 없이 만듭니다. (대신 이 키는 배포에만 쓰고, 유출 시 서버에서 즉시 제거)

---

## 2. 공개키를 배포 서버에 등록

```bash
# 방법 A) ssh-copy-id (가장 간단)
ssh-copy-id -i ~/.ssh/mori_deploy.pub -p <DEPLOY_PORT> <DEPLOY_USER>@<DEPLOY_HOST>

# 방법 B) 수동 — 서버에서
#   ~/.ssh/authorized_keys 에 mori_deploy.pub 내용을 한 줄로 추가
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat mori_deploy.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

접속 테스트(개인키로):

```bash
ssh -i ~/.ssh/mori_deploy -p <DEPLOY_PORT> <DEPLOY_USER>@<DEPLOY_HOST> "echo OK && docker --version"
```

`OK` 가 나오면 성공입니다.

---

## 3. known_hosts 값 얻기 (선택)

`DEPLOY_KNOWN_HOSTS` 를 설정하면 CI가 매번 ssh-keyscan 하지 않아 더 안전합니다.

```bash
ssh-keyscan -p <DEPLOY_PORT> <DEPLOY_HOST>
# 출력된 라인들을 그대로 DEPLOY_KNOWN_HOSTS 값으로 복사
```

설정하지 않으면 워크플로우가 `ssh-keyscan`으로 자동 처리합니다(TOFU).

---

## 4. GitHub 저장소에 시크릿 등록

GitHub 저장소 → **Settings → Secrets and variables → Actions → New repository secret** 에서
아래를 각각 추가합니다.

| Name | Value |
|---|---|
| `DEPLOY_HOST` | 예: `mori.example.com` |
| `DEPLOY_PORT` | 예: `22` |
| `DEPLOY_USER` | 예: `deploy` |
| `DEPLOY_SSH_KEY` | `cat ~/.ssh/mori_deploy` **전체 출력**(`-----BEGIN … END-----` 포함) |
| `DEPLOY_ENV_FILE` | 서버용 `.env` 전체 내용(멀티라인 그대로) |
| `DEPLOY_KNOWN_HOSTS` | 3단계 출력(선택) |

개인키 복사:

```bash
cat ~/.ssh/mori_deploy   # 이 전체를 DEPLOY_SSH_KEY 값에 붙여넣기
```

> ⚠️ **`.pub`(공개키)가 아니라 개인키 파일 내용**을 넣습니다. `DEPLOY_SSH_KEY`가 비어 있으면 "The ssh-private-key argument is empty" 에러로 실패합니다(가드로 스킵되지만 자동 배포는 안 됨).

---

## 5. 동작 확인

- 시크릿 등록 후 `main`에 push하거나 **Actions → deploy-mori-soc → Run workflow**(수동 실행).
- 성공 시: 서버에서 `rsync` → `.env` 업로드 → `docker compose pull && up -d` 순으로 배포됩니다.
- 시크릿을 하나라도 안 넣었으면 워크플로우는 **스킵(초록)** — 실패로 뜨지 않습니다.

## 6. 보안 메모

- 배포 키는 **배포 전용**으로만 사용하고, 서버 `authorized_keys`에서 필요 시 즉시 제거할 수 있게 관리하세요.
- 가능하면 `DEPLOY_USER`는 `docker` 그룹만 가진 **최소 권한 계정**으로 두고, 서버 방화벽에서 SSH 포트를 신뢰 IP로 제한하세요.
- `DEPLOY_ENV_FILE`에는 실운영 비밀번호가 들어가므로 **GitHub Secret으로만** 관리하고 저장소에 커밋하지 마세요.
