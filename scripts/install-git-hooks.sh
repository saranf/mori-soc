#!/usr/bin/env bash
# pre-push 훅 설치(옵트인, R2) — 푸시 전 `scripts/check.sh` 를 돌려 CI 반복 실패를 선제 차단.
# git 훅은 버전관리되지 않으므로, 원하는 개발자가 한 번 실행해 설치한다.
#   bash scripts/install-git-hooks.sh    (또는 make install-hooks)
# 우회(급할 때): git push --no-verify
set -euo pipefail
cd "$(dirname "$0")/.."

hook=".git/hooks/pre-push"
mkdir -p .git/hooks
cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
# MORI pre-push 게이트 — 실패 시 푸시 중단(우회: git push --no-verify).
echo "[pre-push] scripts/check.sh 실행 중… (우회: --no-verify)"
bash scripts/check.sh
HOOK
chmod +x "$hook"
echo "설치 완료: $hook"
echo "이제 git push 전에 scripts/check.sh 가 자동 실행됩니다. (우회: git push --no-verify)"
