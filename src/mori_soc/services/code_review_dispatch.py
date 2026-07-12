"""고객 GitHub 레포의 보안 리뷰를 원격 트리거(Option A — dispatch).

MORI 는 코드를 clone/스캔하지 않는다("증적 층" 원칙). UI 에서 받은 repo URL +
GitHub 토큰으로 GitHub Actions ``workflow_dispatch`` 를 호출해 **그 레포의 CI 러너**
에서 claude-code-security-review 를 돌리게 하고, 결과는 워크플로가 다시
``/ingest/code-review`` 로 push 한다. MORI 는 코드를 만지지 않는다.
"""
from __future__ import annotations

import re

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")

# 코드 리뷰 스캔이 증적을 대는 통제(개발보안 2.8 / SDLC). 각 YAML 의 evidence_sources:[code_review]
# 와 일치해야 한다: controls/isms-p/2.8.1·2.8.5, controls/iso27001/A.8.25·A.8.28.
CODE_REVIEW_CONTROL_IDS = ("2.8.1", "2.8.5", "A.8.25", "A.8.28")


# 고객이 자기 레포 .github/workflows/ 에 복붙하는 무료 Semgrep 워크플로(기존 코드 전체 감사).
# 파일 1개 + Secret 1개(MORI_INGEST_URL)면 끝 — ANTHROPIC 키 불필요. __AUDIENCE__ 만 서빙 시 치환.
WORKFLOW_TEMPLATE = """\
name: code-review-semgrep
# MORI 코드 보안 리뷰 증적 — 무료 Semgrep(SAST)로 기존 코드 전체 스캔 → 결과를 MORI로 전송.
# 준비물: 이 파일 1개 + 레포 Secret 1개(MORI_INGEST_URL). ANTHROPIC 키 불필요(무료).
on:
  workflow_dispatch:            # MORI UI 원격 실행 / 수동 실행
    inputs:
      mori_ingest_url:
        description: "MORI ingest base URL (원격 트리거 시 자동 주입)"
        required: false
        default: ""
  # 정기 베이스라인(월 1회) — 필요하면 주석 해제:
  # schedule:
  #   - cron: "0 0 1 * *"

permissions:
  contents: read
  id-token: write               # GitHub OIDC — MORI가 repo·commit·run을 서명 검증(위조 불가)

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Semgrep scan (free OSS rules)
        run: |
          python3 -m pip install --quiet semgrep
          # auto = 공개 무료 룰, p/secrets = 하드코딩 비밀/자격증명(개인정보·시크릿) 탐지.
          semgrep scan --config auto --config p/secrets --sarif --output semgrep.sarif . || true
      - name: Push results to MORI
        continue-on-error: true
        env:
          MORI_INGEST_URL: ${{ github.event.inputs.mori_ingest_url || secrets.MORI_INGEST_URL }}
          MORI_INGEST_TOKEN: ${{ secrets.MORI_INGEST_TOKEN }}
        run: |
          [ -z "$MORI_INGEST_URL" ] && { echo "MORI_INGEST_URL 미설정 — 스킵"; exit 0; }
          [ -f semgrep.sarif ] || { echo "SARIF 없음 — 스킵"; exit 0; }
          OIDC=""
          if [ -n "$ACTIONS_ID_TOKEN_REQUEST_URL" ]; then
            OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
              "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=__AUDIENCE__" | jq -r '.value // empty')
          fi
          HDR=(-H "Content-Type: application/json")
          [ -n "$MORI_INGEST_TOKEN" ] && HDR+=(-H "Authorization: Bearer ${MORI_INGEST_TOKEN}")
          [ -n "$OIDC" ] && HDR+=(-H "X-MORI-OIDC: ${OIDC}")
          curl -fsS -X POST \\
            "${MORI_INGEST_URL%/}/ingest/code-review?repo=${GITHUB_REPOSITORY}&commit=${GITHUB_SHA}&run_id=${GITHUB_RUN_ID}" \\
            "${HDR[@]}" --data-binary "@semgrep.sarif"
"""


def workflow_template(audience: str = "mori-ingest") -> str:
    """고객 배포용 code-review-semgrep.yml 템플릿(무료, 감사 audience 채워서)."""
    return WORKFLOW_TEMPLATE.replace("__AUDIENCE__", audience or "mori-ingest")


# (선택·유료) Claude 심층 리뷰 워크플로 — code-review-fullscan.yml + scripts/code_review_fullscan.py.
FULLSCAN_WORKFLOW_TEMPLATE = """\
name: code-review-fullscan
# (유료) Claude AI로 기존 코드 전체를 심층 리뷰 → 결과를 MORI로 전송.
# 준비물: 이 파일 + scripts/code_review_fullscan.py, 레포 Secrets(ANTHROPIC_API_KEY·MORI_INGEST_URL).
on:
  workflow_dispatch:
    inputs:
      mori_ingest_url:
        description: "MORI ingest base URL (원격 트리거 시 자동 주입)"
        required: false
        default: ""
  # schedule:
  #   - cron: "0 0 1 * *"

permissions:
  contents: read
  id-token: write

jobs:
  fullscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Full-repo AI security review -> MORI
        continue-on-error: true
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          MORI_INGEST_URL: ${{ github.event.inputs.mori_ingest_url || secrets.MORI_INGEST_URL }}
          MORI_INGEST_TOKEN: ${{ secrets.MORI_INGEST_TOKEN }}
          CLAUDE_MODEL: claude-sonnet-5
        run: |
          [ -z "$MORI_INGEST_URL" ] && { echo "MORI_INGEST_URL 미설정 — 스킵"; exit 0; }
          if [ -n "$ACTIONS_ID_TOKEN_REQUEST_URL" ]; then
            export MORI_OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
              "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=__AUDIENCE__" | jq -r '.value // empty')
          fi
          python3 scripts/code_review_fullscan.py
"""


def fullscan_template(audience: str = "mori-ingest") -> str:
    """(유료) code-review-fullscan.yml 템플릿(감사 audience 채워서)."""
    return FULLSCAN_WORKFLOW_TEMPLATE.replace("__AUDIENCE__", audience or "mori-ingest")


def parse_github_repo(url: str) -> tuple[str, str]:
    """GitHub repo URL/식별자에서 (owner, repo) 를 뽑는다.

    허용 형식: ``https://github.com/owner/repo``, ``…/owner/repo.git``,
    ``…/owner/repo/tree/main``, ``git@github.com:owner/repo.git``, ``owner/repo``.
    """
    s = (url or "").strip()
    if not s:
        raise ValueError("repo URL 이 비어 있습니다.")
    s = re.sub(r"^git@github\.com:", "", s)
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^(www\.)?github\.com/", "", s)
    s = s.rstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    parts = [p for p in s.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"GitHub owner/repo 를 찾을 수 없습니다: {url}")
    owner, repo = parts[0], parts[1]
    if not _SEGMENT.match(owner) or not _SEGMENT.match(repo):
        raise ValueError(f"유효하지 않은 owner/repo: {owner}/{repo}")
    return owner, repo


def dispatch_workflow(
    owner: str,
    repo: str,
    token: str,
    *,
    ref: str = "main",
    workflow: str = "security-review.yml",
    inputs: dict[str, str] | None = None,
    api_base: str = "https://api.github.com",
) -> dict[str, object]:
    """GitHub Actions ``workflow_dispatch`` 호출. 성공 시 GitHub 는 204 를 반환한다.

    토큰은 이 호출에만 쓰고 저장하지 않는다(호출자 책임). ``workflow`` 는 대상 레포에
    존재하고 ``on: workflow_dispatch`` 를 선언해야 한다(security-review.yml 이 이미 그럼).
    """
    import httpx

    if not token:
        raise ValueError("GitHub 토큰이 필요합니다.")
    endpoint = f"{api_base}/repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches"
    resp = httpx.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        json={"ref": ref, "inputs": inputs or {}},
        timeout=30.0,
    )
    if resp.status_code == 204:
        return {"ok": True, "status": 204}
    detail = ""
    try:
        detail = str(resp.json().get("message", "")).strip()
    except Exception:
        detail = (resp.text or "")[:200]
    # 흔한 원인을 사람이 읽을 수 있게 매핑
    hint = {
        401: "토큰이 유효하지 않거나 만료됨",
        403: "토큰 권한 부족(actions:write 필요) 또는 레포 접근 불가",
        404: "레포·워크플로 파일을 찾을 수 없음(security-review.yml 이 대상 레포에 있어야 함)",
        422: "ref(브랜치)가 없거나 workflow_dispatch 미선언",
    }.get(resp.status_code, "")
    msg = f"GitHub dispatch 실패 ({resp.status_code})"
    if hint:
        msg += f" — {hint}"
    if detail:
        msg += f": {detail}"
    raise RuntimeError(msg)
