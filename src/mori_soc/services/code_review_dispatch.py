"""고객 GitHub 레포의 보안 리뷰를 원격 트리거(Option A — dispatch).

MORI 는 코드를 clone/스캔하지 않는다("증적 층" 원칙). UI 에서 받은 repo URL +
GitHub 토큰으로 GitHub Actions ``workflow_dispatch`` 를 호출해 **그 레포의 CI 러너**
에서 claude-code-security-review 를 돌리게 하고, 결과는 워크플로가 다시
``/ingest/code-review`` 로 push 한다. MORI 는 코드를 만지지 않는다.
"""
from __future__ import annotations

import re

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")


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
