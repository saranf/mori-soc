"""로그인 세션 영속 래퍼(M10 Phase A).

``PersistentSessionDict`` 는 dict 를 그대로 흉내내되(login 의 ``sessions[token]=`` ,
logout/만료의 ``sessions.pop`` 를 그대로 지원), 변경을 StateRepository 로 write-through
한다. 따라서 **login/logout/미들웨어 코드는 한 줄도 바뀌지 않는다.**

설계 노트
--------
* **관대 로드**: 최초 부팅에선 ui_sessions 테이블이 아직 없을 수 있어(스키마 적용 전
  세션 객체가 만들어짐) 로드 실패를 삼키고 빈 상태로 시작한다. 재기동 시엔 테이블이
  있으므로 기존 세션이 복원된다.
* **가용성 우선 write**: 영속 쓰기가 실패해도 인메모리 세션은 유지한다(로그인 자체를
  막지 않는다). 런타임 인증 판정은 인메모리 dict 로 하므로 DB 순단이 인증을 끊지 않는다.
  대신 그 세션은 재기동/타 인스턴스에 전파되지 않는다(경고 로그로 남긴다).
* in-place 변경(예: ``sessions[t]["last_seen"]=...``)은 write-through 되지 않는다
  (dict 값 자체의 변경은 __setitem__ 을 거치지 않으므로). last_seen 은 best-effort —
  복원 시 약간 과거일 수 있으나 세션 유효성엔 영향 없다.
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("mori_soc.session")


class PersistentSessionDict(dict):
    """StateRepository 로 write-through 하는 세션 dict."""

    def __init__(self, repo: Any) -> None:
        super().__init__()
        self._repo = repo
        try:
            loaded = repo.load_sessions() or {}
            for token, rec in loaded.items():
                if isinstance(rec, dict):
                    super().__setitem__(token, rec)
            if loaded:
                _log.info("[session] %d 개 세션을 영속 저장소에서 복원", len(loaded))
        except Exception:
            # 테이블 미생성(최초 부팅) 등 — 빈 상태로 시작(관대). 이후 write 가 영속한다.
            _log.debug("[session] 초기 로드 생략(테이블 미생성 가능) — 빈 상태로 시작", exc_info=True)

    def __setitem__(self, token: str, record: dict[str, Any]) -> None:
        super().__setitem__(token, record)
        try:
            self._repo.save_session(token, record)
        except Exception:
            # 영속 실패해도 로그인은 유지(가용성). 재기동/타 인스턴스 전파만 누락.
            _log.warning("[session] 영속 저장 실패 — 인메모리로만 유지(재기동 시 유실)", exc_info=True)

    def __delitem__(self, token: str) -> None:
        super().__delitem__(token)
        self._delete_persisted(token)

    def pop(self, token: str, *default: Any) -> Any:
        existed = token in self
        value = super().pop(token, *default)
        if existed:
            self._delete_persisted(token)
        return value

    def _delete_persisted(self, token: str) -> None:
        try:
            self._repo.delete_session(token)
        except Exception:
            _log.warning("[session] 영속 삭제 실패(토큰 %s…)", str(token)[:8], exc_info=True)


def build_session_store(state_repo: Any) -> dict:
    """MORI_SESSION_BACKEND 에 따라 세션 저장소를 만든다.

    ``postgres`` + Postgres 백엔드일 때만 영속 래퍼, 그 외엔 평범한 dict(현행 동작 유지).
    """
    import os

    backend = os.getenv("MORI_SESSION_BACKEND", "memory").strip().lower()
    if backend == "postgres" and type(state_repo).__name__ == "PostgresStateRepository":
        _log.info("[session] 영속 세션 백엔드 활성화(postgres)")
        return PersistentSessionDict(state_repo)
    return {}


__all__ = ["PersistentSessionDict", "build_session_store"]
