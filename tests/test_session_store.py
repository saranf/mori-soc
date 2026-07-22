"""세션 영속 래퍼(M10 Phase A) — PersistentSessionDict · build_session_store.

DB 없이 가짜 repo 로 write-through·관대 로드·가용성 write 를 검증한다.
"""
from __future__ import annotations

import os
import unittest
from contextlib import contextmanager

from mori_soc.api.session_store import PersistentSessionDict, build_session_store


class FakeRepo:
    """StateRepository 세션 메서드만 흉내내는 가짜 저장소(이름으로 분기되지 않음)."""

    def __init__(self, initial=None, fail_save=False, fail_load=False):
        self.store = dict(initial or {})
        self.saved = []
        self.deleted = []
        self._fail_save = fail_save
        self._fail_load = fail_load

    def load_sessions(self):
        if self._fail_load:
            raise RuntimeError("no table yet")
        return dict(self.store)

    def save_session(self, token, record):
        if self._fail_save:
            raise RuntimeError("db down")
        self.saved.append(token)
        self.store[token] = dict(record)

    def delete_session(self, token):
        self.deleted.append(token)
        self.store.pop(token, None)


@contextmanager
def env(**kv):
    saved = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class PersistentSessionDictTest(unittest.TestCase):
    def test_set_writes_through(self) -> None:
        repo = FakeRepo()
        s = PersistentSessionDict(repo)
        s["tok1"] = {"username": "admin", "role": "admin"}
        self.assertIn("tok1", s)
        self.assertIn("tok1", repo.saved)
        self.assertEqual(repo.store["tok1"]["username"], "admin")

    def test_pop_deletes_persisted(self) -> None:
        repo = FakeRepo({"tok1": {"username": "u"}})
        s = PersistentSessionDict(repo)
        self.assertIn("tok1", s)                 # 초기 로드로 복원
        s.pop("tok1", None)
        self.assertNotIn("tok1", s)
        self.assertIn("tok1", repo.deleted)

    def test_del_deletes_persisted(self) -> None:
        repo = FakeRepo()
        s = PersistentSessionDict(repo)
        s["t"] = {"username": "u"}
        del s["t"]
        self.assertIn("t", repo.deleted)

    def test_loads_existing_on_init(self) -> None:
        repo = FakeRepo({"a": {"username": "x"}, "b": {"username": "y"}})
        s = PersistentSessionDict(repo)
        self.assertEqual(set(s.keys()), {"a", "b"})

    def test_tolerant_load_when_table_missing(self) -> None:
        # 최초 부팅: load 실패해도 크래시 없이 빈 상태로 시작.
        repo = FakeRepo(fail_load=True)
        s = PersistentSessionDict(repo)
        self.assertEqual(len(s), 0)
        s["t"] = {"username": "u"}   # 이후 write 는 정상
        self.assertIn("t", s)

    def test_write_failure_keeps_memory_session(self) -> None:
        # 가용성: 영속 실패해도 인메모리 세션은 유지(로그인 안 끊김).
        repo = FakeRepo(fail_save=True)
        s = PersistentSessionDict(repo)
        s["t"] = {"username": "u"}
        self.assertIn("t", s)              # 메모리엔 남음
        self.assertNotIn("t", repo.saved)  # 영속은 실패


class BuildSessionStoreTest(unittest.TestCase):
    def test_memory_default_is_plain_dict(self) -> None:
        with env(MORI_SESSION_BACKEND=None):
            s = build_session_store(FakeRepo())
            self.assertIsInstance(s, dict)
            self.assertNotIsInstance(s, PersistentSessionDict)

    def test_postgres_flag_but_wrong_repo_is_plain_dict(self) -> None:
        # 플래그가 켜져도 Postgres 백엔드가 아니면 평범한 dict(안전).
        with env(MORI_SESSION_BACKEND="postgres"):
            s = build_session_store(FakeRepo())
            self.assertNotIsInstance(s, PersistentSessionDict)

    def test_postgres_flag_with_matching_repo_activates(self) -> None:
        # 플래그 on + 클래스명이 PostgresStateRepository 면 영속 래퍼 활성.
        class PostgresStateRepository(FakeRepo):
            pass
        with env(MORI_SESSION_BACKEND="postgres"):
            s = build_session_store(PostgresStateRepository())
            self.assertIsInstance(s, PersistentSessionDict)


if __name__ == "__main__":
    unittest.main()
