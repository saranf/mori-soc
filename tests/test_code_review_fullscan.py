"""전체 레포 AI 보안 스캐너(scripts/code_review_fullscan.py)의 순수 함수 테스트.

파일 수집·프롬프트 구성·응답 파싱만 검증(네트워크 호출 제외 — 표준 라이브러리만).
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import tempfile
import unittest

# scripts/ 는 패키지가 아니므로 파일 경로로 로드
_SPEC = importlib.util.spec_from_file_location(
    "code_review_fullscan",
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "code_review_fullscan.py",
)
crf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(crf)


class CollectFilesTests(unittest.TestCase):
    def _mk(self, root: str, rel: str, content: str) -> None:
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)

    def test_includes_code_skips_noise_and_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self._mk(d, "app/main.py", "print(1)\n")
            self._mk(d, "README.md", "# docs\n")                 # 비코드 → 제외
            self._mk(d, "node_modules/pkg/index.js", "x=1\n")    # skip_dir → 제외
            self._mk(d, "src/util.js", "const a=1\n")
            files, truncated = crf.collect_files(d)
            rels = sorted(r for r, _ in files)
            self.assertEqual(rels, ["app/main.py", "src/util.js"])
            self.assertFalse(truncated)

    def test_total_max_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self._mk(d, "a.py", "a" * 100)
            self._mk(d, "b.py", "b" * 100)
            files, truncated = crf.collect_files(d, total_max=120)  # 하나만 들어감
            self.assertEqual(len(files), 1)
            self.assertTrue(truncated)


class BuildPromptTests(unittest.TestCase):
    def test_prompt_has_schema_paths_and_line_numbers(self) -> None:
        prompt = crf.build_combined_prompt([("app/db.py", "q = raw\nrun(q)")])
        self.assertIn('"findings"', prompt)          # 보안 스키마
        self.assertIn('"privacy"', prompt)           # 개인정보 스키마(통합)
        self.assertIn("FILE: app/db.py", prompt)     # 파일 경로
        self.assertIn("1: q = raw", prompt)          # 라인 번호
        self.assertIn("2: run(q)", prompt)


class ParseCombinedTests(unittest.TestCase):
    def test_raw_json(self) -> None:
        fd, pv = crf.parse_combined(
            '{"findings":[{"file":"a.py","line":3,"severity":"HIGH","category":"sqli","description":"x"}],'
            '"privacy":{"items":[{"item":"이메일"}],"gaps":["g"],"summary":{"items":1}}}')
        self.assertEqual(len(fd), 1)
        self.assertEqual(fd[0]["file"], "a.py")
        self.assertEqual(fd[0]["severity"], "HIGH")
        self.assertEqual(len(pv["items"]), 1)
        self.assertEqual(pv["gaps"], ["g"])

    def test_fenced_json(self) -> None:
        txt = '```json\n{"findings":[{"file":"b.py","description":"y"}],"privacy":{"items":[]}}\n```'
        fd, pv = crf.parse_combined(txt)
        self.assertEqual(len(fd), 1)
        self.assertEqual(fd[0]["category"], "security")  # 기본값 채움
        self.assertEqual(fd[0]["severity"], "medium")
        self.assertEqual(pv["items"], [])

    def test_prose_wrapped_json(self) -> None:
        txt = ("Here are the results:\n"
               '{"findings": [{"file":"c.py","line":1,"description":"z"}], "privacy": {"items":[]}}\nDone.')
        fd, pv = crf.parse_combined(txt)
        self.assertEqual(len(fd), 1)
        self.assertEqual(fd[0]["file"], "c.py")
        self.assertIsInstance(pv, dict)

    def test_empty_and_garbage(self) -> None:
        self.assertEqual(crf.parse_combined('{"findings":[],"privacy":{}}'), ([], {}))
        self.assertEqual(crf.parse_combined("no json here"), ([], {}))
        self.assertEqual(crf.parse_combined(""), ([], {}))
        # findings 안의 비-dict 항목은 무시, privacy 없으면 {}
        self.assertEqual(crf.parse_combined('{"findings":["oops", 3]}'), ([], {}))


if __name__ == "__main__":
    unittest.main()
