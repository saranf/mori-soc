"""CSV 공통 헬퍼 — 특수문자(콤마·따옴표·개행·유니코드) 왕복 안전성 검증."""
from __future__ import annotations

import csv
import io
import unittest

from mori_soc.services.csv_export import render_csv


class CsvExportTests(unittest.TestCase):
    def test_header_row_and_field_order(self) -> None:
        out = render_csv([{"a": "1", "b": "2"}], {"a": "가", "b": "나"})
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0], ["가", "나"])   # 표시 헤더가 첫 줄
        self.assertEqual(rows[1], ["1", "2"])

    def test_special_chars_roundtrip(self) -> None:
        # 콤마·따옴표·개행·유니코드가 담긴 값이 깨지지 않고 그대로 파싱돼야 한다.
        row = {"item": '이메일, 이름', "note": 'he said "hi"\n두번째 줄', "loc": "src/앱.ts:42"}
        out = render_csv([row], {"item": "항목", "note": "비고", "loc": "위치"})
        parsed = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["항목"], "이메일, 이름")       # 콤마 보존
        self.assertEqual(parsed[0]["비고"], 'he said "hi"\n두번째 줄')  # 따옴표·개행 보존
        self.assertEqual(parsed[0]["위치"], "src/앱.ts:42")       # 유니코드 보존

    def test_extra_keys_ignored(self) -> None:
        # header_map 에 없는 키는 무시(extrasaction="ignore") — 필드 깨짐 방지.
        out = render_csv([{"a": "1", "extra": "x"}], {"a": "A"})
        parsed = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(parsed[0], {"A": "1"})

    def test_csv_injection_value_is_defused(self) -> None:
        # 수식 인젝션(Formula injection) 무력화: =,+,-,@ 로 시작하는 셀(숫자 아님) 앞에 ' 를 붙여
        # Excel/Sheets 가 수식으로 실행하지 못하게 한다. 필드 1개 무결성도 유지된다.
        out = render_csv(
            [{"a": "=1+2", "b": "@SUM(A1)", "c": "-5", "d": "+cmd", "e": "normal"}],
            {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"})
        parsed = list(csv.reader(io.StringIO(out)))
        self.assertEqual(parsed[1][0], "'=1+2")      # 수식 무력화
        self.assertEqual(parsed[1][1], "'@SUM(A1)")  # DDE 무력화
        self.assertEqual(parsed[1][2], "-5")          # 정상 음수는 그대로(숫자)
        self.assertEqual(parsed[1][3], "'+cmd")       # 위험 문자열 무력화
        self.assertEqual(parsed[1][4], "normal")      # 일반 값은 그대로


class CsvExportCapTests(unittest.TestCase):
    def test_export_row_cap_truncates(self) -> None:
        import os
        from unittest.mock import patch

        from mori_soc.services.csv_export import _cap_rows
        rows = [{"a": i} for i in range(10)]
        with patch.dict(os.environ, {"MORI_MAX_EXPORT_ROWS": "4"}, clear=False):
            capped, truncated = _cap_rows(rows)
        self.assertEqual(len(capped), 4)
        self.assertTrue(truncated)

    def test_no_cap_when_zero(self) -> None:
        import os
        from unittest.mock import patch

        from mori_soc.services.csv_export import _cap_rows
        with patch.dict(os.environ, {"MORI_MAX_EXPORT_ROWS": "0"}, clear=False):
            capped, truncated = _cap_rows([{"a": i} for i in range(10)])
        self.assertEqual(len(capped), 10)
        self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()
