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

    def test_csv_injection_value_is_quoted_not_executed(self) -> None:
        # 수식 시작 문자를 포함한 값도 표준 CSV 이스케이프로 안전하게 담긴다(필드 1개 유지).
        out = render_csv([{"a": '=1+2', "b": "ok"}], {"a": "A", "b": "B"})
        parsed = list(csv.reader(io.StringIO(out)))
        self.assertEqual(parsed[1], ["=1+2", "ok"])


if __name__ == "__main__":
    unittest.main()
