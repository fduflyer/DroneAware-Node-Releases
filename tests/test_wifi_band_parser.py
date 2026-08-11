#!/usr/bin/env python3
"""Regression coverage for iw frequency formats used by Wi-Fi classifiers."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER_FILES = (
    ROOT / "wifi_feeder.py",
    ROOT / "droneaware",
    ROOT / "tools" / "validate-1506.sh",
)
PATTERN_LITERAL = re.compile(r're\.search\(r"([^"]*MHz[^"]*)", line\)')


class WifiBandParserTests(unittest.TestCase):
    def test_all_classifiers_accept_integer_and_decimal_mhz(self) -> None:
        integer_lines = ("* 2412 MHz [1]", "* 5180 MHz [36]")
        decimal_lines = ("* 2412.0 MHz [1]", "* 5180.0 MHz [36]")

        for path in PARSER_FILES:
            source = path.read_text(encoding="utf-8")
            patterns = PATTERN_LITERAL.findall(source)
            self.assertEqual(
                len(patterns),
                1,
                f"expected one Wi-Fi band parser pattern in {path.relative_to(ROOT)}",
            )
            parser = re.compile(patterns[0])
            for line in integer_lines + decimal_lines:
                with self.subTest(path=path.name, line=line):
                    self.assertIsNotNone(parser.search(line))

    def test_classifiers_reject_unrelated_frequency_text(self) -> None:
        for path in PARSER_FILES:
            source = path.read_text(encoding="utf-8")
            parser = re.compile(PATTERN_LITERAL.findall(source)[0])
            for line in ("2412 MHz", "* 2412 MHz", "* 2412 MHz channel 1"):
                with self.subTest(path=path.name, line=line):
                    self.assertIsNone(parser.search(line))


if __name__ == "__main__":
    unittest.main()
