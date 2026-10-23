"""Fontconfig wire-format parsing, not font-engine/rendering certification."""
import json
from pathlib import Path
import tempfile
import unittest

from installer import office


class FontInventoryRecordTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="font-records-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.fonts = self.root / "fonts"
        self.fonts.mkdir()
        self.font = self.fonts / "vendor.ttf"
        self.font.write_bytes(b"synthetic vendor-font bytes, never parsed as a font")
        (self.state / "packages.installed").write_text("fixture-font|1.0|x11-fonts/fixture-font\n")
        (self.state / "fonts-unavailable").write_text("")
        self.generated = (self.root / "browser.js", self.root / "converter.js", self.root / "font_selection.bin")
        for path in self.generated[:2]:
            path.write_text("var names = " + json.dumps(office.REQUIRED_FONT_FAMILIES) + ";\n")
        self.generated[2].write_bytes(b"nonempty fixture selection")
        self.core = f"{self.font}\t{','.join(office.REQUIRED_FONT_FAMILIES)}\tRegular\n"

    def inventory(self, text):
        (self.state / "fontconfig.tsv").write_bytes(text.encode("utf-8"))
        return office.font_inventory({"font_profile": "comprehensive"}, self.state,
                                     roots=(self.fonts,), generated=self.generated)

    def test_nel_in_native_metadata_does_not_create_an_extra_record(self):
        family = "Vendor\u0085Alias"
        style = "Regular\u0085Alternate"
        result = self.inventory(self.core + f"{self.font}\t{family}\t{style}\n")
        faces = result["fonts"][0]["faces"]
        self.assertEqual(len(faces), 2)
        self.assertEqual(faces[1], {"family": family, "style": style})

    def test_other_unicode_line_separators_and_cr_remain_metadata(self):
        for value in ("Family\u2028Alias", "Family\u2029Alias", "Family\rAlias"):
            with self.subTest(value=repr(value)):
                result = self.inventory(self.core + f"{self.font}\t{value}\tRegular\rStyle\n")
                self.assertEqual(result["fonts"][0]["faces"][1], {"family": value, "style": "Regular\rStyle"})

    def test_malformed_physical_records_are_not_silently_skipped(self):
        for suffix in ("orphan\n", "\n", "missing\tfield\n"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.inventory(self.core + suffix)

    def test_required_checks_and_invalid_encoding_remain_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "Required core font families"):
            self.inventory(f"{self.font}\tUnrelated family\tRegular\n")
        self.generated[0].write_text("var no_required_families = [];\n")
        with self.assertRaisesRegex(ValueError, "did not register required"):
            self.inventory(self.core)
        (self.state / "fontconfig.tsv").write_bytes(b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            office.font_inventory({"font_profile": "comprehensive"}, self.state,
                                  roots=(self.fonts,), generated=self.generated)


if __name__ == "__main__":
    unittest.main()
