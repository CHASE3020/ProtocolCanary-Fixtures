"""Focused offline checks for the invalid ScVal discriminant and pointer-flag
fixtures (issue #508).

Each malformed payload is a crate-produced value with one four-byte field
changed: the top-level SCValType discriminant (3 -> 23), or the SCVec / SCMap
optional-pointer flag (1 -> 2). The independent ScVal codec must reject each
for that reason, and restoring the original field must give a value it
accepts and round-trips.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACK = REPO_ROOT / "protocol-28"
_spec = importlib.util.spec_from_file_location("scval_xdr", REPO_ROOT / "tests" / "scval_xdr.py")
assert _spec is not None and _spec.loader is not None
scval_xdr = importlib.util.module_from_spec(_spec)
sys.modules["scval_xdr"] = scval_xdr
_spec.loader.exec_module(scval_xdr)

# (fixture id, directory, offset of the mutated field, original value, mutated
#  value, a term the rejection must name, the restored value)
CASES = [
    ("p28-xdr-scval-unknown-discriminant", "boundaries", 0, 3, 23, "discriminant", ("u32", 7)),
    ("p28-xdr-scval-vec-invalid-pointer-flag", "scval-composite", 4, 1, 2, "flag", ("vec", [("u32", 1)])),
    ("p28-xdr-scval-map-invalid-pointer-flag", "scval-composite", 4, 1, 2, "flag", ("map", [(("symbol", "k"), ("u32", 1))])),
]


def _load(directory: str, fixture_id: str) -> tuple[dict, str, bytes]:
    path = PACK / "xdr" / directory / f"{fixture_id}.toml"
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    return data, text, base64.b64decode(data["value_base64"], validate=True)


class ScValInvalidDiscriminantFixtureTests(unittest.TestCase):
    def test_metadata_is_pinned_and_explained(self) -> None:
        for fixture_id, directory, offset, old, new, _, _ in CASES:
            with self.subTest(fixture_id=fixture_id):
                data, text, _ = _load(directory, fixture_id)
                self.assertEqual(data["id"], fixture_id)
                self.assertEqual(data["type"], "ScVal")
                self.assertEqual(data["kind"], "decode-failure")
                self.assertIn("/blob/9c9c145953e80990d6ff1ae3a6a973a0ce6d0694/", data["source_reference"])
                self.assertIn("stellar-xdr 28.0.1", text)
                self.assertIn(f"offset {offset}", text)
                self.assertIn(f"{old}", text)
                self.assertIn(f"{new}", text)

    def test_mutated_field_holds_the_documented_value(self) -> None:
        for fixture_id, directory, offset, _, new, _, _ in CASES:
            with self.subTest(fixture_id=fixture_id):
                _, _, raw = _load(directory, fixture_id)
                self.assertEqual(int.from_bytes(raw[offset:offset + 4], "big"), new)

    def test_independent_codec_rejects_for_the_documented_reason(self) -> None:
        for fixture_id, directory, _, _, _, reason, _ in CASES:
            with self.subTest(fixture_id=fixture_id):
                _, _, raw = _load(directory, fixture_id)
                with self.assertRaises(scval_xdr.XdrDecodeError) as caught:
                    scval_xdr.decode(raw)
                self.assertIn(reason, str(caught.exception).lower())

    def test_restoring_the_field_gives_the_valid_source_value(self) -> None:
        for fixture_id, directory, offset, old, _, _, value in CASES:
            with self.subTest(fixture_id=fixture_id):
                _, _, raw = _load(directory, fixture_id)
                restored = raw[:offset] + old.to_bytes(4, "big") + raw[offset + 4:]
                self.assertEqual(scval_xdr.decode(restored), value)
                self.assertEqual(scval_xdr.encode(value), restored)

    def test_pack_xdr_test_accepts_flag_as_a_structural_reason(self) -> None:
        source = (REPO_ROOT / "tests" / "test_pack_xdr_independent.py").read_text(encoding="utf-8")
        self.assertIn('"flag"', source)

    def test_evidence_records_bind_the_fixture_bytes(self) -> None:
        for fixture_id, directory, _, _, _, _, _ in CASES:
            with self.subTest(fixture_id=fixture_id):
                record = json.loads(
                    (PACK / "evidence" / "records" / f"{fixture_id}.json").read_text(encoding="utf-8")
                )
                fixture_bytes = (PACK / "xdr" / directory / f"{fixture_id}.toml").read_bytes()
                self.assertEqual(record["fixtureId"], fixture_id)
                self.assertEqual(record["method"], "structural")
                self.assertEqual(record["fixtureSha256"], hashlib.sha256(fixture_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
