"""Focused offline checks for the one-byte XDR padding fixtures (issue #507).

Three-byte ScVal bytes, string and symbol values, and a three-byte CAP-0085
external-reference tag, each need exactly one zero pad byte. Every valid
fixture is paired with a malformed one that differs from it in that pad byte
only, and the independent codecs must accept the first and reject the second
for its padding.
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
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests import xdr_codec  # noqa: E402

PACK = REPO_ROOT / "protocol-28"
_spec = importlib.util.spec_from_file_location("scval_xdr", REPO_ROOT / "tests" / "scval_xdr.py")
assert _spec is not None and _spec.loader is not None
scval_xdr = importlib.util.module_from_spec(_spec)
sys.modules["scval_xdr"] = scval_xdr
_spec.loader.exec_module(scval_xdr)

PINNED = "/blob/9c9c145953e80990d6ff1ae3a6a973a0ce6d0694/"

# (valid fixture, malformed fixture, directory, XDR type, expected valid hex)
PAIRS = [
    ("p28-xdr-scval-bytes-three-payload", "p28-xdr-scval-bytes-nonzero-padding",
     "scval", "ScVal", "0000000d0000000301020300"),
    ("p28-xdr-scval-string-three-payload", "p28-xdr-scval-string-nonzero-padding",
     "scval", "ScVal", "0000000e0000000378647200"),
    ("p28-xdr-scval-symbol-three-payload", "p28-xdr-scval-symbol-nonzero-padding",
     "scval", "ScVal", "0000000f00000003746f6b00"),
    ("p28-xdr-cap85-external-ref-tag-three-byte-roundtrip",
     "p28-xdr-cap85-external-ref-tag-nonzero-padding",
     "cap-0085", "ContractExecutable",
     "00000002" "00000001" + "55" * 32 + "00000003" "76323800"),
]


def _load(directory: str, fixture_id: str) -> tuple[dict, str, bytes]:
    path = PACK / "xdr" / directory / f"{fixture_id}.toml"
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    return data, text, base64.b64decode(data["value_base64"], validate=True)


def _decode(type_name: str, raw: bytes):
    if type_name == "ScVal":
        return scval_xdr.decode(raw)
    return xdr_codec.decode_xdr(type_name, raw)


def _encode(type_name: str, value) -> bytes:
    if type_name == "ScVal":
        return scval_xdr.encode(value)
    return xdr_codec.encode_xdr(type_name, value)


class OneBytePaddingFixtureTests(unittest.TestCase):
    def test_metadata_is_pinned_and_explained(self) -> None:
        for valid_id, bad_id, directory, type_name, _ in PAIRS:
            for fixture_id, kind in ((valid_id, "roundtrip"), (bad_id, "decode-failure")):
                with self.subTest(fixture_id=fixture_id):
                    data, text, _ = _load(directory, fixture_id)
                    self.assertEqual(data["id"], fixture_id)
                    self.assertEqual(data["protocol"], 28)
                    self.assertEqual(data["type"], type_name)
                    self.assertEqual(data["kind"], kind)
                    self.assertIn(PINNED, data["source_reference"])
                    self.assertIn("stellar-xdr 28.0.1", text)
                    self.assertIn("2026-11-20 (UTC)", text)

    def test_valid_values_have_one_zero_pad_byte_and_round_trip(self) -> None:
        for valid_id, _, directory, type_name, expected_hex in PAIRS:
            with self.subTest(fixture_id=valid_id):
                _, _, raw = _load(directory, valid_id)
                self.assertEqual(raw.hex(), expected_hex)
                self.assertEqual(len(raw) % 4, 0)
                self.assertEqual(raw[-4:-1] != b"\x00\x00\x00", True)
                self.assertEqual(raw[-1], 0x00, "the single pad byte must be zero")
                self.assertEqual(_encode(type_name, _decode(type_name, raw)), raw)

    def test_malformed_differs_only_in_the_pad_byte(self) -> None:
        for valid_id, bad_id, directory, _, _ in PAIRS:
            with self.subTest(fixture_id=bad_id):
                _, _, good = _load(directory, valid_id)
                _, text, bad = _load(directory, bad_id)
                self.assertEqual(len(good), len(bad))
                diff = [i for i, (a, b) in enumerate(zip(good, bad, strict=True)) if a != b]
                self.assertEqual(diff, [len(good) - 1])
                self.assertEqual(bad[-1], 0x01)
                self.assertIn(f"offset {len(good) - 1}", text)

    def test_independent_codecs_reject_the_nonzero_pad(self) -> None:
        for _, bad_id, directory, type_name, _ in PAIRS:
            with self.subTest(fixture_id=bad_id):
                _, _, raw = _load(directory, bad_id)
                error = scval_xdr.XdrDecodeError if type_name == "ScVal" else xdr_codec.XdrCodecError
                with self.assertRaises(error) as caught:
                    _decode(type_name, raw)
                self.assertIn("padding", str(caught.exception).lower())

    def test_evidence_records_bind_the_fixture_bytes(self) -> None:
        for valid_id, bad_id, directory, _, _ in PAIRS:
            for fixture_id in (valid_id, bad_id):
                with self.subTest(fixture_id=fixture_id):
                    record = json.loads(
                        (PACK / "evidence" / "records" / f"{fixture_id}.json").read_text(encoding="utf-8")
                    )
                    fixture_bytes = (PACK / "xdr" / directory / f"{fixture_id}.toml").read_bytes()
                    self.assertEqual(record["fixtureId"], fixture_id)
                    self.assertEqual(record["method"], "structural")
                    self.assertEqual(record["outcome"], "matched")
                    self.assertEqual(record["fixtureSha256"], hashlib.sha256(fixture_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
