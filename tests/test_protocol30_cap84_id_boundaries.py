"""Focused tests for CAP-84 muxed-contract id endpoints (issue #516)."""
from __future__ import annotations

import base64
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import scval_xdr  # noqa: E402

FIXTURE_DIR = ROOT / "protocol-30" / "xdr" / "cap-0084"
RECORD_DIR = ROOT / "protocol-30" / "evidence" / "records"
CASES = {
    "p30-xdr-cap0084-muxed-contract-id-zero": 0,
    "p30-xdr-cap0084-muxed-contract-id-u64-max": 2**64 - 1,
}


class Cap84IdBoundaryTests(unittest.TestCase):
    def test_endpoints_decode_and_roundtrip(self) -> None:
        for fixture_id, expected_id in CASES.items():
            with self.subTest(fixture_id):
                data = tomllib.loads((FIXTURE_DIR / f"{fixture_id}.toml").read_text(encoding="utf-8"))
                raw = base64.b64decode(data["value_base64"], validate=True)
                self.assertEqual(data["id"], fixture_id)
                self.assertEqual(data["protocol"], 30)
                self.assertEqual(data["type"], "ScVal")
                self.assertEqual(data["kind"], "roundtrip")
                # SCV_ADDRESS, SC_ADDRESS_TYPE_MUXED_CONTRACT, big-endian uint64 id
                self.assertEqual(raw[4:8], (5).to_bytes(4, "big"))
                self.assertEqual(raw[8:16], expected_id.to_bytes(8, "big"))
                decoded = scval_xdr.decode(raw)
                self.assertEqual(
                    decoded,
                    ("address", {"type": "muxed-contract", "id": expected_id,
                                 "contract_id": b"\x22" * 32}),
                )
                self.assertEqual(raw, scval_xdr.encode(decoded))

    def test_both_endpoints_are_represented(self) -> None:
        self.assertEqual(sorted(CASES.values()), [0, 2**64 - 1])
        for fixture_id in CASES:
            self.assertTrue((RECORD_DIR / f"{fixture_id}.json").is_file())


if __name__ == "__main__":
    unittest.main()
