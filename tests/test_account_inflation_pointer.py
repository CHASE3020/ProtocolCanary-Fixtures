"""Focused test for a present AccountEntry.inflationDest pointer (issue #523)."""
from __future__ import annotations

import base64
import sys
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests import xdr_codec  # noqa: E402

FIXTURE_ID = "p28-xdr-account-inflation-pointer-present"
FIXTURE = REPO_ROOT / "protocol-28" / "xdr" / "campaign" / f"{FIXTURE_ID}.toml"
BASELINE = REPO_ROOT / "protocol-28" / "xdr" / "ledger-entry" / "p28-xdr-ledger-entry-account.toml"
RECORD = REPO_ROOT / "protocol-28" / "evidence" / "records" / f"{FIXTURE_ID}.json"


def load(path: Path) -> tuple[dict, bytes]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data, base64.b64decode(data["value_base64"], validate=True)


class AccountInflationPointerTests(unittest.TestCase):
    def test_present_pointer_decodes_and_roundtrips(self) -> None:
        data, raw = load(FIXTURE)
        self.assertEqual(data["id"], FIXTURE_ID)
        self.assertEqual(data["type"], "LedgerEntry")
        self.assertEqual(data["kind"], "roundtrip")
        decoded = xdr_codec.decode_ledger_entry(raw)
        self.assertEqual(decoded, xdr_codec.decode_xdr("LedgerEntry", raw))
        self.assertEqual(decoded.entry_type, xdr_codec.LEDGER_ENTRY_TYPE_ACCOUNT)
        dest = decoded.account.inflation_dest
        self.assertIsNotNone(dest)
        self.assertEqual(dest.key_type, xdr_codec.PUBLIC_KEY_TYPE_ED25519)
        self.assertEqual(dest.ed25519, b"\x99" * 32)
        self.assertEqual(decoded.account.home_domain, "example.test")
        self.assertEqual(raw, xdr_codec.encode_ledger_entry(decoded))
        self.assertEqual(raw, xdr_codec.encode_xdr("LedgerEntry", decoded))

    def test_only_inflation_dest_differs_from_baseline(self) -> None:
        _, raw = load(FIXTURE)
        _, base_raw = load(BASELINE)
        base = xdr_codec.decode_ledger_entry(base_raw)
        new = xdr_codec.decode_ledger_entry(raw)
        self.assertIsNone(base.account.inflation_dest)
        self.assertEqual(
            replace(new, account=replace(new.account, inflation_dest=None)), base
        )
        # presence word + 4-byte key type + 32-byte key shift later fields by 36 bytes
        self.assertEqual(len(raw) - len(base_raw), 36)

    def test_structural_record_exists(self) -> None:
        self.assertTrue(RECORD.is_file())


if __name__ == "__main__":
    unittest.main()
