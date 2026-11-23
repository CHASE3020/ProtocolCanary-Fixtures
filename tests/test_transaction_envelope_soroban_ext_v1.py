"""Focused test for SorobanTransactionDataExt V1 archivedSorobanEntries (issue #518)."""
from __future__ import annotations

import base64
import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests import xdr_codec  # noqa: E402

FIXTURE_ID = "p28-xdr-transaction-envelope-soroban-archived-entries"
FIXTURE = REPO_ROOT / "protocol-28" / "xdr" / "transaction-envelope" / f"{FIXTURE_ID}.toml"
BASELINE = (REPO_ROOT / "protocol-28" / "xdr" / "transaction-envelope"
            / "p28-xdr-transaction-envelope-soroban-invoke-roundtrip.toml")
RECORD = REPO_ROOT / "protocol-28" / "evidence" / "records" / f"{FIXTURE_ID}.json"


def load(path: Path) -> tuple[dict, bytes]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data, base64.b64decode(data["value_base64"], validate=True)


class SorobanExtV1Tests(unittest.TestCase):
    def test_archived_entries_decode_and_roundtrip(self) -> None:
        data, raw = load(FIXTURE)
        self.assertEqual(data["id"], FIXTURE_ID)
        self.assertEqual(data["type"], "TransactionEnvelope")
        self.assertEqual(data["kind"], "roundtrip")
        decoded = xdr_codec.decode_transaction_envelope(raw)
        self.assertEqual(decoded, xdr_codec.decode_xdr("TransactionEnvelope", raw))
        self.assertEqual(decoded.envelope_type, xdr_codec.ENVELOPE_TYPE_TX)
        tx_ext = decoded.v1.tx.ext
        self.assertEqual(tx_ext.ext_type, 1)
        soroban = tx_ext.soroban_data
        self.assertEqual(soroban.ext.ext_type, 1)
        self.assertEqual(soroban.ext.resource_ext.archived_soroban_entries, [0, 3, 4294967295])
        self.assertEqual(soroban.resources.footprint.read_only, [])
        self.assertEqual(soroban.resources.footprint.read_write, [])
        self.assertEqual(decoded.v1.tx.operations[0].body.invoke_host_function.auth, [])
        self.assertEqual(raw, xdr_codec.encode_transaction_envelope(decoded))
        self.assertEqual(raw, xdr_codec.encode_xdr("TransactionEnvelope", decoded))

    def test_only_soroban_ext_differs_from_baseline(self) -> None:
        _, raw = load(FIXTURE)
        _, base_raw = load(BASELINE)
        base = xdr_codec.decode_transaction_envelope(base_raw)
        new = xdr_codec.decode_transaction_envelope(raw)
        self.assertEqual(base.v1.tx.ext.soroban_data.ext.ext_type, 0)
        self.assertEqual(new.v1.signatures, base.v1.signatures)
        self.assertEqual(new.v1.tx.operations, base.v1.tx.operations)
        self.assertEqual(new.v1.tx.ext.soroban_data.resources, base.v1.tx.ext.soroban_data.resources)
        self.assertEqual(new.v1.tx.ext.soroban_data.resource_fee, base.v1.tx.ext.soroban_data.resource_fee)

    def test_structural_record_exists(self) -> None:
        self.assertTrue(RECORD.is_file())


if __name__ == "__main__":
    unittest.main()
