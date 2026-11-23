"""Focused offline checks for the Offer and Data LedgerEntry fixtures (issue #509).

The independent codec now implements the OFFER and DATA arms. The roundtrip
fixtures must decode to the documented synthetic values and re-encode byte for
byte; the two negative fixtures push `dataName` (string64) and `dataValue`
(opaque<64>) one byte past their bound and must be rejected for the length.
"""
from __future__ import annotations

import base64
import hashlib
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
DIRECTORY = PACK / "xdr" / "ledger-entry"
IDS = [
    "p28-xdr-ledger-entry-offer-roundtrip",
    "p28-xdr-ledger-entry-data-roundtrip",
    "p28-xdr-ledger-entry-data-name-too-long",
    "p28-xdr-ledger-entry-data-value-too-long",
]


def _load(fixture_id: str) -> tuple[dict, str, bytes]:
    text = (DIRECTORY / f"{fixture_id}.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    return data, text, base64.b64decode(data["value_base64"], validate=True)


class LedgerEntryOfferDataFixtureTests(unittest.TestCase):
    def test_metadata_is_pinned_and_explained(self) -> None:
        for fixture_id in IDS:
            with self.subTest(fixture_id=fixture_id):
                data, text, _ = _load(fixture_id)
                self.assertEqual(data["id"], fixture_id)
                self.assertEqual(data["type"], "LedgerEntry")
                self.assertEqual(data["category"], "ledger-entry")
                self.assertIn(
                    "/blob/9c9c145953e80990d6ff1ae3a6a973a0ce6d0694/Stellar-ledger-entries.x",
                    data["source_reference"],
                )
                self.assertIn("stellar-xdr 28.0.1", text)
                self.assertIn("synthetic", text)

    def test_offer_round_trips_with_the_documented_fields(self) -> None:
        _, _, raw = _load("p28-xdr-ledger-entry-offer-roundtrip")
        entry = xdr_codec.decode_xdr("LedgerEntry", raw)
        self.assertEqual(entry.entry_type, xdr_codec.LEDGER_ENTRY_TYPE_OFFER)
        self.assertEqual(entry.last_modified_ledger_seq, 7)
        offer = entry.offer
        self.assertIsNotNone(offer)
        self.assertEqual(offer.offer_id, 42)
        self.assertEqual(offer.amount, 1_000)
        self.assertEqual((offer.price.n, offer.price.d), (3, 2))
        self.assertEqual(offer.flags, 0)
        self.assertEqual(offer.selling.asset_type, 0)  # ASSET_TYPE_NATIVE
        self.assertEqual(offer.buying.alpha_num4.asset_code, b"USDC")
        self.assertEqual(xdr_codec.encode_xdr("LedgerEntry", entry), raw)

    def test_data_round_trips_with_the_documented_fields(self) -> None:
        _, _, raw = _load("p28-xdr-ledger-entry-data-roundtrip")
        entry = xdr_codec.decode_xdr("LedgerEntry", raw)
        self.assertEqual(entry.entry_type, xdr_codec.LEDGER_ENTRY_TYPE_DATA)
        self.assertEqual(entry.data.data_name, b"config")
        self.assertEqual(entry.data.data_value, bytes([1, 2, 3, 4, 5]))
        self.assertEqual(xdr_codec.encode_xdr("LedgerEntry", entry), raw)

    def test_over_limit_fields_are_rejected_for_their_length(self) -> None:
        for fixture_id, offset in (
            ("p28-xdr-ledger-entry-data-name-too-long", 44),
            ("p28-xdr-ledger-entry-data-value-too-long", 56),
        ):
            with self.subTest(fixture_id=fixture_id):
                data, text, raw = _load(fixture_id)
                self.assertEqual(data["kind"], "decode-failure")
                self.assertEqual(int.from_bytes(raw[offset:offset + 4], "big"), 65)
                self.assertIn(f"offset {offset}", text)
                with self.assertRaises(xdr_codec.XdrCodecError) as caught:
                    xdr_codec.decode_xdr("LedgerEntry", raw)
                self.assertIn("exceeds maximum allowed 64", str(caught.exception))

    def test_the_64_byte_boundary_is_accepted(self) -> None:
        account = xdr_codec.PublicKey(key_type=0, ed25519=b"\x11" * 32)
        for name, value in ((b"n" * 64, b"\x01"), (b"config", b"\xab" * 64)):
            entry = xdr_codec.LedgerEntry(
                last_modified_ledger_seq=7,
                entry_type=xdr_codec.LEDGER_ENTRY_TYPE_DATA,
                data=xdr_codec.DataEntry(account_id=account, data_name=name, data_value=value),
            )
            raw = xdr_codec.encode_xdr("LedgerEntry", entry)
            self.assertEqual(xdr_codec.decode_xdr("LedgerEntry", raw), entry)
        with self.assertRaises(xdr_codec.XdrCodecError):
            xdr_codec.encode_xdr(
                "LedgerEntry",
                xdr_codec.LedgerEntry(
                    last_modified_ledger_seq=7,
                    entry_type=xdr_codec.LEDGER_ENTRY_TYPE_DATA,
                    data=xdr_codec.DataEntry(account_id=account, data_name=b"n" * 65, data_value=b""),
                ),
            )

    def test_evidence_records_bind_the_fixture_bytes(self) -> None:
        for fixture_id in IDS:
            with self.subTest(fixture_id=fixture_id):
                record = json.loads(
                    (PACK / "evidence" / "records" / f"{fixture_id}.json").read_text(encoding="utf-8")
                )
                fixture_bytes = (DIRECTORY / f"{fixture_id}.toml").read_bytes()
                self.assertEqual(record["fixtureId"], fixture_id)
                self.assertEqual(record["method"], "structural")
                self.assertEqual(record["fixtureSha256"], hashlib.sha256(fixture_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
