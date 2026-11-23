"""Focused tests for StellarValue upgrade vector bounds (issue #515).

``struct StellarValue`` declares ``UpgradeType upgrades<6>`` and
``typedef opaque UpgradeType<128>`` bounds each item. These fixtures cover a
non-empty vector, both accepted maximums and one-above rejection cases.
"""
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

FIXTURE_DIR = REPO_ROOT / "protocol-28" / "xdr" / "stellar-value"
RECORD_DIR = REPO_ROOT / "protocol-28" / "evidence" / "records"
PREFIX = "p28-xdr-stellar-value-"
ROUNDTRIP_IDS = (
    PREFIX + "one-upgrade-roundtrip",
    PREFIX + "six-upgrades-boundary",
    PREFIX + "upgrade-max-length",
)
REJECT_IDS = (PREFIX + "upgrade-too-long", PREFIX + "seven-upgrades")


def load(fixture_id: str) -> tuple[dict, bytes]:
    data = tomllib.loads((FIXTURE_DIR / f"{fixture_id}.toml").read_text(encoding="utf-8"))
    return data, base64.b64decode(data["value_base64"], validate=True)


class StellarValueUpgradeBoundsTests(unittest.TestCase):
    def _roundtrip(self, fixture_id: str) -> xdr_codec.StellarValue:
        data, raw = load(fixture_id)
        self.assertEqual(data["id"], fixture_id)
        self.assertEqual(data["type"], "StellarValue")
        self.assertEqual(data["kind"], "roundtrip")
        decoded = xdr_codec.decode_stellar_value(raw)
        self.assertEqual(decoded, xdr_codec.decode_xdr("StellarValue", raw))
        self.assertEqual(decoded.tx_set_hash, b"\x11" * 32)
        self.assertEqual(decoded.close_time, 1760000000)
        self.assertEqual(decoded.ext.ext_type, xdr_codec.STELLAR_VALUE_BASIC)
        self.assertEqual(raw, xdr_codec.encode_stellar_value(decoded))
        self.assertEqual(raw, xdr_codec.encode_xdr("StellarValue", decoded))
        return decoded

    def test_one_upgrade(self) -> None:
        decoded = self._roundtrip(PREFIX + "one-upgrade-roundtrip")
        self.assertEqual(decoded.upgrades, [b"\xa1" * 12])

    def test_six_upgrades_is_the_accepted_maximum(self) -> None:
        decoded = self._roundtrip(PREFIX + "six-upgrades-boundary")
        self.assertEqual(len(decoded.upgrades), 6)
        self.assertEqual(decoded.upgrades, [bytes([0xB1 + i]) * (i + 1) for i in range(6)])

    def test_128_byte_upgrade_is_the_accepted_maximum(self) -> None:
        decoded = self._roundtrip(PREFIX + "upgrade-max-length")
        self.assertEqual(decoded.upgrades, [b"\xc1" * 128])

    def test_too_long_is_a_single_length_mutation_of_max_length(self) -> None:
        _, source = load(PREFIX + "upgrade-max-length")
        data, raw = load(PREFIX + "upgrade-too-long")
        self.assertEqual(data["kind"], "decode-failure")
        self.assertEqual(source[44:48], (128).to_bytes(4, "big"))
        expected = source[:44] + (129).to_bytes(4, "big") + b"\xc1" * 129 + b"\x00" * 3 + source[-4:]
        self.assertEqual(raw, expected)

    def test_seven_is_a_single_count_mutation_of_six(self) -> None:
        _, source = load(PREFIX + "six-upgrades-boundary")
        data, raw = load(PREFIX + "seven-upgrades")
        self.assertEqual(data["kind"], "decode-failure")
        self.assertEqual(source[40:44], (6).to_bytes(4, "big"))
        expected = (
            source[:40] + (7).to_bytes(4, "big") + source[44:-4]
            + (1).to_bytes(4, "big") + b"\xb7\x00\x00\x00" + source[-4:]
        )
        self.assertEqual(raw, expected)

    def test_rejections_with_both_decoders(self) -> None:
        for fixture_id in REJECT_IDS:
            with self.subTest(fixture_id):
                _, raw = load(fixture_id)
                with self.assertRaises(xdr_codec.XdrCodecError):
                    xdr_codec.decode_stellar_value(raw)
                with self.assertRaises(xdr_codec.XdrCodecError):
                    xdr_codec.decode_xdr("StellarValue", raw)

    def test_each_fixture_has_a_structural_record(self) -> None:
        for fixture_id in ROUNDTRIP_IDS + REJECT_IDS:
            with self.subTest(fixture_id):
                self.assertTrue((RECORD_DIR / f"{fixture_id}.json").is_file())


if __name__ == "__main__":
    unittest.main()
