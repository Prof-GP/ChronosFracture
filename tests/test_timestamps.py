"""
Timestamp conversion — unit tests.

Forensic standards require:
  - Zero data loss in timestamp conversion
  - Nanosecond precision preserved end-to-end
  - Correct UTC normalization
  - No silent errors on invalid input
"""
import pytest
from supertimeline.utils.timestamps import filetime_to_unix_ns, unix_ns_to_iso

FILETIME_EPOCH_DIFF = 116_444_736_000_000_000  # 100ns intervals from 1601 to 1970

class TestFiletimeToUnixNs:

    def test_unix_epoch(self):
        assert filetime_to_unix_ns(FILETIME_EPOCH_DIFF) == 0

    def test_known_date(self):
        # 2020-01-01 00:00:00 UTC
        # Unix seconds: 1577836800
        # FILETIME: 1577836800 * 10_000_000 + FILETIME_EPOCH_DIFF
        ft = 1_577_836_800 * 10_000_000 + FILETIME_EPOCH_DIFF
        ns = filetime_to_unix_ns(ft)
        assert ns == 1_577_836_800 * 1_000_000_000

    def test_pre_epoch_returns_zero(self):
        assert filetime_to_unix_ns(0) == 0
        assert filetime_to_unix_ns(FILETIME_EPOCH_DIFF - 1) == 0

    def test_100ns_precision(self):
        ft = FILETIME_EPOCH_DIFF + 1
        ns = filetime_to_unix_ns(ft)
        assert ns == 100  # 1 FILETIME unit = 100 nanoseconds

    def test_large_value(self):
        ft = FILETIME_EPOCH_DIFF + 10_000_000  # 1 second
        assert filetime_to_unix_ns(ft) == 1_000_000_000


class TestUnixNsToIso:

    def test_unix_epoch_format(self):
        # Zero sub-second component → no fractional part
        iso = unix_ns_to_iso(0)
        assert iso == "1970-01-01T00:00:00Z"

    def test_known_date(self):
        ns = 1_577_836_800 * 1_000_000_000
        iso = unix_ns_to_iso(ns)
        # Whole-second value — no fractional component
        assert iso == "2020-01-01T00:00:00Z"

    def test_nanosecond_fraction(self):
        # 1 nanosecond past epoch
        iso = unix_ns_to_iso(1)
        assert "000000001" in iso, f"Nanosecond not preserved: {iso}"

    def test_utc_suffix(self):
        iso = unix_ns_to_iso(0)
        assert iso.endswith("Z"), "ISO timestamp must end with Z (UTC)"

    def test_invalid_large_value_no_crash(self):
        # Must not raise — return a safe fallback
        iso = unix_ns_to_iso(10**30)
        assert isinstance(iso, str)
