from datetime import datetime, timezone

FILETIME_EPOCH_DIFF_100NS = 116_444_736_000_000_000

def filetime_to_unix_ns(filetime: int) -> int:
    if filetime < FILETIME_EPOCH_DIFF_100NS:
        return 0
    return (filetime - FILETIME_EPOCH_DIFF_100NS) * 100

def unix_ns_to_iso(ns: int) -> str:
    secs = ns / 1_000_000_000
    try:
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
        frac = ns % 1_000_000_000
        if frac == 0:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + f"{frac:09d}".rstrip("0") + "Z"
    except (OSError, OverflowError, ValueError):
        return "1601-01-01T00:00:00Z"
