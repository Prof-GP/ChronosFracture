# SuperTimeline — Development Plan

Last updated: 2026-05-07
Test image: `D:\Midterm Spring 26.E01`
Baseline run: 2,933,491 events, 82.4s, zero parser errors

---

## PHASE 1 — Fix current bugs (must ship before any new features)

### 1.1 EVTX generic snippet — noise still leaking through
**Problem:** Generic extractor picks "longest" substitution string, which surfaces
GUIDs (`{c5dc3753-...}`) and multi-line script body fragments (`#requires -version 3.0`
from EventID 108 task scheduler records).
**Root cause:** Heuristic "longest wins" is wrong. We have all substitution strings
as a clean list — we should show the first 2–3 non-noise values joined with ` | `
rather than guessing which one is most meaningful.
**Fix:** In `extract_generic_snippet` structured path: filter out GUIDs (36-char, 4
hyphens), strings containing newlines or `#`, strings starting with `{`. Then take
the first 3 remaining values joined with ` | `. If zero remain, return None (no
snippet is better than a bad snippet).
**File:** `core/src/parsers/evtx.rs` — `extract_generic_snippet()`

### 1.2 EVTX — event level missing from message
**Problem:** `event_level` (0=LogAlways, 2=Error, 3=Warning, 4=Info, 5=Verbose) is
parsed but never surfaced. A critical error looks identical to an info event.
**Fix:** Prepend level to message only for levels 2 (Error) and 3 (Warning):
`EventID 1000 - Application Error [Application] [ERROR] - foo.exe`
Level 4/5/0 stay silent (Info is the default, no need to add noise).
**File:** `core/src/parsers/evtx.rs` — message assembly in `parse_evtx_chunk()`

### 1.3 EVTX — record number not in output
**Problem:** Record number lost after parsing. Needed to correlate back to raw log.
**Fix:** Add `record_num` field to `EvtxRecord` and emit it as `record_number` in
the output dict. Already in `EventExtra::Evtx` or add as a new field.
**File:** `core/src/parsers/evtx.rs` + `core/src/types.rs`

### 1.4 SRUM — all timestamps show 1601-01-01
**Problem:** `ts_ns == 0` check at line 427 of srum.py should skip zero-timestamp
records, but they're still appearing. The `TimeStamp` column name likely differs in
this image's schema (dissect may return it as `Timestamp` lowercase or similar).
**Fix:** Log the actual column names from the first record of each table. Make
`get_timestamp_ns` try `TimeStamp`, `Timestamp`, `timestamp`, `EventTime` in order.
**File:** `cli/supertimeline/parsers/srum.py`

### 1.5 SRUM — well-known SID resolution
**Problem:** `User: S-1-5-18` is shown raw. Well-known SIDs should be human-readable.
**Fix:** Add static lookup: S-1-5-18→SYSTEM, S-1-5-19→LOCAL SERVICE,
S-1-5-20→NETWORK SERVICE, S-1-5-21-*-500→Administrator (domain RID 500).
**File:** `cli/supertimeline/parsers/srum.py`

### 1.6 JumpList — missing drive letter on target paths
**Problem:** Paths show as `:\Users\...` instead of `C:\Users\...`.
**Root cause:** First character (`C`) being stripped, likely a null-byte or
off-by-one in the LNK path extraction inside the jump list parser.
**Fix:** Trace the path string from `parse_lnk_bytes_inner` through
`events_from_lnk` — check if `r_ascii_null` / `r_utf16_null` is starting one
byte late, or if the local base path offset calculation is off by 1.
**File:** `core/src/parsers/lnk.rs` or `core/src/parsers/jumplists.rs`

---

## PHASE 2 — Expand existing parsers (more data from artifacts we already parse)

### 2.1 Prefetch — previous run times (highest value, easiest win)
**Problem:** We emit one event per prefetch file (most recent run). Windows stores
up to 8 run times (V26+: last + 7 previous; V17/V23: last + 7 at 0x80).
Each previous run is a real execution event with its own timestamp.
**Fix:** After parsing the primary last_run timestamp, iterate the previous_run_times
array and emit one additional event per non-zero entry with the same message format
`EXE.EXE - Executed (run count: N)` but MACB=`M` and the historical timestamp.
**File:** `cli/supertimeline/parsers/prefetch.py`
**Impact:** ~7× more execution events (1,182 → potentially ~8,000+)

### 2.2 Prefetch — loaded modules list
**Problem:** The list of DLLs/files loaded during execution (`mapped_files`) is
extracted by windowsprefetch but we discard it. Useful for DLL hijack detection.
**Fix:** Include top loaded paths in message or as a separate `modules` field in
the event dict. Cap at 10 entries to avoid bloat.
**File:** `cli/supertimeline/parsers/prefetch.py`

### 2.3 SRUM — NetworkConnectivity table
**Problem:** We parse AppTimeline and NetworkUsage but miss the NetworkConnectivity
table (`{DD6636C4-8929-4683-974E-22C046A43763}`). Records when each app connected
to which network interface (WiFi vs Ethernet transitions).
**Fix:** Add `_parse_network_connectivity()` function, add GUID to table routing.
**File:** `cli/supertimeline/parsers/srum.py`

### 2.4 LNK — command line arguments
**Problem:** LNK files can embed command line arguments. We extract target path,
drive info, timestamps — but discard args. Malware often uses these.
**Fix:** Parse `FL_HAS_ARGUMENTS` string from StringData section (after RelativePath).
Include in message if non-empty: `LNK target: foo.exe /arg1 /arg2`.
**File:** `core/src/parsers/lnk.rs`

### 2.5 LNK — DROID tracking identifiers
**Problem:** Distributed Tracking identifiers (volume GUID + file GUID) let you
link a file to its original location after it's moved/copied. Not extracted.
**Fix:** Parse the TrackerDataBlock from ExtraData section. Emit as extra fields
`droid_volume`, `droid_file` in the event dict.
**File:** `core/src/parsers/lnk.rs`

### 2.6 Amcache — driver binaries and application tables
**Problem:** Our amcache parser likely only hits `InventoryApplicationFile`. Plaso
also parses `InventoryDriverBinary` (rootkit/unsigned driver detection) and
`InventoryApplication` (installed software timeline).
**Fix:** Check which hive keys the current parser reads. Add parsing for:
- `Root\InventoryDriverBinary` — driver SHA1, inf path, driver type
- `Root\InventoryApplication` — install date, publisher, version
**File:** `cli/supertimeline/parsers/amcache.py`

### 2.7 Registry — semantic key plugins
**Problem:** We emit every NK record as a generic "Registry Key" event. High-value
forensic keys need their own artifact type and message format.
**Fix:** After building the full key path, check against a plugin table and
re-format the message if it matches:

| Key pattern | Artifact | Message format |
|-------------|----------|---------------|
| `...\CurrentVersion\Run` | Persistence | `AutoRun: name=value` |
| `...\CurrentVersion\RunOnce` | Persistence | `AutoRunOnce: name=value` |
| `...\RecentDocs` | MRU | `RecentDoc: value` |
| `...\ComDlg32\OpenSavePidlMRU` | MRU | `OpenSave MRU: value` |
| `...\UserAssist\...\Count` | Execution | `UserAssist: name rotN decoded` |
| `...\AppCompatCache` | ShimCache | `ShimCache entry` |
| `...\BAM\State\UserSettings` | BAM | `BAM: exe last run` |
| `NTUSER\Software\Microsoft\Windows\Shell\BagMRU` | ShellBags | `ShellBag: path` |

**File:** `cli/supertimeline/parsers/registry.py`

---

## PHASE 3 — New artifact parsers

### 3.1 Recycle Bin ($I files)
**What:** `$Recycle.Bin\S-1-5-...\$IXXXXXX` files contain original path, deletion
time, and file size for every deleted file.
**Format:** 28-byte header: magic(8) + file_size(8) + deletion_time(FILETIME 8) +
original_path(UTF-16LE, null-terminated).
**Output:** `Deleted: C:\Users\foo\secret.docx (1,234 bytes)`
**Source:** `RECYCLEBIN`
**Complexity:** Low — pure Python, ~60 lines

### 3.2 Scheduled Tasks (XML task files)
**What:** `C:\Windows\System32\Tasks\**\*` — XML files defining scheduled tasks.
Each task has creation/modification times in the XML body and can reveal persistence.
**Output:** `Task: \Microsoft\Windows\Foo | Action: cmd.exe /c malware.bat | Trigger: daily 03:00`
**Source:** `TASK`
**Complexity:** Medium — XML parsing, recursive directory walk

### 3.3 PowerShell ConsoleHost_history.txt
**What:** Per-user `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
Contains every PS command typed interactively. No timestamps — use file mtime.
**Output:** `PS History: Invoke-WebRequest http://... -OutFile malware.exe`
**Source:** `PSHISTORY`
**Complexity:** Low — plain text, one event per line, use file mtime as timestamp

### 3.4 Windows Timeline / ActivitiesCache.db
**What:** `AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db` — SQLite DB
storing app usage, clipboard, and document open history with precise timestamps.
Tables: `Activity`, `ActivityOperation`
**Output:** `Timeline: opened C:\Users\foo\report.docx in WINWORD.EXE`
**Source:** `WINTIMELINE`
**Complexity:** Medium — SQLite, JSON payload parsing

### 3.5 Browser artifacts
Three browsers, similar schema. All use SQLite.

**Chrome / Edge (Chromium-based):**
- `AppData\Local\Google\Chrome\User Data\Default\History` — visits, downloads
- `AppData\Local\Microsoft\Edge\User Data\Default\History`
- Tables: `urls` (visit timestamps + URL + title), `downloads` (start/end time, path, URL)

**Firefox:**
- `AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite`
- Tables: `moz_places` + `moz_historyvisits` (visit time in microseconds since Unix epoch)
- `AppData\Roaming\Mozilla\Firefox\Profiles\*.default\downloads.sqlite` (older) or
  `moz_annos` table in places.sqlite (newer)

**Output format:**
- Visit: `Browser Visit: https://evil.com - "Malware Download Page" [Chrome]`
- Download: `Browser Download: C:\Users\foo\malware.exe from https://evil.com [Edge]`
**Source:** `BROWSER`
**Complexity:** Medium — SQLite, microsecond→ns timestamp conversion, 3 browser variants

### 3.6 Windows Search index (Windows.edb / Windows.db)
**What:** `ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`
(Win10) or `Windows.db` (Win11 SQLite). Contains full-text index of every document
ever opened — file paths, content snippets, timestamps.
**Complexity:** High (Win10 ESE, Win11 SQLite) — defer to later phase

### 3.7 Shellbags (USRCLASS.DAT BagMRU)
**What:** `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
in `UsrClass.dat`. Records every folder ever browsed in Explorer including network
shares, USB devices, ZIP contents, deleted folders.
**Output:** `ShellBag: C:\Users\foo\Desktop\TrueEvidence (last explored)`
**Source:** `SHELLBAG`
**Complexity:** High — nested binary shell item list format, multiple item types
(file, folder, network, drive, zip). May use a library (shellbags, liblnk).
Defer after browser artifacts.

### 3.8 Windows Error Reporting (WER)
**What:** `AppData\Local\Microsoft\Windows\WER\ReportArchive\*\Report.wer`
Plain-text key=value files. Contains crash info: faulting module, exception code,
app version, crash time.
**Output:** `WER Crash: WINWORD.EXE (ver 16.0.x) faulting module ntdll.dll, code 0xC0000005`
**Source:** `WER`
**Complexity:** Low — text parsing

### 3.9 WLAN event logs / Network history
**What:** Already covered by EVTX (EventID 11000/11001/11002 in
`Microsoft-Windows-WLAN-AutoConfig/Operational.evtx`).
Better approach: add these EventIDs to the EVTX event name table and add a
specific snippet extractor for them showing SSID + reason code.
**Complexity:** Low — extends existing EVTX parser

---

## PHASE 4 — Output and infrastructure improvements

### 4.1 Short message field
Add a `message_short` field (≤80 chars) alongside `message`. Used by Timesketch
and other timeline viewers for compact display.

### 4.2 Parquet sort for CSV too
Currently sort step only runs for Parquet output. CSV output is unsorted by
timestamp. Fix: always sort before writing.

### 4.3 Hostname field population
`hostname` comes from EVTX `<Computer>` element. Currently empty for all other
sources. For MFT/Registry/Prefetch, populate from the EVTX records in the same
image (extract once, apply to all events from same image).

### 4.4 SQLite output format
Add `sqlite` as an output format option alongside csv/parquet. Useful for
loading into DB Browser or custom queries.

### 4.5 Timesketch-ready output
Timesketch expects specific column names (`datetime`, `message`, `timestamp_desc`,
`source_short`, `source_long`). Add a `--format timesketch` option that remaps
our schema to their expected format.

---

## Execution Order

```
Phase 1 (bugs):     1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6
Phase 2 (expand):   2.1 → 2.3 → 2.7 → 2.4 → 2.5 → 2.2 → 2.6
Phase 3 (new):      3.1 → 3.3 → 3.8 → 3.2 → 3.5 → 3.4 → 3.7 → 3.6
Phase 4 (output):   4.2 → 4.1 → 4.3 → 4.4 → 4.5
```

After each phase, run full test against `D:\Midterm Spring 26.E01` and verify:
- Zero parser errors
- Event count >= previous baseline
- Spot-check all artifact types with check_snippets.py

---

## Current Baseline (2026-05-07)
| Source | Events |
|--------|--------|
| $MFT | 2,223,485 |
| $UsnJrnl:$J | 287,310 |
| EVTX | 122,544 |
| REGISTRY | 281,505 |
| LOGFILE | 15,976 |
| PREFETCH | 1,182 |
| LNK | 597 |
| JUMPLIST | 12 |
| SRUM | 418 |
| AMCACHE | 462 |
| **Total** | **2,933,491** |
