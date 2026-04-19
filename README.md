# ChronosFracture — supertimeline

High-performance forensic super-timeline generator for Windows disk images and live volumes. Designed as a drop-in replacement for `log2timeline` + `psort` (plaso) with a target of **10x faster execution**.

| | plaso | supertimeline |
|---|---|---|
| Parser language | Python (GIL-limited) | **Rust** (true parallelism) |
| Storage format | SQLite | **Apache Parquet (columnar)** |
| Streaming output | No | **Yes** |
| RAM usage (1TB image) | 4–16 GB | **2–6 GB** |
| 1TB wall clock time | 6–9 hours | **~25–53 minutes** |

---

## Installation

### Prerequisites

- [Python 3.10+](https://www.python.org/downloads/)
- [Rust 1.75+](https://rustup.rs/)

```powershell
# Windows — install Rust via winget
winget install Rustlang.Rustup
rustup default stable
```

### Install

```bash
git clone https://github.com/Prof-GP/ChronosFracture.git
cd ChronosFracture/cli

python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install .
```

`pip install .` compiles the Rust core automatically — no separate build step needed. First build takes 2–5 minutes; rebuilds are ~30 seconds.

### Verify

```bash
supertimeline --help
```

### Optional extras

**Windows** — disk image mounting support:
```bash
pip install -r requirements-windows.txt
```

**Linux / WSL** — system packages + disk image support:
```bash
sudo apt-get install -y build-essential python3-dev ewf-tools ntfs-3g
pip install -r requirements-linux.txt
```

---

## Quick Start

```bash
# Parse a mounted forensic image at E:\
supertimeline run E:\ -o case001.parquet

# JSONL output for Timesketch
supertimeline run E:\ -o case001.jsonl -f jsonl

# Explicit thread count
supertimeline run E:\ -o case001.parquet -w 16

# Discover artifacts without parsing
supertimeline run E:\ --discover-only

# Parse an extracted artifacts directory
supertimeline run C:\Cases\artifacts\ -o case001.parquet
```

---

## Parsers

| Artifact | Method | Events per file |
|---|---|---|
| `$MFT` | Rust, mmap + rayon | 8 timestamps per file entry |
| `$UsnJrnl:$J` | Rust, 64MB parallel chunks | 1 per change record |
| Windows Event Logs (`.evtx`) | Rust, 64KB parallel chunks | 1 per event |
| Prefetch (`.pf`) | Rust, parallel per-file | Up to 8 last-run times |
| Registry hives | Python | 1 per key (last-written time) |
| SRUM (`SRUDB.dat`) | Python | 1 per record |

---

## Output

Default output is **Apache Parquet** (Snappy compressed, ~3–6 GB per 100M events).

```python
import pandas as pd
df = pd.read_parquet("case001.parquet")
print(df[["timestamp_iso", "source", "message"]].head())
```

```sql
-- Query with DuckDB
SELECT timestamp_iso, source, message
FROM read_parquet('case001.parquet')
WHERE source = 'EVTX' AND timestamp_iso > '2024-01-01'
ORDER BY timestamp_ns LIMIT 100;
```

JSONL and CSV are also supported (`-f jsonl` / `-f csv`).

---

## Full Documentation

See [MANUAL.md](MANUAL.md) for the complete analyst reference including CLI options, parser details, timestomp detection, Timesketch integration, and troubleshooting.

---

## License

ChronosFracture is free for personal, academic, educational, and non-profit use under the [ChronosFracture Non-Commercial License](LICENSE).

**Commercial use requires a paid license.** This includes use within for-profit organizations, incorporation into commercial products or services, and providing paid forensic or incident response services using this tool.

To obtain a commercial license, contact: practical4n6@gmail.com
