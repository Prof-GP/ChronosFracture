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
- **Windows only:** [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **Desktop development with C++** workload — required by the Rust MSVC toolchain to compile the native extension.

```powershell
# Windows — install Rust via winget
winget install Rustlang.Rustup
rustup default stable

# Windows — install MSVC build tools via winget (if not already installed)
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
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

### Optional extras — disk image support

By default, supertimeline works with **mounted volumes** (`E:\`, `/mnt/img`) and **extracted artifact directories**. To parse raw/E01/VMDK/VHD images directly, install the platform extra.

**Windows:**
```bash
pip install ".[windows]"
```
Installs `pytsk3` (The Sleuth Kit) and `windowsprefetch` (MAM-compressed prefetch decompression).

> **Tip:** For E01 images on Windows, [Arsenal Image Mounter](https://arsenalrecon.com/products/arsenal-image-mounter) is often simpler — mount the image as a drive letter and point supertimeline at it without needing pytsk3.

**Linux / WSL:**
```bash
# System packages
sudo apt-get install -y build-essential python3-dev ewf-tools ntfs-3g

# Python extras (pytsk3)
pip install ".[linux]"

# pyscca (libscca) — prefetch parsing + MAM decompression (not on PyPI)
sudo apt-get install -y python3-libscca
cp /usr/lib/python3/dist-packages/pyscca*.so \
   $(python -c "import site; print(site.getsitepackages()[0])")
```

See [`requirements-linux.txt`](cli/requirements-linux.txt) for E01 mount commands and WSL-specific notes.

---

## Quick Start

```bash
# Parse a mounted forensic image at E:\
supertimeline run E:\ -o case001.parquet

# JSONL output for Timesketch
supertimeline run E:\ -o case001.jsonl -f jsonl

# CSV output for spreadsheet analysis
supertimeline run E:\ -o case001.csv -f csv

# Explicit thread count
supertimeline run E:\ -o case001.parquet -w 16

# Discover artifacts without parsing
supertimeline run E:\ --discover-only

# Parse an extracted artifacts directory
supertimeline run C:\Cases\artifacts\ -o case001.parquet

# Recover wiped USN journal records from a zeroed $J stream (fast)
supertimeline case.E01 -o case001.parquet --recover-usnjrnl

# Deep carve — scan entire image for USN records including unallocated space (slow)
supertimeline case.E01 -o case001.parquet --recover-usnjrnl-deep
```

### USN Journal Recovery

When `$UsnJrnl:$J` has been wiped, use `--recover-usnjrnl` to carve remnant USN records from the zeroed stream. Recovered events are tagged `artifact = "$J (Recovered)"` in the output so they can be distinguished from live records. Use `--recover-usnjrnl-deep` to additionally scan unallocated space and the full raw image (significantly slower on large images).

---

## Parsers

| Artifact | Method | Events per file |
|---|---|---|
| `$MFT` | Rust, mmap + rayon | 8 timestamps per file entry |
| `$UsnJrnl:$J` | Rust, 64MB parallel chunks | 1 per change record |
| Windows Event Logs (`.evtx`) | Rust, 64KB parallel chunks | 1 per event |
| Prefetch (`.pf`) | Rust, parallel per-file | Up to 8 last-run times |
| LNK / Jump Lists | Rust + Python glue | 3 per `.lnk`; 1 per Jump List entry |
| Registry hives | Python | 1 per key (last-written time) |
| SRUM (`SRUDB.dat`) | Python | 1 per record |
| Amcache (`Amcache.hve`) | Python | 1 per entry |
| PcaSvc (`PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt`) | Python | 1 per execution record (Windows 11 22H2+) |

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
