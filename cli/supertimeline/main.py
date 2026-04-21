"""
supertimeline — High-performance forensic super-timeline generator.
"""
import os
import sys
import time
import click
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.text import Text
from rich.console import Group

from supertimeline.orchestrator import Orchestrator
from supertimeline.storage.writer import StreamingWriter, sort_parquet_by_timestamp

console = Console()


_CLOCK = [
    r"   .-------.  ",
    r"  /   12    \ ",
    r" | 9    .  3| ",
    r" |      |/   ",
    r"  \ 6   |  / ",
    r"   '----'--' ",
]


def _banner():
    try:
        import pyfiglet

        def _art_lines(s: str):
            lines = s.rstrip("\n").split("\n")
            while lines and not lines[-1].strip():
                lines.pop()
            w = max(len(l.rstrip()) for l in lines)
            return [l.ljust(w) for l in lines]

        art_lines = _art_lines(pyfiglet.Figlet(width=200).renderText("ChronosFracture"))

        # Pad art vertically to match clock height
        clock_h = len(_CLOCK)
        art_h   = len(art_lines)
        pad_top = (clock_h - art_h) // 2
        art_padded = [""] * pad_top + art_lines + [""] * (clock_h - art_h - pad_top)

        clock_w = max(len(l) for l in _CLOCK)
        rows = [c.ljust(clock_w) + "  " + a for c, a in zip(_CLOCK, art_padded)]
        combined   = "\n".join(rows)
        combined_w = max(len(r) for r in rows)

        sub = "supertimeline".center(combined_w)
        tag = "Forensic super-timeline generator  |  v1.0.0".center(combined_w)
        sep = "-" * combined_w

        content = Group(
            Text(combined, style="bold cyan", no_wrap=True),
            Text(""),
            Text(sub,  style="cyan"),
            Text(sep,  style="dim"),
            Text(tag,  style="dim"),
        )
        console.print(Panel.fit(content, border_style="cyan", padding=(0, 1)))
    except ImportError:
        W = 52
        content = (
            f"[bold cyan]{'ChronosFracture'.center(W)}[/bold cyan]\n"
            f"[cyan]{'supertimeline'.center(W)}[/cyan]\n"
            f"[dim]{'-' * W}[/dim]\n"
            f"[dim]{'Forensic super-timeline generator  |  v1.0.0'.center(W)}[/dim]"
        )
        console.print(Panel.fit(content, border_style="cyan", padding=(0, 2)))
    console.print()


@click.command()
@click.argument("root_path", type=click.Path(exists=True, path_type=str))
@click.option("-o", "--output",  default="timeline.parquet", show_default=True,
              help="Output file path")
@click.option("-f", "--format",  default="parquet",
              type=click.Choice(["parquet", "jsonl", "csv"]), show_default=True,
              help="Output format")
@click.option("-w", "--workers", default=0, show_default=True,
              help="Worker threads (0 = auto)")
@click.option("--no-sort", is_flag=True, default=False,
              help="Skip timestamp sort (parquet only)")
@click.option("--discover-only", is_flag=True, default=False,
              help="List artifacts without parsing")
@click.option("--debug", is_flag=True, default=False,
              help="Show per-artifact breakdown after parsing")
@click.option("--recover-usnjrnl", is_flag=True, default=False,
              help="Carve zeroed $J streams for recovered USN records (fast)")
@click.option("--recover-usnjrnl-deep", is_flag=True, default=False,
              help="Carve entire image for USN records including unallocated space (slow)")
def run(root_path, output, format, workers, no_sort, discover_only, debug, recover_usnjrnl, recover_usnjrnl_deep):
    """
    Generate a forensic super-timeline from ROOT_PATH.

    ROOT_PATH can be a forensic image (.E01, .dd, .vmdk, .vhd),
    a mounted drive, or a directory of extracted artifacts.

    \b
    Examples:
      supertimeline case.E01
      supertimeline case.E01 -f csv -o timeline.csv
      supertimeline /mnt/image -f jsonl -o events.jsonl
      supertimeline C:\\ --discover-only
    """
    _banner()
    wall_start  = time.perf_counter()
    max_workers = workers if workers > 0 else os.cpu_count()

    # ── Open image ──────────────────────────────────────────────────────────
    try:
        with console.status("[cyan]Opening image...[/cyan]") as status:
            def _extract_cb(src_path: str):
                label = src_path.split("/")[-1] or src_path
                status.update(f"[cyan]Extracting  [bold]{label}[/bold]...[/cyan]")
            orc = Orchestrator(root_path, max_workers=max_workers,
                               output_format=format, progress_cb=_extract_cb)
    except RuntimeError as exc:
        console.print(f"[red bold]Cannot open image:[/red bold]\n{exc}")
        sys.exit(1)

    # Run info table — printed once after image opens so we have the format name
    info = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    info.add_column(style="bold cyan",  no_wrap=True)
    info.add_column(style="white",      no_wrap=True)
    info.add_row("Input",   root_path)
    info.add_row("Output",  f"{output}  ({format.upper()})")
    info.add_row("Format",  orc.image_format.name)
    info.add_row("Workers", f"{max_workers} threads")
    if orc.root != root_path:
        info.add_row("Extracted", f"[dim]{orc.root}[/dim]")
    console.print(info)
    console.print()

    # ── Discovery ───────────────────────────────────────────────────────────
    with console.status("[cyan]Discovering artifacts...[/cyan]"):
        t0 = time.perf_counter()
        jobs = orc.discover()
        discovery_secs = time.perf_counter() - t0

    if not jobs:
        console.print("[yellow]No artifacts found.[/yellow]")
        sys.exit(1)

    # Compact discovery summary — one row per type, not per file
    type_summary: dict = defaultdict(lambda: {"count": 0, "size_mb": 0.0})
    for job in jobs:
        type_summary[job.artifact_type]["count"]   += 1
        type_summary[job.artifact_type]["size_mb"] += job.size_bytes / 1_048_576

    tbl = Table(title=f"Discovered Artifacts  ({len(jobs)} files, {discovery_secs:.2f}s)")
    tbl.add_column("Type",   style="cyan",  no_wrap=True)
    tbl.add_column("Files",  style="white", justify="right")
    tbl.add_column("Size",   style="green", justify="right")
    for atype, summary in sorted(type_summary.items()):
        tbl.add_row(atype, str(summary["count"]), f"{summary['size_mb']:.1f} MB")
    console.print(tbl)

    if discover_only:
        return

    # ── Parallel parsing ────────────────────────────────────────────────────
    console.print()
    total_events = 0
    errors = 0
    parse_start = time.perf_counter()

    type_counts: dict = {}

    # Pre-count files per type so we know when a section is fully done
    type_totals:  dict = {}
    for job in jobs:
        type_totals[job.artifact_type] = type_totals.get(job.artifact_type, 0) + 1
    type_done:    dict = {}
    type_evts:    dict = {}
    type_errs:    dict = {}
    type_t0:      dict = {}

    with StreamingWriter(output, format=format) as writer:
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[cyan]{task.fields[current]:<12}[/cyan]"),
            BarColumn(bar_width=35),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("[bold cyan]{task.fields[events]}[/bold cyan] events"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("", total=len(jobs), current="Starting...", events="0")

            for result in orc.run():
                writer.write_events(result.events)
                total_events += result.event_count
                if result.error:
                    errors += 1

                t = result.artifact_type
                if t not in type_t0:
                    type_t0[t] = time.perf_counter()
                type_done[t] = type_done.get(t, 0) + 1
                type_evts[t] = type_evts.get(t, 0) + result.event_count
                type_errs[t] = type_errs.get(t, 0) + (1 if result.error else 0)
                type_counts[t] = type_evts[t]

                # Print one summary line when all files of this type are done
                if type_done[t] == type_totals[t]:
                    elapsed = time.perf_counter() - type_t0[t]
                    tag = "[red]ERR[/red]" if type_errs[t] else "[green] OK[/green]"
                    progress.print(
                        f"  {tag}  [cyan]{t:<10}[/cyan]  "
                        f"[white]{type_evts[t]:>10,}[/white] events  "
                        f"[dim]{elapsed:.1f}s[/dim]"
                    )

                progress.update(
                    task,
                    advance=1,
                    current=t,
                    events=f"{total_events:,}",
                )

    parse_elapsed = time.perf_counter() - parse_start

    # ── USN Journal recovery ─────────────────────────────────────────────────
    recovered_parquet = None
    if recover_usnjrnl or recover_usnjrnl_deep:
        console.print()
        console.print("[cyan]USN Journal recovery:[/cyan] scanning for wiped records...")
        recovered_events = []

        from supertimeline.parsers.usnjrnl_recover import (
            recover_from_image, recover_from_zeroed_j, recover_from_zeroed_j_image
        )

        usnjrnl_live_events = sum(
            r.event_count for r in orc.results if r.artifact_type == "USNJRNL"
        )

        # 1. Scan zeroed $J — triggered when $J existed on image but live parse
        #    found nothing (extractor skips all-zero streams, so check the image directly)
        if usnjrnl_live_events == 0 and orc.original_path != orc.root:
            with console.status("[cyan]Carving zeroed $J stream from image...[/cyan]"):
                evs = recover_from_zeroed_j_image(orc.original_path)
            if evs:
                recovered_events.extend(evs)
                console.print(
                    f"  [green]RECOVERED[/green] [cyan]USNJRNL[/cyan] "
                    f"[white]{len(evs):>8,}[/white] events  [dim](zeroed $J)[/dim]"
                )
        elif usnjrnl_live_events == 0:
            # Extracted dir — check for a zeroed UsnJrnl_J file
            for job in jobs:
                if job.artifact_type == "USNJRNL":
                    with console.status(f"[cyan]Carving zeroed $J: {os.path.basename(job.path)}[/cyan]"):
                        evs = recover_from_zeroed_j(job.path)
                    if evs:
                        recovered_events.extend(evs)
                        console.print(
                            f"  [green]RECOVERED[/green] [cyan]USNJRNL[/cyan] "
                            f"[white]{len(evs):>8,}[/white] events  [dim](zeroed $J)[/dim]"
                        )

        # 2. Full image scan — only when --recover-usnjrnl-deep is set (slow)
        if recover_usnjrnl_deep and orc.original_path != orc.root:
            console.print("  [yellow]Deep scan:[/yellow] scanning full image (this may take a while)...")
            with console.status("[cyan]Carving image for USN records...[/cyan]"):
                evs = recover_from_image(orc.original_path)
            if evs:
                recovered_events.extend(evs)
                console.print(
                    f"  [green]RECOVERED[/green] [cyan]USNJRNL[/cyan] "
                    f"[white]{len(evs):>8,}[/white] events  [dim](full image scan)[/dim]"
                )

        if not recovered_events:
            console.print("  [dim]No additional USN records recovered.[/dim]")
        else:
            total_events += len(recovered_events)
            # Write recovered events to a sidecar parquet; merged into main before sort
            recovered_parquet = output.replace(".parquet", "_recovered_tmp.parquet")
            with StreamingWriter(recovered_parquet, format="parquet") as rw:
                rw.write_events(recovered_events)
            console.print(
                f"  [bold green]{len(recovered_events):,} total USN records recovered[/bold green]"
            )

    # ── Sort ────────────────────────────────────────────────────────────────
    sort_elapsed = 0.0
    sorted_path = output
    if not no_sort and format == "parquet" and total_events > 0:
        console.print()
        with console.status(f"[cyan]Sorting {total_events:,} events by timestamp...[/cyan]"):
            t_sort = time.perf_counter()
            sorted_path = output.replace(".parquet", "_sorted.parquet")
            if recovered_parquet and os.path.exists(recovered_parquet):
                from supertimeline.storage.writer import merge_and_sort_parquet
                merge_and_sort_parquet([output, recovered_parquet], sorted_path)
                os.remove(recovered_parquet)
            else:
                sort_parquet_by_timestamp(output, sorted_path)
            sort_elapsed = time.perf_counter() - t_sort
        console.print(f"[green]Sorted:[/green] {sorted_path} ({sort_elapsed:.1f}s)")

    # ── Summary ─────────────────────────────────────────────────────────────
    wall_elapsed = time.perf_counter() - wall_start
    throughput   = int(total_events / parse_elapsed) if parse_elapsed > 0 else 0

    console.print()
    console.print(Panel(
        f"[bold green]Timeline complete[/bold green]\n\n"
        f"  Total events  : [cyan]{total_events:,}[/cyan]\n"
        f"  Parse time    : [cyan]{parse_elapsed:.1f}s[/cyan]\n"
        f"  Sort time     : [cyan]{sort_elapsed:.1f}s[/cyan]\n"
        f"  Wall time     : [bold cyan]{wall_elapsed:.1f}s[/bold cyan]\n"
        f"  Throughput    : [cyan]{throughput:,} events/sec[/cyan]\n"
        f"  Output        : [white]{sorted_path}[/white]"
        + (f"\n  [yellow]Errors        : {errors}[/yellow]" if errors else ""),
        border_style="green",
        title="Summary",
    ))

    if debug:
        # Per-artifact-type aggregate table
        stbl = Table(title="Per-Artifact Summary")
        stbl.add_column("Type",     style="cyan")
        stbl.add_column("Events",   style="green",  justify="right")
        stbl.add_column("Time (s)", style="yellow", justify="right")
        stbl.add_column("Ev/sec",   style="white",  justify="right")
        stbl.add_column("Error",    style="red")

        for row in orc.summary()["per_artifact"]:
            stbl.add_row(
                row["type"],
                f"{row['events']:,}",
                f"{row['elapsed_secs']:.2f}",
                f"{row['events_per_sec']:,}",
                row.get("error", ""),
            )
        console.print(stbl)


@click.command()
@click.argument("parquet_file", type=click.Path(exists=True, path_type=str))
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("-f", "--format", default="csv",
              type=click.Choice(["csv", "jsonl"]), show_default=True)
@click.option("--start", default=None, help="ISO timestamp start filter")
@click.option("--end",   default=None, help="ISO timestamp end filter")
@click.option("--type",  "artifact_type", default=None,
              help="Artifact type filter (MFT, EVTX, PREFETCH, ...)")
def convert(parquet_file, output, format, start, end, artifact_type):
    """
    Convert a supertimeline Parquet file to CSV or JSONL.

    \b
    Examples:
      supertimeline convert timeline_sorted.parquet -o timeline.csv
      supertimeline convert timeline_sorted.parquet -o evtx.jsonl -f jsonl --type EVTX
    """
    import csv as _csv
    import json as _json
    import datetime

    try:
        import pyarrow.parquet as pq
        import pyarrow.compute as pc
    except ImportError:
        console.print("[red]pyarrow required: pip install pyarrow[/red]")
        sys.exit(1)

    with console.status(f"[cyan]Loading {parquet_file}...[/cyan]"):
        table = pq.read_table(parquet_file)

    mask = None
    for flag, col, op in [
        (start, "timestamp_ns", "ge"),
        (end,   "timestamp_ns", "le"),
    ]:
        if flag:
            try:
                dt = datetime.datetime.fromisoformat(flag).replace(tzinfo=datetime.timezone.utc)
                ns = int(dt.timestamp() * 1_000_000_000)
                m = getattr(pc, "greater_equal" if op == "ge" else "less_equal")(
                    table.column("timestamp_ns"), ns)
                mask = m if mask is None else pc.and_(mask, m)
            except Exception as e:
                console.print(f"[yellow]Warning: invalid timestamp ({e})[/yellow]")

    if artifact_type:
        m = pc.equal(table.column("artifact"), artifact_type.upper())
        mask = m if mask is None else pc.and_(mask, m)

    if mask is not None:
        table = table.filter(mask)

    row_count = len(table)
    console.print(f"[bold]Rows to export:[/bold] {row_count:,}")

    fields = [f.name for f in table.schema]

    with console.status(f"[cyan]Writing {output}...[/cyan]"):
        if format == "csv":
            with open(output, "w", newline="", encoding="utf-8") as f:
                writer = _csv.writer(f)
                writer.writerow(fields)
                for batch in table.to_batches(max_chunksize=100_000):
                    rows = {name: batch.column(name).to_pylist() for name in fields}
                    for i in range(len(batch)):
                        writer.writerow([rows[name][i] for name in fields])
        else:
            with open(output, "w", encoding="utf-8") as f:
                for batch in table.to_batches(max_chunksize=100_000):
                    rows = {name: batch.column(name).to_pylist() for name in fields}
                    for i in range(len(batch)):
                        f.write(_json.dumps({name: rows[name][i] for name in fields}, default=str) + "\n")

    console.print(f"[green]Exported {row_count:,} rows to {output}[/green]")


@click.command()
@click.argument("parquet_file", type=click.Path(exists=True, path_type=str))
@click.option("-n", "--rows", default=50, show_default=True, help="Rows to display")
@click.option("--type", "artifact_type", default=None, help="Filter by artifact type")
@click.option("--grep", default=None, help="Filter rows where message contains string")
def view(parquet_file, rows, artifact_type, grep):
    """
    Preview events from a supertimeline Parquet file.

    \b
    Examples:
      supertimeline view timeline_sorted.parquet -n 100
      supertimeline view timeline_sorted.parquet --type EVTX --grep "4624"
    """
    try:
        import pyarrow.parquet as pq
        import pyarrow.compute as pc
    except ImportError:
        console.print("[red]pyarrow required: pip install pyarrow[/red]")
        sys.exit(1)

    with console.status("[cyan]Loading...[/cyan]"):
        table = pq.read_table(parquet_file)

    if artifact_type:
        table = table.filter(pc.equal(table.column("artifact"), artifact_type.upper()))
    if grep:
        table = table.filter(pc.match_substring(table.column("message"), grep))

    display = table.slice(0, rows)
    tbl = Table(title=f"{parquet_file}  ({len(table):,} matching rows, showing {len(display)})")
    tbl.add_column("Timestamp (UTC)", style="cyan",   no_wrap=True, min_width=26)
    tbl.add_column("MACB",            style="yellow", no_wrap=True, width=6)
    tbl.add_column("Artifact",        style="green",  no_wrap=True)
    tbl.add_column("FN?",             style="red",    no_wrap=True, width=4)
    tbl.add_column("Message",         style="white",  overflow="fold")

    iso_col      = display.column("timestamp_iso").to_pylist()
    macb_col     = display.column("macb").to_pylist()
    artifact_col = display.column("artifact").to_pylist()
    fn_col       = display.column("is_fn_timestamp").to_pylist()
    msg_col      = display.column("message").to_pylist()

    for i in range(len(display)):
        tbl.add_row(
            str(iso_col[i] or ""),
            str(macb_col[i] or ""),
            str(artifact_col[i] or ""),
            "[red]FN[/red]" if fn_col[i] else "",
            str(msg_col[i] or ""),
        )
    console.print(tbl)


@click.group()
def cli():
    """supertimeline — High-performance forensic super-timeline generator."""
    pass


cli.add_command(run,     name="run")
cli.add_command(convert, name="convert")
cli.add_command(view,    name="view")


def entry_point():
    """Console script entry point.
    Allows `supertimeline image.E01 ...` as shorthand for `supertimeline run image.E01 ...`
    """
    if len(sys.argv) > 1 and sys.argv[1] not in ("run", "convert", "view", "--help", "-h"):
        sys.argv.insert(1, "run")
    cli()


if __name__ == "__main__":
    entry_point()
