"""
supertimeline — High-performance forensic super-timeline generator.
"""
import os
import sys
import time
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.text import Text

from supertimeline.orchestrator import Orchestrator
from supertimeline.storage.writer import StreamingWriter, sort_parquet_by_timestamp

console = Console()


def _banner():
    console.print(Panel.fit(
        "[bold cyan]supertimeline[/bold cyan] [dim]v0.1.0[/dim]\n"
        "[dim]Forensic super-timeline generator | Rust core + Arrow storage[/dim]",
        border_style="cyan",
    ))


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
@click.option("--no-summary", is_flag=True, default=False,
              help="Suppress per-artifact summary table")
def run(root_path, output, format, workers, no_sort, discover_only, no_summary):
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

    max_workers = workers if workers > 0 else os.cpu_count()
    console.print(f"[bold]Input:[/bold]   {root_path}")
    console.print(f"[bold]Output:[/bold]  {output} ({format.upper()})")
    console.print(f"[bold]Workers:[/bold] {max_workers} threads\n")

    # ── Open image ──────────────────────────────────────────────────────────
    try:
        with console.status("[cyan]Opening image...[/cyan]"):
            orc = Orchestrator(root_path, max_workers=max_workers, output_format=format)
    except RuntimeError as exc:
        console.print(f"[red bold]Cannot open image:[/red bold]\n{exc}")
        sys.exit(1)

    console.print(f"[bold]Format:[/bold]  [cyan]{orc.image_format.name}[/cyan]")
    if orc.root != root_path:
        console.print(f"[bold]Extracted to:[/bold] [dim]{orc.root}[/dim]")
    console.print()

    # ── Discovery ───────────────────────────────────────────────────────────
    with console.status("[cyan]Discovering artifacts...[/cyan]"):
        t0 = time.perf_counter()
        jobs = orc.discover()
        discovery_secs = time.perf_counter() - t0

    if not jobs:
        console.print("[yellow]No artifacts found.[/yellow]")
        sys.exit(1)

    tbl = Table(title=f"Discovered Artifacts ({len(jobs)} items, {discovery_secs:.2f}s)")
    tbl.add_column("Type",  style="cyan",  no_wrap=True)
    tbl.add_column("Path",  style="white")
    tbl.add_column("Size",  style="green", justify="right")
    for job in jobs:
        tbl.add_row(job.artifact_type, job.path, f"{job.size_bytes/1_048_576:.1f} MB")
    console.print(tbl)

    if discover_only:
        return

    # ── Parallel parsing ────────────────────────────────────────────────────
    console.print()
    total_events = 0
    errors = 0
    parse_start = time.perf_counter()

    # Aggregate counts per artifact type for the live display
    type_counts: dict = {}

    with StreamingWriter(output, format=format) as writer:
        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("[cyan]{task.fields[events]}[/cyan] events"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Parsing...[/cyan]", total=len(jobs), events="0")

            for result in orc.run():
                writer.write_events(result.events)
                total_events += result.event_count
                if result.error:
                    errors += 1

                # Accumulate per-type counts
                t = result.artifact_type
                type_counts[t] = type_counts.get(t, 0) + result.event_count

                # Per-artifact status line
                status   = "[green]OK[/green]" if not result.error else "[red]ERR[/red]"
                eps      = int(result.event_count / result.elapsed_secs) if result.elapsed_secs > 0 else 0
                name     = os.path.basename(result.path)
                progress.print(
                    f"  {status} [cyan]{result.artifact_type:<10}[/cyan] "
                    f"[white]{result.event_count:>8,}[/white] events  "
                    f"[dim]{eps:>7,} ev/s  {result.elapsed_secs:.1f}s  {name}[/dim]"
                )

                progress.update(task, advance=1, events=f"{total_events:,}")

    parse_elapsed = time.perf_counter() - parse_start

    # ── Sort ────────────────────────────────────────────────────────────────
    sort_elapsed = 0.0
    sorted_path = output
    if not no_sort and format == "parquet" and total_events > 0:
        console.print()
        with console.status(f"[cyan]Sorting {total_events:,} events by timestamp...[/cyan]"):
            t_sort = time.perf_counter()
            sorted_path = output.replace(".parquet", "_sorted.parquet")
            sort_parquet_by_timestamp(output, sorted_path)
            sort_elapsed = time.perf_counter() - t_sort
        console.print(f"[green]Sorted:[/green] {sorted_path} ({sort_elapsed:.1f}s)")

    # ── Summary ─────────────────────────────────────────────────────────────
    total_elapsed = parse_elapsed + sort_elapsed
    throughput = int(total_events / total_elapsed) if total_elapsed > 0 else 0

    console.print()
    console.print(Panel(
        f"[bold green]Timeline complete[/bold green]\n\n"
        f"  Total events  : [cyan]{total_events:,}[/cyan]\n"
        f"  Parse time    : [cyan]{parse_elapsed:.1f}s[/cyan]\n"
        f"  Sort time     : [cyan]{sort_elapsed:.1f}s[/cyan]\n"
        f"  Total time    : [bold cyan]{total_elapsed:.1f}s[/bold cyan]\n"
        f"  Throughput    : [cyan]{throughput:,} events/sec[/cyan]\n"
        f"  Output        : [white]{sorted_path}[/white]"
        + (f"\n  [yellow]Errors        : {errors}[/yellow]" if errors else ""),
        border_style="green",
        title="Summary",
    ))

    if not no_summary:
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
