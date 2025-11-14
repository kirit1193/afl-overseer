"""Terminal output formatting using rich."""

from typing import List
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from .models import FuzzerStats, CampaignSummary, MonitorConfig
from .utils import (
    format_duration, format_time_ago, format_number,
    format_execs, format_speed, format_percent
)
from .monitor import AFLMonitor

console = Console()


class TerminalOutput:
    """Terminal output formatter."""

    def __init__(self, config: MonitorConfig):
        self.config = config
        self.use_color = not config.no_color

    def print_banner(self):
        """Print application banner."""
        if self.config.minimal:
            return

        banner = Text()
        banner.append("AFL Overseer", style="bold cyan")
        banner.append(" v0.1\n", style="dim")
        console.print(banner)

    def print_campaign_summary(
        self,
        summary: CampaignSummary,
        system_info: dict = None
    ):
        """Print campaign summary."""
        # Create summary table
        table = Table(title="Campaign Summary", box=box.ROUNDED, show_header=False)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="bold")

        # Fuzzer counts
        alive_style = "bold green" if summary.alive_fuzzers > 0 else "dim"
        fuzzer_status = f"[{alive_style}]{summary.alive_fuzzers}[/] / {summary.total_fuzzers}"

        if summary.dead_fuzzers > 0:
            fuzzer_status += f" ([red]{summary.dead_fuzzers} dead[/])"
        if summary.starting_fuzzers > 0:
            fuzzer_status += f" ([yellow]{summary.starting_fuzzers} starting[/])"

        table.add_row("Fuzzers (Alive/Total)", fuzzer_status)

        # Execution stats
        table.add_row("Total Executions", format_execs(summary.total_execs))

        if summary.alive_fuzzers > 0:
            table.add_row("Current Speed", format_speed(summary.total_speed))
            table.add_row(
                "Average Speed/Core",
                format_speed(summary.avg_speed_per_core)
            )
            table.add_row(
                "Current Avg Speed",
                format_speed(summary.current_avg_speed)
            )

        # Corpus stats
        if not self.config.minimal:
            table.add_row(
                "Corpus (Favs/All)",
                f"{format_number(summary.total_pending_favs)} / {format_number(summary.total_corpus)}"
            )
            table.add_row(
                "Pending (Favs/All)",
                f"{format_number(summary.total_pending_favs)} / {format_number(summary.total_pending)}"
            )

        # Coverage
        coverage_style = "green" if summary.max_coverage > 5 else "yellow"
        table.add_row(
            "Coverage Reached",
            f"[{coverage_style}]{format_percent(summary.max_coverage)}[/]"
        )

        if not self.config.minimal and summary.total_fuzzers > 0:
            table.add_row(
                "Avg Stability",
                format_percent(summary.avg_stability)
            )
            table.add_row(
                "Stability Range",
                f"{format_percent(summary.min_stability)} - {format_percent(summary.max_stability)}"
            )

        # Findings
        crash_style = "bold red" if summary.total_crashes > 0 else "dim"
        crash_text = f"[{crash_style}]{summary.total_crashes}[/]"
        if summary.new_crashes > 0:
            crash_text += f" ([bold red]+{summary.new_crashes} new![/])"
        table.add_row("Crashes Saved", crash_text)

        if not self.config.minimal:
            table.add_row("Hangs Saved", str(summary.total_hangs))

        # Timing
        table.add_row("Time Without Finds", format_time_ago(summary.last_find_time))
        table.add_row("Last Crash", format_time_ago(summary.last_crash_time))

        if not self.config.minimal:
            table.add_row("Last Hang", format_time_ago(summary.last_hang_time))
            if summary.total_fuzzers > 0:
                table.add_row("Avg Cycle", f"{summary.avg_cycle:.1f}")
                table.add_row("Max Cycle", str(summary.max_cycle))
                table.add_row("Cycles w/o Finds", summary.cycles_wo_finds)

        # Advanced stats
        if not self.config.minimal and summary.max_total_edges > 0:
            coverage_ratio = (summary.total_edges_found / summary.max_total_edges) * 100
            table.add_row(
                "Edge Coverage",
                f"{format_number(summary.total_edges_found)} / {format_number(summary.max_total_edges)} ({coverage_ratio:.2f}%)"
            )

        # System info
        if system_info and not self.config.minimal:
            table.add_row("", "")  # Separator
            table.add_row(
                "System CPU",
                f"{system_info.get('cpu_percent', 0):.1f}% ({system_info.get('cpu_count', 0)} cores)"
            )
            table.add_row(
                "System Memory",
                f"{system_info.get('memory_percent', 0):.1f}% ({system_info.get('memory_used_gb', 0):.1f} / {system_info.get('memory_total_gb', 0):.1f} GB)"
            )

        console.print(table)
        console.print()

    def print_fuzzer_details(self, all_stats: List[FuzzerStats], monitor: AFLMonitor):
        """Print detailed per-fuzzer statistics."""
        if not self.config.verbose:
            return

        console.print("\n[bold cyan]Per-Fuzzer Details[/bold cyan]")
        console.print("=" * 80)
        console.print()

        for stats in all_stats:
            self._print_single_fuzzer(stats, monitor)

    def _print_single_fuzzer(self, stats: FuzzerStats, monitor: AFLMonitor):
        """Print details for a single fuzzer."""
        # Status indicator
        status_colors = {
            "alive": "bold green",
            "dead": "bold red",
            "starting": "bold yellow",
            "unknown": "dim",
        }
        status_style = status_colors.get(stats.status.value, "dim")

        # Header
        header = Text()
        header.append(f"[{stats.afl_banner}] ", style="bold blue")
        header.append(f"{stats.fuzzer_name}", style="bold")
        header.append(f" - ", style="dim")
        header.append(f"{stats.status.value.upper()}", style=status_style)
        console.print(header)

        # Create info table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="cyan")
        table.add_column("Value")

        # Runtime
        runtime = format_duration(stats.run_time)
        table.add_row("Runtime", runtime)

        # Execution stats
        table.add_row("Executions", format_number(stats.execs_done))

        if stats.is_alive:
            table.add_row("Current Speed", format_speed(stats.execs_per_sec))
            table.add_row("Last Min Speed", format_speed(stats.execs_ps_last_min))

        # Corpus
        table.add_row(
            "Corpus Progress",
            f"{stats.cur_item}/{stats.corpus_count} ({stats.corpus_progress:.1f}%)"
        )
        table.add_row(
            "Paths (Favs/All)",
            f"{format_number(stats.corpus_favored)} / {format_number(stats.corpus_count)}"
        )
        table.add_row(
            "Pending (Favs/All)",
            f"{format_number(stats.pending_favs)} / {format_number(stats.pending_total)}"
        )

        # Coverage
        table.add_row("Coverage", format_percent(stats.bitmap_cvg))
        table.add_row("Stability", format_percent(stats.stability))
        table.add_row("Cycle", str(stats.cycles_done))

        # Timing
        table.add_row("Last Path", format_time_ago(stats.last_find))
        table.add_row("Last Crash", format_time_ago(stats.last_crash))
        if not self.config.minimal:
            table.add_row("Last Hang", format_time_ago(stats.last_hang))

        # Findings
        crash_style = "bold red" if stats.saved_crashes > 0 else "dim"
        table.add_row("Unique Crashes", f"[{crash_style}]{stats.saved_crashes}[/]")

        if not self.config.minimal:
            table.add_row("Unique Hangs", str(stats.saved_hangs))

        # Resources
        if stats.is_alive and stats.cpu_usage >= 0:
            table.add_row(
                "Resources",
                f"CPU: {stats.cpu_usage:.1f}%, Memory: {stats.memory_usage:.1f}%"
            )

        console.print(table)

        # Warnings
        warnings = monitor.get_fuzzer_warnings(stats)
        if warnings:
            console.print()
            for warning in warnings:
                console.print(f"  [yellow]![/yellow]  {warning}")

        console.print()

    def print_watch_header(self, timestamp: str):
        """Print header for watch mode."""
        console.clear()
        console.print(f"[dim]Updated: {timestamp}[/dim]")
        console.print()
        self.print_banner()
