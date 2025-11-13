"""Interactive TUI (Text User Interface) for AFL Monitor using Textual."""

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, TabbedContent, TabPane
from textual.containers import Container, Vertical, Horizontal
from textual.reactive import reactive
from textual import on
from textual.binding import Binding
from rich.text import Text
from datetime import datetime
import asyncio
from pathlib import Path

from .monitor import AFLMonitor
from .models import MonitorConfig
from .process import ProcessMonitor
from .utils import (
    format_duration, format_time_ago, format_number,
    format_speed, format_percent
)


class DetailLevel:
    """Detail level for display."""
    COMPACT = "compact"
    NORMAL = "normal"
    DETAILED = "detailed"


class SummaryPanel(Static):
    """Summary statistics panel."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.summary_data = None

    def update_summary(self, summary, system_info=None):
        """Update summary display."""
        self.summary_data = summary
        self.system_info = system_info
        self.refresh()

    def render(self) -> str:
        """Render the summary panel."""
        if not self.summary_data:
            return "[dim]Loading...[/dim]"

        s = self.summary_data
        output = []

        # Status line
        alive_color = "green" if s.alive_fuzzers > 0 else "red"
        status = f"[bold {alive_color}]{s.alive_fuzzers} alive[/bold {alive_color}] / {s.total_fuzzers} total"
        if s.dead_fuzzers > 0:
            status += f" ([red]{s.dead_fuzzers} dead[/red])"
        if s.starting_fuzzers > 0:
            status += f" ([yellow]{s.starting_fuzzers} starting[/yellow])"
        output.append(f"[bold cyan]Fuzzers:[/bold cyan] {status}")

        # Execution stats
        output.append(f"[bold cyan]Executions:[/bold cyan] {format_number(s.total_execs)}")
        if s.alive_fuzzers > 0:
            output.append(f"[bold cyan]Speed:[/bold cyan] {format_speed(s.total_speed)} (avg: {format_speed(s.avg_speed_per_core)}/core)")

        # Coverage
        cov_color = "green" if s.max_coverage > 10 else "yellow" if s.max_coverage > 5 else "red"
        output.append(f"[bold cyan]Coverage:[/bold cyan] [{cov_color}]{format_percent(s.max_coverage)}[/{cov_color}]")

        # Crashes
        crash_color = "bold red" if s.total_crashes > 0 else "dim"
        crash_text = f"[{crash_color}]{s.total_crashes}[/{crash_color}]"
        if s.new_crashes > 0:
            crash_text += f" [bold red](+{s.new_crashes} NEW!)[/bold red]"
        output.append(f"[bold cyan]Crashes:[/bold cyan] {crash_text}")

        # Last activity
        output.append(f"[bold cyan]Last Find:[/bold cyan] {format_time_ago(s.last_find_time)}")

        return "\n".join(output)


class FuzzersTable(DataTable):
    """Interactive table for fuzzer instances."""

    BINDINGS = [
        Binding("n", "sort_name", "Sort by Name"),
        Binding("s", "sort_speed", "Sort by Speed"),
        Binding("c", "sort_coverage", "Sort by Coverage"),
        Binding("e", "sort_execs", "Sort by Execs"),
        Binding("r", "sort_crashes", "Sort by Crashes"),
    ]

    def __init__(self, detail_level: str = DetailLevel.NORMAL, **kwargs):
        super().__init__(**kwargs)
        self.detail_level = detail_level
        self.sort_key = "name"
        self.sort_reverse = False
        self.fuzzer_data = []
        self.cursor_type = "row"

    def on_mount(self) -> None:
        """Set up the table when mounted."""
        self.setup_columns()

    def setup_columns(self):
        """Set up table columns based on detail level."""
        self.clear(columns=True)

        if self.detail_level == DetailLevel.COMPACT:
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Speed", key="speed")
            self.add_column("Coverage", key="coverage")
            self.add_column("Crashes", key="crashes")
        elif self.detail_level == DetailLevel.NORMAL:
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Runtime", key="runtime")
            self.add_column("Execs", key="execs")
            self.add_column("Speed", key="speed")
            self.add_column("Corpus", key="corpus")
            self.add_column("Coverage", key="coverage")
            self.add_column("Crashes", key="crashes")
        else:  # DETAILED
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Runtime", key="runtime")
            self.add_column("Execs", key="execs")
            self.add_column("Speed", key="speed")
            self.add_column("Corpus", key="corpus")
            self.add_column("Pending", key="pending")
            self.add_column("Coverage", key="coverage")
            self.add_column("Stability", key="stability")
            self.add_column("Cycle", key="cycle")
            self.add_column("Crashes", key="crashes")
            self.add_column("CPU%", key="cpu")

    def update_data(self, fuzzers):
        """Update table with fuzzer data."""
        self.fuzzer_data = fuzzers
        self._sort_data()
        self._populate_table()

    def _sort_data(self):
        """Sort fuzzer data based on current sort key."""
        if self.sort_key == "name":
            self.fuzzer_data.sort(key=lambda f: f.fuzzer_name, reverse=self.sort_reverse)
        elif self.sort_key == "speed":
            self.fuzzer_data.sort(key=lambda f: f.execs_per_sec, reverse=not self.sort_reverse)
        elif self.sort_key == "coverage":
            self.fuzzer_data.sort(key=lambda f: f.bitmap_cvg, reverse=not self.sort_reverse)
        elif self.sort_key == "execs":
            self.fuzzer_data.sort(key=lambda f: f.execs_done, reverse=not self.sort_reverse)
        elif self.sort_key == "crashes":
            self.fuzzer_data.sort(key=lambda f: f.saved_crashes, reverse=not self.sort_reverse)

    def _populate_table(self):
        """Populate table with sorted data."""
        self.clear()

        for fuzzer in self.fuzzer_data:
            # Status with color
            if fuzzer.status.value == "alive":
                status = Text("●", style="bold green") + Text(" ALIVE")
            elif fuzzer.status.value == "dead":
                status = Text("●", style="bold red") + Text(" DEAD")
            elif fuzzer.status.value == "starting":
                status = Text("●", style="bold yellow") + Text(" START")
            else:
                status = Text("●", style="dim") + Text(" UNKN")

            if self.detail_level == DetailLevel.COMPACT:
                self.add_row(
                    fuzzer.fuzzer_name,
                    status,
                    format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-",
                    format_percent(fuzzer.bitmap_cvg, 1),
                    str(fuzzer.saved_crashes),
                )
            elif self.detail_level == DetailLevel.NORMAL:
                self.add_row(
                    fuzzer.fuzzer_name,
                    status,
                    format_duration(fuzzer.run_time),
                    format_number(fuzzer.execs_done),
                    format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-",
                    f"{fuzzer.cur_item}/{fuzzer.corpus_count}",
                    format_percent(fuzzer.bitmap_cvg, 1),
                    str(fuzzer.saved_crashes),
                )
            else:  # DETAILED
                self.add_row(
                    fuzzer.fuzzer_name,
                    status,
                    format_duration(fuzzer.run_time),
                    format_number(fuzzer.execs_done),
                    format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-",
                    f"{fuzzer.cur_item}/{fuzzer.corpus_count}",
                    f"{fuzzer.pending_favs}/{fuzzer.pending_total}",
                    format_percent(fuzzer.bitmap_cvg, 1),
                    format_percent(fuzzer.stability, 0),
                    str(fuzzer.cycles_done),
                    str(fuzzer.saved_crashes),
                    f"{fuzzer.cpu_usage:.1f}" if fuzzer.cpu_usage >= 0 else "-",
                )

    def action_sort_name(self):
        """Sort by name."""
        self.sort_key = "name"
        self.sort_reverse = not self.sort_reverse
        self.update_data(self.fuzzer_data)

    def action_sort_speed(self):
        """Sort by speed."""
        self.sort_key = "speed"
        self.sort_reverse = False
        self.update_data(self.fuzzer_data)

    def action_sort_coverage(self):
        """Sort by coverage."""
        self.sort_key = "coverage"
        self.sort_reverse = False
        self.update_data(self.fuzzer_data)

    def action_sort_execs(self):
        """Sort by executions."""
        self.sort_key = "execs"
        self.sort_reverse = False
        self.update_data(self.fuzzer_data)

    def action_sort_crashes(self):
        """Sort by crashes."""
        self.sort_key = "crashes"
        self.sort_reverse = False
        self.update_data(self.fuzzer_data)


class AFLMonitorApp(App):
    """AFL Monitor Interactive TUI Application."""

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        background: $primary;
        color: $text;
    }

    Footer {
        background: $primary-darken-2;
    }

    SummaryPanel {
        height: 8;
        background: $panel;
        border: solid $primary;
        padding: 1 2;
        margin: 1;
    }

    FuzzersTable {
        height: 1fr;
        margin: 0 1;
    }

    #tabs {
        height: 1fr;
    }

    .detail-info {
        padding: 1 2;
        background: $panel;
        margin: 0 1 1 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh Now"),
        Binding("1", "detail_compact", "Compact View"),
        Binding("2", "detail_normal", "Normal View"),
        Binding("3", "detail_detailed", "Detailed View"),
        Binding("d", "toggle_dead", "Toggle Dead"),
        Binding("p", "pause", "Pause/Resume"),
    ]

    TITLE = "AFL Monitor - Interactive Dashboard"

    detail_level = reactive(DetailLevel.NORMAL)
    paused = reactive(False)

    def __init__(self, sync_dir: Path, refresh_interval: int = 5):
        super().__init__()
        self.sync_dir = sync_dir
        self.refresh_interval = refresh_interval
        self.show_dead = False
        self.config = MonitorConfig(
            findings_dir=sync_dir,
            show_dead=self.show_dead,
            verbose=True,
        )
        self.monitor = AFLMonitor(self.config)
        self.monitor.load_previous_state()

    def compose(self) -> ComposeResult:
        """Compose the UI."""
        yield Header()
        yield SummaryPanel(id="summary")

        with TabbedContent(id="tabs"):
            with TabPane("Fuzzers", id="fuzzers-tab"):
                yield Static("Detail Level: Normal | Sort: Name", classes="detail-info", id="detail-info")
                yield FuzzersTable(detail_level=self.detail_level, id="fuzzers-table")

            with TabPane("System", id="system-tab"):
                yield Static("System information", id="system-info")

        yield Footer()

    def on_mount(self) -> None:
        """Set up the app when mounted."""
        self.set_interval(self.refresh_interval, self.refresh_data)
        self.call_later(self.refresh_data)

    async def refresh_data(self) -> None:
        """Refresh fuzzer data."""
        if self.paused:
            return

        # Collect stats
        all_stats, summary = self.monitor.collect_stats()
        system_info = ProcessMonitor.get_system_info()

        # Update summary panel
        summary_panel = self.query_one("#summary", SummaryPanel)
        summary_panel.update_summary(summary, system_info)

        # Update fuzzers table
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.update_data(all_stats)

        # Update system info
        system_text = self._format_system_info(system_info)
        self.query_one("#system-info", Static).update(system_text)

        # Update detail info
        detail_info = f"Detail Level: {self.detail_level.title()} | Sort: {table.sort_key.title()} | Refresh: {self.refresh_interval}s"
        if self.paused:
            detail_info += " | [yellow]PAUSED[/yellow]"
        self.query_one("#detail-info", Static).update(detail_info)

        # Save state
        self.monitor.save_current_state(summary)

    def _format_system_info(self, system_info: dict) -> str:
        """Format system information."""
        if not system_info:
            return "[dim]No system information available[/dim]"

        lines = [
            "[bold cyan]System Resources[/bold cyan]\n",
            f"[bold]CPU:[/bold] {system_info.get('cpu_percent', 0):.1f}% ({system_info.get('cpu_count', 0)} cores)",
            f"[bold]Memory:[/bold] {system_info.get('memory_used_gb', 0):.1f} / {system_info.get('memory_total_gb', 0):.1f} GB ({system_info.get('memory_percent', 0):.1f}%)",
            f"[bold]Disk:[/bold] {system_info.get('disk_used_gb', 0):.1f} / {system_info.get('disk_total_gb', 0):.1f} GB ({system_info.get('disk_percent', 0):.1f}%)",
        ]
        return "\n".join(lines)

    def action_refresh(self) -> None:
        """Manually refresh data."""
        self.call_later(self.refresh_data)
        self.notify("Refreshing data...")

    def action_detail_compact(self) -> None:
        """Switch to compact detail level."""
        self.detail_level = DetailLevel.COMPACT
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.detail_level = self.detail_level
        table.setup_columns()
        table.update_data(table.fuzzer_data)
        self.notify("Switched to Compact view")

    def action_detail_normal(self) -> None:
        """Switch to normal detail level."""
        self.detail_level = DetailLevel.NORMAL
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.detail_level = self.detail_level
        table.setup_columns()
        table.update_data(table.fuzzer_data)
        self.notify("Switched to Normal view")

    def action_detail_detailed(self) -> None:
        """Switch to detailed level."""
        self.detail_level = DetailLevel.DETAILED
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.detail_level = self.detail_level
        table.setup_columns()
        table.update_data(table.fuzzer_data)
        self.notify("Switched to Detailed view")

    def action_toggle_dead(self) -> None:
        """Toggle showing dead fuzzers."""
        self.show_dead = not self.show_dead
        self.config.show_dead = self.show_dead
        self.call_later(self.refresh_data)
        status = "shown" if self.show_dead else "hidden"
        self.notify(f"Dead fuzzers {status}")

    def action_pause(self) -> None:
        """Pause/resume auto-refresh."""
        self.paused = not self.paused
        status = "paused" if self.paused else "resumed"
        self.notify(f"Auto-refresh {status}")


def run_interactive_tui(sync_dir: Path, refresh_interval: int = 5):
    """Run the interactive TUI."""
    app = AFLMonitorApp(sync_dir, refresh_interval)
    app.run()
