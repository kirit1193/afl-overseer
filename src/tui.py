"""Interactive TUI (Text User Interface) for AFL Overseer using Textual."""

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
    format_speed, format_percent, generate_sparkline
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

        # Status line - use dim grey for labels, subtle colors for values
        alive_color = "#5fd75f" if s.alive_fuzzers > 0 else "#d75f5f"  # Muted green/red
        status = f"[{alive_color}]{s.alive_fuzzers}[/{alive_color}]/{s.total_fuzzers}"
        if s.dead_fuzzers > 0:
            status += f" [#af5f5f]({s.dead_fuzzers} dead)[/#af5f5f]"
        if s.starting_fuzzers > 0:
            status += f" [#d7af5f]({s.starting_fuzzers} starting)[/#d7af5f]"
        output.append(f"[#808080]fuzzers:[/#808080] {status}")

        # Total runtime (cumulative across all fuzzers)
        if s.total_runtime > 0:
            output.append(f"[#808080] runtime:[/#808080] {format_duration(s.total_runtime)}")

        # Execution stats
        output.append(f"[#808080]   execs:[/#808080] {format_number(s.total_execs)}")
        if s.alive_fuzzers > 0:
            output.append(f"[#808080]   speed:[/#808080] {format_speed(s.total_speed)} [dim]({format_speed(s.avg_speed_per_core)}/core)[/dim]")

        # Coverage - subtle yellow/orange for low coverage
        cov_color = "#5fd75f" if s.max_coverage > 10 else "#d7af5f" if s.max_coverage > 5 else "#af5f5f"
        output.append(f"[#808080]coverage:[/#808080] [{cov_color}]{format_percent(s.max_coverage)}[/{cov_color}]")

        # Crashes and Hangs
        crash_color = "#d75f5f" if s.total_crashes > 0 else "#4e4e4e"
        crash_text = f"[{crash_color}]{s.total_crashes}[/{crash_color}]"
        if s.new_crashes > 0:
            crash_text += f" [#ff5f5f](+{s.new_crashes}!)[/#ff5f5f]"

        hang_color = "#d7875f" if s.total_hangs > 0 else "#4e4e4e"
        hang_text = f"[{hang_color}]{s.total_hangs}[/{hang_color}]"
        if s.new_hangs > 0:
            hang_text += f" [#ff875f](+{s.new_hangs}!)[/#ff875f]"

        output.append(f"[#808080] crashes:[/#808080] {crash_text}  [#808080]hangs:[/#808080] {hang_text}")

        # Corpus stats - pending paths
        output.append(f"[#808080]  corpus:[/#808080] {format_number(s.total_corpus)}  [#808080]pending:[/#808080] {s.total_pending} [dim]({s.total_pending_favs} favs)[/dim]")

        # Last activity
        output.append(f"[#808080]   finds:[/#808080] {format_time_ago(s.last_find_time)}")

        # Cycles without finds indicator
        if s.cycles_wo_finds and s.cycles_wo_finds != "N/A":
            cwof_display = s.cycles_wo_finds
            # Parse to determine color - look for highest value
            try:
                cwof_values = [int(x) for x in s.cycles_wo_finds.split('/') if x.isdigit()]
                max_cwof = max(cwof_values) if cwof_values else 0
                cwof_color = "#d75f5f" if max_cwof > 50 else "#d7af5f" if max_cwof > 10 else "#808080"
            except:
                cwof_color = "#808080"
            output.append(f"[#808080] no finds:[/#808080] [{cwof_color}]{cwof_display}[/{cwof_color}] cycles")

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
            # Compact: Essential info only
            self.add_column("Name", key="name")
            self.add_column("St", key="status")  # Abbreviated
            self.add_column("Speed", key="speed")
            self.add_column("Cov%", key="coverage")
            self.add_column("Crashes", key="crashes")
        elif self.detail_level == DetailLevel.NORMAL:
            # Normal: Core metrics without clutter
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Execs", key="execs")
            self.add_column("Speed", key="speed")
            self.add_column("Corpus", key="corpus")
            self.add_column("Pending", key="pending")
            self.add_column("Coverage", key="coverage")
            self.add_column("Last Find", key="last_find")
            self.add_column("Cycles w/o", key="cycles_wo")
            self.add_column("Crash/Hang", key="findings")
        else:  # DETAILED
            # Detailed: All available metrics
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Execs", key="execs")
            self.add_column("Speed", key="speed")
            self.add_column("Corpus", key="corpus")
            self.add_column("Pending", key="pending")
            self.add_column("Coverage", key="coverage")
            self.add_column("Last Find", key="last_find")
            self.add_column("Cycles w/o", key="cycles_wo")
            self.add_column("Stabil", key="stability")
            self.add_column("Cycle", key="cycle")
            self.add_column("Crash/Hang", key="findings")
            self.add_column("CPU%", key="cpu")
            self.add_column("Tmout", key="timeout")

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
        """Populate table with sorted data using muted AFL-style colors."""
        self.clear()

        for fuzzer in self.fuzzer_data:
            # Status with muted colors - just colored dot, no bold text
            if fuzzer.status.value == "alive":
                status_compact = Text("▪", style="#5fd75f")  # Muted green dot
                status_full = Text("▪", style="#5fd75f") + Text(" alive", style="#808080")
            elif fuzzer.status.value == "dead":
                status_compact = Text("▪", style="#d75f5f")  # Muted red dot
                status_full = Text("▪", style="#d75f5f") + Text(" dead", style="#808080")
            elif fuzzer.status.value == "starting":
                status_compact = Text("▪", style="#d7af5f")  # Muted yellow dot
                status_full = Text("▪", style="#d7af5f") + Text(" start", style="#808080")
            else:
                status_compact = Text("▪", style="#4e4e4e")  # Dark grey dot
                status_full = Text("▪", style="#4e4e4e") + Text(" unkn", style="#4e4e4e")

            # Format findings (crashes/hangs) for compact display
            findings = f"{fuzzer.saved_crashes}/{fuzzer.saved_hangs}"

            if self.detail_level == DetailLevel.COMPACT:
                self.add_row(
                    Text(fuzzer.fuzzer_name, style="#a8a8a8"),
                    status_compact,
                    Text(format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-", style="#808080"),
                    Text(format_percent(fuzzer.bitmap_cvg, 1), style="#808080"),
                    Text(str(fuzzer.saved_crashes), style="#af5f5f" if fuzzer.saved_crashes > 0 else "#4e4e4e"),
                )
            elif self.detail_level == DetailLevel.NORMAL:
                # Format last find time
                last_find_str = format_time_ago(fuzzer.last_find) if fuzzer.last_find > 0 else "never"

                # Format cycles without finds with color
                cwof = fuzzer.cycles_wo_finds
                cwof_color = "#d75f5f" if cwof > 50 else "#d7af5f" if cwof > 10 else "#808080"
                cwof_text = Text(str(cwof) if cwof >= 0 else "-", style=cwof_color)

                self.add_row(
                    Text(fuzzer.fuzzer_name, style="#a8a8a8"),
                    status_full,
                    Text(format_number(fuzzer.execs_done), style="#808080"),
                    Text(format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-", style="#808080"),
                    Text(f"{fuzzer.cur_item}/{fuzzer.corpus_count}", style="#808080"),
                    Text(f"{fuzzer.pending_favs}/{fuzzer.pending_total}", style="#808080"),
                    Text(format_percent(fuzzer.bitmap_cvg, 1), style="#808080"),
                    Text(last_find_str, style="#808080"),
                    cwof_text,
                    Text(findings, style="#af5f5f" if (fuzzer.saved_crashes + fuzzer.saved_hangs) > 0 else "#4e4e4e"),
                )
            else:  # DETAILED
                # Format last find time
                last_find_str = format_time_ago(fuzzer.last_find) if fuzzer.last_find > 0 else "never"

                # Format cycles without finds with color
                cwof = fuzzer.cycles_wo_finds
                cwof_color = "#d75f5f" if cwof > 50 else "#d7af5f" if cwof > 10 else "#808080"
                cwof_text = Text(str(cwof) if cwof >= 0 else "-", style=cwof_color)

                self.add_row(
                    Text(fuzzer.fuzzer_name, style="#a8a8a8"),
                    status_full,
                    Text(format_number(fuzzer.execs_done), style="#808080"),
                    Text(format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-", style="#808080"),
                    Text(f"{fuzzer.cur_item}/{fuzzer.corpus_count}", style="#808080"),
                    Text(f"{fuzzer.pending_favs}/{fuzzer.pending_total}", style="#808080"),
                    Text(format_percent(fuzzer.bitmap_cvg, 1), style="#808080"),
                    Text(last_find_str, style="#808080"),
                    cwof_text,
                    Text(format_percent(fuzzer.stability, 0), style="#808080"),
                    Text(str(fuzzer.cycles_done), style="#808080"),
                    Text(findings, style="#af5f5f" if (fuzzer.saved_crashes + fuzzer.saved_hangs) > 0 else "#4e4e4e"),
                    Text(f"{fuzzer.cpu_usage:.1f}" if fuzzer.cpu_usage >= 0 else "-", style="#808080"),
                    Text(str(fuzzer.total_tmout), style="#d7875f" if fuzzer.total_tmout > 100 else "#808080"),
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


class GraphPanel(Static):
    """Panel for displaying sparkline graphs from plot data."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fuzzer_data = []
        self.monitor = None

    def update_graphs(self, fuzzers, monitor):
        """Update graphs with fuzzer data."""
        self.fuzzer_data = fuzzers
        self.monitor = monitor
        self.refresh()

    def render(self) -> str:
        """Render sparkline graphs."""
        if not self.fuzzer_data or not self.monitor:
            return "[dim]Loading graphs...[/dim]"

        output = []
        output.append("[bold #808080]Historical Trends (from plot_data)[/bold #808080]\n")

        # Aggregate data from all fuzzers
        all_speeds = []
        all_coverage = []
        all_pending = []

        for fuzzer in self.fuzzer_data[:3]:  # Limit to first 3 fuzzers to avoid clutter
            try:
                plot_data = self.monitor.get_fuzzer_plot_data(fuzzer.directory, max_points=50)
                if plot_data:
                    # Extract values from plot data
                    speeds = [p.execs_per_sec for p in plot_data if p.execs_per_sec > 0]
                    coverage = [p.map_size for p in plot_data if p.map_size > 0]
                    pending = [p.pending_total for p in plot_data]

                    if speeds:
                        sparkline = generate_sparkline(speeds, width=50)
                        min_speed = min(speeds)
                        max_speed = max(speeds)
                        latest_speed = speeds[-1]
                        output.append(
                            f"[#808080]{fuzzer.fuzzer_name[:12]:<12} speed:[/#808080] "
                            f"[#5fd75f]{sparkline}[/#5fd75f]  "
                            f"[dim][{min_speed:.0f}..{max_speed:.0f}] now: {latest_speed:.0f} ex/s[/dim]"
                        )

                    if coverage:
                        sparkline = generate_sparkline(coverage, width=50)
                        min_cov = min(coverage)
                        max_cov = max(coverage)
                        latest_cov = coverage[-1]
                        output.append(
                            f"[#808080]{fuzzer.fuzzer_name[:12]:<12} coverage:[/#808080] "
                            f"[#d7af5f]{sparkline}[/#d7af5f]  "
                            f"[dim][{min_cov:.1f}%..{max_cov:.1f}%] now: {latest_cov:.1f}%[/dim]"
                        )

                    if pending:
                        sparkline = generate_sparkline(pending, width=50)
                        min_pend = min(pending)
                        max_pend = max(pending)
                        latest_pend = pending[-1]
                        output.append(
                            f"[#808080]{fuzzer.fuzzer_name[:12]:<12} pending:[/#808080] "
                            f"[#af5f5f]{sparkline}[/#af5f5f]  "
                            f"[dim][{min_pend}..{max_pend}] now: {latest_pend}[/dim]\n"
                        )

                    # Collect for aggregate
                    if speeds:
                        all_speeds.extend(speeds)
                    if coverage:
                        all_coverage.extend(coverage)
                    if pending:
                        all_pending.extend(pending)

            except Exception as e:
                # Skip fuzzers with no plot data
                continue

        # Show aggregate trends if we have data from multiple fuzzers
        if len(self.fuzzer_data) > 1 and all_speeds:
            output.append("[bold #808080]Campaign Trends:[/bold #808080]")

            if all_speeds:
                # Sample to get trend over time
                sample_size = min(len(all_speeds), 50)
                step = max(1, len(all_speeds) // sample_size)
                sampled = all_speeds[::step][:50]

                sparkline = generate_sparkline(sampled, width=50)
                output.append(
                    f"[#808080]Overall speed:[/#808080] [#5fd75f]{sparkline}[/#5fd75f]  "
                    f"[dim]avg: {sum(sampled)/len(sampled):.0f} ex/s[/dim]"
                )

            if all_coverage:
                sample_size = min(len(all_coverage), 50)
                step = max(1, len(all_coverage) // sample_size)
                sampled = all_coverage[::step][:50]

                sparkline = generate_sparkline(sampled, width=50)
                output.append(
                    f"[#808080]Overall coverage:[/#808080] [#d7af5f]{sparkline}[/#d7af5f]  "
                    f"[dim]avg: {sum(sampled)/len(sampled):.1f}%[/dim]"
                )

        if len(output) == 1:  # Only header
            output.append("[dim]No plot_data available. Graphs will appear after fuzzers run for a while.[/dim]")

        return "\n".join(output)


class AFLMonitorApp(App):
    """AFL Overseer Interactive TUI Application."""

    CSS = """
    Screen {
        background: #0a0a0a;
    }

    Header {
        background: #1a1a1a;
        color: #808080;
    }

    Footer {
        background: #121212;
        color: #606060;
    }

    SummaryPanel {
        height: 10;
        background: #0f0f0f;
        border: solid #2a2a2a;
        padding: 1 2;
        margin: 1;
    }

    FuzzersTable {
        height: 1fr;
        margin: 0 1;
        background: #0a0a0a;
    }

    DataTable {
        background: #0a0a0a;
        color: #808080;
    }

    DataTable > .datatable--header {
        background: #1a1a1a;
        color: #606060;
    }

    DataTable > .datatable--cursor {
        background: #1f1f1f;
    }

    #tabs {
        height: 1fr;
        background: #0a0a0a;
    }

    .detail-info {
        padding: 1 2;
        background: #0f0f0f;
        color: #606060;
        margin: 0 1 1 1;
    }

    GraphPanel {
        height: auto;
        background: #0f0f0f;
        border: solid #2a2a2a;
        padding: 1 2;
        margin: 0 1 1 1;
        color: #808080;
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

    TITLE = "AFL Overseer - Interactive Dashboard"

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
        try:
            self.monitor.load_previous_state()
        except Exception:
            # State loading failure is non-critical
            pass

    def compose(self) -> ComposeResult:
        """Compose the UI."""
        yield Header()
        yield SummaryPanel(id="summary")

        with TabbedContent(id="tabs"):
            with TabPane("Fuzzers", id="fuzzers-tab"):
                yield Static("Detail Level: Normal | Sort: Name", classes="detail-info", id="detail-info")
                yield FuzzersTable(detail_level=self.detail_level, id="fuzzers-table")

            with TabPane("Graphs", id="graphs-tab"):
                yield GraphPanel(id="graphs-panel")

            with TabPane("System", id="system-tab"):
                yield Static("System information", id="system-info")

        yield Footer()

    def on_mount(self) -> None:
        """Set up the app when mounted."""
        self.set_interval(self.refresh_interval, self.refresh_data)
        self.call_later(self.refresh_data)

    async def refresh_data(self) -> None:
        """Refresh fuzzer data with error handling."""
        if self.paused:
            return

        try:
            # Collect stats
            all_stats, summary = self.monitor.collect_stats()
            system_info = ProcessMonitor.get_system_info()

            # Update summary panel
            try:
                summary_panel = self.query_one("#summary", SummaryPanel)
                summary_panel.update_summary(summary, system_info)
            except Exception as e:
                self.notify(f"Failed to update summary: {e}", severity="error")

            # Update fuzzers table
            try:
                table = self.query_one("#fuzzers-table", FuzzersTable)
                table.update_data(all_stats)
            except Exception as e:
                self.notify(f"Failed to update table: {e}", severity="error")

            # Update graphs panel
            try:
                graphs = self.query_one("#graphs-panel", GraphPanel)
                graphs.update_graphs(all_stats, self.monitor)
            except Exception as e:
                # Non-critical, graphs may not be visible
                pass

            # Update system info
            try:
                system_text = self._format_system_info(system_info)
                self.query_one("#system-info", Static).update(system_text)
            except Exception as e:
                self.notify(f"Failed to update system info: {e}", severity="warning")

            # Update detail info
            try:
                detail_info = f"Detail Level: {self.detail_level.title()} | Sort: {table.sort_key.title()} | Refresh: {self.refresh_interval}s"
                if self.paused:
                    detail_info += " | [yellow]PAUSED[/yellow]"
                self.query_one("#detail-info", Static).update(detail_info)
            except Exception as e:
                pass  # Non-critical

            # Save state
            try:
                self.monitor.save_current_state(summary)
            except Exception as e:
                # State saving is non-critical, just log it
                pass

        except Exception as e:
            self.notify(f"Error refreshing data: {e}", severity="error")

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
