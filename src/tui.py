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
        sys_info = self.system_info if self.system_info else {}

        # Build two columns: main stats on left, system info on right
        left_col = []
        right_col = []

        # LEFT COLUMN - Fuzzing stats
        # Status line - use dim grey for labels, subtle colors for values
        alive_color = "#5fd75f" if s.alive_fuzzers > 0 else "#d75f5f"  # Muted green/red
        status = f"[{alive_color}]{s.alive_fuzzers}[/{alive_color}]/{s.total_fuzzers}"
        if s.dead_fuzzers > 0:
            status += f" [#af5f5f]({s.dead_fuzzers} dead)[/#af5f5f]"
        if s.starting_fuzzers > 0:
            status += f" [#d7af5f]({s.starting_fuzzers} starting)[/#d7af5f]"
        left_col.append(f"[#808080]fuzzers:[/#808080] {status}")

        # Total runtime (cumulative across all fuzzers)
        if s.total_runtime > 0:
            left_col.append(f"[#808080] runtime:[/#808080] {format_duration(s.total_runtime)}")

        # Execution stats
        left_col.append(f"[#808080]   execs:[/#808080] {format_number(s.total_execs)}")

        # Coverage - subtle yellow/orange for low coverage (moved above speed)
        cov_color = "#5fd75f" if s.max_coverage > 10 else "#d7af5f" if s.max_coverage > 5 else "#af5f5f"
        left_col.append(f"[#808080]coverage:[/#808080] [{cov_color}]{format_percent(s.max_coverage)}[/{cov_color}]")

        # Speed (moved below coverage)
        if s.alive_fuzzers > 0:
            left_col.append(f"[#808080]   speed:[/#808080] {format_speed(s.total_speed)} [dim]({format_speed(s.avg_speed_per_core)} /core)[/dim]")

        # Crashes and Hangs
        crash_color = "#d75f5f" if s.total_crashes > 0 else "#4e4e4e"
        crash_text = f"[{crash_color}]{s.total_crashes}[/{crash_color}]"
        if s.new_crashes > 0:
            crash_text += f" [#ff5f5f](+{s.new_crashes}!)[/#ff5f5f]"

        hang_color = "#d7875f" if s.total_hangs > 0 else "#4e4e4e"
        hang_text = f"[{hang_color}]{s.total_hangs}[/{hang_color}]"
        if s.new_hangs > 0:
            hang_text += f" [#ff875f](+{s.new_hangs}!)[/#ff875f]"

        left_col.append(f"[#808080] crashes:[/#808080] {crash_text}  [#808080]hangs:[/#808080] {hang_text}")

        # Corpus stats - pending paths
        left_col.append(f"[#808080]  corpus:[/#808080] {format_number(s.total_corpus)}  [#808080]pending:[/#808080] {s.total_pending} [dim]({s.total_pending_favs} favs)[/dim]")

        # Last activity (latest find across all fuzzers) - ALWAYS show
        last_find_display = format_time_ago(s.last_find_time) if s.last_find_time > 0 else "never"
        left_col.append(f"[#808080]last find:[/#808080] {last_find_display}")

        # Total pending paths - ALWAYS show
        pending_color = "#d7af5f" if s.total_pending > 1000 else "#5f8787" if s.total_pending > 0 else "#4e4e4e"
        left_col.append(f"[#808080] pending:[/#808080] [{pending_color}]{s.total_pending}[/{pending_color}] paths [dim]({s.total_pending_favs} favs)[/dim]")

        # Cycles without finds indicator - ALWAYS show
        if s.cycles_wo_finds and s.cycles_wo_finds != "N/A" and s.total_fuzzers > 0:
            cwof_display = s.cycles_wo_finds
            # Parse to determine color - look for highest value
            try:
                cwof_values = [int(x) for x in s.cycles_wo_finds.split('/') if x.isdigit()]
                max_cwof = max(cwof_values) if cwof_values else 0
                cwof_color = "#d75f5f" if max_cwof > 50 else "#d7af5f" if max_cwof > 10 else "#808080"
            except:
                cwof_color = "#808080"
            left_col.append(f"[#808080] no finds:[/#808080] [{cwof_color}]{cwof_display}[/{cwof_color}] cycles")
        else:
            left_col.append(f"[#808080] no finds:[/#808080] [dim]N/A[/dim]")

        # RIGHT COLUMN - System info (right-aligned)
        if sys_info:
            right_col.append(f"[bold #808080]System[/bold #808080]")
            # Use text labels instead of icons for better compatibility
            right_col.append(f"[#5f8787]CPU:[/#5f8787] {sys_info.get('cpu_percent', 0):.1f}%")
            right_col.append(f"[#875f87]RAM:[/#875f87] {sys_info.get('memory_used_gb', 0):.1f}/{sys_info.get('memory_total_gb', 0):.1f} GB")
            right_col.append(f"[#5f875f]DSK:[/#5f875f] {sys_info.get('disk_used_gb', 0):.0f}/{sys_info.get('disk_total_gb', 0):.0f} GB")

        # Combine columns side by side with proper alignment
        # Use Rich's Text object to properly handle markup and measure width
        from rich.text import Text as RichText
        output = []
        max_lines = max(len(left_col), len(right_col))

        for i in range(max_lines):
            left = left_col[i] if i < len(left_col) else ""
            right = right_col[i] if i < len(right_col) else ""

            if right:
                # Create Text objects to measure actual rendered width
                left_text = RichText.from_markup(left)
                right_text = RichText.from_markup(right)

                # Calculate padding needed (assume 80 char width, right column at ~55)
                left_width = len(left_text.plain)
                right_width = len(right_text.plain)
                target_right_pos = 55

                if left_width < target_right_pos:
                    padding = " " * (target_right_pos - left_width)
                    output.append(f"{left}{padding}{right}")
                else:
                    output.append(f"{left}  {right}")
            else:
                output.append(left)

        return "\n".join(output)


class FuzzersTable(DataTable):
    """Interactive table for fuzzer instances."""

    # Sort bindings removed - users can click column headers to sort
    BINDINGS = []

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
            self.add_column("Crashes", key="crashes")
        elif self.detail_level == DetailLevel.NORMAL:
            # Normal: Core metrics without clutter
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Speed", key="speed")
            self.add_column("Pending", key="pending")
            self.add_column("Crash/Hang", key="findings")
        else:  # DETAILED
            # Detailed: All available metrics
            self.add_column("Name", key="name")
            self.add_column("Status", key="status")
            self.add_column("Speed", key="speed")
            self.add_column("Pending", key="pending")
            self.add_column("Stabil", key="stability")
            self.add_column("Crash/Hang", key="findings")
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
                    Text(str(fuzzer.saved_crashes), style="#af5f5f" if fuzzer.saved_crashes > 0 else "#4e4e4e"),
                )
            elif self.detail_level == DetailLevel.NORMAL:
                self.add_row(
                    Text(fuzzer.fuzzer_name, style="#a8a8a8"),
                    status_full,
                    Text(format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-", style="#808080"),
                    Text(f"{fuzzer.pending_favs}/{fuzzer.pending_total}", style="#808080"),
                    Text(findings, style="#af5f5f" if (fuzzer.saved_crashes + fuzzer.saved_hangs) > 0 else "#4e4e4e"),
                )
            else:  # DETAILED
                self.add_row(
                    Text(fuzzer.fuzzer_name, style="#a8a8a8"),
                    status_full,
                    Text(format_speed(fuzzer.execs_per_sec) if fuzzer.is_alive else "-", style="#808080"),
                    Text(f"{fuzzer.pending_favs}/{fuzzer.pending_total}", style="#808080"),
                    Text(format_percent(fuzzer.stability, 0), style="#808080"),
                    Text(findings, style="#af5f5f" if (fuzzer.saved_crashes + fuzzer.saved_hangs) > 0 else "#4e4e4e"),
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
    """Panel for displaying campaign trend sparkline graphs."""

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
        """Render campaign trend sparkline graphs."""
        if not self.fuzzer_data or not self.monitor:
            return "[dim]Loading graphs...[/dim]"

        output = []
        output.append("\n[bold #808080]Campaign Trends[/bold #808080]\n")

        # Aggregate data from all fuzzers
        all_speeds = []
        all_coverage = []
        all_pending = []

        for fuzzer in self.fuzzer_data:
            try:
                plot_data = self.monitor.get_fuzzer_plot_data(fuzzer.directory, max_points=50)
                if plot_data:
                    # Extract values from plot data
                    speeds = [p.execs_per_sec for p in plot_data if p.execs_per_sec > 0]
                    coverage = [p.map_size for p in plot_data if p.map_size > 0]
                    pending = [p.pending_total for p in plot_data]

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

        # Show aggregate campaign trends
        if all_speeds:
            # Sample to get trend over time
            sample_size = min(len(all_speeds), 60)
            step = max(1, len(all_speeds) // sample_size)
            sampled = all_speeds[::step][:60]

            sparkline = generate_sparkline(sampled, width=60)
            output.append(
                f"  [#808080]Execution speed:[/#808080]  [#5fd75f]{sparkline}[/#5fd75f]  "
                f"[dim]avg: {sum(sampled)/len(sampled):.0f} ex/s[/dim]\n"
            )

        if all_coverage:
            sample_size = min(len(all_coverage), 60)
            step = max(1, len(all_coverage) // sample_size)
            sampled = all_coverage[::step][:60]

            sparkline = generate_sparkline(sampled, width=60)
            output.append(
                f"  [#808080]Code coverage:  [/#808080]  [#d7af5f]{sparkline}[/#d7af5f]  "
                f"[dim]avg: {sum(sampled)/len(sampled):.1f}%[/dim]\n"
            )

        if all_pending:
            sample_size = min(len(all_pending), 60)
            step = max(1, len(all_pending) // sample_size)
            sampled = all_pending[::step][:60]

            sparkline = generate_sparkline(sampled, width=60)
            avg_pending = sum(sampled) / len(sampled)
            output.append(
                f"  [#808080]Pending paths:  [/#808080]  [#af5f5f]{sparkline}[/#af5f5f]  "
                f"[dim]avg: {avg_pending:.0f}[/dim]\n"
            )

        if len(output) == 1:  # Only header
            output.append("[dim]No plot_data available. Graphs will appear after fuzzers generate data.[/dim]\n")

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
        color: #505050;
        height: 1;
    }

    SummaryPanel {
        height: 14;
        background: #0f0f0f;
        border: solid #2a2a2a;
        padding: 0 2;
        margin: 1 1 0 1;
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
        Binding("1", "detail_compact", "Compact"),
        Binding("2", "detail_normal", "Normal"),
        Binding("3", "detail_detailed", "Detailed"),
        Binding("d", "toggle_dead", "Toggle Dead"),
    ]

    TITLE = "AFL Overseer"

    detail_level = reactive(DetailLevel.NORMAL)
    paused = reactive(False)

    def __init__(self, sync_dir: Path, refresh_interval: int = 1):
        super().__init__()
        self.sync_dir = sync_dir
        self.refresh_interval = refresh_interval
        self.show_dead = False
        self.command_line = ""  # Store command line for display
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
        yield Static("Detail Level: Normal | Sort: Name", classes="detail-info", id="detail-info")
        yield FuzzersTable(detail_level=self.detail_level, id="fuzzers-table")
        yield GraphPanel(id="graphs-panel")
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

            # Update graphs panel (only visible in detailed view)
            try:
                graphs = self.query_one("#graphs-panel", GraphPanel)
                if self.detail_level == DetailLevel.DETAILED:
                    graphs.update_graphs(all_stats, self.monitor)
                    graphs.styles.display = "block"
                else:
                    graphs.styles.display = "none"
            except Exception as e:
                # Non-critical, graphs may not be visible
                pass

            # Update detail info with command line if available
            try:
                detail_info = f"Detail Level: {self.detail_level.title()} | Sort: {table.sort_key.title()} | Refresh: {self.refresh_interval}s"
                if self.paused:
                    detail_info += " | [yellow]PAUSED[/yellow]"

                # Add command line if available
                if self.command_line:
                    detail_info += f"\n[dim]cmd:[/dim] {self.command_line}"
                elif all_stats:
                    # Get command line from first fuzzer
                    cmd = all_stats[0].command_line
                    if cmd:
                        self.command_line = cmd
                        detail_info += f"\n[dim]cmd:[/dim] {cmd}"

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

    def action_refresh(self) -> None:
        """Manually refresh data."""
        self.call_later(self.refresh_data)
        self.notify("Refreshing data...")

    def action_detail_compact(self) -> None:
        """Switch to compact detail level - show ONLY summary."""
        self.detail_level = DetailLevel.COMPACT
        # Hide table, detail info, and graphs in compact mode
        self.query_one("#fuzzers-table").display = False
        self.query_one("#detail-info").display = False
        self.query_one("#graphs-panel").display = False
        self.notify("Switched to Compact view (summary only)")
        # Trigger immediate refresh
        self.call_later(self.refresh_data)

    def action_detail_normal(self) -> None:
        """Switch to normal detail level."""
        self.detail_level = DetailLevel.NORMAL
        # Show table and detail info, hide graphs
        self.query_one("#fuzzers-table").display = True
        self.query_one("#detail-info").display = True
        self.query_one("#graphs-panel").display = False
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.detail_level = self.detail_level
        table.setup_columns()
        table.update_data(table.fuzzer_data)
        self.notify("Switched to Normal view")
        # Trigger immediate refresh
        self.call_later(self.refresh_data)

    def action_detail_detailed(self) -> None:
        """Switch to detailed level."""
        self.detail_level = DetailLevel.DETAILED
        # Show everything
        self.query_one("#fuzzers-table").display = True
        self.query_one("#detail-info").display = True
        self.query_one("#graphs-panel").display = True
        table = self.query_one("#fuzzers-table", FuzzersTable)
        table.detail_level = self.detail_level
        table.setup_columns()
        table.update_data(table.fuzzer_data)
        self.notify("Switched to Detailed view")
        # Trigger immediate refresh
        self.call_later(self.refresh_data)

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


def run_interactive_tui(sync_dir: Path, refresh_interval: int = 1):
    """Run the interactive TUI."""
    app = AFLMonitorApp(sync_dir, refresh_interval)
    app.run()
