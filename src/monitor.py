"""Core monitoring logic for AFL fuzzing campaigns."""

from __future__ import annotations

import time
import json
import threading
import fcntl
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .models import FuzzerStats, CampaignSummary, MonitorConfig
from .parser import FuzzerStatsParser, PlotDataParser, discover_fuzzers
from .process import ProcessMonitor, ProcessValidator
from . import constants

logger = logging.getLogger(__name__)


class AFLMonitor:
    """Main AFL monitoring class with thread-safe state management."""

    # Class-level lock for state file access (shared across all instances)
    _state_file_lock = threading.Lock()

    def __init__(self, config: MonitorConfig):
        """Initialize monitor with configuration."""
        self.config = config
        self._previous_summary: Optional[CampaignSummary] = None
        self._summary_lock = threading.Lock()  # Instance lock for previous_summary
        self.state_file = Path.home() / constants.STATE_FILE_NAME
        self.state_lock_file = Path.home() / constants.STATE_LOCK_FILE_NAME

    def collect_stats(self) -> tuple[List[FuzzerStats], CampaignSummary]:
        """
        Collect statistics from all fuzzers using parallel processing.
        Thread-safe implementation that avoids list mutation from multiple threads.

        Returns:
            Tuple of (fuzzer_stats_list, campaign_summary)
        """
        # Discover all fuzzers
        fuzzer_dirs = discover_fuzzers(self.config.findings_dir)

        if not fuzzer_dirs:
            logger.warning(f"No fuzzers found in {self.config.findings_dir}")
            return [], CampaignSummary()

        # Parse each fuzzer in parallel for better performance
        if len(fuzzer_dirs) > 1:
            # Limit workers to avoid overwhelming the system
            max_workers = min(len(fuzzer_dirs), constants.MAX_WORKER_THREADS)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks and collect futures (no shared state mutation)
                futures = [
                    executor.submit(self._collect_fuzzer_stats, fuzzer_dir)
                    for fuzzer_dir in fuzzer_dirs
                ]

                # Collect results safely - each thread returns, main thread collects
                all_stats = []
                for future in as_completed(futures):
                    try:
                        stats = future.result()
                        if stats and (stats.is_alive or self.config.show_dead):
                            all_stats.append(stats)
                    except Exception as e:
                        logger.error(f"Error collecting stats: {e}")
        else:
            # Single fuzzer, no need for threading
            stats = self._collect_fuzzer_stats(fuzzer_dirs[0])
            all_stats = [stats] if stats and (stats.is_alive or self.config.show_dead) else []

        # Create summary
        summary = self._create_summary(all_stats)

        return all_stats, summary

    def _collect_fuzzer_stats(self, fuzzer_dir: Path) -> Optional[FuzzerStats]:
        """Collect stats for a single fuzzer."""
        try:
            fuzzer_name = fuzzer_dir.name
            stats_file = fuzzer_dir / "fuzzer_stats"

            # Parse stats file
            stats = FuzzerStatsParser.parse_file(stats_file, fuzzer_name)
            if not stats:
                return None

            # Check process status and get resource usage
            status, cpu, mem = ProcessMonitor.check_process_status(
                stats.fuzzer_pid, fuzzer_dir
            )
            stats.status = status
            stats.cpu_usage = cpu
            stats.memory_usage = mem

            return stats

        except Exception as e:
            logger.error(f"Error collecting stats for {fuzzer_dir}: {e}")
            return None

    def _create_summary(self, all_stats: List[FuzzerStats]) -> CampaignSummary:
        """Create campaign summary from all fuzzer stats."""
        summary = CampaignSummary()

        if not all_stats:
            return summary

        # Count statuses
        summary.total_fuzzers = len(all_stats)
        summary.alive_fuzzers = sum(1 for s in all_stats if s.status.value == "alive")
        summary.dead_fuzzers = sum(1 for s in all_stats if s.status.value == "dead")
        summary.starting_fuzzers = sum(1 for s in all_stats if s.status.value == "starting")

        # Aggregate execution stats
        summary.total_execs = sum(s.execs_done for s in all_stats)
        summary.total_speed = sum(s.execs_per_sec for s in all_stats if s.is_alive)
        summary.current_avg_speed = sum(s.execs_ps_last_min for s in all_stats if s.is_alive)

        if summary.alive_fuzzers > 0:
            summary.avg_speed_per_core = summary.total_speed / summary.alive_fuzzers

        # Aggregate corpus stats
        summary.total_corpus = sum(s.corpus_count for s in all_stats)
        summary.total_pending = sum(s.pending_total for s in all_stats)
        summary.total_pending_favs = sum(s.pending_favs for s in all_stats)

        # Coverage stats
        summary.max_coverage = max((s.bitmap_cvg for s in all_stats), default=0.0)

        stabilities = [s.stability for s in all_stats if s.stability > 0]
        if stabilities:
            summary.avg_stability = sum(stabilities) / len(stabilities)
            summary.min_stability = min(stabilities)
            summary.max_stability = max(stabilities)

        # Findings
        summary.total_crashes = sum(s.saved_crashes for s in all_stats)
        summary.total_hangs = sum(s.saved_hangs for s in all_stats)

        # Calculate new crashes/hangs (thread-safe access)
        with self._summary_lock:
            if self._previous_summary:
                summary.new_crashes = summary.total_crashes - self._previous_summary.total_crashes
                summary.new_hangs = summary.total_hangs - self._previous_summary.total_hangs

        # Timing
        summary.total_runtime = sum(s.run_time for s in all_stats)
        summary.last_find_time = max((s.last_find for s in all_stats), default=0)
        summary.last_crash_time = max((s.last_crash for s in all_stats), default=0)
        summary.last_hang_time = max((s.last_hang for s in all_stats), default=0)

        # Cycles
        cycles = [s.cycles_done for s in all_stats if s.cycles_done > 0]
        if cycles:
            summary.max_cycle = max(cycles)
            summary.avg_cycle = sum(cycles) / len(cycles)

        # Cycles without finds
        cwof_values = [str(s.cycles_wo_finds) for s in all_stats if s.cycles_wo_finds >= 0]
        summary.cycles_wo_finds = "/".join(cwof_values) if cwof_values else "N/A"

        # Advanced stats
        summary.total_edges_found = sum(s.edges_found for s in all_stats)
        summary.max_total_edges = max((s.total_edges for s in all_stats), default=0)

        # System resources
        summary.total_cpu_usage = sum(s.cpu_usage for s in all_stats if s.cpu_usage >= 0)
        summary.total_memory_usage = sum(s.memory_usage for s in all_stats if s.memory_usage >= 0)

        return summary

    def load_previous_state(self):
        """
        Load previous campaign state from file with file-based locking.
        Thread-safe across all AFLMonitor instances.
        """
        try:
            # Use class-level lock for file access across all instances
            with self._state_file_lock:
                if not self.state_file.exists():
                    return

                # Read state file with shared lock
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    try:
                        # Try to acquire shared lock (multiple readers OK)
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                        try:
                            data = json.load(f)
                            new_summary = CampaignSummary(**data.get('summary', {}))

                            # Atomic update to instance variable
                            with self._summary_lock:
                                self._previous_summary = new_summary
                            logger.debug("Loaded previous state")
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except BlockingIOError:
                        logger.debug("State file locked by another process, skipping load")
        except Exception as e:
            logger.debug(f"Could not load previous state: {e}")
            with self._summary_lock:
                self._previous_summary = None

    def save_current_state(self, summary: CampaignSummary):
        """
        Save current campaign state to file with atomic write and file locking.
        Thread-safe across all AFLMonitor instances.
        """
        try:
            data = {
                'timestamp': int(time.time()),
                'summary': summary.to_dict(),
            }

            # Use class-level lock for file access across all instances
            with self._state_file_lock:
                # Write to temporary file first (safer)
                temp_file = self.state_file.with_suffix('.tmp')

                try:
                    # Write to temp file with exclusive lock
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        try:
                            # Acquire exclusive lock (no readers/writers allowed)
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            try:
                                json.dump(data, f, indent=2)
                                f.flush()
                                # Atomic rename (POSIX guarantee)
                                temp_file.replace(self.state_file)
                                logger.debug("Saved current state")
                            finally:
                                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                        except BlockingIOError:
                            logger.debug("State file locked by another process, skipping save")
                            if temp_file.exists():
                                temp_file.unlink()
                except Exception as e:
                    logger.error(f"Could not save state: {e}")
                    # Clean up temp file on error
                    if temp_file.exists():
                        try:
                            temp_file.unlink()
                        except:
                            pass
        except Exception as e:
            logger.error(f"Could not save state: {e}")

    def get_fuzzer_plot_data(self, fuzzer_dir: Path, max_points: int = 1000):
        """Get plot data for a specific fuzzer."""
        plot_file = fuzzer_dir / "plot_data"
        return PlotDataParser.parse_file(plot_file, max_points)

    def get_fuzzer_warnings(self, stats: FuzzerStats) -> List[str]:
        """Get all warnings for a fuzzer."""
        return ProcessValidator.get_all_warnings(stats)


class DeltaTracker:
    """Track changes between monitoring intervals."""

    def __init__(self):
        self.previous: Dict[str, any] = {}

    def calculate_delta(self, key: str, current_value: float) -> float:
        """Calculate delta from previous value."""
        if key not in self.previous:
            self.previous[key] = current_value
            return 0.0

        delta = current_value - self.previous[key]
        self.previous[key] = current_value
        return delta

    def format_delta(self, delta: float, use_color: bool = True) -> str:
        """Format delta as string with optional color."""
        if abs(delta) < 0.01:
            return ""

        sign = "+" if delta > 0 else ""
        value = f"{sign}{delta:,.2f}"

        if not use_color:
            return f" ({value})"

        from .utils import ColorFormatter
        if delta > 0:
            color = ColorFormatter.GREEN
        elif delta < 0:
            color = ColorFormatter.RED
        else:
            return ""

        return f" {ColorFormatter.colorize(f'({value})', color)}"
