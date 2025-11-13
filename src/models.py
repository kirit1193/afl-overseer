"""Data models for AFL fuzzer statistics."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from enum import Enum


class FuzzerStatus(Enum):
    """Fuzzer instance status."""
    ALIVE = "alive"
    DEAD = "dead"
    STARTING = "starting"
    UNKNOWN = "unknown"


@dataclass
class FuzzerStats:
    """Complete fuzzer statistics from fuzzer_stats file."""

    # Instance info
    directory: Path
    fuzzer_name: str
    afl_banner: str = ""
    afl_version: str = ""
    target_mode: str = ""
    command_line: str = ""

    # Process info
    fuzzer_pid: int = 0
    status: FuzzerStatus = FuzzerStatus.UNKNOWN
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    cpu_affinity: int = -1

    # Timing
    start_time: int = 0
    last_update: int = 0
    run_time: int = 0
    time_wo_finds: int = 0
    fuzz_time: int = 0
    calibration_time: int = 0
    cmplog_time: int = 0
    sync_time: int = 0
    trim_time: int = 0

    # Execution stats
    execs_done: int = 0
    execs_per_sec: float = 0.0
    execs_ps_last_min: float = 0.0
    exec_timeout: int = 0
    total_tmout: int = 0
    slowest_exec_ms: int = 0
    execs_since_crash: int = 0

    # Corpus stats
    corpus_count: int = 0
    corpus_favored: int = 0
    corpus_found: int = 0
    corpus_imported: int = 0
    corpus_variable: int = 0
    cur_item: int = 0
    pending_favs: int = 0
    pending_total: int = 0
    max_depth: int = 0

    # Coverage stats
    bitmap_cvg: float = 0.0
    stability: float = 0.0
    edges_found: int = 0
    total_edges: int = 0

    # Crashes and hangs
    saved_crashes: int = 0
    saved_hangs: int = 0
    last_find: int = 0
    last_crash: int = 0
    last_hang: int = 0

    # Cycles
    cycles_done: int = 0
    cycles_wo_finds: int = 0

    # Advanced features
    var_byte_count: int = 0
    havoc_expansion: int = 0
    auto_dict_entries: int = 0
    testcache_size: int = 0
    testcache_count: int = 0
    testcache_evict: int = 0
    peak_rss_mb: int = 0

    def __post_init__(self):
        """Validate and normalize data."""
        if isinstance(self.directory, str):
            self.directory = Path(self.directory)
        if isinstance(self.status, str):
            self.status = FuzzerStatus(self.status)

    @property
    def is_alive(self) -> bool:
        """Check if fuzzer is alive."""
        return self.status == FuzzerStatus.ALIVE

    @property
    def coverage_percent(self) -> float:
        """Get coverage as percentage (0-100)."""
        return self.bitmap_cvg

    @property
    def corpus_progress(self) -> float:
        """Get corpus progress percentage."""
        if self.corpus_count == 0:
            return 0.0
        return (self.cur_item / self.corpus_count) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'directory': str(self.directory),
            'fuzzer_name': self.fuzzer_name,
            'status': self.status.value,
            'afl_banner': self.afl_banner,
            'afl_version': self.afl_version,
            'target_mode': self.target_mode,
            'command_line': self.command_line,
            'fuzzer_pid': self.fuzzer_pid,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'cpu_affinity': self.cpu_affinity,
            'start_time': self.start_time,
            'last_update': self.last_update,
            'run_time': self.run_time,
            'time_wo_finds': self.time_wo_finds,
            'fuzz_time': self.fuzz_time,
            'calibration_time': self.calibration_time,
            'cmplog_time': self.cmplog_time,
            'sync_time': self.sync_time,
            'trim_time': self.trim_time,
            'execs_done': self.execs_done,
            'execs_per_sec': self.execs_per_sec,
            'execs_ps_last_min': self.execs_ps_last_min,
            'exec_timeout': self.exec_timeout,
            'total_tmout': self.total_tmout,
            'slowest_exec_ms': self.slowest_exec_ms,
            'execs_since_crash': self.execs_since_crash,
            'corpus_count': self.corpus_count,
            'corpus_favored': self.corpus_favored,
            'corpus_found': self.corpus_found,
            'corpus_imported': self.corpus_imported,
            'corpus_variable': self.corpus_variable,
            'cur_item': self.cur_item,
            'pending_favs': self.pending_favs,
            'pending_total': self.pending_total,
            'max_depth': self.max_depth,
            'bitmap_cvg': self.bitmap_cvg,
            'stability': self.stability,
            'edges_found': self.edges_found,
            'total_edges': self.total_edges,
            'saved_crashes': self.saved_crashes,
            'saved_hangs': self.saved_hangs,
            'last_find': self.last_find,
            'last_crash': self.last_crash,
            'last_hang': self.last_hang,
            'cycles_done': self.cycles_done,
            'cycles_wo_finds': self.cycles_wo_finds,
            'var_byte_count': self.var_byte_count,
            'havoc_expansion': self.havoc_expansion,
            'auto_dict_entries': self.auto_dict_entries,
            'testcache_size': self.testcache_size,
            'testcache_count': self.testcache_count,
            'testcache_evict': self.testcache_evict,
            'peak_rss_mb': self.peak_rss_mb,
        }


@dataclass
class PlotDataPoint:
    """Single data point from plot_data file."""
    relative_time: int
    cycles_done: int
    cur_item: int
    corpus_count: int
    pending_total: int
    pending_favs: int
    map_size: float
    saved_crashes: int
    saved_hangs: int
    max_depth: int
    execs_per_sec: float
    total_execs: int
    edges_found: int
    total_crashes: int
    servers_count: int


@dataclass
class CampaignSummary:
    """Summary statistics for entire fuzzing campaign."""

    # Counts
    total_fuzzers: int = 0
    alive_fuzzers: int = 0
    dead_fuzzers: int = 0
    starting_fuzzers: int = 0

    # Aggregated stats
    total_execs: int = 0
    total_speed: float = 0.0
    avg_speed_per_core: float = 0.0
    current_avg_speed: float = 0.0

    # Corpus
    total_corpus: int = 0
    total_pending: int = 0
    total_pending_favs: int = 0

    # Coverage
    max_coverage: float = 0.0
    avg_stability: float = 0.0
    min_stability: float = 100.0
    max_stability: float = 0.0

    # Findings
    total_crashes: int = 0
    total_hangs: int = 0
    new_crashes: int = 0
    new_hangs: int = 0

    # Timing
    total_runtime: int = 0
    last_find_time: int = 0
    last_crash_time: int = 0
    last_hang_time: int = 0

    # Cycles
    max_cycle: int = 0
    avg_cycle: float = 0.0
    cycles_wo_finds: str = "N/A"

    # Advanced
    total_edges_found: int = 0
    max_total_edges: int = 0

    # System resources
    total_cpu_usage: float = 0.0
    total_memory_usage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'total_fuzzers': self.total_fuzzers,
            'alive_fuzzers': self.alive_fuzzers,
            'dead_fuzzers': self.dead_fuzzers,
            'starting_fuzzers': self.starting_fuzzers,
            'total_execs': self.total_execs,
            'total_speed': self.total_speed,
            'avg_speed_per_core': self.avg_speed_per_core,
            'current_avg_speed': self.current_avg_speed,
            'total_corpus': self.total_corpus,
            'total_pending': self.total_pending,
            'total_pending_favs': self.total_pending_favs,
            'max_coverage': self.max_coverage,
            'avg_stability': self.avg_stability,
            'min_stability': self.min_stability,
            'max_stability': self.max_stability,
            'total_crashes': self.total_crashes,
            'total_hangs': self.total_hangs,
            'new_crashes': self.new_crashes,
            'new_hangs': self.new_hangs,
            'total_runtime': self.total_runtime,
            'last_find_time': self.last_find_time,
            'last_crash_time': self.last_crash_time,
            'last_hang_time': self.last_hang_time,
            'max_cycle': self.max_cycle,
            'avg_cycle': self.avg_cycle,
            'cycles_wo_finds': self.cycles_wo_finds,
            'total_edges_found': self.total_edges_found,
            'max_total_edges': self.max_total_edges,
            'total_cpu_usage': self.total_cpu_usage,
            'total_memory_usage': self.total_memory_usage,
        }


@dataclass
class MonitorConfig:
    """Configuration for monitor."""
    findings_dir: Path
    output_format: List[str] = field(default_factory=lambda: ['terminal'])
    html_dir: Optional[Path] = None
    json_file: Optional[Path] = None
    verbose: bool = False
    no_color: bool = False
    watch_mode: bool = False
    watch_interval: int = 5
    execute_command: Optional[str] = None
    notification_enabled: bool = False
    show_dead: bool = False
    minimal: bool = False

    def __post_init__(self):
        """Validate configuration."""
        if isinstance(self.findings_dir, str):
            self.findings_dir = Path(self.findings_dir)
        if self.html_dir and isinstance(self.html_dir, str):
            self.html_dir = Path(self.html_dir)
        if self.json_file and isinstance(self.json_file, str):
            self.json_file = Path(self.json_file)
