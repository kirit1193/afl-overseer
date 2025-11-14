"""Parsers for AFL fuzzer statistics and plot data."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Dict, Optional

from .models import FuzzerStats, PlotDataPoint

logger = logging.getLogger(__name__)


class FuzzerStatsParser:
    """Parser for fuzzer_stats files."""

    @staticmethod
    def parse_file(stats_file: Path, fuzzer_name: str) -> Optional[FuzzerStats]:
        """Parse a fuzzer_stats file into FuzzerStats object."""
        try:
            if not stats_file.exists():
                logger.warning(f"Stats file not found: {stats_file}")
                return None

            data = {}
            with open(stats_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue

                    key, _, value = line.partition(':')
                    key = key.strip()
                    value = value.strip()

                    if key and value:
                        data[key] = value

            return FuzzerStatsParser._create_stats_object(
                data, stats_file.parent, fuzzer_name
            )

        except Exception as e:
            logger.error(f"Error parsing {stats_file}: {e}")
            return None

    @staticmethod
    def _create_stats_object(
        data: Dict[str, str], directory: Path, fuzzer_name: str
    ) -> FuzzerStats:
        """Create FuzzerStats object from parsed data."""

        def get_int(key: str, default: int = 0) -> int:
            """Safely get integer value."""
            try:
                return int(data.get(key, default))
            except (ValueError, TypeError):
                return default

        def get_float(key: str, default: float = 0.0) -> float:
            """Safely get float value."""
            try:
                value = data.get(key, default)
                # Handle percentages
                if isinstance(value, str) and '%' in value:
                    value = value.rstrip('%')
                return float(value)
            except (ValueError, TypeError):
                return default

        def get_str(key: str, default: str = "") -> str:
            """Safely get string value."""
            return data.get(key, default)

        stats = FuzzerStats(
            directory=directory,
            fuzzer_name=fuzzer_name,
            afl_banner=get_str('afl_banner'),
            afl_version=get_str('afl_version'),
            target_mode=get_str('target_mode'),
            command_line=get_str('command_line'),
            fuzzer_pid=get_int('fuzzer_pid'),
            cpu_affinity=get_int('cpu_affinity', -1),
            start_time=get_int('start_time'),
            last_update=get_int('last_update'),
            run_time=get_int('run_time'),
            time_wo_finds=get_int('time_wo_finds'),
            fuzz_time=get_int('fuzz_time'),
            calibration_time=get_int('calibration_time'),
            cmplog_time=get_int('cmplog_time'),
            sync_time=get_int('sync_time'),
            trim_time=get_int('trim_time'),
            execs_done=get_int('execs_done'),
            execs_per_sec=get_float('execs_per_sec'),
            execs_ps_last_min=get_float('execs_ps_last_min'),
            exec_timeout=get_int('exec_timeout'),
            total_tmout=get_int('total_tmout'),
            slowest_exec_ms=get_int('slowest_exec_ms'),
            execs_since_crash=get_int('execs_since_crash'),
            corpus_count=get_int('corpus_count'),
            corpus_favored=get_int('corpus_favored'),
            corpus_found=get_int('corpus_found'),
            corpus_imported=get_int('corpus_imported'),
            corpus_variable=get_int('corpus_variable'),
            cur_item=get_int('cur_item'),
            pending_favs=get_int('pending_favs'),
            pending_total=get_int('pending_total'),
            max_depth=get_int('max_depth'),
            bitmap_cvg=get_float('bitmap_cvg'),
            stability=get_float('stability'),
            edges_found=get_int('edges_found'),
            total_edges=get_int('total_edges'),
            saved_crashes=get_int('saved_crashes'),
            saved_hangs=get_int('saved_hangs'),
            last_find=get_int('last_find'),
            last_crash=get_int('last_crash'),
            last_hang=get_int('last_hang'),
            cycles_done=get_int('cycles_done'),
            cycles_wo_finds=get_int('cycles_wo_finds'),
            var_byte_count=get_int('var_byte_count'),
            havoc_expansion=get_int('havoc_expansion'),
            auto_dict_entries=get_int('auto_dict_entries'),
            testcache_size=get_int('testcache_size'),
            testcache_count=get_int('testcache_count'),
            testcache_evict=get_int('testcache_evict'),
            peak_rss_mb=get_int('peak_rss_mb'),
        )

        return stats


class PlotDataParser:
    """Parser for plot_data files."""

    @staticmethod
    def parse_file(plot_file: Path, max_points: int = 1000) -> List[PlotDataPoint]:
        """Parse plot_data file with intelligent sampling."""
        try:
            if not plot_file.exists():
                return []

            points = []
            with open(plot_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    point = PlotDataParser._parse_line(line)
                    if point:
                        points.append(point)

            # Sample data if too many points
            if len(points) > max_points:
                points = PlotDataParser._sample_points(points, max_points)

            return points

        except Exception as e:
            logger.error(f"Error parsing plot data {plot_file}: {e}")
            return []

    @staticmethod
    def _parse_line(line: str) -> Optional[PlotDataPoint]:
        """Parse a single line from plot_data."""
        try:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 15:
                return None

            # Handle percentage in map_size
            map_size = parts[6].rstrip('%') if '%' in parts[6] else parts[6]

            return PlotDataPoint(
                relative_time=int(parts[0]),
                cycles_done=int(parts[1]),
                cur_item=int(parts[2]),
                corpus_count=int(parts[3]),
                pending_total=int(parts[4]),
                pending_favs=int(parts[5]),
                map_size=float(map_size),
                saved_crashes=int(parts[7]),
                saved_hangs=int(parts[8]),
                max_depth=int(parts[9]),
                execs_per_sec=float(parts[10]),
                total_execs=int(parts[11]),
                edges_found=int(parts[12]),
                total_crashes=int(parts[13]),
                servers_count=int(parts[14]),
            )
        except (ValueError, IndexError) as e:
            logger.debug(f"Could not parse plot line: {line} - {e}")
            return None

    @staticmethod
    def _sample_points(points: List[PlotDataPoint], max_points: int) -> List[PlotDataPoint]:
        """Sample points using Bresenham's line algorithm for even distribution."""
        if len(points) <= max_points:
            return points

        # Bresenham sampling
        sampled = []
        step = len(points) / max_points

        for i in range(max_points):
            index = int(i * step + step / 2)
            if index < len(points):
                sampled.append(points[index])

        return sampled


def discover_fuzzers(sync_dir: Path) -> List[Path]:
    """
    Discover all fuzzer instances. Intelligently detects:
    - Individual fuzzer directory (contains fuzzer_stats directly)
    - Sync directory (contains subdirectories with fuzzer_stats)

    Args:
        sync_dir: Path to AFL sync directory or individual fuzzer directory

    Returns:
        List of paths to fuzzer instance directories
    """
    fuzzers = []

    try:
        if not sync_dir.exists():
            logger.error(f"Directory not found: {sync_dir}")
            return fuzzers

        if not sync_dir.is_dir():
            logger.error(f"Not a directory: {sync_dir}")
            return fuzzers
    except (PermissionError, OSError) as e:
        logger.error(f"Cannot access directory {sync_dir}: {e}")
        return fuzzers

    # Check if this is an individual fuzzer directory
    try:
        if (sync_dir / "fuzzer_stats").exists():
            logger.info(f"Detected individual fuzzer directory: {sync_dir.name}")
            fuzzers.append(sync_dir)
            return fuzzers
    except (PermissionError, OSError) as e:
        logger.warning(f"Cannot check for fuzzer_stats in {sync_dir}: {e}")

    # This is a sync directory - find all subdirectories with fuzzer_stats
    try:
        for item in sync_dir.iterdir():
            try:
                if item.is_dir() and (item / "fuzzer_stats").exists():
                    fuzzers.append(item)
                    logger.debug(f"Found fuzzer: {item.name}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot access fuzzer directory {item}: {e}")
                continue
    except (PermissionError, OSError) as e:
        logger.error(f"Cannot iterate directory {sync_dir}: {e}")
        return fuzzers

    if not fuzzers:
        logger.warning(f"No fuzzer instances found in {sync_dir}")

    return sorted(fuzzers)
