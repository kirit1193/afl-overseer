"""Process detection and system resource monitoring."""

import os
import psutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple
from .models import FuzzerStatus
import logging

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitor fuzzer processes and system resources."""

    @staticmethod
    def check_process_status(
        pid: int, fuzzer_dir: Path
    ) -> Tuple[FuzzerStatus, float, float]:
        """
        Check if a fuzzer process is alive and get resource usage.

        Args:
            pid: Process ID from fuzzer_stats
            fuzzer_dir: Path to fuzzer directory

        Returns:
            Tuple of (status, cpu_usage, memory_usage)
        """
        if pid <= 0:
            return FuzzerStatus.UNKNOWN, 0.0, 0.0

        # Check if process exists
        if not ProcessMonitor._is_process_alive(pid):
            # Check if starting
            if ProcessMonitor._is_fuzzer_starting(fuzzer_dir):
                return FuzzerStatus.STARTING, 0.0, 0.0
            return FuzzerStatus.DEAD, 0.0, 0.0

        # Get resource usage
        cpu, mem = ProcessMonitor._get_process_resources(pid)
        return FuzzerStatus.ALIVE, cpu, mem

    @staticmethod
    def _is_process_alive(pid: int) -> bool:
        """Check if process is alive using kill -0."""
        try:
            # Send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Process exists but we don't have permission
            return True
        except Exception as e:
            logger.debug(f"Error checking process {pid}: {e}")
            return False

    @staticmethod
    def _is_fuzzer_starting(fuzzer_dir: Path) -> bool:
        """
        Check if fuzzer is still starting up.

        Uses the afl-whatsup logic: fuzzer_setup newer than fuzzer_stats
        and afl-fuzz process accessing the directory.
        """
        try:
            stats_file = fuzzer_dir / "fuzzer_stats"
            setup_file = fuzzer_dir / "fuzzer_setup"

            if not stats_file.exists() or not setup_file.exists():
                return False

            # Check if setup is newer than stats
            if setup_file.stat().st_mtime <= stats_file.stat().st_mtime:
                return False

            # Try to find afl-fuzz process using this directory
            try:
                # Use fuser to check if afl-fuzz is accessing the directory
                result = subprocess.run(
                    ['fuser', '-v', str(fuzzer_dir)],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if 'afl-fuzz' in result.stderr:
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Fallback: check for recent activity
            # If setup was modified very recently, assume starting
            import time
            age = time.time() - setup_file.stat().st_mtime
            return age < 60  # Consider starting if setup modified in last minute

        except Exception as e:
            logger.debug(f"Error checking startup status for {fuzzer_dir}: {e}")
            return False

    @staticmethod
    def _get_process_resources(pid: int) -> Tuple[float, float]:
        """Get CPU and memory usage for a process."""
        try:
            process = psutil.Process(pid)

            # Get CPU usage (percentage)
            cpu_percent = process.cpu_percent(interval=0.1)

            # Get memory usage (percentage)
            mem_percent = process.memory_percent()

            return cpu_percent, mem_percent

        except psutil.NoSuchProcess:
            return 0.0, 0.0
        except psutil.AccessDenied:
            # Can't access process info, but it exists
            return -1.0, -1.0
        except Exception as e:
            logger.debug(f"Error getting resources for PID {pid}: {e}")
            return 0.0, 0.0

    @staticmethod
    def get_system_info() -> dict:
        """Get system resource information."""
        try:
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                'cpu_count': cpu_count,
                'cpu_percent': cpu_percent,
                'memory_total_gb': memory.total / (1024 ** 3),
                'memory_used_gb': memory.used / (1024 ** 3),
                'memory_percent': memory.percent,
                'disk_total_gb': disk.total / (1024 ** 3),
                'disk_used_gb': disk.used / (1024 ** 3),
                'disk_percent': disk.percent,
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}


class ProcessValidator:
    """Validate fuzzer processes and detect issues."""

    @staticmethod
    def check_timeout_ratio(stats) -> Optional[str]:
        """Check if timeout ratio is too high."""
        if stats.execs_done == 0:
            return None

        timeout_ratio = (stats.total_tmout / stats.execs_done) * 100
        if timeout_ratio >= 10:
            return f"High timeout ratio: {timeout_ratio:.1f}%"
        return None

    @staticmethod
    def check_execution_speed(stats) -> Optional[str]:
        """Check if execution speed is suspiciously low."""
        if stats.execs_per_sec == 0 and stats.execs_done > 0:
            return "No execution data yet"
        elif stats.execs_per_sec < 100 and stats.execs_per_sec > 0:
            return f"Slow execution: {stats.execs_per_sec:.1f} execs/sec"
        return None

    @staticmethod
    def check_cycles_without_finds(stats) -> Optional[str]:
        """Check cycles without finding new paths."""
        if stats.cycles_wo_finds > 50:
            return f"Many cycles without finds: {stats.cycles_wo_finds}"
        elif stats.cycles_wo_finds > 10:
            return f"Cycles without finds: {stats.cycles_wo_finds}"
        return None

    @staticmethod
    def check_stability(stats) -> Optional[str]:
        """Check corpus stability."""
        if stats.stability < 80:
            return f"Low stability: {stats.stability:.1f}%"
        return None

    @staticmethod
    def get_all_warnings(stats) -> list:
        """Get all warnings for a fuzzer."""
        warnings = []

        warning = ProcessValidator.check_timeout_ratio(stats)
        if warning:
            warnings.append(warning)

        warning = ProcessValidator.check_execution_speed(stats)
        if warning:
            warnings.append(warning)

        warning = ProcessValidator.check_cycles_without_finds(stats)
        if warning:
            warnings.append(warning)

        warning = ProcessValidator.check_stability(stats)
        if warning:
            warnings.append(warning)

        return warnings
