"""Constants used across the AFL Overseer application."""

from __future__ import annotations

# Process monitoring timeouts (seconds)
FUZZER_STARTING_AGE_THRESHOLD = 60  # Consider fuzzer starting if setup file modified within this time
FUZZER_STARTING_CHECK_WINDOW = 300  # Only check fuser for recent setups (5 minutes)
FUSER_TIMEOUT = 0.5  # Timeout for fuser command (seconds)

# Performance warning thresholds
TIMEOUT_RATIO_THRESHOLD = 10.0  # High timeout ratio percentage
LOW_EXEC_SPEED_THRESHOLD = 100.0  # Executions per second
HIGH_CYCLES_WITHOUT_FINDS = 50  # Cycles without finding new paths
WARNING_CYCLES_WITHOUT_FINDS = 10  # Warning level for cycles without finds
LOW_STABILITY_THRESHOLD = 80.0  # Percentage

# Pending paths warning thresholds
HIGH_PENDING_PATHS = 1000  # Color threshold for high pending paths

# Resource monitoring
BYTES_PER_GB = 1024 ** 3  # Bytes in a gigabyte
BYTES_PER_MB = 1024 ** 2  # Bytes in a megabyte

# ThreadPool configuration
MAX_WORKER_THREADS = 10  # Maximum number of worker threads for parallel processing

# File monitoring
STATE_FILE_NAME = ".afl-monitor-ng.json"
STATE_LOCK_FILE_NAME = ".afl-monitor-ng.lock"

# Default configuration
DEFAULT_REFRESH_INTERVAL = 1  # Default refresh interval in seconds
DEFAULT_WEB_PORT = 8080  # Default web server port

# Display formatting
MAX_SUMMARY_UNITS = 2  # Maximum time units to show in duration formatting
SPARKLINE_WIDTH = 60  # Default width for sparkline graphs
SPARKLINE_HEIGHT = 8  # Default height for sparkline graphs (using block characters)
