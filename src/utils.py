"""Utility functions for formatting and calculations."""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta
from typing import Union

# Compiled regex for stripping ANSI codes (performance optimization)
_ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def format_duration(seconds: int) -> str:
    """
    Format duration in seconds to compact string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string like "2d3h15m" or "1h42m30s"
    """
    if seconds <= 0:
        return "0s"

    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 and days == 0:  # Don't show minutes if showing days
        parts.append(f"{minutes}m")
    if secs > 0 and days == 0 and hours == 0:  # Only show seconds for short durations
        parts.append(f"{secs}s")

    return "".join(parts[:3]) if parts else "0s"  # Show at most 3 units


def format_time_ago(timestamp: int) -> str:
    """
    Format timestamp to 'X time ago' string.

    Args:
        timestamp: Unix timestamp

    Returns:
        Formatted string like "2 hours ago" or "never"
    """
    if timestamp <= 0:
        return "never"

    now = int(time.time())
    elapsed = now - timestamp

    if elapsed < 0:
        return "in the future"

    return f"{format_duration(elapsed)} ago"


def format_number(num: Union[int, float], decimals: int = 0) -> str:
    """
    Format number with thousands separators.

    Args:
        num: Number to format
        decimals: Number of decimal places

    Returns:
        Formatted string like "1,234,567" or "1,234.56"
    """
    if decimals > 0:
        return f"{num:,.{decimals}f}"
    return f"{int(num):,}"


def format_execs(total_execs: int) -> str:
    """
    Format execution count in millions/thousands.

    Args:
        total_execs: Total number of executions

    Returns:
        Formatted string like "123 millions" or "456 thousands"
    """
    millions = total_execs // 1_000_000
    thousands = (total_execs % 1_000_000) // 1_000

    if millions > 9:
        return f"{millions:,} millions"
    elif millions > 0:
        return f"{millions:,} millions, {thousands:,} thousands"
    elif thousands > 0:
        return f"{thousands:,} thousands"
    else:
        return f"{total_execs:,}"


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes to human-readable size.

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string like "1.23 GB" or "456 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_speed(execs_per_sec: float) -> str:
    """
    Format execution speed.

    Args:
        execs_per_sec: Executions per second

    Returns:
        Formatted string like "1,234.56/s"
    """
    if execs_per_sec >= 1000:
        return f"{execs_per_sec:,.0f}/s"
    elif execs_per_sec >= 1:
        return f"{execs_per_sec:.1f}/s"
    else:
        return f"{execs_per_sec:.2f}/s"


def format_percent(value: float, decimals: int = 2) -> str:
    """
    Format percentage value.

    Args:
        value: Percentage value (0-100)
        decimals: Number of decimal places

    Returns:
        Formatted string like "12.34%"
    """
    return f"{value:.{decimals}f}%"


def get_timestamp() -> str:
    """Get current timestamp as formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def calculate_percentage(part: float, total: float) -> float:
    """Calculate percentage safely."""
    if total == 0:
        return 0.0
    return (part / total) * 100


def calculate_eta(current: int, total: int, elapsed_seconds: int) -> str:
    """
    Calculate estimated time to completion.

    Args:
        current: Current progress
        total: Total work
        elapsed_seconds: Time elapsed so far

    Returns:
        Formatted ETA string
    """
    if current <= 0 or total <= 0 or current >= total:
        return "N/A"

    progress_ratio = current / total
    if progress_ratio <= 0:
        return "N/A"

    total_time = elapsed_seconds / progress_ratio
    remaining = int(total_time - elapsed_seconds)

    return format_duration(remaining)


def generate_sparkline(values: list, width: int = 20, height: int = 8) -> str:
    """
    Generate ASCII sparkline for a series of values.

    Args:
        values: List of numeric values
        width: Number of characters for the sparkline
        height: Number of vertical levels (1-8 for block characters)

    Returns:
        String representing the sparkline
    """
    if not values or len(values) == 0:
        return " " * width

    # Sample values if we have more than width
    if len(values) > width:
        step = len(values) / width
        sampled = [values[int(i * step)] for i in range(width)]
    else:
        sampled = values + [values[-1]] * (width - len(values))  # Pad if needed

    # Normalize to 0-height range
    min_val = min(sampled)
    max_val = max(sampled)

    if max_val == min_val:
        # All values are the same
        normalized = [height // 2] * len(sampled)
    else:
        normalized = [int((v - min_val) / (max_val - min_val) * (height - 1)) for v in sampled]

    # Block characters for sparkline (Unicode block elements)
    blocks = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']

    # Build sparkline
    sparkline = ''.join(blocks[min(n, len(blocks) - 1)] for n in normalized)

    return sparkline


def generate_mini_graph(values: list, width: int = 40, label: str = "") -> list:
    """
    Generate a mini text-based graph with values.

    Args:
        values: List of numeric values
        width: Width of the graph
        label: Label for the graph

    Returns:
        List of strings representing the graph lines
    """
    if not values or len(values) == 0:
        return [f"{label}: [no data]"]

    min_val = min(values)
    max_val = max(values)
    latest_val = values[-1]

    sparkline = generate_sparkline(values, width=width)

    # Format with min, max, and current values
    info = f"{label}: {sparkline}  [min: {min_val:.1f}, max: {max_val:.1f}, now: {latest_val:.1f}]"

    return [info]


class ColorFormatter:
    """ANSI color codes for terminal output."""

    # Colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @staticmethod
    def strip_colors(text: str) -> str:
        """Remove ANSI color codes from text."""
        return _ANSI_ESCAPE_PATTERN.sub('', text)

    @staticmethod
    def colorize(text: str, color: str, bold: bool = False) -> str:
        """Add color to text."""
        prefix = ColorFormatter.BOLD if bold else ''
        return f"{prefix}{color}{text}{ColorFormatter.RESET}"

    @staticmethod
    def status_color(status: str) -> str:
        """Get color for status."""
        from .models import FuzzerStatus
        if status == FuzzerStatus.ALIVE.value:
            return ColorFormatter.GREEN
        elif status == FuzzerStatus.DEAD.value:
            return ColorFormatter.RED
        elif status == FuzzerStatus.STARTING.value:
            return ColorFormatter.YELLOW
        else:
            return ColorFormatter.WHITE

    @staticmethod
    def value_color(value: float, thresholds: dict) -> str:
        """Get color based on threshold."""
        if 'critical' in thresholds and value >= thresholds['critical']:
            return ColorFormatter.RED
        elif 'warning' in thresholds and value >= thresholds['warning']:
            return ColorFormatter.YELLOW
        elif 'good' in thresholds and value >= thresholds['good']:
            return ColorFormatter.GREEN
        else:
            return ColorFormatter.WHITE
