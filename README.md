# AFL Overseer

Monitoring and visualization tool for AFL/AFL++ fuzzing campaigns.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## Overview

AFL Overseer monitors AFL and AFL++ fuzzing campaigns, providing real-time statistics and performance metrics. It combines features from the original afl-monitor and AFLplusplus/afl-whatsup with additional capabilities.

### Features

- **Interactive TUI** - Terminal interface with live updates, sortable columns, and multiple detail levels
- **Web Dashboard** - Browser-based UI with real-time graphs and REST API
- **Process Detection** - Identifies alive, dead, and starting fuzzer instances
- **Resource Monitoring** - CPU and memory usage per fuzzer
- **Performance Warnings** - Detects dead fuzzers, low stability, high timeouts, and stalled campaigns
- **Crash Notifications** - Execute custom commands when new crashes are found
- **Comprehensive Stats** - Parses all fuzzer_stats fields including AFL++ 4.x extensions

### Tracked Metrics

Standard AFL metrics plus AFL++ extensions:
- `testcache_size`, `testcache_count`, `testcache_evict`
- `cpu_affinity`, `peak_rss_mb`
- `edges_found`, `total_edges`
- `var_byte_count`, `havoc_expansion`, `auto_dict_entries`
- `afl_version`, `target_mode`
- `slowest_exec_ms`, `execs_since_crash`
- Per-fuzzer CPU and memory usage
- Time without finds and comprehensive timing metrics

## Installation

### Requirements

- Python 3.8+
- Linux, macOS, or WSL2

### Using a Virtual Environment

```bash
git clone https://github.com/kirit1193/afl-overseer.git
cd afl-overseer

python3 -m venv venv
source venv/bin/activate

pip3 install -r requirements.txt
chmod +x afl-overseer

./afl-overseer /path/to/sync_dir
```

### User Installation

```bash
git clone https://github.com/kirit1193/afl-overseer.git
cd afl-overseer

pip3 install --user -r requirements.txt
chmod +x afl-overseer

# Optional: Install globally
sudo ln -s $(pwd)/afl-overseer /usr/local/bin/
```

### Dependencies

```
click>=8.1.0      # CLI framework
rich>=13.0.0      # Terminal output
psutil>=5.9.0     # Process monitoring
textual>=0.40.0   # Interactive TUI
aiohttp>=3.8.0    # Web server
```

## Usage

### Interactive TUI

```bash
# Launch TUI (default mode)
afl-overseer /path/to/sync_dir

# Keyboard controls:
#   q - Quit
#   r - Refresh now
#   1/2/3 - Compact/Normal/Detailed view
#   n/s/c/e/r - Sort by Name/Speed/Coverage/Execs/Crashes
#   d - Toggle dead fuzzers
#   p - Pause/Resume auto-refresh
```

### Web Dashboard

```bash
# Start web server with TUI
afl-overseer -w /path/to/sync_dir

# Headless mode (no TUI)
afl-overseer -w --headless /path/to/sync_dir

# Custom port
afl-overseer -w -p 3000 /path/to/sync_dir

# Access at http://localhost:8080
```

### Static Output

```bash
# One-time output
afl-overseer -s /path/to/sync_dir

# Detailed per-fuzzer stats
afl-overseer -s -v /path/to/sync_dir

# Execute command on new crash
afl-overseer -s -e './send_alert.sh' /path/to/sync_dir
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t`, `--tui` | Interactive TUI mode (default) |
| `-s`, `--static` | Static terminal output |
| `-w`, `--web` | Start web server |
| `-p`, `--port PORT` | Web server port (default: 8080) |
| `--headless` | Run web server without TUI |
| `-v`, `--verbose` | Show detailed per-fuzzer statistics |
| `-n`, `--no-color` | Disable colored output |
| `-i`, `--interval SEC` | Refresh interval in seconds (default: 5) |
| `-d`, `--show-dead` | Include dead fuzzers in output |
| `-m`, `--minimal` | Minimal output mode |
| `-e`, `--execute CMD` | Execute command on new crash |
| `--version` | Show version |
| `--help` | Show help message |

## Architecture

```
afl-overseer/
├── afl-overseer            # Main executable
├── src/
│   ├── cli.py              # Command-line interface
│   ├── tui.py              # Interactive TUI
│   ├── webserver.py        # Web server and dashboard
│   ├── models.py           # Data models
│   ├── parser.py           # Stats and plot data parsers
│   ├── process.py          # Process detection and monitoring
│   ├── monitor.py          # Core monitoring logic
│   ├── utils.py            # Utility functions
│   └── output_terminal.py  # Terminal output formatter
├── requirements.txt        # Python dependencies
└── testing/                # Test utilities and benchmarks
```

### Process Detection

Fuzzer status is determined by:

- **Alive**: Process exists and responds to signals
- **Dead**: Process PID not found or no recent activity
- **Starting**: `fuzzer_setup` newer than `fuzzer_stats` with recent modification

### Performance Warnings

Automatic detection of:
- Dead fuzzer instances
- High timeout ratio (≥10%)
- Slow execution (<100 execs/sec)
- Cycles without finds (>10 cycles warning, >50 cycles critical)
- Low stability (<80%)
- High slowest execution time (>100ms)

## Web Dashboard

The web interface provides:
- Real-time graphs for speed, coverage, and paths/crashes
- Live fuzzer status table with warnings
- System resource monitoring
- Light/Dark theme toggle
- Mobile-responsive design
- REST API endpoint at `/api/stats`

Example API response:
```json
{
  "summary": {
    "alive_fuzzers": 3,
    "total_fuzzers": 3,
    "total_execs": 1000000,
    "current_speed": 500.0,
    "max_coverage": 45.2,
    "total_crashes": 5,
    "corpus_count": 250
  },
  "fuzzers": [...],
  "system": {...}
}
```

## Crash Notifications

Execute custom commands when new crashes are detected:

```bash
afl-overseer -s -e './notify.sh' /path/to/sync_dir
```

The command receives summary information via stdin:
```
AFL Overseer - New Crash Detected!

Timestamp: 2024-01-15 14:30:00
Total Crashes: 5
New Crashes: 2
Active Fuzzers: 8/10
Coverage: 12.34%
```

Example notification script:
```bash
#!/bin/bash
MESSAGE=$(cat)
curl -X POST https://hooks.slack.com/... -d "{\"text\": \"$MESSAGE\"}"
```

## Integration Examples

### Systemd Service

```ini
[Unit]
Description=AFL Overseer Web Dashboard
After=network.target

[Service]
Type=simple
User=fuzzer
WorkingDirectory=/home/fuzzer
ExecStart=/usr/local/bin/afl-overseer -w --headless -i 60 /fuzzing/sync_dir
Restart=always

[Install]
WantedBy=multi-user.target
```

### Remote Access

```bash
# Start headless web server
afl-overseer -w --headless -p 8080 /sync_dir

# SSH tunnel from local machine
ssh -L 8080:localhost:8080 user@remote-server

# Access at http://localhost:8080
```

## Performance

Optimized for scanning large fuzzing campaigns:
- **4 fuzzers**: ~7ms per scan
- **20 fuzzers**: ~28ms per scan
- **100 fuzzers**: ~111ms per scan

Achieves ~600-900 fuzzers/sec throughput through:
- Parallel processing with ThreadPoolExecutor
- Non-blocking CPU monitoring
- Efficient file parsing
- Optimized process detection

See `testing/benchmark.py` for performance testing.

## Troubleshooting

### Permission Denied

If you see warnings about process access:
```bash
# Add user to fuzzer's group
sudo usermod -a -G fuzzer $USER
```

### No Fuzzers Found

Check directory structure:
```
/sync_dir/
  ├── fuzzer01/
  │   └── fuzzer_stats
  ├── fuzzer02/
  │   └── fuzzer_stats
  └── ...
```

Use: `afl-overseer /sync_dir` (not `/sync_dir/fuzzer01`)

## Project History

AFL Overseer is a rewrite of the original [afl-monitor](https://github.com/reflare/afl-monitor) tool by Paul S. Ziegler. This version addresses security issues in the Python 2.7 codebase (unsafe pickle usage, deprecated modules) and adds support for AFL++ 4.x features, interactive TUI, and web dashboard capabilities.

**Key differences from the original:**
- Python 3.8+ with type hints (vs Python 2.7)
- Interactive TUI and web dashboard (vs static output only)
- Secure implementation without pickle or command injection
- AFL++ 4.x field support with 50+ metrics
- Real-time resource monitoring per fuzzer
- Parallel processing for improved performance

Thanks to Paul S. Ziegler for the original afl-monitor.

## License

Copyright (c) 2024 AFL Overseer Contributors. Licensed under the MIT License.

Original afl-monitor: Copyright (c) 2017 Paul S. Ziegler, Reflare Ltd. (Apache License 2.0)

See [LICENSE](LICENSE) for details.

## Acknowledgments

- Original afl-monitor by Paul S. Ziegler
- AFLplusplus project and afl-whatsup
- AFL by Michal Zalewski

## Support

- Issues: [GitHub Issues](https://github.com/kirit1193/afl-overseer/issues)
- Discussions: [GitHub Discussions](https://github.com/kirit1193/afl-overseer/discussions)
