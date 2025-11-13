# AFL Monitor - Next Generation

**Modern monitoring and reporting tool for AFL/AFL++ fuzzing campaigns**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 What's New in v2.0

AFL Monitor has been completely rewritten from the ground up with modern Python 3, incorporating the best features from both the original afl-monitor and AFLplusplus/afl-whatsup:

### ✨ Major Features

- **🖥️ Interactive TUI** - htop-like interface with live updates, sortable columns, and 3 detail levels
- **🐍 Modern Python 3.8+** - Type hints, dataclasses, async/await support
- **🎨 Beautiful Terminal UI** - Rich terminal output with colors, tables, and progress indicators
- **📊 Interactive HTML Reports** - Responsive, modern web interface with gradient styling
- **📈 JSON Export** - Machine-readable output for automation and integrations
- **🔄 Watch Mode** - Auto-refresh monitoring with configurable intervals
- **⚡ Comprehensive Stats** - Parses ALL fuzzer_stats fields including AFL++ 4.x features
- **🔍 Smart Process Detection** - Detects alive, dead, and starting instances
- **💻 Resource Monitoring** - CPU and memory usage per fuzzer
- **⚠️ Intelligent Warnings** - Automatic detection of performance issues
- **🔔 Crash Notifications** - Execute custom commands on new crashes
- **🔒 Security** - No unsafe pickle, no command injection, proper input validation

### 🆕 New Metrics Tracked

- `testcache_size`, `testcache_count`, `testcache_evict`
- `cpu_affinity`, `peak_rss_mb`
- `edges_found`, `total_edges`
- `var_byte_count`, `havoc_expansion`, `auto_dict_entries`
- `afl_version`, `target_mode`
- `slowest_exec_ms`, `execs_since_crash`
- Per-fuzzer CPU and memory usage
- Time without finds, comprehensive timing metrics

---

## 📦 Installation

### Requirements

- Python 3.8 or higher
- Linux, macOS, or WSL2 (Windows)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourrepo/afl-monitor.git
cd afl-monitor

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x afl-monitor-ng

# Optional: Install globally
sudo ln -s $(pwd)/afl-monitor-ng /usr/local/bin/
```

### Dependencies

```bash
pip3 install click rich psutil textual
```

---

## 🎯 Usage

### Interactive TUI Mode (Default)

```bash
# Launch interactive TUI (like htop) - NO FLAGS NEEDED!
./afl-monitor-ng /path/to/sync_dir

# Or explicitly request TUI mode
./afl-monitor-ng -t /path/to/sync_dir

# Interactive controls:
#   q - Quit
#   r - Refresh now
#   1/2/3 - Compact/Normal/Detailed view
#   n/s/c/e/r - Sort by Name/Speed/Coverage/Execs/Crashes
#   d - Toggle dead fuzzers
#   p - Pause/Resume auto-refresh
```

### Static Terminal Output

```bash
# One-time static output
./afl-monitor-ng -s /path/to/sync_dir

# Static with detailed per-fuzzer statistics
./afl-monitor-ng -s -v /path/to/sync_dir

# Static with auto-refresh (watch mode)
./afl-monitor-ng -s -w -i 10 /path/to/sync_dir
```

### File Output Formats

```bash
# Generate HTML report
./afl-monitor-ng -h ./report /path/to/sync_dir

# Export to JSON
./afl-monitor-ng -j stats.json /path/to/sync_dir

# Multiple outputs simultaneously
./afl-monitor-ng -s -v -j stats.json -h ./report /path/to/sync_dir
```

### Advanced Examples

```bash
# Execute notification on new crash (in static mode)
./afl-monitor-ng -s -e './send_alert.sh' /path/to/sync_dir

# Minimal output (summary only)
./afl-monitor-ng -s -m /path/to/sync_dir

# Include dead fuzzers in output
./afl-monitor-ng -s -d /path/to/sync_dir

# No color output (for logs)
./afl-monitor-ng -s -n /path/to/sync_dir

# Watch mode with JSON export
./afl-monitor-ng -s -w -i 30 -j /var/www/stats.json /path/to/sync_dir
```

---

## 📚 Command-Line Options

| Option | Description |
|--------|-------------|
| `-t`, `--tui` | Interactive TUI mode like htop (default when no output flags) |
| `-s`, `--static` | Static terminal output (non-interactive) |
| `-h`, `--html DIR` | Generate HTML report in directory |
| `-j`, `--json FILE` | Write JSON output to file |
| `-v`, `--verbose` | Show detailed per-fuzzer statistics |
| `-n`, `--no-color` | Disable colored output |
| `-w`, `--watch` | Watch mode - auto-refresh (for static output) |
| `-i`, `--interval SEC` | Refresh interval in seconds (default: 5) |
| `-d`, `--show-dead` | Include dead fuzzers in output |
| `-m`, `--minimal` | Minimal output mode (summary only) |
| `-e`, `--execute CMD` | Execute command on new crash (stats passed via stdin) |
| `--version` | Show version and exit |
| `--help` | Show help message |

### Interactive TUI Controls

When using the interactive TUI mode (default), you can use these keyboard shortcuts:

| Key | Action |
|-----|--------|
| `q` | Quit the application |
| `r` | Refresh now (force update) |
| `1` | Compact view (5 columns: Name, Status, Speed, Coverage, Crashes) |
| `2` | Normal view (8 columns: + Runtime, Execs, Corpus) |
| `3` | Detailed view (12 columns: + Pending, Stability, Cycle, CPU%) |
| `n` | Sort by fuzzer Name |
| `s` | Sort by execution Speed |
| `c` | Sort by Coverage |
| `e` | Sort by total Executions |
| `r` | Sort by cRashes (unique crashes) |
| `d` | Toggle showing dead fuzzers |
| `p` | Pause/Resume auto-refresh |

---

## 📊 Output Formats

### Terminal Output

Beautiful, colorized terminal output with:
- Campaign summary with key metrics
- Per-fuzzer detailed statistics (with `-v`)
- Status indicators (alive/dead/starting)
- Performance warnings
- Resource usage
- Delta tracking between runs

### HTML Report

Modern, responsive HTML with:
- Gradient design with hover effects
- Campaign summary cards
- Per-fuzzer detailed cards
- Status badges
- Performance warnings
- Mobile-friendly responsive layout
- Auto-refresh support in watch mode

### JSON Export

Machine-readable JSON containing:
- Metadata (timestamp, version, directory)
- Complete campaign summary
- Array of all fuzzer statistics
- System resource information

Example structure:
```json
{
  "metadata": {
    "timestamp": 1234567890,
    "timestamp_str": "2024-01-15 14:30:00",
    "monitor_version": "2.0",
    "findings_directory": "/path/to/sync_dir"
  },
  "summary": { ... },
  "fuzzers": [ ... ],
  "system": { ... }
}
```

---

## 🏗️ Architecture

### Project Structure

```
afl-monitor/
├── afl-monitor-ng          # Main executable
├── src/
│   ├── __init__.py          # Package init
│   ├── cli.py               # Command-line interface
│   ├── tui.py               # Interactive TUI (htop-like interface)
│   ├── models.py            # Data models (dataclasses)
│   ├── parser.py            # Stats and plot data parsers
│   ├── process.py           # Process detection and monitoring
│   ├── monitor.py           # Core monitoring logic
│   ├── utils.py             # Utility functions
│   ├── output_terminal.py   # Terminal output formatter
│   ├── output_json.py       # JSON output formatter
│   └── output_html.py       # HTML output formatter
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

### Key Components

- **Interactive TUI**: Textual-based htop-like interface with live updates, sortable tables, and keyboard controls
- **Models**: Type-safe data structures using Python dataclasses
- **Parser**: Robust parsing of fuzzer_stats and plot_data files
- **Process Monitor**: Detects process status, CPU/memory usage, startup detection
- **Core Monitor**: Aggregates stats, calculates summaries, tracks deltas
- **Output Formatters**: Modular output system supporting multiple formats (TUI, terminal, JSON, HTML)
- **CLI**: Modern click-based interface with async support

---

## 🔍 Fuzzer Detection

AFL Monitor uses intelligent detection to determine fuzzer status:

### Alive
- Process exists (validated with `kill -0`)
- Can retrieve CPU/memory usage via psutil

### Dead
- Process PID not found
- No recent activity

### Starting
- `fuzzer_setup` file newer than `fuzzer_stats`
- afl-fuzz process detected accessing directory
- Recent modification (< 60 seconds)

---

## ⚠️ Performance Warnings

Automatic detection and warnings for:

- **High Timeout Ratio**: ≥10% timeout rate
- **Slow Execution**: <100 execs/sec
- **Cycles Without Finds**: >10 cycles (yellow), >50 cycles (red)
- **Low Stability**: <80% corpus stability

---

## 🔔 Crash Notifications

Execute custom commands when new crashes are detected:

```bash
./afl-monitor-ng -c -e './notify.sh' /path/to/sync_dir
```

The command receives a summary via stdin:
```
AFL Monitor - New Crash Detected!

Timestamp: 2024-01-15 14:30:00
Total Crashes: 5
New Crashes: 2
Active Fuzzers: 8/10
Coverage: 12.34%
```

Example notification script:
```bash
#!/bin/bash
# notify.sh
MESSAGE=$(cat)
curl -X POST https://hooks.slack.com/... -d "{\"text\": \"$MESSAGE\"}"
```

---

## 📈 Integration Examples

### Continuous Monitoring with Systemd

```ini
[Unit]
Description=AFL Monitor
After=network.target

[Service]
Type=simple
User=fuzzer
WorkingDirectory=/home/fuzzer
ExecStart=/usr/local/bin/afl-monitor-ng -w -i 60 -j /var/www/html/afl-stats.json /fuzzing/sync_dir
Restart=always

[Install]
WantedBy=multi-user.target
```

### Web Dashboard Integration

Export JSON and serve with nginx:
```bash
# Continuous JSON export
./afl-monitor-ng -w -i 30 -j /var/www/html/stats.json /sync_dir

# Serve with nginx
# Your web dashboard can fetch /stats.json and visualize
```

### CI/CD Integration

```yaml
# .github/workflows/fuzzing.yml
- name: Check Fuzzing Progress
  run: |
    afl-monitor-ng -j stats.json /sync_dir
    python3 analyze_coverage.py stats.json
```

---

## 🆚 Comparison with Legacy Tools

| Feature | Legacy afl-monitor | afl-whatsup | AFL Monitor NG |
|---------|-------------------|-------------|----------------|
| Python Version | 2.7 (EOL) | N/A (Shell) | 3.8+ |
| Modern UI | ❌ | ❌ | ✅ Rich terminal |
| HTML Reports | ✅ Basic | ❌ | ✅ Modern responsive |
| JSON Export | ❌ | ❌ | ✅ |
| Process Detection | Weak | Good | Excellent |
| Starting Detection | ❌ | ✅ | ✅ |
| Resource Monitoring | ❌ | Basic | ✅ CPU + Memory |
| Watch Mode | Basic | ❌ | ✅ Advanced |
| Security | ⚠️ Vulnerabilities | ✅ Safe | ✅ Secure |
| All AFL++ Fields | ❌ | Partial | ✅ Complete |
| Performance Warnings | ❌ | Some | ✅ Comprehensive |
| Crash Notifications | ⚠️ Unsafe | ❌ | ✅ Secure |
| Maintainable | ❌ | ✅ | ✅ |

---

## 🐛 Troubleshooting

### Permission Denied for Process Info

If you see warnings about process access:
```bash
# Run with sudo (not recommended)
sudo ./afl-monitor-ng ...

# Or add user to fuzzer's group
sudo usermod -a -G fuzzer $USER
```

### Empty Output

Check that:
1. Directory contains fuzzer subdirectories
2. Each subdirectory has `fuzzer_stats` file
3. You're pointing to sync directory, not individual fuzzer directory

```bash
# Correct structure:
/sync_dir/
  ├── fuzzer01/
  │   └── fuzzer_stats
  ├── fuzzer02/
  │   └── fuzzer_stats
  └── ...

# Correct usage:
./afl-monitor-ng -c /sync_dir

# Incorrect (will show error):
./afl-monitor-ng -c /sync_dir/fuzzer01
```

### No Color Output

If colors don't work:
```bash
# Set TERM environment variable
export TERM=xterm-256color
./afl-monitor-ng -c /sync_dir
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

### Development Setup

```bash
# Clone for development
git clone https://github.com/yourrepo/afl-monitor.git
cd afl-monitor

# Install in development mode
pip3 install -e .

# Run tests (when implemented)
python3 -m pytest tests/
```

---

## 📝 License

Copyright 2024. Licensed under the Apache License, Version 2.0.

Original afl-monitor by Paul S. Ziegler, Copyright 2017 Reflare Ltd.

---

## 🙏 Acknowledgments

- Original afl-monitor by Paul S. Ziegler
- AFLplusplus project and afl-whatsup
- AFL by Michal Zalewski
- Click, Rich, and psutil libraries

---

## 📧 Support

- Issues: [GitHub Issues](https://github.com/yourrepo/afl-monitor/issues)
- Discussions: [GitHub Discussions](https://github.com/yourrepo/afl-monitor/discussions)

---

## 🗺️ Roadmap

Future enhancements:
- [ ] Plotly interactive charts in HTML
- [ ] Configuration file support (YAML/TOML)
- [ ] WebSocket-based real-time updates
- [ ] Slack/Discord/Telegram integrations
- [ ] Historical trending and analysis
- [ ] Multi-host campaign aggregation
- [ ] Prometheus metrics exporter
- [ ] Grafana dashboard templates

---

**Happy Fuzzing! 🐛💥**
