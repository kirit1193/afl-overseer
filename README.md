# AFL Overseer

**Modern monitoring and visualization tool for AFL/AFL++ fuzzing campaigns**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 What's New in v2.0

AFL Overseer is a complete rewrite from the ground up with modern Python 3, incorporating the best features from both the original afl-monitor and AFLplusplus/afl-whatsup:

### ✨ Major Features

- **🖥️ Interactive TUI** - htop-like interface with live updates, sortable columns, and 3 detail levels
- **🌐 Web Dashboard** - Modern netdata-like web UI with real-time graphs, light/dark themes, and mobile-friendly design
- **🐍 Modern Python 3.8+** - Type hints, dataclasses, async/await support
- **🎨 Beautiful Terminal UI** - Rich terminal output with colors, tables, and progress indicators
- **📊 REST API** - JSON API endpoint for integrations and custom dashboards
- **⚡ Comprehensive Stats** - Parses ALL fuzzer_stats fields including AFL++ 4.x features
- **🔍 Smart Process Detection** - Detects alive, dead, and starting instances
- **💻 Resource Monitoring** - CPU and memory usage per fuzzer
- **⚠️ Intelligent Warnings** - Automatic detection of performance issues (dead fuzzers, low stability, high timeouts)
- **🔔 Crash Notifications** - Execute custom commands on new crashes
- **🔒 Security** - No unsafe pickle, no command injection, proper input validation
- **⚡ Minimal Dependencies** - Lightweight with only essential packages (aiohttp for web server)

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
git clone https://github.com/yourrepo/afl-overseer.git
cd afl-overseer

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x afl-overseer

# Optional: Install globally
sudo ln -s $(pwd)/afl-overseer /usr/local/bin/
```

### Dependencies

```bash
pip3 install click rich psutil textual aiohttp
```

---

## 🎯 Usage

### Interactive TUI Mode (Default)

```bash
# Launch interactive TUI (like htop) - NO FLAGS NEEDED!
afl-overseer /path/to/sync_dir

# Or explicitly request TUI mode
afl-overseer -t /path/to/sync_dir

# Interactive controls:
#   q - Quit
#   r - Refresh now
#   1/2/3 - Compact/Normal/Detailed view
#   n/s/c/e/r - Sort by Name/Speed/Coverage/Execs/Crashes
#   d - Toggle dead fuzzers
#   p - Pause/Resume auto-refresh
```

### Web Dashboard Mode

```bash
# Web dashboard with TUI (default port 8080)
afl-overseer -w /path/to/sync_dir

# Web dashboard headless (no TUI, perfect for remote servers)
afl-overseer -w --headless /path/to/sync_dir

# Custom port
afl-overseer -w -p 3000 /path/to/sync_dir

# Then open http://localhost:8080 in your browser
# Features:
#   - Real-time metrics and graphs (speed, coverage, paths, pending)
#   - Live fuzzer status table with warnings
#   - Light/Dark theme toggle
#   - System resource monitoring
#   - Auto-refresh every 5 seconds (customizable with -i)
#   - Mobile-friendly responsive design
#   - REST API at /api/stats
```

### Static Terminal Output

```bash
# One-time static output
afl-overseer -s /path/to/sync_dir

# Static with detailed per-fuzzer statistics
afl-overseer -s -v /path/to/sync_dir
```

### Advanced Examples

```bash
# Execute notification on new crash (in static mode)
afl-overseer -s -e './send_alert.sh' /path/to/sync_dir

# Minimal output (summary only)
afl-overseer -s -m /path/to/sync_dir

# Include dead fuzzers in output
afl-overseer -s -d /path/to/sync_dir

# No color output (for logs)
afl-overseer -s -n /path/to/sync_dir

# Web dashboard on custom port with 10-second refresh
afl-overseer -w -p 9090 -i 10 --headless /path/to/sync_dir
```

---

## 📚 Command-Line Options

| Option | Description |
|--------|-------------|
| `-t`, `--tui` | Interactive TUI mode like htop (default when no flags) |
| `-s`, `--static` | Static terminal output (non-interactive) |
| `-w`, `--web` | Start web server with live dashboard |
| `-p`, `--port PORT` | Web server port (default: 8080) |
| `--headless` | Run web server without TUI (headless mode) |
| `-v`, `--verbose` | Show detailed per-fuzzer statistics |
| `-n`, `--no-color` | Disable colored output |
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

## 📊 Output Modes

### Interactive TUI (Default)

Beautiful terminal interface with:
- Campaign summary with key metrics
- Per-fuzzer detailed statistics with 3 detail levels
- Status indicators (alive/dead/starting)
- Sortable columns
- Live updates with keyboard controls
- Resource usage per fuzzer

### Web Dashboard

Modern netdata-like web interface with:
- **Real-time graphs**: Execution speed, coverage, paths/crashes (dual axis), pending paths over time
- **Live metrics**: Campaign summary with auto-refresh
- **Alert system**: Visual alerts for dead fuzzers, low stability, high timeouts
- **Fuzzer table**: Sortable table showing all fuzzers with warning badges
- **System monitoring**: CPU, memory, cycle statistics
- **Light/Dark themes**: Toggle between themes with persistent preference
- **Responsive design**: Works perfectly on mobile devices
- **Tabbed interface**: Overview, Fuzzers, Graphs, System tabs
- **REST API**: `/api/stats` endpoint for integrations

Example API response structure:
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
  "fuzzers": [
    {
      "name": "master",
      "status": "ALIVE",
      "run_time": 3600,
      "execs_done": 500000,
      "exec_speed": 200.5,
      "bitmap_cvg": 45.2,
      "saved_crashes": 3,
      "corpus_count": 120
    }
  ],
  "system": {
    "cpu_cores": 16,
    "cpu_percent": 25.5,
    "memory_total_gb": 32.0,
    "memory_used_gb": 8.5,
    "memory_percent": 26.6
  }
}
```

### Static Terminal Output

One-time terminal output with:
- Colorized campaign summary
- Per-fuzzer statistics (with `-v`)
- Status indicators
- Resource usage
- Performance warnings
- Delta tracking between runs

---

## 🏗️ Architecture

### Project Structure

```
afl-overseer/
├── afl-overseer            # Main executable
├── src/
│   ├── __init__.py         # Package init
│   ├── cli.py              # Command-line interface
│   ├── tui.py              # Interactive TUI (htop-like interface)
│   ├── webserver.py        # Web server and dashboard (netdata-like UI)
│   ├── models.py           # Data models (dataclasses)
│   ├── parser.py           # Stats and plot data parsers
│   ├── process.py          # Process detection and monitoring
│   ├── monitor.py          # Core monitoring logic
│   ├── utils.py            # Utility functions
│   └── output_terminal.py  # Terminal output formatter
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

### Key Components

- **Interactive TUI**: Textual-based htop-like interface with live updates, sortable tables, and keyboard controls
- **Web Dashboard**: Aiohttp-based web server with embedded modern HTML/CSS/JS dashboard, real-time graphs (Chart.js), light/dark themes, and REST API
- **Models**: Type-safe data structures using Python dataclasses
- **Parser**: Robust parsing of fuzzer_stats and plot_data files
- **Process Monitor**: Detects process status, CPU/memory usage, startup detection
- **Core Monitor**: Aggregates stats, calculates summaries, tracks deltas
- **Output Formatters**: Modular output system for terminal display
- **CLI**: Modern click-based interface with async support

---

## 🔍 Fuzzer Detection

AFL Overseer uses intelligent detection to determine fuzzer status:

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

- **Dead Fuzzers**: Any non-responsive fuzzer instances
- **High Timeout Ratio**: ≥10% timeout rate
- **Slow Execution**: <100 execs/sec
- **Cycles Without Finds**: >10 cycles (yellow), >50 cycles (red)
- **Low Stability**: <80% corpus stability
- **High Timeouts**: slowest_exec_ms > 100ms

Warnings are shown in:
- CLI output with ⚠ indicators
- Web dashboard with alert banners and warning badges

---

## 🔔 Crash Notifications

Execute custom commands when new crashes are detected:

```bash
afl-overseer -s -e './notify.sh' /path/to/sync_dir
```

The command receives a summary via stdin:
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
# notify.sh
MESSAGE=$(cat)
curl -X POST https://hooks.slack.com/... -d "{\"text\": \"$MESSAGE\"}"
```

---

## 📈 Integration Examples

### Continuous Monitoring with Systemd

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

### Web Dashboard Integration

Run headless web server for remote monitoring:
```bash
# Start web dashboard on remote server
afl-overseer -w --headless -p 8080 /sync_dir

# Access from anywhere via SSH tunnel
ssh -L 8080:localhost:8080 user@remote-server

# Open http://localhost:8080 in your browser
```

### CI/CD Integration

```yaml
# .github/workflows/fuzzing.yml
- name: Check Fuzzing Progress
  run: |
    afl-overseer -s /sync_dir
    # Parse output for coverage thresholds
```

---

## 🆚 Comparison with Legacy Tools

| Feature | Legacy afl-monitor | afl-whatsup | AFL Overseer |
|---------|-------------------|-------------|--------------|
| Python Version | 2.7 (EOL) | N/A (Shell) | 3.8+ |
| Interactive TUI | ❌ | ❌ | ✅ htop-like |
| Web Dashboard | ❌ | ❌ | ✅ netdata-like |
| Modern UI | ❌ | ❌ | ✅ Rich terminal |
| Light/Dark Themes | ❌ | ❌ | ✅ |
| Real-time Graphs | ❌ | ❌ | ✅ Chart.js |
| REST API | ❌ | ❌ | ✅ JSON |
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
sudo afl-overseer ...

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
afl-overseer /sync_dir

# Incorrect (will show error):
afl-overseer /sync_dir/fuzzer01
```

### No Color Output

If colors don't work:
```bash
# Set TERM environment variable
export TERM=xterm-256color
afl-overseer -s /sync_dir
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
git clone https://github.com/yourrepo/afl-overseer.git
cd afl-overseer

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
- Click, Rich, Textual, and aiohttp libraries

---

## 📧 Support

- Issues: [GitHub Issues](https://github.com/yourrepo/afl-overseer/issues)
- Discussions: [GitHub Discussions](https://github.com/yourrepo/afl-overseer/discussions)

---

## 🗺️ Roadmap

Future enhancements:
- [ ] Plotly interactive charts in web dashboard
- [ ] Configuration file support (YAML/TOML)
- [ ] WebSocket-based real-time updates (no polling)
- [ ] Slack/Discord/Telegram integrations
- [ ] Historical trending and analysis
- [ ] Multi-host campaign aggregation
- [ ] Prometheus metrics exporter
- [ ] Grafana dashboard templates
- [ ] CLI lightweight graphs (sparklines)

---

**Happy Fuzzing! 🐛💥**
