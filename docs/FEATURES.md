# Features

## Directory Detection

The tool detects whether you're pointing to:
- A single fuzzer directory (contains `fuzzer_stats` directly)
- A sync directory (contains multiple fuzzer subdirectories)

This allows monitoring individual fuzzers or entire campaigns.

## User Interfaces

### Interactive TUI (Default)

Terminal interface with real-time updates:
- Sortable columns (name, speed, coverage, executions, crashes)
- Three detail levels: Compact (5 cols), Normal (7 cols), Detailed (12 cols)
- Keyboard controls for sorting and filtering
- Dark color scheme with muted highlighting

Keyboard shortcuts:
- `q` - Quit
- `r` - Refresh now
- `1/2/3` - Switch detail levels
- `n/s/c/e/r` - Sort columns
- `d` - Toggle dead fuzzers
- `p` - Pause/Resume auto-refresh

### Web Dashboard

Browser-based interface on port 8080 (configurable):
- Real-time graphs using Chart.js
- Light/Dark theme toggle
- REST API endpoint at `/api/stats`
- Responsive design for mobile devices
- Optional headless mode (web server without TUI)

### Static Terminal Output

One-time snapshot for scripts and automation:
- Terminal output using Rich library
- Supports crash notifications via command execution
- Suitable for cron jobs and CI/CD pipelines

## Error Handling

Critical operations include error handling:
- Permission errors on inaccessible directories
- Missing or corrupt data files
- API failures (returns HTTP 500 with error details)
- Port conflicts (port already in use)
- TUI errors display user notifications

## Security

- State persistence uses JSON instead of pickle
- No command injection vulnerabilities
- Input validation on parsed fields
- File operations use pathlib

## Statistics

### Campaign Summary
- Fuzzer status counts (alive/dead/starting/total)
- Cumulative runtime across all fuzzers
- Total executions and speed metrics
- Average speed per core
- Maximum coverage reached
- Total crashes and hangs with delta indicators
- Last activity timestamps

### Per-Fuzzer Metrics
- All fields from `fuzzer_stats` (50+ metrics)
- Process status detection
- CPU and memory usage
- Execution speed and totals
- Corpus progress
- Coverage percentage
- Crashes and hangs
- Stability metrics
- Cycle counts
- Timeout information

## AFL++ 4.x Support

Parses all AFL++ 4.x fields including:
- Test cache metrics (`testcache_size`, `testcache_count`, `testcache_evict`)
- CPU affinity and peak RSS
- Edge coverage (`edges_found`, `total_edges`)
- Mutation metrics (`var_byte_count`, `havoc_expansion`)
- Dictionary entries
- Execution timing (`slowest_exec_ms`, `execs_since_crash`)
- Version and target mode info

## Process Status Detection

Fuzzer status is determined by:
- **Alive**: Process exists (validated via `os.kill(pid, 0)`)
- **Dead**: Process PID not found
- **Starting**: `fuzzer_setup` file is newer than `fuzzer_stats`
- **Unknown**: Status cannot be determined

## Performance Warnings

Detects potential issues:
- Dead fuzzer instances
- High timeout ratio (≥10%)
- Slow execution speed (<100 execs/sec)
- Cycles without new finds (>10 cycles warning, >50 critical)
- Low corpus stability (<80%)
- High execution timeouts (>100ms)

## Usage Examples

### TUI Mode
```bash
afl-overseer /path/to/sync_dir
```

### Web Dashboard
```bash
# With TUI
afl-overseer -w /path/to/sync_dir

# Headless mode
afl-overseer -w --headless /path/to/sync_dir

# Custom port
afl-overseer -w -p 3000 /path/to/sync_dir
```

### Static Output
```bash
# One-time snapshot
afl-overseer -s /path/to/sync_dir

# With per-fuzzer details
afl-overseer -s -v /path/to/sync_dir

# Execute command on new crashes
afl-overseer -s -e './notify.sh' /path/to/sync_dir
```

## Comparison with Existing Tools

| Feature | afl-whatsup | afl-monitor (legacy) | afl-overseer |
|---------|-------------|---------------------|--------------|
| Language | Shell script | Python 2.7 | Python 3.8+ |
| Interactive TUI | No | No | Yes |
| Web Dashboard | No | No | Yes |
| Single Fuzzer Support | No | No | Yes |
| Error Handling | Basic | Limited | Comprehensive |
| Security Issues | None known | pickle, deprecated modules | None |
| AFL++ 4.x Fields | Partial | No | Complete |
| Resource Monitoring | Basic (via ps) | No | CPU + Memory (psutil) |
| Color Output | Basic | Bright colors | Muted colors |
