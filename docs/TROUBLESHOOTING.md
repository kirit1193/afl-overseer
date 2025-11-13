# Troubleshooting

## Installation Issues

### Old Textual Version

Error: `cannot import name 'ComposeResult' from 'textual.app'`

System has Textual < 0.40.0. Fix with:

```bash
# Virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# Or upgrade user packages
pip3 install --user --upgrade textual>=0.40.0
```

### Missing Dependencies

Error: `ModuleNotFoundError: No module named 'click'`

The tool detects missing packages and displays installation commands automatically.

## Runtime Issues

### Permission Denied

Cannot access fuzzer directories:

```bash
# Add user to fuzzer's group
sudo usermod -a -G fuzzer $USER

# Or run with elevated permissions
sudo afl-overseer /path/to/sync_dir
```

### Port Already in Use

Error: `Port 8080 is already in use`

```bash
# Use different port
afl-overseer -w -p 9090 /path/to/sync_dir

# Or stop process using the port
lsof -i :8080
kill <PID>
```

### No Fuzzers Detected

Check directory structure:
```
/sync_dir/
  ├── fuzzer01/fuzzer_stats
  ├── fuzzer02/fuzzer_stats
  └── ...
```

Verify fuzzer_stats files exist:
```bash
ls -la /path/to/sync_dir/*/fuzzer_stats
```

Tool works with both sync directories and single fuzzer directories:
```bash
afl-overseer /path/to/sync_dir          # Multiple fuzzers
afl-overseer /path/to/sync_dir/fuzzer01 # Single fuzzer
```

### Color Issues

Terminal doesn't display colors correctly:

```bash
# Set TERM variable
export TERM=xterm-256color

# Or disable colors
afl-overseer -s -n /path/to/sync_dir
```

## Data Collection Issues

### Fuzzer Shows as Dead

Possible causes:
- Fuzzer actually stopped
- Permission issues reading PID
- Process in zombie state

Debug:
```bash
ps aux | grep afl-fuzz
cat /path/to/fuzzer/fuzzer_stats | grep fuzzer_pid
sudo -u fuzzer afl-overseer /path/to/sync_dir
```

### Incorrect Statistics

Possible causes:
- Corrupted fuzzer_stats file
- AFL++ version mismatch
- Partial file read

Debug:
```bash
cat /path/to/fuzzer/fuzzer_stats
ls -la /path/to/fuzzer/fuzzer_stats
afl-overseer -s -v /path/to/sync_dir
```

### Web Dashboard Not Loading

Verify server is running:
```bash
afl-overseer -w /path/to/sync_dir  # Should show startup message
curl http://localhost:8080
```

Check firewall:
```bash
sudo iptables -L -n | grep 8080
```

URLs:
- Local: `http://localhost:8080`
- Network: `http://<server-ip>:8080`

## Performance Issues

### High CPU Usage

Causes:
- Frequent refresh interval
- Many fuzzers monitored
- Large plot_data files

Solutions:
```bash
# Increase refresh interval
afl-overseer -t -i 10 /path/to/sync_dir

# Use static mode with watch
watch -n 5 "afl-overseer -s /path/to/sync_dir"
```

### Slow Startup

Causes:
- Many fuzzers with large plot_data files
- Network mounted filesystems
- Slow permission checks

Solutions:
- Use local filesystem
- Reduce number of monitored fuzzers
- Check filesystem performance: `iostat`

## Common Error Messages

### "Directory not found"

Path doesn't exist. Verify:
```bash
ls -la /path/to/sync_dir
```

### "Cannot iterate directory"

Permission denied reading directory. Fix:
```bash
ls -ld /path/to/sync_dir
chmod +rx /path/to/sync_dir
```

### "Failed to collect stats"

Error parsing fuzzer_stats files. Check:
1. Files are readable
2. AFL/AFL++ is writing valid data
3. No file corruption

### "API endpoint returned 500"

Web server error. Debug:
1. Check server logs in terminal
2. Verify directory accessibility
3. Test with static mode: `afl-overseer -s /path/to/sync_dir`

## Reporting Issues

When reporting bugs on GitHub, include:
- AFL Overseer version: `afl-overseer --version`
- Python version: `python3 --version`
- AFL/AFL++ version
- Operating system and version
- Full error message
- Directory structure: `tree -L 2 /path/to/sync_dir`

GitHub Issues: https://github.com/kirit1193/afl-overseer/issues
