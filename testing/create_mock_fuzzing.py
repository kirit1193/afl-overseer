#!/usr/bin/env python3
"""Create a mock AFL fuzzing environment for testing performance."""

import os
import time
import random
from pathlib import Path

def create_fuzzer_stats(fuzzer_dir: Path, fuzzer_name: str, pid: int):
    """Create a realistic fuzzer_stats file."""
    current_time = int(time.time())
    start_time = current_time - random.randint(3600, 36000)

    stats_content = f"""start_time        : {start_time}
last_update       : {current_time}
run_time          : {current_time - start_time}
fuzzer_pid        : {pid}
cycles_done       : {random.randint(5, 50)}
cycles_wo_finds   : {random.randint(0, 15)}
execs_done        : {random.randint(100000, 5000000)}
execs_per_sec     : {random.uniform(200, 1500):.2f}
execs_ps_last_min : {random.uniform(180, 1600):.2f}
corpus_count      : {random.randint(50, 500)}
corpus_favored    : {random.randint(20, 200)}
corpus_found      : {random.randint(50, 500)}
corpus_imported   : 0
max_depth         : {random.randint(3, 10)}
cur_item          : {random.randint(0, 400)}
pending_favs      : {random.randint(0, 50)}
pending_total     : {random.randint(0, 100)}
bitmap_cvg        : {random.uniform(5.0, 45.0):.2f}%
saved_crashes     : {random.randint(0, 10)}
saved_hangs       : {random.randint(0, 3)}
last_find         : {current_time - random.randint(60, 3600)}
last_crash        : {current_time - random.randint(600, 7200)}
last_hang         : 0
exec_timeout      : 1000
afl_banner        : {fuzzer_name}
afl_version       : 4.09c
target_mode       : default
command_line      : afl-fuzz -i input -o sync -M {fuzzer_name} -- ./target
slowest_exec_ms   : {random.randint(50, 200)}
peak_rss_mb       : {random.randint(50, 300)}
cpu_affinity      : {random.randint(0, 15)}
edges_found       : {random.randint(1000, 5000)}
total_edges       : {random.randint(5000, 10000)}
var_byte_count    : {random.randint(100, 1000)}
havoc_expansion   : {random.randint(10, 100)}
auto_dict_entries : {random.randint(0, 50)}
testcache_size    : 50
testcache_count   : {random.randint(0, 50)}
testcache_evict   : {random.randint(0, 20)}
stability         : {random.uniform(85.0, 99.9):.2f}%
total_tmout       : {random.randint(0, 100)}
time_wo_finds     : {random.randint(0, 1800)}
fuzz_time         : {current_time - start_time - random.randint(0, 3600)}
calibration_time  : {random.randint(0, 300)}
cmplog_time       : 0
sync_time         : {random.randint(0, 600)}
trim_time         : {random.randint(0, 300)}
execs_since_crash : {random.randint(10000, 500000)}
"""

    stats_file = fuzzer_dir / "fuzzer_stats"
    with open(stats_file, 'w') as f:
        f.write(stats_content)

def create_plot_data(fuzzer_dir: Path):
    """Create a realistic plot_data file."""
    plot_file = fuzzer_dir / "plot_data"

    lines = ["# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec, total_execs, edges_found, total_crashes, servers_count\n"]

    # Generate 100 data points
    for i in range(100):
        rel_time = i * 60  # One per minute
        cycles = min(i // 20, 10)
        cur_item = min(i * 5, 400)
        corpus = min(50 + i * 3, 500)
        pending_total = max(0, 100 - i)
        pending_favs = max(0, 50 - i // 2)
        map_size = min(5.0 + i * 0.3, 45.0)
        crashes = min(i // 30, 5)
        hangs = min(i // 50, 2)
        depth = min(3 + i // 20, 8)
        speed = 500 + random.uniform(-100, 100)
        total_execs = i * 50000
        edges = min(1000 + i * 40, 5000)
        total_crashes = crashes
        servers = 4

        line = f"{rel_time}, {cycles}, {cur_item}, {corpus}, {pending_total}, {pending_favs}, {map_size:.2f}%, {crashes}, {hangs}, {depth}, {speed:.2f}, {total_execs}, {edges}, {total_crashes}, {servers}\n"
        lines.append(line)

    with open(plot_file, 'w') as f:
        f.writelines(lines)

def create_mock_environment(sync_dir: Path, num_slaves: int = 3):
    """Create a complete mock fuzzing environment."""
    print(f"Creating mock fuzzing environment in {sync_dir}")

    # Create sync directory
    sync_dir.mkdir(parents=True, exist_ok=True)

    # Create master fuzzer
    master_dir = sync_dir / "master"
    master_dir.mkdir(exist_ok=True)

    # Use current process PID + offset to simulate fuzzer PIDs
    base_pid = os.getpid() + 1000

    print(f"Creating master fuzzer...")
    create_fuzzer_stats(master_dir, "master", base_pid)
    create_plot_data(master_dir)

    # Create slave directories
    (master_dir / "queue").mkdir(exist_ok=True)
    (master_dir / "crashes").mkdir(exist_ok=True)
    (master_dir / "hangs").mkdir(exist_ok=True)

    # Create dummy queue files
    for i in range(10):
        (master_dir / "queue" / f"id:{i:06d},src:000000,time:0,execs:0").touch()

    # Create slave fuzzers
    for i in range(num_slaves):
        slave_name = f"slave{i+1:02d}"
        slave_dir = sync_dir / slave_name
        slave_dir.mkdir(exist_ok=True)

        print(f"Creating {slave_name}...")
        create_fuzzer_stats(slave_dir, slave_name, base_pid + i + 1)
        create_plot_data(slave_dir)

        (slave_dir / "queue").mkdir(exist_ok=True)
        (slave_dir / "crashes").mkdir(exist_ok=True)
        (slave_dir / "hangs").mkdir(exist_ok=True)

        for j in range(8):
            (slave_dir / "queue" / f"id:{j:06d},src:000000,time:0,execs:0").touch()

    print(f"\nMock environment created successfully!")
    print(f"Total fuzzers: 1 master + {num_slaves} slaves")
    print(f"Location: {sync_dir}")

if __name__ == "__main__":
    testing_dir = Path(__file__).parent
    sync_dir = testing_dir / "mock_sync"

    create_mock_environment(sync_dir, num_slaves=3)

    print("\nYou can now test afl-overseer with:")
    print(f"  ./afl-overseer {sync_dir}")
