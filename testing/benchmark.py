#!/usr/bin/env python3
"""Benchmark afl-overseer performance with various fuzzer counts."""

import os
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import MonitorConfig
from src.monitor import AFLMonitor

def create_large_mock_environment(sync_dir: Path, num_fuzzers: int):
    """Create a mock environment with many fuzzers."""
    import random

    sync_dir.mkdir(parents=True, exist_ok=True)

    # Use actual running PIDs to make fuzzers appear alive
    current_pid = os.getpid()

    for i in range(num_fuzzers):
        fuzzer_name = f"fuzzer{i:03d}"
        fuzzer_dir = sync_dir / fuzzer_name
        fuzzer_dir.mkdir(exist_ok=True)

        current_time = int(time.time())
        start_time = current_time - random.randint(3600, 36000)

        # Use current PID to make it seem alive
        stats_content = f"""start_time        : {start_time}
last_update       : {current_time}
run_time          : {current_time - start_time}
fuzzer_pid        : {current_pid}
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

        with open(fuzzer_dir / "fuzzer_stats", 'w') as f:
            f.write(stats_content)

def benchmark_collection(num_fuzzers: int, num_runs: int = 5):
    """Benchmark stats collection."""
    sync_dir = Path(__file__).parent / f"bench_{num_fuzzers}"

    # Clean up and create environment
    import shutil
    if sync_dir.exists():
        shutil.rmtree(sync_dir)

    print(f"\nCreating environment with {num_fuzzers} fuzzers...")
    create_large_mock_environment(sync_dir, num_fuzzers)

    # Benchmark
    config = MonitorConfig(findings_dir=sync_dir)
    monitor = AFLMonitor(config)

    # Warm up psutil cache
    import psutil
    psutil.cpu_percent(interval=0.1)

    print(f"Benchmarking {num_fuzzers} fuzzers ({num_runs} runs):")

    times = []
    for i in range(num_runs):
        start = time.time()
        stats, summary = monitor.collect_stats()
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)
        print(f"  Run {i+1}: {elapsed:.1f}ms ({len(stats)} fuzzers found)")

    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)

    print(f"  Average: {avg_time:.1f}ms")
    print(f"  Min: {min_time:.1f}ms")
    print(f"  Max: {max_time:.1f}ms")
    print(f"  Throughput: {num_fuzzers / (avg_time / 1000):.0f} fuzzers/sec")

    # Clean up
    shutil.rmtree(sync_dir)

    return avg_time

if __name__ == "__main__":
    print("=" * 60)
    print("AFL Overseer Performance Benchmark")
    print("=" * 60)

    # Test with different fuzzer counts
    fuzzer_counts = [4, 10, 20, 50, 100]

    results = {}
    for count in fuzzer_counts:
        avg_time = benchmark_collection(count)
        results[count] = avg_time

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"{'Fuzzers':<10} {'Avg Time':<15} {'Throughput':<15}")
    print("-" * 60)
    for count, avg_time in results.items():
        throughput = count / (avg_time / 1000)
        print(f"{count:<10} {avg_time:>8.1f}ms      {throughput:>8.0f} fuzzers/sec")

    print("\nOptimizations applied:")
    print("  ✓ CPU monitoring uses interval=0 (instant cached readings)")
    print("  ✓ Parallel fuzzer processing with ThreadPoolExecutor")
    print("  ✓ Reduced fuser timeout from 2s to 0.5s")
    print("  ✓ Optimized startup detection logic")
