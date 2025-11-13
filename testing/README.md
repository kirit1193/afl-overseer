# Testing Directory

This directory contains testing utilities for afl-overseer.

## Mock Fuzzing Environment

The `create_mock_fuzzing.py` script creates a simulated AFL fuzzing directory structure for testing and performance benchmarking.

### Usage

```bash
# Create mock environment (1 master + 3 slaves by default)
python3 create_mock_fuzzing.py

# Test afl-overseer against the mock environment
cd ..
./afl-overseer testing/mock_sync
```

### What it Creates

- `mock_sync/master/` - Master fuzzer instance
- `mock_sync/slave01/` - First slave instance
- `mock_sync/slave02/` - Second slave instance
- `mock_sync/slave03/` - Third slave instance

Each fuzzer directory contains:
- `fuzzer_stats` - Realistic AFL stats file
- `plot_data` - Historical performance data
- `queue/`, `crashes/`, `hangs/` - Standard AFL directories

### Files

- `target.c` - Simple vulnerable C program for demonstration
- `create_mock_fuzzing.py` - Script to generate mock fuzzing environment
- `mock_sync/` - Generated mock environment (created by script)

## Performance Testing

The mock environment is useful for:
- Testing afl-overseer features without running actual fuzzers
- Performance benchmarking and optimization
- Developing new features
- Regression testing
