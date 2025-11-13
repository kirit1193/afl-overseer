"""Command-line interface for AFL Monitor."""

import sys
import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Optional

import click

from .models import MonitorConfig
from .monitor import AFLMonitor
from .process import ProcessMonitor
from .output_terminal import TerminalOutput
from .output_json import JSONOutput
from .output_html import HTMLOutput
from .utils import get_timestamp


def setup_logging(verbose: bool):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


@click.command()
@click.argument('findings_directory', type=click.Path(exists=True, file_okay=False), required=False)
@click.option('-c', '--terminal', 'output_terminal', is_flag=True, help='Output to terminal (default)')
@click.option('-h', '--html', 'html_dir', type=click.Path(), help='Generate HTML report in directory')
@click.option('-j', '--json', 'json_file', type=click.Path(), help='Write JSON output to file')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed per-fuzzer statistics')
@click.option('-n', '--no-color', is_flag=True, help='Disable colored output')
@click.option('-w', '--watch', 'watch_mode', is_flag=True, help='Watch mode - refresh automatically')
@click.option('-i', '--interval', default=5, help='Watch mode refresh interval in seconds (default: 5)')
@click.option('-d', '--show-dead', is_flag=True, help='Include dead fuzzers in output')
@click.option('-m', '--minimal', is_flag=True, help='Minimal output mode')
@click.option('-e', '--execute', 'execute_cmd', help='Execute command on new crash (pass stats via stdin)')
@click.option('--version', is_flag=True, help='Show version and exit')
def main(**kwargs):
    """
    AFL Monitor - Next Generation

    Modern monitoring and reporting tool for AFL/AFL++ fuzzing campaigns.

    FINDINGS_DIRECTORY should point to the AFL sync directory containing
    one or more fuzzer instance subdirectories.

    Examples:

    \b
      # Basic terminal output with details
      afl-monitor-ng -c -v /path/to/sync_dir

    \b
      # Generate HTML report
      afl-monitor-ng -h ./report /path/to/sync_dir

    \b
      # JSON output for automation
      afl-monitor-ng -j stats.json /path/to/sync_dir

    \b
      # Watch mode with auto-refresh every 10 seconds
      afl-monitor-ng -c -v -w -i 10 /path/to/sync_dir

    \b
      # Execute command on new crashes
      afl-monitor-ng -c -e './notify.sh' /path/to/sync_dir
    """
    if kwargs['version']:
        click.echo("AFL Monitor - Next Generation v2.0")
        sys.exit(0)

    # Check if findings_directory is provided
    if not kwargs.get('findings_directory'):
        click.echo("Error: Missing argument 'FINDINGS_DIRECTORY'.", err=True)
        click.echo("Try 'afl-monitor-ng --help' for help.")
        sys.exit(2)

    # Setup
    setup_logging(kwargs['verbose'])

    # Create config
    config = create_config(**kwargs)

    # Validate
    if not any([kwargs['output_terminal'], kwargs['html_dir'], kwargs['json_file']]):
        # Default to terminal if nothing specified
        config.output_format = ['terminal']

    # Run monitor
    try:
        if config.watch_mode:
            asyncio.run(run_watch_mode(config))
        else:
            asyncio.run(run_once(config))
    except KeyboardInterrupt:
        click.echo("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        if kwargs['verbose']:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def create_config(**kwargs) -> MonitorConfig:
    """Create monitor configuration from CLI arguments."""
    output_formats = []
    if kwargs.get('output_terminal') or not any([kwargs.get('html_dir'), kwargs.get('json_file')]):
        output_formats.append('terminal')
    if kwargs.get('html_dir'):
        output_formats.append('html')
    if kwargs.get('json_file'):
        output_formats.append('json')

    return MonitorConfig(
        findings_dir=Path(kwargs['findings_directory']),
        output_format=output_formats,
        html_dir=Path(kwargs['html_dir']) if kwargs.get('html_dir') else None,
        json_file=Path(kwargs['json_file']) if kwargs.get('json_file') else None,
        verbose=kwargs.get('verbose', False),
        no_color=kwargs.get('no_color', False),
        watch_mode=kwargs.get('watch_mode', False),
        watch_interval=kwargs.get('interval', 5),
        execute_command=kwargs.get('execute_cmd'),
        show_dead=kwargs.get('show_dead', False),
        minimal=kwargs.get('minimal', False),
    )


async def run_once(config: MonitorConfig):
    """Run monitoring once."""
    monitor = AFLMonitor(config)

    # Load previous state for delta calculation
    monitor.load_previous_state()

    # Collect statistics
    all_stats, summary = monitor.collect_stats()

    # Get system info
    system_info = ProcessMonitor.get_system_info()

    # Output
    if 'terminal' in config.output_format:
        terminal = TerminalOutput(config)
        terminal.print_banner()
        terminal.print_campaign_summary(summary, system_info)
        terminal.print_fuzzer_details(all_stats, monitor)

    if 'json' in config.output_format:
        json_out = JSONOutput(config)
        json_out.write_output(all_stats, summary, system_info)

    if 'html' in config.output_format:
        html_out = HTMLOutput(config)
        html_out.write_output(all_stats, summary, monitor, system_info)

    # Execute command on new crashes
    if config.execute_command and summary.new_crashes > 0:
        await execute_notification(config, summary, all_stats)

    # Save current state
    monitor.save_current_state(summary)


async def run_watch_mode(config: MonitorConfig):
    """Run monitoring in watch mode with auto-refresh."""
    monitor = AFLMonitor(config)
    terminal = TerminalOutput(config) if 'terminal' in config.output_format else None

    iteration = 0
    while True:
        # Load previous state
        monitor.load_previous_state()

        # Collect stats
        all_stats, summary = monitor.collect_stats()
        system_info = ProcessMonitor.get_system_info()

        # Output
        if terminal:
            terminal.print_watch_header(get_timestamp())
            terminal.print_campaign_summary(summary, system_info)
            terminal.print_fuzzer_details(all_stats, monitor)

            # Show next update time
            click.echo(f"\n[Refreshing every {config.watch_interval} seconds. Press Ctrl+C to exit]")

        if 'json' in config.output_format:
            json_out = JSONOutput(config)
            json_out.write_output(all_stats, summary, system_info)

        if 'html' in config.output_format:
            html_out = HTMLOutput(config)
            html_out.write_output(all_stats, summary, monitor, system_info)

        # Execute command on new crashes
        if config.execute_command and summary.new_crashes > 0:
            await execute_notification(config, summary, all_stats)

        # Save state
        monitor.save_current_state(summary)

        # Wait for next iteration
        iteration += 1
        await asyncio.sleep(config.watch_interval)


async def execute_notification(config: MonitorConfig, summary, all_stats):
    """Execute notification command."""
    try:
        # Prepare summary text
        summary_text = f"""AFL Monitor - New Crash Detected!

Timestamp: {get_timestamp()}
Total Crashes: {summary.total_crashes}
New Crashes: {summary.new_crashes}
Active Fuzzers: {summary.alive_fuzzers}/{summary.total_fuzzers}
Coverage: {summary.max_coverage:.2f}%

"""
        # Run command with summary as stdin
        process = await asyncio.create_subprocess_shell(
            config.execute_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate(summary_text.encode())

        if process.returncode != 0:
            logging.error(f"Notification command failed: {stderr.decode()}")
        else:
            logging.info("Notification command executed successfully")

    except Exception as e:
        logging.error(f"Error executing notification command: {e}")


if __name__ == '__main__':
    main()
