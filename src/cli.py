"""Command-line interface for AFL Overseer."""

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
@click.option('-t', '--tui', 'interactive_tui', is_flag=True, help='Interactive TUI mode (like htop)')
@click.option('-s', '--static', 'static_output', is_flag=True, help='Static terminal output (non-interactive)')
@click.option('-w', '--web', 'web_server', is_flag=True, help='Start web server with live dashboard')
@click.option('-p', '--port', 'web_port', default=8080, help='Web server port (default: 8080)')
@click.option('--headless', is_flag=True, help='Run web server in headless mode (without TUI)')
@click.option('-v', '--verbose', is_flag=True, help='Show detailed per-fuzzer statistics')
@click.option('-n', '--no-color', is_flag=True, help='Disable colored output')
@click.option('-i', '--interval', default=1, help='Refresh interval in seconds (default: 1)')
@click.option('-d', '--show-dead', is_flag=True, help='Include dead fuzzers in output')
@click.option('-m', '--minimal', is_flag=True, help='Minimal output mode')
@click.option('-e', '--execute', 'execute_cmd', help='Execute command on new crash (pass stats via stdin)')
@click.option('--version', is_flag=True, help='Show version and exit')
def main(**kwargs):
    """
    AFL Overseer

    Advanced monitoring and visualization tool for AFL/AFL++ fuzzing campaigns.

    FINDINGS_DIRECTORY should point to the AFL sync directory containing
    one or more fuzzer instance subdirectories.

    By default, starts interactive TUI mode (like htop). Use -s for static output
    or -w for web dashboard.

    Examples:

    \b
      # Interactive TUI (default, like htop)
      afl-overseer /path/to/sync_dir
      afl-overseer -t /path/to/sync_dir

    \b
      # Web dashboard with TUI
      afl-overseer -w /path/to/sync_dir

    \b
      # Web dashboard headless (no TUI)
      afl-overseer -w --headless /path/to/sync_dir

    \b
      # Static terminal output (one-time)
      afl-overseer -s /path/to/sync_dir

    \b
      # Interactive TUI controls:
      #   q - Quit
      #   r - Refresh now
      #   1/2/3 - Compact/Normal/Detailed view
      #   n/s/c/e - Sort by Name/Speed/Coverage/Execs
      #   d - Toggle dead fuzzers
      #   p - Pause/Resume
    """
    if kwargs['version']:
        click.echo("AFL Overseer v0.1")
        sys.exit(0)

    # Check if findings_directory is provided
    if not kwargs.get('findings_directory'):
        click.echo("Error: Missing argument 'FINDINGS_DIRECTORY'.", err=True)
        click.echo("Try 'afl-overseer --help' for help.")
        sys.exit(2)

    # Setup
    # Only show logs if verbose, otherwise suppress
    if kwargs['verbose']:
        setup_logging(True)
    else:
        logging.basicConfig(level=logging.ERROR)

    # Determine mode
    wants_static = kwargs['static_output']
    wants_web = kwargs['web_server']
    wants_headless = kwargs['headless']

    # Web server mode
    if wants_web:
        # Handle non-headless mode specially - TUI must run in main thread
        if not wants_headless:
            from .webserver import start_web_server_background
            from .tui import run_interactive_tui
            try:
                # Start web server in background thread
                web_thread = start_web_server_background(
                    findings_dir=Path(kwargs['findings_directory']),
                    port=kwargs['web_port'],
                    refresh_interval=kwargs['interval']
                )
                # Run TUI in main thread (required for signal handling)
                run_interactive_tui(
                    Path(kwargs['findings_directory']),
                    refresh_interval=kwargs['interval']
                )
            except KeyboardInterrupt:
                click.echo("\n\nShutting down...")
            except Exception as e:
                click.echo(f"\nError: {e}", err=True)
                if kwargs['verbose']:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
        else:
            # Headless mode - run web server in main async context
            from .webserver import run_web_server
            try:
                asyncio.run(run_web_server(
                    findings_dir=Path(kwargs['findings_directory']),
                    port=kwargs['web_port'],
                    headless=True,
                    refresh_interval=kwargs['interval']
                ))
            except KeyboardInterrupt:
                click.echo("\n\nShutting down...")
            except Exception as e:
                click.echo(f"\nError: {e}", err=True)
                if kwargs['verbose']:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
        return

    # Default to interactive TUI if just a directory is provided
    if not wants_static:
        # Interactive TUI mode (default)
        from .tui import run_interactive_tui
        try:
            run_interactive_tui(
                Path(kwargs['findings_directory']),
                refresh_interval=kwargs['interval']
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            click.echo(f"\nError: {e}", err=True)
            if kwargs['verbose']:
                import traceback
                traceback.print_exc()
            sys.exit(1)
        return

    # Static output mode
    config = create_config(**kwargs)

    # Run monitor
    try:
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
    return MonitorConfig(
        findings_dir=Path(kwargs['findings_directory']),
        output_format=['terminal'],
        html_dir=None,
        json_file=None,
        verbose=kwargs.get('verbose', False),
        no_color=kwargs.get('no_color', False),
        watch_mode=False,
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

    # Output to terminal
    terminal = TerminalOutput(config)
    terminal.print_banner()
    terminal.print_campaign_summary(summary, system_info)
    terminal.print_fuzzer_details(all_stats, monitor)

    # Execute command on new crashes
    if config.execute_command and summary.new_crashes > 0:
        await execute_notification(config, summary, all_stats)

    # Save current state
    monitor.save_current_state(summary)


async def execute_notification(config: MonitorConfig, summary, all_stats):
    """Execute notification command."""
    try:
        # Prepare summary text
        summary_text = f"""AFL Overseer - New Crash Detected!

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
