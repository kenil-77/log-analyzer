import argparse
import sys
import os

from parsers.ssh_parser import parse_ssh_log
from analyzers.brute_force import detect_brute_force, detect_username_attacks
from reporters.report import (
    print_summary_panel,
    print_brute_force_table,
    print_username_table,
    export_json_report
)
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description='Log Analyzer — SSH Brute Force Detection Tool',
        epilog='Example: python main.py --log /var/log/auth.log --threshold 10 --export'
    )

    parser.add_argument(
        '--log',
        required=True,
        help='Path to the log file to analyze (e.g., /var/log/auth.log)'
    )

    parser.add_argument(
        '--threshold',
        type=int,
        default=5,
        help='Number of failed attempts before flagging an IP (default: 5)'
    )

    parser.add_argument(
        '--export',
        action='store_true',
        help='Export findings to report.json'
    )

    args = parser.parse_args()

    # Validate that the file actually exists before trying to parse it
    if not os.path.exists(args.log):
        console.print(f"[red]Error:[/red] File not found: {args.log}")
        sys.exit(1)

    console.print(f"\n[cyan][*][/cyan] Parsing log file: [white]{args.log}[/white]")

    # Step 1: Parse the log file
    failed_logins, successful_logins = parse_ssh_log(args.log)

    console.print(f"[cyan][*][/cyan] Found [red]{len(failed_logins)}[/red] failed logins, "
                  f"[green]{len(successful_logins)}[/green] successful logins")

    # Step 2: Analyze for brute force
    console.print(f"[cyan][*][/cyan] Analyzing with threshold: [yellow]{args.threshold}[/yellow]")
    brute_force_counts, ip_targets = detect_brute_force(failed_logins, args.threshold)
    username_attacks = detect_username_attacks(failed_logins)

    # Step 3: Print the report
    print_summary_panel(failed_logins, successful_logins, brute_force_counts)
    print_brute_force_table(ip_targets)
    print_username_table(username_attacks)

    # Step 4: Export if requested
    if args.export:
        export_json_report(failed_logins, successful_logins, ip_targets)


if __name__ == '__main__':
    main()
