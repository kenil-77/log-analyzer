from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import json
from datetime import datetime

console = Console()

def print_summary_panel(failed_logins, successful_logins, brute_force_ips):
    summary = Text()
    summary.append(f"Total Failed Logins: ", style="white")
    summary.append(f"{len(failed_logins)}\n", style="bold red")
    summary.append(f"Total Successful Logins: ", style="white")
    summary.append(f"{len(successful_logins)}\n", style="bold green")
    summary.append(f"Suspicious IPs Detected: ", style="white")
    summary.append(f"{len(brute_force_ips)}", style="bold yellow")

    console.print(Panel(summary, title="[bold cyan]LOG ANALYZER — SECURITY REPORT[/bold cyan]",
                        border_style="cyan"))


def print_brute_force_table(ip_targets):
    if not ip_targets:
        console.print("\n[green]✓ No brute force attempts detected.[/green]")
        return

    table = Table(
        title="🚨 Brute Force Suspects",
        box=box.ROUNDED,
        border_style="red",
        show_lines=True
    )

    table.add_column("IP Address",     style="cyan",   no_wrap=True)
    table.add_column("Attempts",       style="red",    justify="center")
    table.add_column("Targeted Users", style="yellow")
    table.add_column("First Seen",     style="white")
    table.add_column("Last Seen",      style="white")

    for ip, data in ip_targets.items():
        users = ", ".join(data['targeted_users'][:5])
        if len(data['targeted_users']) > 5:
            users += f" (+{len(data['targeted_users'])-5} more)"

        table.add_row(
            ip,
            str(data['count']),
            users,
            data['first_seen'],
            data['last_seen']
        )

    console.print("\n")
    console.print(table)


def print_username_table(username_attacks):
    table = Table(title="🎯 Most Targeted Usernames", box=box.SIMPLE)
    table.add_column("Username",       style="yellow")
    table.add_column("Times Targeted", style="red", justify="center")

    for username, count in list(username_attacks.items())[:10]:
        table.add_row(username, str(count))

    console.print("\n")
    console.print(table)


def export_json_report(failed_logins, successful_logins, ip_targets, output_path="report.json"):
    report = {
        'generated_at': datetime.now().isoformat(),
        'summary': {
            'total_failed': len(failed_logins),
            'total_successful': len(successful_logins),
            'suspicious_ips': len(ip_targets)
        },
        'brute_force_suspects': ip_targets,
        'failed_logins': failed_logins[:100],
    }

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[green]✓ JSON report saved to:[/green] {output_path}")
