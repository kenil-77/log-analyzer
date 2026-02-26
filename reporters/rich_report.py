from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Console is the main rich object — all output goes through it
console = Console()

def print_rich_report(results, failed_logins, successful_logins):
    """
    Takes brute force results and prints a beautiful
    formatted report using the rich library.
    """

    # ── Summary Panel ──────────────────────────────────────
    console.print(Panel.fit(
        f"[bold cyan]SSH LOG ANALYSIS REPORT[/bold cyan]\n"
        f"[white]Total Failed Logins:     [red]{len(failed_logins)}[/red]\n"
        f"Total Successful Logins: [green]{len(successful_logins)}[/green]\n"
        f"Suspicious IPs Detected: [yellow]{len(results)}[/yellow][/white]",
        title="[bold white]Summary[/bold white]",
        border_style="cyan"
    ))

    console.print()  # empty line for spacing

    # ── Brute Force Table ───────────────────────────────────
    table = Table(
        title="Brute Force Detection Results",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True
    )

    # Add columns to the table
    table.add_column("IP Address",       style="cyan",   min_width=18)
    table.add_column("Attempts",         style="white",  min_width=10, justify="center")
    table.add_column("Users Targeted",   style="yellow", min_width=20)
    table.add_column("First Seen",       style="white",  min_width=20)
    table.add_column("Last Seen",        style="white",  min_width=20)
    table.add_column("Status",           style="white",  min_width=12, justify="center")

    # Add one row per IP
    for r in results:
        # Flagged IPs get red status, low ones get yellow
        if r['is_flagged']:
            status = "[bold red]⚠ FLAGGED[/bold red]"
            attempts = f"[bold red]{r['total_attempts']}[/bold red]"
        else:
            status = "[yellow]LOW[/yellow]"
            attempts = f"[yellow]{r['total_attempts']}[/yellow]"

        table.add_row(
            r['ip'],
            attempts,
            ', '.join(r['usernames_tried']),
            r['first_seen'],
            r['last_seen'],
            status
        )

    console.print(table)
    console.print()

    # ── Successful Logins Table ─────────────────────────────
    if successful_logins:
        success_table = Table(
            title="Successful Logins",
            box=box.ROUNDED,
            border_style="green",
            header_style="bold green",
            show_lines=True
        )

        success_table.add_column("Timestamp", style="white", min_width=20)
        success_table.add_column("Username",  style="green", min_width=15)
        success_table.add_column("IP Address", style="cyan", min_width=18)

        for login in successful_logins:
            success_table.add_row(
                login['timestamp'],
                login['user'],
                login['ip']
            )

        console.print(success_table)
        console.print()
