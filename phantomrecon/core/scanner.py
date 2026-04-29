"""
PhantomRecon -- Scanner Orchestrator

Coordinates all recon modules, displays professional results, and manages scan execution.
"""
import asyncio
import time
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from phantomrecon.modules import subdomain, dns_enum, whois_lookup, port_scan
from phantomrecon.modules import headers, ssl_check, tech_detect, email_harvest
from phantomrecon.modules import virustotal
from phantomrecon.ai.analyzer import analyze
from phantomrecon.config import Config


# All available modules
MODULES = {
    "subdomain": {"name": "Subdomain Enumeration", "icon": "🔍", "runner": subdomain},
    "dns": {"name": "DNS Records", "icon": "📡", "runner": dns_enum},
    "whois": {"name": "WHOIS Lookup", "icon": "📋", "runner": whois_lookup},
    "ports": {"name": "Port Scanning", "icon": "🔌", "runner": port_scan},
    "headers": {"name": "Security Headers", "icon": "🛡️", "runner": headers},
    "ssl": {"name": "SSL/TLS Check", "icon": "🔒", "runner": ssl_check},
    "tech": {"name": "Tech Detection", "icon": "🖥️", "runner": tech_detect},
    "email": {"name": "Email Harvesting", "icon": "📧", "runner": email_harvest},
    "virustotal": {"name": "VirusTotal Lookup", "icon": "🦠", "runner": virustotal},
}

# Scan profiles
PROFILES = {
    "quick": ["dns", "headers", "ssl"],
    "standard": ["subdomain", "dns", "whois", "ports", "headers", "ssl", "tech", "email"],
    "deep": ["subdomain", "dns", "whois", "ports", "headers", "ssl", "tech", "email", "virustotal"],
}


def get_module_list(selected: str = None) -> list[str]:
    """Get list of modules to run."""
    if selected:
        # Check if it's a profile name
        if selected in PROFILES:
            return PROFILES[selected]
        names = [m.strip() for m in selected.split(",")]
        return [n for n in names if n in MODULES]
    # Default: standard profile
    default = [k for k in MODULES if k != "virustotal"]
    if Config.has_virustotal():
        default.append("virustotal")
    return default


def _display_subdomain_results(result: dict, console: Console):
    """Display subdomain results in a professional table."""
    subs = result.get("subdomains", [])
    if not subs:
        return

    table = Table(title="Discovered Subdomains", box=box.ROUNDED,
                  border_style="cyan", show_lines=False, pad_edge=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Subdomain", style="bold white")
    table.add_column("IP Address", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Source", style="dim")

    for i, s in enumerate(subs[:30], 1):
        status = "[green]LIVE[/green]" if s.get("status") == "live" else "[red]DEAD[/red]"
        table.add_row(str(i), s.get("subdomain", ""), s.get("ip", ""), status, s.get("source", ""))

    if len(subs) > 30:
        table.add_row("...", f"[dim]+{len(subs) - 30} more[/dim]", "", "", "")

    console.print(table)


def _display_dns_results(result: dict, console: Console):
    """Display DNS records in a professional table."""
    records = result.get("records", {})
    if not records:
        return

    table = Table(title="DNS Records", box=box.ROUNDED,
                  border_style="cyan", show_lines=False)
    table.add_column("Type", style="bold yellow", width=8)
    table.add_column("Value", style="white")
    table.add_column("TTL", style="dim", justify="right", width=8)

    for rtype, recs in records.items():
        for r in recs:
            table.add_row(rtype, r.get("value", ""), str(r.get("ttl", "")))

    console.print(table)


def _display_whois_results(result: dict, console: Console):
    """Display WHOIS data in a panel."""
    if result.get("error"):
        return

    table = Table(box=None, show_header=False, padding=(0, 2))
    fields = [
        ("Domain", "domain_name"), ("Registrar", "registrar"),
        ("Created", "creation_date"), ("Expires", "expiration_date"),
        ("Updated", "updated_date"), ("Nameservers", "name_servers"),
        ("Organization", "org"), ("Country", "country"),
        ("DNSSEC", "dnssec"),
    ]
    for label, key in fields:
        val = result.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val[:3])
            table.add_row(f"[bold]{label}[/bold]", str(val))

    console.print(Panel(table, title="[bold]WHOIS Registration[/bold]", border_style="cyan"))


def _display_port_results(result: dict, console: Console):
    """Display port scan results."""
    ports = result.get("open_ports", [])
    if not ports:
        console.print("  [dim]No open ports found[/dim]")
        return

    table = Table(title="Open Ports", box=box.ROUNDED,
                  border_style="cyan", show_lines=False)
    table.add_column("Port", style="bold red", justify="right", width=7)
    table.add_column("Service", style="yellow")
    table.add_column("Banner", style="dim", max_width=50)

    for p in ports:
        port_str = str(p["port"])
        table.add_row(port_str, p.get("service", ""), p.get("banner", "")[:50])

    console.print(table)

    # Shodan enrichment
    shodan = result.get("shodan", {})
    if shodan and not shodan.get("error"):
        vulns = shodan.get("vulns", [])
        if vulns:
            console.print(f"\n  [bold red]Shodan Vulnerabilities: {', '.join(vulns[:10])}[/bold red]")
        console.print(f"  [dim]Shodan: {shodan.get('org', '')} | {shodan.get('isp', '')} | {shodan.get('country_name', '')}[/dim]")


def _display_header_results(result: dict, console: Console):
    """Display security headers with grade."""
    grade = result.get("grade", "N/A")
    score = result.get("score", 0)

    # Color the grade
    grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "bold red"}
    grade_color = grade_colors.get(grade, "white")

    # Grade display
    grade_panel = Panel(
        f"[{grade_color}][bold]{grade}[/bold][/{grade_color}]\n[dim]{score}%[/dim]",
        title="Grade", border_style=grade_color, width=12
    )

    primary = result.get("results", {}).get("https", result.get("results", {}).get("http", {}))
    header_list = primary.get("headers", [])

    table = Table(box=None, show_header=False, padding=(0, 1))
    for h in header_list:
        icon = "[green]✓[/green]" if h["present"] else "[red]✗[/red]"
        sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(h["severity"], "white")
        table.add_row(icon, f"[{sev_color}]{h['header']}[/{sev_color}]")

    console.print(Panel(
        table, title=f"[bold]Security Headers — Grade: [{grade_color}]{grade}[/{grade_color}][/bold]",
        border_style="cyan"
    ))


def _display_ssl_results(result: dict, console: Console):
    """Display SSL certificate info."""
    if result.get("error"):
        console.print(f"  [yellow]{result['error']}[/yellow]")
        return

    valid = result.get("valid", False)
    days = result.get("days_remaining", 0)
    status_color = "green" if valid and days > 30 else ("yellow" if days > 0 else "red")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_row("[bold]Valid[/bold]", f"[{status_color}]{'Yes' if valid else 'No'}[/{status_color}]")
    table.add_row("[bold]Days Left[/bold]", f"[{status_color}]{days}[/{status_color}]")
    table.add_row("[bold]Issuer[/bold]", str(result.get("issuer", {}).get("organizationName", "N/A")))
    table.add_row("[bold]Subject[/bold]", str(result.get("subject", {}).get("commonName", "N/A")))
    table.add_row("[bold]SANs[/bold]", str(result.get("san_count", 0)))
    table.add_row("[bold]Status[/bold]", result.get("status", ""))

    console.print(Panel(table, title="[bold]SSL/TLS Certificate[/bold]", border_style="cyan"))


def _display_tech_results(result: dict, console: Console):
    """Display detected technologies."""
    categories = result.get("categories", {})
    if not categories:
        return

    table = Table(title="Detected Technologies", box=box.ROUNDED,
                  border_style="cyan", show_lines=False)
    table.add_column("Category", style="bold yellow")
    table.add_column("Technologies", style="white")

    for cat, techs in categories.items():
        table.add_row(cat, ", ".join(techs))

    console.print(table)


def _display_email_results(result: dict, console: Console):
    """Display harvested emails."""
    domain_emails = result.get("domain_emails", [])
    other_emails = result.get("other_emails", [])
    all_emails = domain_emails + other_emails
    if not all_emails:
        return

    table = Table(title="Harvested Emails", box=box.ROUNDED,
                  border_style="cyan", show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("Email", style="bold white")
    table.add_column("Type", justify="center")

    for i, e in enumerate(domain_emails[:20], 1):
        table.add_row(str(i), e, "[green]Domain[/green]")
    for i, e in enumerate(other_emails[:10], len(domain_emails) + 1):
        table.add_row(str(i), e, "[dim]External[/dim]")

    console.print(table)


def _display_vt_results(result: dict, console: Console):
    """Display VirusTotal results."""
    if not result.get("available"):
        return

    rep = result.get("reputation", "CLEAN")
    rep_colors = {"CLEAN": "green", "SUSPICIOUS": "yellow", "MALICIOUS": "bold red"}
    rep_color = rep_colors.get(rep, "white")

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_row("[bold]Reputation[/bold]", f"[{rep_color}]{rep}[/{rep_color}]")
    table.add_row("[bold]Malicious[/bold]", str(result.get("malicious_detections", 0)))
    table.add_row("[bold]Suspicious[/bold]", str(result.get("suspicious_detections", 0)))
    table.add_row("[bold]Engines[/bold]", str(result.get("total_engines", 0)))

    console.print(Panel(table, title="[bold]VirusTotal Intelligence[/bold]", border_style="cyan"))


# Module result display functions
DISPLAY_MAP = {
    "subdomain": _display_subdomain_results,
    "dns": _display_dns_results,
    "whois": _display_whois_results,
    "ports": _display_port_results,
    "headers": _display_header_results,
    "ssl": _display_ssl_results,
    "tech": _display_tech_results,
    "email": _display_email_results,
    "virustotal": _display_vt_results,
}


def _display_scan_summary(domain: str, results: dict, total_time: float, console: Console):
    """Display a professional summary dashboard at the end."""
    console.print()
    console.print(Panel("[bold white]SCAN SUMMARY[/bold white]",
                        border_style="bright_cyan", padding=(0, 2)))

    summary = Table(box=None, show_header=False, padding=(0, 3))

    # Gather stats
    subs = results.get("subdomain", {}).get("total_count", 0)
    live_subs = results.get("subdomain", {}).get("live_count", 0)
    ports = results.get("ports", {}).get("open_count", 0)
    grade = results.get("headers", {}).get("grade", "N/A")
    ssl_days = results.get("ssl", {}).get("days_remaining", "N/A")
    techs = results.get("tech", {}).get("total_detected", 0)
    emails = results.get("email", {}).get("total_found", 0)
    dns_count = results.get("dns", {}).get("total_records", 0)

    grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "bold red"}
    gc = grade_colors.get(grade, "white")

    summary.add_row(
        f"[bold]Target[/bold]       [cyan]{domain}[/cyan]",
        f"[bold]Subdomains[/bold]   [white]{subs}[/white] ({live_subs} live)",
        f"[bold]Open Ports[/bold]   [{'red' if ports > 5 else 'white'}]{ports}[/{'red' if ports > 5 else 'white'}]",
    )
    summary.add_row(
        f"[bold]DNS Records[/bold]  [white]{dns_count}[/white]",
        f"[bold]Technologies[/bold] [white]{techs}[/white]",
        f"[bold]Emails[/bold]       [white]{emails}[/white]",
    )
    summary.add_row(
        f"[bold]Headers[/bold]      [{gc}]{grade}[/{gc}]",
        f"[bold]SSL Expiry[/bold]   {ssl_days} days",
        f"[bold]Scan Time[/bold]    {total_time:.1f}s",
    )

    console.print(summary)
    console.print()


async def run_scan(domain: str, modules: list[str] = None, no_ai: bool = False,
                   output: str = None, output_format: str = "md", console: Console = None) -> dict:
    """
    Run a full reconnaissance scan.
    """
    if console is None:
        console = Console()

    if modules is None:
        modules = get_module_list()

    results = {}
    start_time = time.time()
    total = len(modules)
    timings = {}

    # ── Scan Header ──
    console.print()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = Table.grid(padding=(0, 1))
    header.add_row(Text("Target:", style="bold white"), Text(domain, style="bold cyan"))
    header.add_row(Text("Modules:", style="bold white"), Text(str(total), style="bold green"))
    header.add_row(Text("Started:", style="bold white"), Text(now, style="dim"))
    header.add_row(Text("Provider:", style="bold white"),
                   Text(f"{Config.PROVIDERS.get(Config.AI_PROVIDER, {}).get('name', Config.AI_PROVIDER)}", style="bold"))
    header.add_row(Text("Model:", style="bold white"), Text(Config.AI_MODEL, style="bold"))
    console.print(Panel(header, title="[bold white]SCAN CONFIGURATION[/bold white]",
                        border_style="bright_cyan", padding=(1, 2)))

    # ── Run Modules ──
    console.print()
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}[/bold]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        for idx, mod_name in enumerate(modules, 1):
            mod = MODULES.get(mod_name)
            if not mod:
                continue

            icon = mod["icon"]
            name = mod["name"]
            task_id = progress.add_task(f"{icon} [{idx}/{total}] {name}...", total=None)

            try:
                mod_start = time.time()
                result = await mod["runner"].run(domain, console=None)  # Suppress sub-module output
                elapsed = time.time() - mod_start
                timings[mod_name] = elapsed

                results[mod_name] = result
                progress.remove_task(task_id)

                # Print summary line
                summary = _get_module_summary(mod_name, result)
                console.print(
                    f"  [green]✓[/green] [bold cyan][{idx}/{total}][/bold cyan] {icon} "
                    f"[bold]{name}[/bold]  [green]{summary}[/green]  [dim]{elapsed:.1f}s[/dim]"
                )

            except Exception as e:
                results[mod_name] = {"error": str(e)}
                progress.remove_task(task_id)
                console.print(
                    f"  [red]✗[/red] [bold cyan][{idx}/{total}][/bold cyan] {icon} "
                    f"[bold]{name}[/bold]  [red]{str(e)[:60]}[/red]"
                )

    # ── Detailed Results ──
    console.print()
    console.print(Panel("[bold white]DETAILED RESULTS[/bold white]",
                        border_style="bright_cyan", padding=(0, 2)))
    console.print()

    for mod_name in modules:
        result = results.get(mod_name, {})
        if "error" in result:
            continue

        display_fn = DISPLAY_MAP.get(mod_name)
        if display_fn:
            try:
                display_fn(result, console)
                console.print()
            except Exception:
                pass  # Skip display errors gracefully

    # ── Summary Dashboard ──
    total_time = time.time() - start_time
    _display_scan_summary(domain, results, total_time, console)

    # ── AI Analysis ──
    if not no_ai:
        prov_name = Config.PROVIDERS.get(Config.AI_PROVIDER, {}).get("name", Config.AI_PROVIDER)
        console.print(Panel(
            f"[bold]AI ANALYSIS[/bold]  [dim]{prov_name} / {Config.AI_MODEL}[/dim]",
            border_style="bright_magenta", padding=(0, 2)
        ))
        ai_result = analyze(domain, results, console=console)
        results["ai_analysis"] = ai_result
    else:
        console.print("  [dim]AI analysis skipped (--no-ai flag)[/dim]")

    # ── Footer ──
    total_time = time.time() - start_time
    console.print()
    console.print(f"  [bold bright_cyan]Scan completed in {total_time:.1f}s[/bold bright_cyan]")
    console.print(f"  [dim]{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print()

    # Generate report if output specified
    if output:
        from phantomrecon.core.reporter import generate_report
        generate_report(domain, results, output, output_format, console)

    return results


def _get_module_summary(mod_name: str, result: dict) -> str:
    """Get a one-line summary for a module result."""
    if "error" in result:
        return f"Error: {result['error'][:40]}"

    summaries = {
        "subdomain": lambda r: f"{r.get('total_count', 0)} subdomains ({r.get('live_count', 0)} live)",
        "dns": lambda r: f"{r.get('total_records', 0)} records",
        "whois": lambda r: "retrieved" if not r.get("available") else "domain available",
        "ports": lambda r: f"{r.get('open_count', 0)} open ports",
        "headers": lambda r: f"Grade {r.get('grade', 'N/A')} ({r.get('missing_count', 0)} missing)",
        "ssl": lambda r: f"{'valid' if r.get('valid') else 'invalid'} ({r.get('days_remaining', '?')}d left)",
        "tech": lambda r: f"{r.get('total_detected', 0)} technologies",
        "email": lambda r: f"{r.get('total_found', 0)} emails",
        "virustotal": lambda r: f"{r.get('reputation', 'N/A')}" if r.get("available") else "not configured",
    }

    formatter = summaries.get(mod_name, lambda r: "done")
    try:
        return formatter(result)
    except Exception:
        return "done"
