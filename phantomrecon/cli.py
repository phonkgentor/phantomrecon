"""
PhantomRecon -- CLI Interface

Cross-platform CLI built with Click + Rich.
Works on: Windows, Linux, macOS, Termux (Android), iSH (iOS), WSL
"""
import os
import sys
import platform
import asyncio
import click

# Cross-platform encoding fix
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phantomrecon import __version__
from phantomrecon.config import Config
from phantomrecon.core.scanner import run_scan, get_module_list, MODULES


console = Console(force_terminal=True)

BANNER = r"""
[bright_cyan]
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bright_cyan][bold bright_magenta]
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold bright_magenta]
[dim]    👻 AI-Powered Reconnaissance • v{version} • For Authorized Testing Only[/dim]
"""

DISCLAIMER = """[yellow]⚠️  DISCLAIMER: This tool is designed for authorized security testing only.
Always obtain proper written authorization before scanning any target.
Unauthorized scanning may violate local laws.[/yellow]"""


@click.group()
@click.version_option(version=__version__, prog_name="PhantomRecon")
def main():
    """👻 PhantomRecon — AI-Powered Reconnaissance Tool for Ethical Hackers"""
    pass


@main.command()
@click.argument("target")
@click.option("--modules", "-m", default=None, help="Comma-separated modules: subdomain,dns,whois,ports,headers,ssl,tech,email,virustotal")
@click.option("--profile", "-P", default=None, type=click.Choice(["quick", "standard", "deep"]), help="Scan profile: quick (3 modules), standard (8), deep (all)")
@click.option("--output", "-o", default=None, help="Output report file path")
@click.option("--format", "-f", "output_format", default="md", type=click.Choice(["md", "json", "html"]), help="Report format")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI analysis")
@click.option("--model", "-M", default=None, help="AI model to use (run 'phantomrecon models' to see list)")
@click.option("--provider", "-p", default=None, help="AI provider: groq, openai, anthropic, google, mistral, ollama, openrouter")
def scan(target, modules, profile, output, output_format, no_ai, model, provider):
    """Scan a target domain for reconnaissance data.

    Examples:

        phantomrecon scan example.com

        phantomrecon scan example.com --profile quick

        phantomrecon scan example.com --profile deep

        phantomrecon scan example.com --modules dns,headers,ssl

        phantomrecon scan example.com --provider openai --model gpt-4o

        phantomrecon scan example.com --no-ai
    """
    # Validate and set provider/model
    if provider:
        if provider not in Config.PROVIDERS:
            console.print(f"[red]Invalid provider: {provider}[/red]")
            console.print(f"[dim]Available: {', '.join(Config.PROVIDERS.keys())}[/dim]")
            return
        Config.AI_PROVIDER = provider
        if not model:
            # Use default model for that provider
            for mid, minfo in Config.PROVIDERS[provider]["models"].items():
                if minfo.get("default"):
                    Config.AI_MODEL = mid
                    break

    if model:
        if not Config.is_valid_model(model):
            console.print(f"[red]Unknown model: {model}[/red]")
            console.print("[dim]Run 'phantomrecon models' to see available models.[/dim]")
            return
        Config.AI_MODEL = model
        # Auto-detect provider from model
        detected = Config.get_provider_for_model(model)
        if detected and not provider:
            Config.AI_PROVIDER = detected
    # Display banner
    console.print(BANNER.format(version=__version__))
    console.print(DISCLAIMER)
    console.print()

    # Parse modules
    module_list = None
    if modules:
        module_list = get_module_list(modules)
        if not module_list:
            console.print("[red]No valid modules specified.[/red]")
            for name, mod in MODULES.items():
                console.print(f"  {mod['icon']} {name}")
            return
    elif profile:
        module_list = get_module_list(profile)
    else:
        module_list = get_module_list()

    # Display API status + model
    api_table = Table(show_header=False, box=None, padding=(0, 2))
    for api_name, status in Config.get_api_status().items():
        api_table.add_row(api_name, status)
    prov = Config.PROVIDERS.get(Config.AI_PROVIDER, {})
    prov_name = prov.get("name", Config.AI_PROVIDER)
    api_table.add_row("AI Provider", f"[bold]{prov_name}[/bold]")
    api_table.add_row("AI Model", f"[bold]{Config.AI_MODEL}[/bold]")
    console.print(Panel(api_table, title="[bold]Configuration[/bold]", border_style="dim", padding=(0, 2)))
    console.print()

    # Run scan
    try:
        results = asyncio.run(
            run_scan(
                domain=target,
                modules=module_list,
                no_ai=no_ai,
                output=output,
                output_format=output_format,
                console=console,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Scan failed: {str(e)}[/red]")


@main.command()
def modules():
    """📦 List all available recon modules."""
    console.print(f"\n[bold]👻 PhantomRecon v{__version__} — Available Modules[/bold]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Module", style="bold")
    table.add_column("Name")
    table.add_column("Description")

    module_descriptions = {
        "subdomain": "Enumerate subdomains via crt.sh, SecurityTrails, DNS brute-force",
        "dns": "Query all DNS record types (A, AAAA, MX, NS, TXT, SOA, etc.)",
        "whois": "WHOIS domain registration lookup",
        "ports": "Async TCP port scan + Shodan enrichment",
        "headers": "HTTP security header analysis with grading",
        "ssl": "SSL/TLS certificate inspection",
        "tech": "Web technology stack detection",
        "email": "Email address harvesting from public pages",
        "virustotal": "VirusTotal domain reputation (requires API key)",
    }

    for name, mod in MODULES.items():
        desc = module_descriptions.get(name, "")
        table.add_row(f"{mod['icon']} {name}", mod["name"], desc)

    console.print(table)
    console.print()


@main.command()
def apikeys():
    """Check API key configuration status."""
    console.print(f"\n[bold]PhantomRecon -- API Key Status[/bold]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Get Key")

    for api_name, status in Config.get_api_status().items():
        # Find website
        website = ""
        for p, pinfo in Config.PROVIDERS.items():
            if pinfo["name"] in api_name or api_name == pinfo["name"]:
                website = pinfo.get("website", "")
                break
        table.add_row(api_name, status, website)

    console.print(table)
    console.print("\n[dim]Configure API keys in your .env file. See .env.example for reference.[/dim]\n")


@main.command()
@click.option("--provider", "-p", default=None, help="Filter by provider: groq, openai, anthropic, google, mistral, ollama, openrouter")
def models(provider):
    """List available AI models for analysis."""
    console.print(f"\n[bold]PhantomRecon -- Available AI Models[/bold]\n")

    providers_to_show = {provider: Config.PROVIDERS[provider]} if provider and provider in Config.PROVIDERS else Config.PROVIDERS

    for prov_id, pinfo in providers_to_show.items():
        configured = Config.has_provider(prov_id)
        status = "[green]READY[/green]" if configured else "[dim]needs API key[/dim]"
        if prov_id == "ollama":
            status = "[green]LOCAL[/green]"

        console.print(f"  [bold bright_cyan]{pinfo['name']}[/bold bright_cyan] {status}")
        console.print(f"  [dim]{pinfo['description']}[/dim]")
        if pinfo.get('website'):
            console.print(f"  [dim]Key: {pinfo['website']}[/dim]")
        console.print()

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Model ID", style="bold")
        table.add_column("Name")
        table.add_column("Params")
        table.add_column("Speed")
        table.add_column("Info")

        for model_id, minfo in pinfo["models"].items():
            marker = " *" if minfo.get("default") else ""
            table.add_row(
                f"{model_id}{marker}",
                minfo["name"],
                minfo.get("params", ""),
                minfo.get("speed", ""),
                minfo.get("description", ""),
            )

        console.print(table)
        console.print()

    console.print(f"[dim]Current: provider=[bold]{Config.AI_PROVIDER}[/bold]  model=[bold]{Config.AI_MODEL}[/bold][/dim]")
    console.print("[dim]Usage:   phantomrecon scan example.com --provider openai --model gpt-4o[/dim]")
    console.print("[dim]         phantomrecon scan example.com --model claude-sonnet-4-20250514[/dim]")
    console.print("[dim]Or set AI_PROVIDER and AI_MODEL in your .env file.[/dim]\n")


if __name__ == "__main__":
    main()
