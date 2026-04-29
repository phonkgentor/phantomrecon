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
@click.option("--provider", "-p", default=None, help="Configure a specific provider directly")
def setup(provider):
    """🔑 Interactive API key setup wizard.

    Configure your AI providers and security API keys directly from the CLI.
    Opens the provider's website so you can grab your key instantly.

    Examples:

        phantomrecon setup

        phantomrecon setup --provider groq

        phantomrecon setup --provider openai
    """
    import webbrowser
    from pathlib import Path

    console.print(f"\n[bold]PhantomRecon -- API Key Setup Wizard[/bold]\n")

    env_path = Path(__file__).parent.parent / ".env"

    # Read existing .env content
    env_lines = {}
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    env_lines[key.strip()] = val.strip()

    # Build provider list with security tools
    all_services = []
    for prov_id, pinfo in Config.PROVIDERS.items():
        if prov_id == "ollama":
            continue  # No key needed
        all_services.append({
            "id": prov_id,
            "name": pinfo["name"],
            "env_key": pinfo["env_key"],
            "website": pinfo.get("website", ""),
            "description": pinfo["description"],
            "type": "ai",
        })

    # Add security tool APIs
    all_services.extend([
        {"id": "shodan", "name": "Shodan", "env_key": "SHODAN_API_KEY",
         "website": "https://account.shodan.io", "description": "Port & service intelligence", "type": "security"},
        {"id": "virustotal", "name": "VirusTotal", "env_key": "VIRUSTOTAL_API_KEY",
         "website": "https://www.virustotal.com/gui/join-us", "description": "Domain reputation & threat intel", "type": "security"},
        {"id": "securitytrails", "name": "SecurityTrails", "env_key": "SECURITYTRAILS_API_KEY",
         "website": "https://securitytrails.com/app/signup", "description": "Historical DNS & subdomain data", "type": "security"},
    ])

    # Filter to specific provider if requested
    if provider:
        all_services = [s for s in all_services if s["id"] == provider]
        if not all_services:
            console.print(f"[red]Unknown provider: {provider}[/red]")
            console.print(f"[dim]Available: groq, openai, anthropic, google, mistral, openrouter, shodan, virustotal, securitytrails[/dim]")
            return

    # Show current status
    console.print("[bold cyan]Current API Key Status:[/bold cyan]\n")
    status_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    status_table.add_column("#", style="dim", width=3)
    status_table.add_column("Provider", style="bold")
    status_table.add_column("Status")
    status_table.add_column("Type", style="dim")

    for i, svc in enumerate(all_services, 1):
        current_val = env_lines.get(svc["env_key"], "")
        if current_val and current_val not in ("", "your_groq_api_key_here"):
            status = "[green]✅ Configured[/green]"
        else:
            status = "[dim]⬜ Not set[/dim]"
        svc_type = "[cyan]AI Provider[/cyan]" if svc["type"] == "ai" else "[yellow]Security API[/yellow]"
        status_table.add_row(str(i), svc["name"], status, svc_type)

    console.print(status_table)
    console.print()

    # Interactive setup
    if not provider:
        console.print("[bold]Enter the number of the provider to configure (or 'q' to quit):[/bold]")
        choice = click.prompt("Select provider", type=str)
        if choice.lower() in ("q", "quit", "exit"):
            console.print("[dim]Setup cancelled.[/dim]")
            return
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(all_services):
                console.print("[red]Invalid selection.[/red]")
                return
            selected = all_services[idx]
        except ValueError:
            # Try matching by name/id
            selected = None
            for svc in all_services:
                if choice.lower() in (svc["id"], svc["name"].lower()):
                    selected = svc
                    break
            if not selected:
                console.print(f"[red]Unknown provider: {choice}[/red]")
                return
    else:
        selected = all_services[0]

    # Show provider info and guide
    console.print()
    console.print(Panel(
        f"[bold]{selected['name']}[/bold]\n"
        f"[dim]{selected['description']}[/dim]\n\n"
        f"[bold cyan]Get your API key here:[/bold cyan]\n"
        f"[link={selected['website']}]{selected['website']}[/link]\n\n"
        f"[dim]Steps:[/dim]\n"
        f"  1. Click the link above (or it will open in your browser)\n"
        f"  2. Sign up / Log in to your account\n"
        f"  3. Create a new API key\n"
        f"  4. Copy the key and paste it below",
        title=f"[bold]Setup: {selected['name']}[/bold]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))

    # Open website in browser
    try:
        console.print(f"\n[dim]Opening {selected['website']} in your browser...[/dim]")
        webbrowser.open(selected["website"])
    except Exception:
        console.print(f"[dim]Could not open browser. Visit: {selected['website']}[/dim]")

    # Prompt for API key
    console.print()
    current = env_lines.get(selected["env_key"], "")
    if current and current not in ("", "your_groq_api_key_here"):
        masked = current[:8] + "..." + current[-4:] if len(current) > 12 else "***"
        console.print(f"[dim]Current key: {masked}[/dim]")

    api_key = click.prompt(
        f"\nPaste your {selected['name']} API key",
        type=str,
        default="",
        show_default=False,
    ).strip()

    if not api_key:
        console.print("[yellow]No key entered. Skipping.[/yellow]")
        return

    # Save to .env
    env_lines[selected["env_key"]] = api_key

    # Write back .env
    with open(env_path, "w") as f:
        f.write("# PhantomRecon Configuration\n")
        f.write("# Generated by: phantomrecon setup\n\n")

        # AI config
        f.write("# AI Provider Selection\n")
        f.write(f"AI_PROVIDER={env_lines.get('AI_PROVIDER', Config.AI_PROVIDER)}\n")
        f.write(f"AI_MODEL={env_lines.get('AI_MODEL', Config.AI_MODEL)}\n\n")

        # Provider keys
        f.write("# LLM Provider API Keys\n")
        for prov_id, pinfo in Config.PROVIDERS.items():
            if pinfo.get("env_key"):
                val = env_lines.get(pinfo["env_key"], "")
                f.write(f"{pinfo['env_key']}={val}\n")

        f.write(f"\nOLLAMA_HOST={env_lines.get('OLLAMA_HOST', 'http://localhost:11434')}\n")

        # Security keys
        f.write("\n# Security Tool API Keys\n")
        for key_name in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY"):
            val = env_lines.get(key_name, "")
            f.write(f"{key_name}={val}\n")

    # Update runtime config
    attr_map = {
        "GROQ_API_KEY": "GROQ_API_KEY",
        "OPENAI_API_KEY": "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY": "GOOGLE_API_KEY",
        "MISTRAL_API_KEY": "MISTRAL_API_KEY",
        "OPENROUTER_API_KEY": "OPENROUTER_API_KEY",
        "SHODAN_API_KEY": "SHODAN_API_KEY",
        "VIRUSTOTAL_API_KEY": "VIRUSTOTAL_API_KEY",
        "SECURITYTRAILS_API_KEY": "SECURITYTRAILS_API_KEY",
    }
    if selected["env_key"] in attr_map:
        setattr(Config, attr_map[selected["env_key"]], api_key)

    console.print()
    console.print(Panel(
        f"[green]✅ {selected['name']} API key saved successfully![/green]\n\n"
        f"[dim]Saved to: {env_path}[/dim]\n"
        f"[dim]Variable: {selected['env_key']}[/dim]\n\n"
        f"[bold]You can now use {selected['name']} for scans:[/bold]\n"
        + (f"  phantomrecon scan example.com --provider {selected['id']}\n" if selected["type"] == "ai" else
           f"  phantomrecon scan example.com --profile deep\n"),
        title="[bold green]Success[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))

    # Ask if they want to configure another
    if not provider:
        console.print()
        if click.confirm("Configure another provider?", default=False):
            # Re-invoke setup
            ctx = click.get_current_context()
            ctx.invoke(setup, provider=None)


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
