"""
👻 PhantomRecon — Subdomain Enumeration Module

Discovers subdomains using:
  1. DNS brute-force with wordlist
  2. Certificate Transparency logs (crt.sh)
  3. External APIs (SecurityTrails if configured)
"""
import socket
import asyncio
import aiohttp
import dns.resolver
from typing import Optional
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from phantomrecon.config import Config


async def query_crtsh(domain: str) -> list[dict]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    seen = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and sub.endswith(f".{domain}") and sub not in seen:
                                seen.add(sub)
                                subdomains.append({"subdomain": sub, "source": "crt.sh"})
    except Exception:
        pass  # crt.sh may be slow or unavailable

    return subdomains


async def query_securitytrails(domain: str) -> list[dict]:
    """Query SecurityTrails API for subdomains (if API key configured)."""
    if not Config.has_securitytrails():
        return []

    subdomains = []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": Config.SECURITYTRAILS_API_KEY, "Accept": "application/json"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for sub in data.get("subdomains", []):
                        full = f"{sub}.{domain}"
                        subdomains.append({"subdomain": full, "source": "SecurityTrails"})
    except Exception:
        pass

    return subdomains


def brute_force_subdomains(domain: str, wordlist_path: Optional[str] = None, progress=None, task_id=None) -> list[dict]:
    """Brute-force subdomains using a wordlist and DNS resolution."""
    subdomains = []
    wl_path = wordlist_path or Config.WORDLIST_PATH

    try:
        with open(wl_path, "r") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        words = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "app", "m", "mobile", "portal", "vpn", "remote",
            "cdn", "static", "assets", "img", "images", "media", "docs",
            "wiki", "help", "support", "status", "monitor", "dashboard",
            "git", "gitlab", "jenkins", "ci", "cd", "deploy", "build",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "ns1", "ns2", "ns3", "dns", "mx", "smtp", "pop", "imap",
            "webmail", "exchange", "owa", "autodiscover", "cpanel",
            "whm", "plesk", "panel", "login", "sso", "auth", "oauth",
            "beta", "alpha", "sandbox", "demo", "preview", "stage",
            "internal", "intranet", "extranet", "gateway", "proxy",
            "backup", "bak", "old", "new", "v2", "v3", "legacy",
        ]

    if progress and task_id is not None:
        progress.update(task_id, total=len(words))

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for word in words:
        subdomain = f"{word}.{domain}"
        try:
            answers = resolver.resolve(subdomain, "A")
            ip = str(answers[0])
            subdomains.append({
                "subdomain": subdomain,
                "ip": ip,
                "source": "brute-force",
                "status": "live"
            })
        except Exception:
            pass

        if progress and task_id is not None:
            progress.advance(task_id)

    return subdomains


def resolve_subdomain(subdomain: str) -> Optional[str]:
    """Resolve a subdomain to its IP address."""
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None


async def run(domain: str, console=None) -> dict:
    """
    Run subdomain enumeration module.

    Returns:
        dict with 'subdomains' list and 'count' integer
    """
    all_subdomains = {}

    # 1. Query crt.sh (Certificate Transparency)
    if console:
        console.print("  [dim]├─ Querying Certificate Transparency logs (crt.sh)...[/dim]")
    crtsh_results = await query_crtsh(domain)
    for entry in crtsh_results:
        sub = entry["subdomain"]
        if sub not in all_subdomains:
            all_subdomains[sub] = entry

    # 2. Query SecurityTrails (if available)
    if Config.has_securitytrails():
        if console:
            console.print("  [dim]├─ Querying SecurityTrails API...[/dim]")
        st_results = await query_securitytrails(domain)
        for entry in st_results:
            sub = entry["subdomain"]
            if sub not in all_subdomains:
                all_subdomains[sub] = entry

    # 3. DNS Brute-force
    if console:
        console.print("  [dim]├─ DNS brute-force enumeration...[/dim]")
    bf_results = brute_force_subdomains(domain)
    for entry in bf_results:
        sub = entry["subdomain"]
        if sub not in all_subdomains:
            all_subdomains[sub] = entry

    # 4. Resolve IPs for all discovered subdomains
    if console:
        console.print("  [dim]└─ Resolving IP addresses...[/dim]")
    for sub_name, entry in all_subdomains.items():
        if "ip" not in entry or not entry.get("ip"):
            ip = resolve_subdomain(sub_name)
            entry["ip"] = ip or "unresolved"
            entry["status"] = "live" if ip else "dead"

    subdomains_list = list(all_subdomains.values())

    return {
        "subdomains": subdomains_list,
        "live_count": sum(1 for s in subdomains_list if s.get("status") == "live"),
        "total_count": len(subdomains_list),
    }
