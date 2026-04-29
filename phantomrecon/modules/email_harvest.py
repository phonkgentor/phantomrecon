"""
👻 PhantomRecon — Email Harvesting Module

Harvests email addresses from public sources and web pages.
"""
import re
import requests
from bs4 import BeautifulSoup
from phantomrecon.config import Config


EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)


def harvest_from_webpage(url: str) -> set[str]:
    """Extract email addresses from a web page."""
    emails = set()
    try:
        resp = requests.get(
            url,
            timeout=Config.DEFAULT_TIMEOUT,
            headers={"User-Agent": "PhantomRecon/1.0 (Security Scanner)"},
            allow_redirects=True,
        )
        found = EMAIL_REGEX.findall(resp.text)
        for email in found:
            # Filter out common false positives
            if not any(fp in email.lower() for fp in [".png", ".jpg", ".gif", ".css", ".js", "example.com", "wixpress"]):
                emails.add(email.lower())
    except Exception:
        pass
    return emails


async def run(domain: str, console=None) -> dict:
    """Run email harvesting module."""
    all_emails = set()

    # 1. Harvest from main website
    if console:
        console.print("  [dim]├─ Scanning website for email addresses...[/dim]")
    for scheme in ["https", "http"]:
        found = harvest_from_webpage(f"{scheme}://{domain}")
        all_emails.update(found)
        if found:
            break

    # 2. Check common pages
    if console:
        console.print("  [dim]├─ Checking common pages...[/dim]")
    common_paths = ["/contact", "/about", "/team", "/support", "/privacy", "/impressum"]
    for path in common_paths:
        for scheme in ["https", "http"]:
            found = harvest_from_webpage(f"{scheme}://{domain}{path}")
            all_emails.update(found)
            if found:
                break

    # Filter to only emails matching the target domain
    domain_emails = [e for e in all_emails if domain.lower() in e.lower()]
    other_emails = [e for e in all_emails if domain.lower() not in e.lower()]

    return {
        "domain_emails": sorted(domain_emails),
        "other_emails": sorted(other_emails),
        "total_found": len(all_emails),
    }
