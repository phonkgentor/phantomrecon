"""
👻 PhantomRecon — VirusTotal Integration Module

Queries VirusTotal API for domain reputation and threat intelligence.
"""
import requests
from phantomrecon.config import Config


async def query_domain(domain: str) -> dict:
    """Query VirusTotal for domain reputation data."""
    if not Config.has_virustotal():
        return {}

    headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"VirusTotal returned status {resp.status_code}"}

        data = resp.json().get("data", {}).get("attributes", {})

        # Parse analysis stats
        stats = data.get("last_analysis_stats", {})
        total_engines = sum(stats.values())
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Determine reputation
        if malicious > 5:
            reputation = "MALICIOUS"
        elif malicious > 0 or suspicious > 2:
            reputation = "SUSPICIOUS"
        else:
            reputation = "CLEAN"

        return {
            "reputation": reputation,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "total_engines": total_engines,
            "categories": data.get("categories", {}),
            "popularity_ranks": data.get("popularity_ranks", {}),
            "creation_date": data.get("creation_date", ""),
            "whois": data.get("whois", "")[:500],
            "last_analysis_date": data.get("last_analysis_date", ""),
            "tags": data.get("tags", []),
        }
    except Exception as e:
        return {"error": str(e)}


async def run(domain: str, console=None) -> dict:
    """Run VirusTotal lookup."""
    if not Config.has_virustotal():
        return {"available": False, "message": "VirusTotal API key not configured"}

    if console:
        console.print("  [dim]└─ Querying VirusTotal API...[/dim]")

    result = await query_domain(domain)
    result["available"] = True
    return result
