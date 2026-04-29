"""
👻 PhantomRecon — WHOIS Lookup Module

Retrieves domain registration information via WHOIS protocol.
"""
import whois


async def run(domain: str, console=None) -> dict:
    """
    Run WHOIS lookup module.

    Returns:
        dict with registration data
    """
    if console:
        console.print("  [dim]└─ Querying WHOIS database...[/dim]")

    try:
        w = whois.whois(domain)

        # Normalize fields (whois library can return lists or strings)
        def normalize(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else None

        result = {
            "domain_name": normalize(w.domain_name),
            "registrar": normalize(w.registrar),
            "whois_server": normalize(w.whois_server),
            "creation_date": normalize(w.creation_date),
            "expiration_date": normalize(w.expiration_date),
            "updated_date": normalize(w.updated_date),
            "name_servers": normalize(w.name_servers),
            "status": normalize(w.status),
            "emails": normalize(w.emails),
            "registrant": normalize(getattr(w, "name", None)),
            "org": normalize(getattr(w, "org", None)),
            "country": normalize(getattr(w, "country", None)),
            "state": normalize(getattr(w, "state", None)),
            "city": normalize(getattr(w, "city", None)),
            "dnssec": normalize(getattr(w, "dnssec", None)),
            "available": False,
        }

        return result

    except whois.parser.PywhoisError:
        return {
            "domain_name": domain,
            "available": True,
            "error": "Domain may not be registered or WHOIS data unavailable",
        }
    except Exception as e:
        return {
            "domain_name": domain,
            "error": str(e),
        }
