"""
👻 PhantomRecon — DNS Enumeration Module

Queries all DNS record types for comprehensive domain intelligence.
"""
import dns.resolver
from phantomrecon.config import Config


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]


def query_records(domain: str, record_type: str) -> list[dict]:
    """Query DNS records of a specific type."""
    records = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = Config.DEFAULT_TIMEOUT
    resolver.lifetime = Config.DEFAULT_TIMEOUT

    try:
        answers = resolver.resolve(domain, record_type)
        for rdata in answers:
            record = {
                "type": record_type,
                "value": str(rdata),
                "ttl": answers.rrset.ttl,
            }

            # Extract priority for MX records
            if record_type == "MX":
                record["priority"] = rdata.preference
                record["exchange"] = str(rdata.exchange)

            # Extract details for SOA records
            if record_type == "SOA":
                record["mname"] = str(rdata.mname)
                record["rname"] = str(rdata.rname)
                record["serial"] = rdata.serial
                record["refresh"] = rdata.refresh
                record["retry"] = rdata.retry
                record["expire"] = rdata.expire

            records.append(record)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoNameservers:
        pass
    except Exception:
        pass

    return records


async def run(domain: str, console=None) -> dict:
    """
    Run DNS enumeration module.

    Returns:
        dict with all DNS records organized by type
    """
    results = {}
    total_count = 0

    for rtype in RECORD_TYPES:
        if console:
            console.print(f"  [dim]├─ Querying {rtype} records...[/dim]")
        records = query_records(domain, rtype)
        if records:
            results[rtype] = records
            total_count += len(records)

    return {
        "records": results,
        "record_types_found": list(results.keys()),
        "total_records": total_count,
    }
