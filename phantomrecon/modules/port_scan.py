"""
👻 PhantomRecon — Port Scanning Module

Fast async TCP connect scan with service banner grabbing.
Optionally enriched with Shodan data.
"""
import asyncio
import socket
from phantomrecon.config import Config


# Common port -> service name mapping
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "WebUI", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 27017: "MongoDB",
    5000: "Flask/UPnP", 5001: "Synology", 8000: "HTTP-Alt",
    10000: "Webmin", 49152: "Dynamic", 49153: "Dynamic",
    49154: "Dynamic", 49155: "Dynamic",
}


async def scan_port(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """Scan a single port using async TCP connect."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        # Try to grab banner
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(
                asyncio.ensure_future(_read_banner(_, writer)),
                timeout=2.0
            )
            banner = data
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        service = SERVICE_MAP.get(port, "Unknown")

        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner.strip() if banner else "",
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _read_banner(reader, writer):
    """Read banner from service."""
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


async def query_shodan(target: str) -> dict:
    """Query Shodan API for host information (if API key configured)."""
    if not Config.has_shodan():
        return {}

    try:
        import shodan
        api = shodan.Shodan(Config.SHODAN_API_KEY)

        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {}

        host = api.host(ip)
        return {
            "ip": host.get("ip_str", ""),
            "org": host.get("org", ""),
            "os": host.get("os", ""),
            "isp": host.get("isp", ""),
            "ports": host.get("ports", []),
            "vulns": host.get("vulns", []),
            "hostnames": host.get("hostnames", []),
            "city": host.get("city", ""),
            "country_name": host.get("country_name", ""),
            "last_update": host.get("last_update", ""),
            "services": [
                {
                    "port": svc.get("port", 0),
                    "transport": svc.get("transport", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": svc.get("data", "")[:200],
                }
                for svc in host.get("data", [])
            ],
        }
    except Exception:
        return {}


async def run(domain: str, console=None) -> dict:
    """
    Run port scanning module.

    Returns:
        dict with open ports, Shodan data (if available)
    """
    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": f"Could not resolve {domain}", "open_ports": [], "shodan": {}}

    if console:
        console.print(f"  [dim]├─ Target IP: {ip}[/dim]")
        console.print(f"  [dim]├─ Scanning {len(Config.TOP_PORTS)} common ports...[/dim]")

    # Scan ports concurrently
    tasks = [scan_port(ip, port) for port in Config.TOP_PORTS]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r is not None]
    open_ports.sort(key=lambda x: x["port"])

    # Query Shodan if available
    shodan_data = {}
    if Config.has_shodan():
        if console:
            console.print("  [dim]├─ Querying Shodan API...[/dim]")
        shodan_data = await query_shodan(domain)

    return {
        "target_ip": ip,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "scanned_count": len(Config.TOP_PORTS),
        "shodan": shodan_data,
    }
