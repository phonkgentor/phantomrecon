"""
👻 PhantomRecon — SSL/TLS Certificate Check Module
"""
import ssl
import socket
import datetime
from phantomrecon.config import Config


async def run(domain: str, console=None) -> dict:
    """Run SSL/TLS certificate check."""
    if console:
        console.print("  [dim]└─ Fetching SSL/TLS certificate...[/dim]")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(Config.DEFAULT_TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()

        # Parse dates
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days_left = (not_after - now).days

        # Extract SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            sans.append(san_value)

        # Extract subject
        subject = {}
        for field in cert.get("subject", []):
            for key, value in field:
                subject[key] = value

        # Extract issuer
        issuer = {}
        for field in cert.get("issuer", []):
            for key, value in field:
                issuer[key] = value

        # Determine status
        if days_left < 0:
            status = "EXPIRED"
            risk = "CRITICAL"
        elif days_left < 30:
            status = "EXPIRING_SOON"
            risk = "HIGH"
        elif days_left < 90:
            status = "WARNING"
            risk = "MEDIUM"
        else:
            status = "VALID"
            risk = "LOW"

        return {
            "valid": days_left >= 0,
            "status": status,
            "risk": risk,
            "subject": subject,
            "issuer": issuer,
            "not_before": str(not_before),
            "not_after": str(not_after),
            "days_remaining": days_left,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", ""),
            "sans": sans,
            "san_count": len(sans),
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "status": "INVALID", "risk": "CRITICAL", "error": str(e)}
    except socket.timeout:
        return {"valid": False, "error": "Connection timed out on port 443"}
    except ConnectionRefusedError:
        return {"valid": False, "error": "Port 443 is closed — no SSL/TLS"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
