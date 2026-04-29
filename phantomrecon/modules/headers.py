"""
👻 PhantomRecon — HTTP Security Headers Module

Analyzes HTTP response headers for security best practices.
"""
import requests
from phantomrecon.config import Config

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks (CSP)",
        "severity": "HIGH",
        "recommendation": "Implement a Content-Security-Policy header with strict directives",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter",
        "severity": "LOW",
        "recommendation": "Add 'X-XSS-Protection: 0' (rely on CSP instead)",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "severity": "LOW",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin'",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource sharing",
        "severity": "LOW",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin'",
    },
}


def analyze_headers(url: str) -> dict:
    """Fetch and analyze HTTP headers from a URL."""
    try:
        resp = requests.get(
            url, timeout=Config.DEFAULT_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "PhantomRecon/1.0 (Security Scanner)"}, verify=True,
        )
        analysis = []
        for header_name, info in SECURITY_HEADERS.items():
            present = header_name in resp.headers
            analysis.append({
                "header": header_name, "present": present,
                "value": resp.headers.get(header_name, "") if present else None,
                "severity": info["severity"], "description": info["description"],
                "recommendation": info["recommendation"] if not present else None,
            })

        total = len(SECURITY_HEADERS)
        present_count = sum(1 for a in analysis if a["present"])
        score = round((present_count / total) * 100)
        if score >= 90: grade = "A+"
        elif score >= 80: grade = "A"
        elif score >= 70: grade = "B"
        elif score >= 60: grade = "C"
        elif score >= 50: grade = "D"
        else: grade = "F"

        return {
            "url": str(resp.url), "status_code": resp.status_code,
            "server": resp.headers.get("Server", "Unknown"), "headers": analysis,
            "present_count": present_count, "missing_count": total - present_count,
            "score": score, "grade": grade, "all_headers": dict(resp.headers),
        }
    except requests.exceptions.SSLError:
        return {"url": url, "error": "SSL certificate verification failed"}
    except requests.exceptions.ConnectionError:
        return {"url": url, "error": "Connection refused or host unreachable"}
    except requests.exceptions.Timeout:
        return {"url": url, "error": "Connection timed out"}
    except Exception as e:
        return {"url": url, "error": str(e)}


async def run(domain: str, console=None) -> dict:
    """Run security headers analysis module."""
    results = {}
    if console:
        console.print("  [dim]├─ Checking HTTPS headers...[/dim]")
    https_result = analyze_headers(f"https://{domain}")
    if "error" not in https_result:
        results["https"] = https_result
    else:
        results["https_error"] = https_result.get("error", "")

    if console:
        console.print("  [dim]└─ Checking HTTP headers...[/dim]")
    http_result = analyze_headers(f"http://{domain}")
    if "error" not in http_result:
        results["http"] = http_result
    else:
        results["http_error"] = http_result.get("error", "")

    primary = results.get("https", results.get("http", {}))
    return {
        "results": results, "grade": primary.get("grade", "N/A"),
        "score": primary.get("score", 0), "missing_count": primary.get("missing_count", 0),
        "present_count": primary.get("present_count", 0), "server": primary.get("server", "Unknown"),
    }
