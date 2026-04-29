"""
👻 PhantomRecon — Technology Detection Module

Detects web technologies from HTTP headers, HTML content, and scripts.
"""
import re
import requests
from bs4 import BeautifulSoup
from phantomrecon.config import Config


# Technology signatures: (name, category, detection patterns)
TECH_SIGNATURES = {
    # Web Servers
    "Apache": {"category": "Web Server", "headers": ["apache"], "html": []},
    "Nginx": {"category": "Web Server", "headers": ["nginx"], "html": []},
    "IIS": {"category": "Web Server", "headers": ["microsoft-iis"], "html": []},
    "LiteSpeed": {"category": "Web Server", "headers": ["litespeed"], "html": []},
    "Cloudflare": {"category": "CDN/WAF", "headers": ["cloudflare"], "html": []},
    # Frameworks
    "React": {"category": "JS Framework", "headers": [], "html": ["react", "__NEXT_DATA__", "_reactRoot"]},
    "Next.js": {"category": "JS Framework", "headers": ["x-powered-by: next.js"], "html": ["__NEXT_DATA__", "_next/"]},
    "Vue.js": {"category": "JS Framework", "headers": [], "html": ["vue.js", "vue.min.js", "__vue__"]},
    "Angular": {"category": "JS Framework", "headers": [], "html": ["ng-version", "angular"]},
    "jQuery": {"category": "JS Library", "headers": [], "html": ["jquery.min.js", "jquery.js"]},
    # CMS
    "WordPress": {"category": "CMS", "headers": [], "html": ["wp-content", "wp-includes", "wordpress"]},
    "Drupal": {"category": "CMS", "headers": ["x-drupal"], "html": ["drupal.js", "drupal.min.js"]},
    "Joomla": {"category": "CMS", "headers": [], "html": ["/media/jui/", "joomla"]},
    # Analytics
    "Google Analytics": {"category": "Analytics", "headers": [], "html": ["google-analytics.com", "gtag", "ga.js"]},
    "Google Tag Manager": {"category": "Analytics", "headers": [], "html": ["googletagmanager.com"]},
    # Security
    "reCAPTCHA": {"category": "Security", "headers": [], "html": ["recaptcha", "g-recaptcha"]},
    # Hosting
    "AWS": {"category": "Hosting", "headers": ["amazons3", "awselb", "x-amz"], "html": ["amazonaws.com"]},
    "Vercel": {"category": "Hosting", "headers": ["x-vercel", "vercel"], "html": []},
    "Netlify": {"category": "Hosting", "headers": ["x-nf-request-id", "netlify"], "html": []},
    # Languages
    "PHP": {"category": "Language", "headers": ["x-powered-by: php"], "html": [".php"]},
    "ASP.NET": {"category": "Language", "headers": ["x-aspnet-version", "x-powered-by: asp.net"], "html": ["__viewstate"]},
    "Python": {"category": "Language", "headers": ["x-powered-by: python", "x-powered-by: flask", "x-powered-by: django"], "html": ["csrfmiddlewaretoken"]},
}


def detect_from_response(resp: requests.Response) -> list[dict]:
    """Detect technologies from an HTTP response."""
    detected = []
    headers_str = str(resp.headers).lower()
    html = resp.text.lower() if resp.text else ""

    for tech_name, sigs in TECH_SIGNATURES.items():
        found = False

        # Check headers
        for pattern in sigs["headers"]:
            if pattern.lower() in headers_str:
                found = True
                break

        # Check HTML content
        if not found:
            for pattern in sigs["html"]:
                if pattern.lower() in html:
                    found = True
                    break

        if found:
            detected.append({
                "name": tech_name,
                "category": sigs["category"],
            })

    return detected


async def run(domain: str, console=None) -> dict:
    """Run technology detection module."""
    if console:
        console.print("  [dim]├─ Analyzing HTTP response for technologies...[/dim]")

    technologies = []
    errors = []

    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=Config.DEFAULT_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "PhantomRecon/1.0 (Security Scanner)"},
            )
            techs = detect_from_response(resp)
            for t in techs:
                if not any(existing["name"] == t["name"] for existing in technologies):
                    technologies.append(t)
            break  # Success, no need to try HTTP
        except Exception as e:
            errors.append(f"{scheme}: {str(e)}")

    # Group by category
    categories = {}
    for tech in technologies:
        cat = tech["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tech["name"])

    return {
        "technologies": technologies,
        "categories": categories,
        "total_detected": len(technologies),
    }
