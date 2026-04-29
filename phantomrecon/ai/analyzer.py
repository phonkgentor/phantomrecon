"""
👻 PhantomRecon — AI Analysis Engine (Multi-Provider)

Supports: Groq, OpenAI, Anthropic, Google Gemini, Mistral, Ollama, OpenRouter
"""
import json
import requests
from phantomrecon.config import Config
from phantomrecon.ai.prompts import SYSTEM_PROMPT, ANALYSIS_PROMPT


def format_data(data: dict, max_items: int = 20) -> str:
    """Format data dict to readable string for the AI prompt."""
    if not data:
        return "No data available"
    try:
        truncated = {}
        for key, value in data.items():
            if isinstance(value, list) and len(value) > max_items:
                truncated[key] = value[:max_items]
                truncated[f"{key}_note"] = f"(Showing {max_items} of {len(value)} total)"
            else:
                truncated[key] = value
        return json.dumps(truncated, indent=2, default=str)
    except Exception:
        return str(data)


def _call_groq(model: str, messages: list, console=None) -> str:
    """Call Groq API."""
    from groq import Groq
    client = Groq(api_key=Config.GROQ_API_KEY)
    stream = client.chat.completions.create(
        model=model, messages=messages, temperature=0.3, max_tokens=4096, stream=True,
    )
    full = ""
    for chunk in stream:
        delta = chunk.choices[0].delta.content or ""
        full += delta
        if console:
            console.print(delta, end="")
    return full


def _call_openai(model: str, messages: list, console=None) -> str:
    """Call OpenAI API."""
    from openai import OpenAI
    client = OpenAI(api_key=Config.OPENAI_API_KEY)
    stream = client.chat.completions.create(
        model=model, messages=messages, temperature=0.3, max_tokens=4096, stream=True,
    )
    full = ""
    for chunk in stream:
        delta = chunk.choices[0].delta.content or ""
        full += delta
        if console:
            console.print(delta, end="")
    return full


def _call_anthropic(model: str, messages: list, console=None) -> str:
    """Call Anthropic API."""
    from anthropic import Anthropic
    client = Anthropic(api_key=Config.ANTHROPIC_API_KEY)
    # Anthropic uses system separately
    system_msg = ""
    user_msgs = []
    for msg in messages:
        if msg["role"] == "system":
            system_msg = msg["content"]
        else:
            user_msgs.append(msg)

    with client.messages.stream(
        model=model, system=system_msg, messages=user_msgs,
        max_tokens=4096, temperature=0.3,
    ) as stream:
        full = ""
        for text in stream.text_stream:
            full += text
            if console:
                console.print(text, end="")
    return full


def _call_google(model: str, messages: list, console=None) -> str:
    """Call Google Gemini API."""
    import google.generativeai as genai
    genai.configure(api_key=Config.GOOGLE_API_KEY)
    gmodel = genai.GenerativeModel(model)
    # Convert messages to Gemini format
    system_text = ""
    user_text = ""
    for msg in messages:
        if msg["role"] == "system":
            system_text = msg["content"]
        else:
            user_text = msg["content"]

    prompt = f"{system_text}\n\n{user_text}" if system_text else user_text
    response = gmodel.generate_content(prompt, stream=True)
    full = ""
    for chunk in response:
        text = chunk.text or ""
        full += text
        if console:
            console.print(text, end="")
    return full


def _call_mistral(model: str, messages: list, console=None) -> str:
    """Call Mistral AI API."""
    from mistralai import Mistral
    client = Mistral(api_key=Config.MISTRAL_API_KEY)
    stream = client.chat.stream(
        model=model, messages=messages, temperature=0.3, max_tokens=4096,
    )
    full = ""
    for event in stream:
        delta = event.data.choices[0].delta.content or ""
        full += delta
        if console:
            console.print(delta, end="")
    return full


def _call_ollama(model: str, messages: list, console=None) -> str:
    """Call Ollama local API."""
    url = f"{Config.OLLAMA_HOST}/api/chat"
    payload = {"model": model, "messages": messages, "stream": True}
    full = ""
    with requests.post(url, json=payload, stream=True, timeout=300) as resp:
        for line in resp.iter_lines():
            if line:
                data = json.loads(line)
                text = data.get("message", {}).get("content", "")
                full += text
                if console:
                    console.print(text, end="")
                if data.get("done"):
                    break
    return full


def _call_openrouter(model: str, messages: list, console=None) -> str:
    """Call OpenRouter API (OpenAI-compatible)."""
    from openai import OpenAI
    client = OpenAI(
        api_key=Config.OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1",
    )
    stream = client.chat.completions.create(
        model=model, messages=messages, temperature=0.3, max_tokens=4096, stream=True,
    )
    full = ""
    for chunk in stream:
        delta = chunk.choices[0].delta.content or ""
        full += delta
        if console:
            console.print(delta, end="")
    return full


# Provider -> function mapping
PROVIDER_CALLERS = {
    "groq": _call_groq,
    "openai": _call_openai,
    "anthropic": _call_anthropic,
    "google": _call_google,
    "mistral": _call_mistral,
    "ollama": _call_ollama,
    "openrouter": _call_openrouter,
}


def analyze(domain: str, scan_results: dict, console=None) -> str:
    """
    Run AI analysis on scan results using the configured provider.

    Args:
        domain: Target domain
        scan_results: Dict of all module results
        console: Rich console for output

    Returns:
        AI analysis text
    """
    provider = Config.AI_PROVIDER
    model = Config.AI_MODEL

    # Check if provider is available
    if not Config.has_provider(provider):
        if Config.has_any_ai():
            # Try to find any configured provider
            for p in Config.PROVIDERS:
                if Config.has_provider(p):
                    provider = p
                    # Use default model for that provider
                    for mid, minfo in Config.PROVIDERS[p]["models"].items():
                        if minfo.get("default"):
                            model = mid
                            break
                    else:
                        model = list(Config.PROVIDERS[p]["models"].keys())[0]
                    if console:
                        console.print(f"  [yellow]Switched to {Config.PROVIDERS[p]['name']} ({model})[/yellow]")
                    break
        else:
            return ("⚠️ AI analysis skipped — no LLM provider configured.\n"
                    "Set an API key in your .env file. Run 'phantomrecon apikeys' to see options.")

    # Build the prompt
    subdomain_data = scan_results.get("subdomain", {})
    dns_data = scan_results.get("dns", {})
    whois_data = scan_results.get("whois", {})
    port_data = scan_results.get("ports", {})
    header_data = scan_results.get("headers", {})
    ssl_data = scan_results.get("ssl", {})
    tech_data = scan_results.get("tech", {})
    email_data = scan_results.get("email", {})

    external_parts = []
    if scan_results.get("virustotal"):
        external_parts.append(f"VirusTotal: {format_data(scan_results['virustotal'])}")
    if port_data.get("shodan"):
        external_parts.append(f"Shodan: {format_data(port_data.get('shodan', {}))}")
    external_str = "\n".join(external_parts) if external_parts else "No external API data"

    prompt = ANALYSIS_PROMPT.format(
        domain=domain,
        subdomain_count=subdomain_data.get("total_count", 0),
        subdomain_data=format_data(subdomain_data),
        dns_data=format_data(dns_data),
        whois_data=format_data(whois_data),
        port_count=port_data.get("open_count", 0),
        port_data=format_data(port_data),
        header_grade=header_data.get("grade", "N/A"),
        header_data=format_data(header_data),
        ssl_data=format_data(ssl_data),
        tech_data=format_data(tech_data),
        email_data=format_data(email_data),
        external_data=external_str,
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    try:
        provider_name = Config.PROVIDERS.get(provider, {}).get("name", provider)
        if console:
            console.print(f"\n  [dim]Provider: {provider_name} | Model: {model}[/dim]")
            console.print(f"  [dim]Streaming AI analysis...[/dim]\n")

        caller = PROVIDER_CALLERS.get(provider)
        if not caller:
            return f"⚠️ Unknown provider: {provider}"

        result = caller(model, messages, console)

        if console:
            console.print()  # Final newline

        return result

    except Exception as e:
        return f"⚠️ AI analysis failed ({provider}): {str(e)}"
