"""
👻 PhantomRecon — Configuration Management

Supports multiple LLM providers: Groq, OpenAI, Anthropic, Google Gemini, Ollama, Mistral, OpenRouter
"""
import os
from pathlib import Path
from dotenv import load_dotenv


# Load .env file from project root
_env_path = Path(__file__).parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    load_dotenv()  # Try default location


class Config:
    """Central configuration for PhantomRecon."""

    # ──────────────────────────────────────────────
    # LLM Provider API Keys
    # ──────────────────────────────────────────────
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    MISTRAL_API_KEY: str = os.getenv("MISTRAL_API_KEY", "")
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    # Active provider & model (can be overridden by CLI flags)
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "groq")
    AI_MODEL: str = os.getenv("AI_MODEL", "llama-3.3-70b-versatile")

    # ──────────────────────────────────────────────
    # Security Tool API Keys
    # ──────────────────────────────────────────────
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    SECURITYTRAILS_API_KEY: str = os.getenv("SECURITYTRAILS_API_KEY", "")

    # ──────────────────────────────────────────────
    # Available LLM Providers & Models
    # ──────────────────────────────────────────────
    PROVIDERS: dict = {
        "groq": {
            "name": "Groq",
            "description": "Ultra-fast inference (free tier available)",
            "env_key": "GROQ_API_KEY",
            "website": "https://console.groq.com",
            "models": {
                "llama-3.3-70b-versatile": {
                    "name": "LLaMA 3.3 70B",
                    "params": "70B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Best overall — excellent quality + speed",
                    "default": True,
                },
                "llama-3.1-8b-instant": {
                    "name": "LLaMA 3.1 8B",
                    "params": "8B",
                    "speed": "Ultra Fast",
                    "quality": "★★★",
                    "description": "Fastest — good for quick scans",
                },
                "llama-3.1-70b-versatile": {
                    "name": "LLaMA 3.1 70B",
                    "params": "70B",
                    "speed": "Fast",
                    "quality": "★★★★",
                    "description": "Strong reasoning for complex analysis",
                },
                "gemma2-9b-it": {
                    "name": "Gemma 2 9B",
                    "params": "9B",
                    "speed": "Ultra Fast",
                    "quality": "★★★",
                    "description": "Google lightweight model",
                },
                "mixtral-8x7b-32768": {
                    "name": "Mixtral 8x7B",
                    "params": "8x7B MoE",
                    "speed": "Fast",
                    "quality": "★★★★",
                    "description": "Mixture of Experts — balanced",
                },
                "deepseek-r1-distill-llama-70b": {
                    "name": "DeepSeek R1 70B",
                    "params": "70B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Deep vulnerability reasoning",
                },
                "llama-3.2-90b-vision-preview": {
                    "name": "LLaMA 3.2 90B Vision",
                    "params": "90B",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "Largest model — deepest analysis",
                },
                "llama-3.2-11b-vision-preview": {
                    "name": "LLaMA 3.2 11B Vision",
                    "params": "11B",
                    "speed": "Fast",
                    "quality": "★★★",
                    "description": "Compact vision model",
                },
            },
        },
        "openai": {
            "name": "OpenAI",
            "description": "GPT-4o, GPT-4, GPT-3.5 (paid)",
            "env_key": "OPENAI_API_KEY",
            "website": "https://platform.openai.com/api-keys",
            "models": {
                "gpt-4o": {
                    "name": "GPT-4o",
                    "params": "~200B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Best OpenAI model — multimodal",
                    "default": True,
                },
                "gpt-4o-mini": {
                    "name": "GPT-4o Mini",
                    "params": "~8B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★",
                    "description": "Cheapest GPT-4 — great value",
                },
                "gpt-4-turbo": {
                    "name": "GPT-4 Turbo",
                    "params": "~200B",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "Powerful reasoning with 128K context",
                },
                "gpt-3.5-turbo": {
                    "name": "GPT-3.5 Turbo",
                    "params": "~20B",
                    "speed": "Ultra Fast",
                    "quality": "★★★",
                    "description": "Cheapest option — basic analysis",
                },
                "o1-preview": {
                    "name": "o1 Preview",
                    "params": "~200B",
                    "speed": "Slow",
                    "quality": "★★★★★",
                    "description": "Advanced reasoning — deepest analysis",
                },
                "o1-mini": {
                    "name": "o1 Mini",
                    "params": "~100B",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "Reasoning model — faster than o1",
                },
            },
        },
        "anthropic": {
            "name": "Anthropic",
            "description": "Claude 4, Claude 3.5, Claude 3 (paid)",
            "env_key": "ANTHROPIC_API_KEY",
            "website": "https://console.anthropic.com",
            "models": {
                "claude-sonnet-4-20250514": {
                    "name": "Claude Sonnet 4",
                    "params": "~175B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Latest Claude — best code + reasoning",
                    "default": True,
                },
                "claude-3-5-sonnet-20241022": {
                    "name": "Claude 3.5 Sonnet",
                    "params": "~175B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Excellent analysis + coding",
                },
                "claude-3-5-haiku-20241022": {
                    "name": "Claude 3.5 Haiku",
                    "params": "~20B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★",
                    "description": "Fastest Claude — good value",
                },
                "claude-3-opus-20240229": {
                    "name": "Claude 3 Opus",
                    "params": "~200B",
                    "speed": "Slow",
                    "quality": "★★★★★",
                    "description": "Most powerful Claude 3 — deep analysis",
                },
            },
        },
        "google": {
            "name": "Google Gemini",
            "description": "Gemini 2.5, 2.0, 1.5 (free tier available)",
            "env_key": "GOOGLE_API_KEY",
            "website": "https://aistudio.google.com/apikey",
            "models": {
                "gemini-2.5-flash-preview-04-17": {
                    "name": "Gemini 2.5 Flash",
                    "params": "~100B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★★",
                    "description": "Latest Gemini — thinking + fast",
                    "default": True,
                },
                "gemini-2.0-flash": {
                    "name": "Gemini 2.0 Flash",
                    "params": "~100B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★",
                    "description": "Fast multimodal with tool use",
                },
                "gemini-1.5-pro": {
                    "name": "Gemini 1.5 Pro",
                    "params": "~175B",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "1M token context — massive input",
                },
                "gemini-1.5-flash": {
                    "name": "Gemini 1.5 Flash",
                    "params": "~50B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★",
                    "description": "Fast and efficient",
                },
            },
        },
        "mistral": {
            "name": "Mistral AI",
            "description": "Mistral Large, Medium, Small (paid)",
            "env_key": "MISTRAL_API_KEY",
            "website": "https://console.mistral.ai/api-keys",
            "models": {
                "mistral-large-latest": {
                    "name": "Mistral Large",
                    "params": "~123B",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "Flagship model — top-tier reasoning",
                    "default": True,
                },
                "mistral-medium-latest": {
                    "name": "Mistral Medium",
                    "params": "~70B",
                    "speed": "Fast",
                    "quality": "★★★★",
                    "description": "Balanced performance and cost",
                },
                "mistral-small-latest": {
                    "name": "Mistral Small",
                    "params": "~22B",
                    "speed": "Ultra Fast",
                    "quality": "★★★",
                    "description": "Cost-efficient for simple tasks",
                },
                "codestral-latest": {
                    "name": "Codestral",
                    "params": "~22B",
                    "speed": "Fast",
                    "quality": "★★★★",
                    "description": "Code-specialized — great for vuln analysis",
                },
            },
        },
        "ollama": {
            "name": "Ollama (Local)",
            "description": "Run models locally — free, private, no API key needed",
            "env_key": None,
            "website": "https://ollama.com",
            "models": {
                "llama3.1:8b": {
                    "name": "LLaMA 3.1 8B",
                    "params": "8B",
                    "speed": "Depends on HW",
                    "quality": "★★★",
                    "description": "Lightweight local model",
                    "default": True,
                },
                "llama3.1:70b": {
                    "name": "LLaMA 3.1 70B",
                    "params": "70B",
                    "speed": "Depends on HW",
                    "quality": "★★★★★",
                    "description": "Full-size local model (needs 48GB+ RAM)",
                },
                "mistral:7b": {
                    "name": "Mistral 7B",
                    "params": "7B",
                    "speed": "Depends on HW",
                    "quality": "★★★",
                    "description": "Fast local model",
                },
                "deepseek-r1:8b": {
                    "name": "DeepSeek R1 8B",
                    "params": "8B",
                    "speed": "Depends on HW",
                    "quality": "★★★★",
                    "description": "Reasoning-focused local model",
                },
                "qwen2.5:7b": {
                    "name": "Qwen 2.5 7B",
                    "params": "7B",
                    "speed": "Depends on HW",
                    "quality": "★★★",
                    "description": "Alibaba's lightweight model",
                },
                "gemma2:9b": {
                    "name": "Gemma 2 9B",
                    "params": "9B",
                    "speed": "Depends on HW",
                    "quality": "★★★",
                    "description": "Google's local model",
                },
            },
        },
        "openrouter": {
            "name": "OpenRouter",
            "description": "Access 200+ models through one API (pay-per-use)",
            "env_key": "OPENROUTER_API_KEY",
            "website": "https://openrouter.ai/keys",
            "models": {
                "meta-llama/llama-3.3-70b-instruct": {
                    "name": "LLaMA 3.3 70B",
                    "params": "70B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Via OpenRouter — cheapest 70B access",
                    "default": True,
                },
                "anthropic/claude-sonnet-4": {
                    "name": "Claude Sonnet 4",
                    "params": "~175B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "Claude via OpenRouter",
                },
                "openai/gpt-4o": {
                    "name": "GPT-4o",
                    "params": "~200B",
                    "speed": "Fast",
                    "quality": "★★★★★",
                    "description": "GPT-4o via OpenRouter",
                },
                "google/gemini-2.5-flash-preview": {
                    "name": "Gemini 2.5 Flash",
                    "params": "~100B",
                    "speed": "Ultra Fast",
                    "quality": "★★★★★",
                    "description": "Gemini via OpenRouter",
                },
                "deepseek/deepseek-r1": {
                    "name": "DeepSeek R1",
                    "params": "671B MoE",
                    "speed": "Medium",
                    "quality": "★★★★★",
                    "description": "Full DeepSeek R1 via OpenRouter",
                },
            },
        },
    }

    # ──────────────────────────────────────────────
    # Scan defaults
    # ──────────────────────────────────────────────
    DEFAULT_TIMEOUT: int = 10
    DEFAULT_THREADS: int = 50
    TOP_PORTS: list = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090,
        27017, 5432, 6379, 11211, 1433, 1521, 2049, 5000, 5001,
        8000, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        9000, 9200, 9300, 10000, 49152, 49153, 49154, 49155
    ]
    WORDLIST_PATH: str = str(Path(__file__).parent / "data" / "subdomains.txt")

    # ──────────────────────────────────────────────
    # Provider detection helpers
    # ──────────────────────────────────────────────
    @classmethod
    def has_provider(cls, provider: str) -> bool:
        """Check if a provider's API key is configured."""
        key_map = {
            "groq": cls.GROQ_API_KEY,
            "openai": cls.OPENAI_API_KEY,
            "anthropic": cls.ANTHROPIC_API_KEY,
            "google": cls.GOOGLE_API_KEY,
            "mistral": cls.MISTRAL_API_KEY,
            "openrouter": cls.OPENROUTER_API_KEY,
            "ollama": "local",  # No key needed
        }
        val = key_map.get(provider, "")
        return bool(val and val != "your_groq_api_key_here")

    @classmethod
    def has_any_ai(cls) -> bool:
        """Check if any AI provider is configured."""
        return any(cls.has_provider(p) for p in cls.PROVIDERS)

    @classmethod
    def get_api_key(cls, provider: str) -> str:
        """Get API key for a provider."""
        key_map = {
            "groq": cls.GROQ_API_KEY,
            "openai": cls.OPENAI_API_KEY,
            "anthropic": cls.ANTHROPIC_API_KEY,
            "google": cls.GOOGLE_API_KEY,
            "mistral": cls.MISTRAL_API_KEY,
            "openrouter": cls.OPENROUTER_API_KEY,
        }
        return key_map.get(provider, "")

    @classmethod
    def get_provider_for_model(cls, model_id: str) -> str | None:
        """Find which provider a model belongs to."""
        for provider, info in cls.PROVIDERS.items():
            if model_id in info["models"]:
                return provider
        return None

    @classmethod
    def is_valid_model(cls, model_id: str) -> bool:
        """Check if a model ID exists in any provider."""
        return cls.get_provider_for_model(model_id) is not None

    @classmethod
    def get_all_models(cls) -> list[dict]:
        """Get flat list of all models across all providers."""
        models = []
        for provider, pinfo in cls.PROVIDERS.items():
            for model_id, minfo in pinfo["models"].items():
                models.append({
                    "id": model_id,
                    "provider": provider,
                    "provider_name": pinfo["name"],
                    **minfo,
                })
        return models

    # ──────────────────────────────────────────────
    # Security tool helpers (unchanged)
    # ──────────────────────────────────────────────
    @classmethod
    def has_groq(cls) -> bool:
        return cls.has_provider("groq")

    @classmethod
    def has_shodan(cls) -> bool:
        return bool(cls.SHODAN_API_KEY)

    @classmethod
    def has_virustotal(cls) -> bool:
        return bool(cls.VIRUSTOTAL_API_KEY)

    @classmethod
    def has_securitytrails(cls) -> bool:
        return bool(cls.SECURITYTRAILS_API_KEY)

    @classmethod
    def get_api_status(cls) -> dict:
        """Return status of all API keys."""
        status = {}
        # LLM Providers
        for provider, info in cls.PROVIDERS.items():
            if provider == "ollama":
                status[f"{info['name']}"] = "⬜ Local (no key needed)"
            else:
                configured = cls.has_provider(provider)
                status[f"{info['name']}"] = "✅ Configured" if configured else "⬜ Not set"
        # Security APIs
        status["Shodan"] = "✅ Configured" if cls.has_shodan() else "⬜ Not set"
        status["VirusTotal"] = "✅ Configured" if cls.has_virustotal() else "⬜ Not set"
        status["SecurityTrails"] = "✅ Configured" if cls.has_securitytrails() else "⬜ Not set"
        return status
