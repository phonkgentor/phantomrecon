<div align="center">

# 👻 PhantomRecon

### AI-Powered Reconnaissance Tool for Ethical Hackers

[![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS%20|%20Termux%20|%20iOS-orange?style=for-the-badge)]()
[![AI](https://img.shields.io/badge/AI-7%20Providers%20|%2040%2B%20Models-purple?style=for-the-badge)]()

**The first AI-powered recon tool that doesn't just find data — it tells you what it *means*.**

Traditional recon tools dump raw data. PhantomRecon uses AI to **analyze, correlate, and prioritize** findings — telling you *what matters* and *where to look next*.

[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Modules](#-modules) •
[AI Models](#-ai-providers--models) •
[Platforms](#-cross-platform-support) •
[Contributing](#-contributing)

---

</div>

## ⚡ Features

- 🔍 **9 Recon Modules** — Subdomains, DNS, WHOIS, Ports, Headers, SSL, Tech, Email, VirusTotal
- 🤖 **7 AI Providers** — Groq, OpenAI, Anthropic, Google Gemini, Mistral, Ollama, OpenRouter
- 🧠 **40+ AI Models** — GPT-4o, Claude 4, Gemini 2.5, LLaMA 3.3, DeepSeek R1, and more
- 📊 **Scan Profiles** — Quick (3 modules), Standard (8), Deep (all)
- 📋 **Pro Reports** — Export to Markdown, JSON, or HTML
- 🖥️ **Cross-Platform** — Windows, Linux, macOS, Termux (Android), iSH (iOS), WSL
- 🎨 **Beautiful CLI** — Rich tables, spinners, color-coded risk indicators

---

## 📦 Installation

### 🪟 Windows
```cmd
git clone https://github.com/yourusername/phantomrecon.git
cd phantomrecon
install.bat
```

### 🐧 Linux / macOS / WSL
```bash
git clone https://github.com/yourusername/phantomrecon.git
cd phantomrecon
chmod +x install.sh
./install.sh
```

### 📱 Termux (Android)
```bash
pkg update && pkg install python git
git clone https://github.com/yourusername/phantomrecon.git
cd phantomrecon
pip install -r requirements.txt
pip install -e .
cp .env.example .env
```

### 🍎 iSH (iOS)
```bash
apk add python3 py3-pip git
git clone https://github.com/yourusername/phantomrecon.git
cd phantomrecon
pip3 install -r requirements.txt
pip3 install -e .
cp .env.example .env
```

### 🐍 Any Platform (pip)
```bash
git clone https://github.com/yourusername/phantomrecon.git
cd phantomrecon
pip install -e .
```

## ⚙️ Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit with your API keys (you only need ONE AI provider)
# Groq is recommended — free and fast
```

## 🚀 Quick Start

```bash
# Full scan with AI analysis
phantomrecon scan example.com

# Quick scan (DNS + Headers + SSL only)
phantomrecon scan example.com --profile quick

# Deep scan (all modules + VirusTotal)
phantomrecon scan example.com --profile deep

# Select specific modules
phantomrecon scan example.com --modules dns,headers,ssl,ports

# Use a specific AI provider
phantomrecon scan example.com --provider openai --model gpt-4o

# Use local AI (no internet needed for analysis)
phantomrecon scan example.com --provider ollama --model llama3.1:8b

# Export report
phantomrecon scan example.com --output report.md --format md

# Scan without AI
phantomrecon scan example.com --no-ai

# List all AI models
phantomrecon models

# Filter models by provider
phantomrecon models --provider anthropic

# Check API key status
phantomrecon apikeys
```

## 📡 Modules

| Module | Description | External API |
|--------|-------------|:---:|
| `subdomain` | Subdomain enumeration via crt.sh, DNS brute-force | SecurityTrails |
| `dns` | DNS record analysis (A, AAAA, MX, NS, TXT, SOA, etc.) | — |
| `whois` | WHOIS domain registration lookup | — |
| `ports` | Async TCP port scan + banner grabbing | Shodan |
| `headers` | HTTP security header analysis & grading (A+ to F) | — |
| `ssl` | SSL/TLS certificate inspection | — |
| `tech` | Web technology stack detection | — |
| `email` | Email address harvesting | — |
| `virustotal` | Domain reputation & threat intel | VirusTotal |

### Scan Profiles

| Profile | Modules | Best For |
|---------|---------|----------|
| `--profile quick` | dns, headers, ssl | Fast checks |
| `--profile standard` | All except VirusTotal | Normal scans |
| `--profile deep` | All modules | Full assessment |

## 🤖 AI Providers & Models

| Provider | Models | Cost | Install |
|----------|--------|------|---------|
| **Groq** | LLaMA 3.3, Mixtral, DeepSeek R1 | Free tier | [console.groq.com](https://console.groq.com) |
| **OpenAI** | GPT-4o, o1, GPT-3.5 | Paid | [platform.openai.com](https://platform.openai.com) |
| **Anthropic** | Claude 4, Claude 3.5 | Paid | [console.anthropic.com](https://console.anthropic.com) |
| **Google** | Gemini 2.5, 2.0, 1.5 | Free tier | [aistudio.google.com](https://aistudio.google.com) |
| **Mistral** | Large, Medium, Codestral | Paid | [console.mistral.ai](https://console.mistral.ai) |
| **Ollama** | Any local model | Free/Local | [ollama.com](https://ollama.com) |
| **OpenRouter** | 200+ models | Pay-per-use | [openrouter.ai](https://openrouter.ai) |

```bash
# See all available models
phantomrecon models

# Filter by provider
phantomrecon models --provider groq
```

## 🌐 Cross-Platform Support

| Platform | Status | Notes |
|----------|:------:|-------|
| 🪟 Windows 10/11 | ✅ | Full support |
| 🐧 Ubuntu/Debian | ✅ | Full support |
| 🐧 Fedora/RHEL | ✅ | Full support |
| 🐧 Arch Linux | ✅ | Full support |
| 🍎 macOS | ✅ | Full support |
| 📱 Termux (Android) | ✅ | Full support |
| 🍎 iSH (iOS) | ✅ | Full support |
| 💻 WSL | ✅ | Full support |

## ⚠️ Disclaimer

**This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**

- Always obtain written authorization before scanning any target
- Only scan systems you own or have explicit permission to test
- Unauthorized scanning may violate laws

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with 💀 by the PhantomRecon Team**

*If PhantomRecon helped you, give it a ⭐ on GitHub!*

</div>
