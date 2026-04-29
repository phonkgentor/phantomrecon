#!/bin/bash
# ============================================================
# PhantomRecon -- Universal Installer
# Works on: Linux, macOS, Termux (Android), iSH (iOS), WSL
# ============================================================

set -e

echo ""
echo "  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗"
echo "  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║"
echo "  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║"
echo "  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║"
echo "  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
echo "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
echo ""
echo "  PhantomRecon Installer"
echo "  ──────────────────────────────────────────────────────────"
echo ""

# Detect platform
PLATFORM="unknown"
if [ -d "/data/data/com.termux" ]; then
    PLATFORM="termux"
elif [ -f "/proc/ish/version" ] || [ "$(uname -s)" = "iSH" ]; then
    PLATFORM="ish"
elif [ "$(uname -s)" = "Darwin" ]; then
    PLATFORM="macos"
elif [ "$(uname -s)" = "Linux" ]; then
    if grep -qi microsoft /proc/version 2>/dev/null; then
        PLATFORM="wsl"
    else
        PLATFORM="linux"
    fi
fi

echo "  [*] Detected platform: $PLATFORM"
echo ""

# Install system dependencies based on platform
install_deps() {
    case $PLATFORM in
        termux)
            echo "  [*] Installing Termux dependencies..."
            pkg update -y
            pkg install -y python python-pip git
            ;;
        ish)
            echo "  [*] Installing iSH dependencies..."
            apk update
            apk add python3 py3-pip git
            ;;
        macos)
            echo "  [*] Checking macOS dependencies..."
            if ! command -v python3 &> /dev/null; then
                echo "  [!] Python3 not found. Install with: brew install python3"
                exit 1
            fi
            ;;
        linux|wsl)
            echo "  [*] Checking Linux dependencies..."
            if ! command -v python3 &> /dev/null; then
                echo "  [*] Installing Python3..."
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
                elif command -v dnf &> /dev/null; then
                    sudo dnf install -y python3 python3-pip
                elif command -v pacman &> /dev/null; then
                    sudo pacman -S --noconfirm python python-pip
                elif command -v apk &> /dev/null; then
                    sudo apk add python3 py3-pip
                fi
            fi
            ;;
    esac
}

# Install PhantomRecon
install_phantomrecon() {
    echo "  [*] Installing Python dependencies..."
    pip3 install --user -r requirements.txt 2>/dev/null || pip install -r requirements.txt

    echo "  [*] Installing PhantomRecon..."
    pip3 install --user -e . 2>/dev/null || pip install -e .

    # Setup .env if not exists
    if [ ! -f ".env" ]; then
        echo "  [*] Creating .env from template..."
        cp .env.example .env
        echo "  [!] Edit .env and add your API keys"
    fi
}

# Verify installation
verify() {
    echo ""
    echo "  [*] Verifying installation..."
    if python3 -m phantomrecon --version 2>/dev/null || python -m phantomrecon --version 2>/dev/null; then
        echo ""
        echo "  ✓ PhantomRecon installed successfully!"
        echo ""
        echo "  Usage:"
        echo "    phantomrecon scan example.com"
        echo "    phantomrecon scan example.com --profile quick"
        echo "    phantomrecon models"
        echo ""
    else
        echo ""
        echo "  ✗ Installation failed. Try:"
        echo "    pip3 install -e ."
        echo ""
    fi
}

# Run
install_deps
install_phantomrecon
verify
