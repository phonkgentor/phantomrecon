@echo off
REM ============================================================
REM PhantomRecon -- Windows Installer
REM ============================================================

echo.
echo   PhantomRecon -- Windows Installer
echo   ──────────────────────────────────────────────────────
echo.

echo   [*] Installing Python dependencies...
pip install -r requirements.txt

echo   [*] Installing PhantomRecon...
pip install -e .

if not exist ".env" (
    echo   [*] Creating .env from template...
    copy .env.example .env
    echo   [!] Edit .env and add your API keys
)

echo.
echo   [*] Verifying installation...
python -m phantomrecon --version

echo.
echo   PhantomRecon installed successfully!
echo.
echo   Usage:
echo     phantomrecon scan example.com
echo     phantomrecon scan example.com --profile quick
echo     phantomrecon models
echo.
pause
