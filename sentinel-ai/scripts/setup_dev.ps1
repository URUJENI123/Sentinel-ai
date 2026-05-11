# scripts/setup_dev.ps1
# Development environment setup script for Windows

Write-Host "🚀 Setting up Sentinel AI development environment..." -ForegroundColor Cyan

# Check Python version
$pythonVersion = python --version 2>&1 | Select-String -Pattern "(\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
$requiredVersion = [version]"3.11.0"

if ([version]$pythonVersion -lt $requiredVersion) {
    Write-Host "❌ Python 3.11 or higher is required. Found: $pythonVersion" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Python version: $pythonVersion" -ForegroundColor Green

# Create virtual environment
if (-not (Test-Path "venv")) {
    Write-Host "📦 Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
Write-Host "🔌 Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host "⬆️  Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install dependencies
Write-Host "📥 Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Install dev dependencies
Write-Host "📥 Installing dev dependencies..." -ForegroundColor Yellow
pip install pytest pytest-asyncio pytest-cov black ruff mypy

# Create .env from example if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "📝 Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
    Write-Host "⚠️  Please edit .env and add your API keys!" -ForegroundColor Yellow
}

# Create required directories
Write-Host "📁 Creating required directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path logs | Out-Null
New-Item -ItemType Directory -Force -Path models\checkpoints | Out-Null

# Check Docker
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "✅ Docker is installed" -ForegroundColor Green
} else {
    Write-Host "⚠️  Docker not found. Install Docker Desktop to run infrastructure services." -ForegroundColor Yellow
}

# Check Docker Compose
if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    Write-Host "✅ Docker Compose is installed" -ForegroundColor Green
} else {
    Write-Host "⚠️  Docker Compose not found. It's included with Docker Desktop." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✨ Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Edit .env and add your API keys (OPENAI_API_KEY, etc.)"
Write-Host "  2. Start infrastructure: docker-compose up -d"
Write-Host "  3. Run tests: pytest"
Write-Host "  4. Start API: python main.py api"
Write-Host ""
Write-Host "For more info, see README.md"
