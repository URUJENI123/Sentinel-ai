#!/bin/bash
# scripts/setup_dev.sh
# Development environment setup script

set -e

echo "🚀 Setting up Sentinel AI development environment..."

# Check Python version
python_version=$(python --version 2>&1 | awk '{print $2}')
required_version="3.11"

if [[ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]]; then
    echo "❌ Python $required_version or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Install dev dependencies
echo "📥 Installing dev dependencies..."
pip install pytest pytest-asyncio pytest-cov black ruff mypy

# Create .env from example if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env from .env.example..."
    cp .env.example .env
    echo "⚠️  Please edit .env and add your API keys!"
fi

# Create required directories
echo "📁 Creating required directories..."
mkdir -p logs models/checkpoints

# Check Docker
if command -v docker &> /dev/null; then
    echo "✅ Docker is installed"
else
    echo "⚠️  Docker not found. Install Docker to run infrastructure services."
fi

# Check Docker Compose
if command -v docker-compose &> /dev/null; then
    echo "✅ Docker Compose is installed"
else
    echo "⚠️  Docker Compose not found. Install it to run the full stack."
fi

echo ""
echo "✨ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your API keys (OPENAI_API_KEY, etc.)"
echo "  2. Start infrastructure: docker-compose up -d"
echo "  3. Run tests: pytest"
echo "  4. Start API: python main.py api"
echo ""
echo "For more info, see README.md"
