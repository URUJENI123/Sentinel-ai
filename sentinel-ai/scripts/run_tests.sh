#!/bin/bash
# scripts/run_tests.sh
# Run the test suite with coverage

set -e

echo "🧪 Running Sentinel AI test suite..."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run pytest with coverage
pytest \
    --cov=agents \
    --cov=api \
    --cov=detection \
    --cov=ingestion \
    --cov=mitigation \
    --cov=simulation \
    --cov=graph \
    --cov-report=html \
    --cov-report=term-missing \
    "$@"

echo ""
echo "✅ Tests complete!"
echo "📊 Coverage report: htmlcov/index.html"
