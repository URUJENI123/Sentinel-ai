#!/bin/bash
# scripts/train_rl.sh
# Train the RL mitigation agent

set -e

TIMESTEPS=${1:-100000}
SAVE_PATH=${2:-models/rl_agent.zip}

echo "🤖 Training RL agent for $TIMESTEPS timesteps..."
echo "📁 Model will be saved to: $SAVE_PATH"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run training
python main.py train --timesteps "$TIMESTEPS" --save-path "$SAVE_PATH"

echo ""
echo "✅ Training complete!"
echo "📦 Model saved to: $SAVE_PATH"
