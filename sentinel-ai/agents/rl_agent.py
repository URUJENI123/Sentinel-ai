"""
agents/rl_agent.py
───────────────────
Reinforcement learning mitigation agent using Stable Baselines3 PPO.
Learns optimal response policies from simulated threat environments.

State space:  [anomaly_score, threat_type_enc, affected_count, attack_stage_enc, time_since_detection]
Action space: Discrete(6) — do_nothing, alert_only, block_ip, isolate_system, kill_process, escalate
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

try:
    import gymnasium as gym
    from gymnasium import spaces
    _GYM_AVAILABLE = True
except ImportError:
    _GYM_AVAILABLE = False
    logger.warning("Gymnasium not available")

try:
    from stable_baselines3 import PPO
    from stable_baselines3.common.callbacks import EvalCallback, CheckpointCallback
    from stable_baselines3.common.env_util import make_vec_env
    from stable_baselines3.common.monitor import Monitor
    _SB3_AVAILABLE = True
except ImportError:
    _SB3_AVAILABLE = False
    logger.warning("Stable Baselines3 not available")

from config.settings import get_settings


# ── Action definitions ────────────────────────────────────────────

ACTIONS: List[str] = [
    "do_nothing",
    "alert_only",
    "block_ip",
    "isolate_system",
    "kill_process",
    "escalate_to_human",
]

THREAT_TYPES: List[str] = [
    "unknown",
    "brute_force",
    "lateral_movement",
    "data_exfiltration",
    "malware_execution",
    "privilege_escalation",
    "reconnaissance",
    "ransomware",
]

ATTACK_STAGES: List[str] = [
    "unknown",
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "c2",
    "actions_on_objectives",
]


# ── Threat environment ────────────────────────────────────────────

if _GYM_AVAILABLE:

    class ThreatEnvironment(gym.Env):
        """
        Gymnasium environment simulating cyber threat scenarios for RL training.

        Observation space (5 continuous features):
            0: anomaly_score          [0, 1]
            1: threat_type_encoded    [0, 1]  (normalised index)
            2: affected_systems_count [0, 1]  (normalised, max=100)
            3: attack_stage_encoded   [0, 1]  (normalised index)
            4: time_since_detection   [0, 1]  (normalised, max=3600s)

        Action space: Discrete(6)
            0: do_nothing
            1: alert_only
            2: block_ip
            3: isolate_system
            4: kill_process
            5: escalate_to_human

        Reward function:
            +10  : correct mitigation (true positive)
            -5   : false positive (action on benign activity)
            -20  : missed threat (threat escalated without action)
            -1   : do_nothing when threat present
            +2   : alert_only when threat is low severity
        """

        metadata = {"render_modes": ["human"]}

        def __init__(self, settings: Optional[Any] = None) -> None:
            super().__init__()
            self._settings = settings or get_settings()
            self._rl_cfg = self._settings.rl

            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(5,), dtype=np.float32
            )
            self.action_space = spaces.Discrete(len(ACTIONS))

            # Episode state
            self._state: np.ndarray = np.zeros(5, dtype=np.float32)
            self._is_threat: bool = False
            self._threat_severity: float = 0.0
            self._steps: int = 0
            self._max_steps: int = 200
            self._rng = np.random.default_rng()

        def reset(
            self, *, seed: Optional[int] = None, options: Optional[Dict] = None
        ) -> Tuple[np.ndarray, Dict]:
            super().reset(seed=seed)
            self._steps = 0

            # Randomly decide if this episode has a real threat
            self._is_threat = self._rng.random() < 0.6
            self._threat_severity = self._rng.uniform(0.3, 1.0) if self._is_threat else 0.0

            self._state = self._generate_observation()
            return self._state.copy(), {}

        def _generate_observation(self) -> np.ndarray:
            """Generate a realistic observation vector."""
            if self._is_threat:
                anomaly_score = np.clip(
                    self._threat_severity + self._rng.normal(0, 0.1), 0.0, 1.0
                )
                threat_type = self._rng.integers(1, len(THREAT_TYPES)) / len(THREAT_TYPES)
                affected = self._rng.integers(1, 20) / 100.0
                stage = self._rng.integers(1, len(ATTACK_STAGES)) / len(ATTACK_STAGES)
                time_since = self._rng.uniform(0, 0.5)
            else:
                anomaly_score = self._rng.uniform(0.0, 0.3)
                threat_type = 0.0
                affected = self._rng.uniform(0, 0.05)
                stage = 0.0
                time_since = self._rng.uniform(0, 1.0)

            return np.array(
                [anomaly_score, threat_type, affected, stage, time_since],
                dtype=np.float32,
            )

        def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
            self._steps += 1
            reward = self._compute_reward(action)
            terminated = self._steps >= self._max_steps
            truncated = False

            # Update state
            self._state = self._generate_observation()

            info = {
                "action": ACTIONS[action],
                "is_threat": self._is_threat,
                "threat_severity": self._threat_severity,
                "reward": reward,
            }
            return self._state.copy(), reward, terminated, truncated, info

        def _compute_reward(self, action: int) -> float:
            """Compute reward based on action correctness."""
            cfg = self._rl_cfg
            action_name = ACTIONS[action]
            severity = self._threat_severity

            if not self._is_threat:
                # No threat — penalise aggressive actions (false positives)
                if action_name in ("block_ip", "isolate_system", "kill_process"):
                    return cfg.reward_false_positive
                if action_name == "escalate_to_human":
                    return cfg.reward_false_positive * 0.5
                return 0.5  # do_nothing or alert_only on benign = small positive

            # Real threat present
            if action_name == "do_nothing":
                return cfg.reward_do_nothing * severity

            if action_name == "alert_only":
                if severity < 0.5:
                    return 2.0  # appropriate for low severity
                return -2.0  # insufficient for high severity

            if action_name == "block_ip":
                if 0.4 <= severity < 0.8:
                    return cfg.reward_true_positive
                if severity >= 0.8:
                    return cfg.reward_true_positive * 0.5  # should isolate instead
                return cfg.reward_false_positive * 0.5

            if action_name == "isolate_system":
                if severity >= 0.7:
                    return cfg.reward_true_positive * 1.2  # bonus for correct escalation
                return cfg.reward_false_positive

            if action_name == "kill_process":
                if severity >= 0.6:
                    return cfg.reward_true_positive
                return cfg.reward_false_positive * 0.3

            if action_name == "escalate_to_human":
                if severity >= 0.85:
                    return cfg.reward_true_positive * 1.5  # critical threats need human
                return 1.0  # always somewhat positive to escalate

            return 0.0

        def render(self) -> None:
            print(
                f"Step {self._steps}: threat={self._is_threat} "
                f"severity={self._threat_severity:.2f} state={self._state}"
            )


# ── RLMitigationAgent ─────────────────────────────────────────────


class RLMitigationAgent:
    """
    PPO-based mitigation decision agent.

    Wraps Stable Baselines3 PPO with a ThreatEnvironment for training
    and provides an inference interface for production use.

    Usage::

        agent = RLMitigationAgent()
        agent.load()  # load pre-trained model

        action, confidence = agent.predict(state_dict)
        # action = "block_ip", confidence = 0.87
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._rl_cfg = self._settings.rl
        self._model: Optional[Any] = None
        self._env: Optional[Any] = None

    # ── Model management ──────────────────────────────────────────

    def load(self, path: Optional[str] = None) -> bool:
        """Load a pre-trained PPO model from disk."""
        if not _SB3_AVAILABLE:
            logger.warning("SB3 not available — RL agent in mock mode")
            return False

        model_path = Path(path or self._rl_cfg.model_path)
        if not model_path.exists():
            logger.warning("RL model not found at {}. Using untrained model.", model_path)
            return self._init_untrained()

        try:
            self._model = PPO.load(str(model_path))
            logger.info("Loaded RL model from {}", model_path)
            return True
        except Exception as exc:
            logger.error("Failed to load RL model: {}", exc)
            return self._init_untrained()

    def _init_untrained(self) -> bool:
        """Initialise a fresh (untrained) PPO model."""
        if not _SB3_AVAILABLE or not _GYM_AVAILABLE:
            return False
        try:
            env = ThreatEnvironment()
            self._model = PPO(
                "MlpPolicy",
                env,
                learning_rate=self._rl_cfg.learning_rate,
                n_steps=self._rl_cfg.n_steps,
                batch_size=self._rl_cfg.batch_size,
                n_epochs=self._rl_cfg.n_epochs,
                gamma=self._rl_cfg.gamma,
                verbose=0,
            )
            logger.info("Initialised untrained PPO model")
            return True
        except Exception as exc:
            logger.error("Failed to init RL model: {}", exc)
            return False

    def save(self, path: Optional[str] = None) -> None:
        """Save the current model to disk."""
        if self._model is None:
            return
        save_path = path or self._rl_cfg.model_path
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        self._model.save(save_path)
        logger.info("RL model saved to {}", save_path)

    # ── Training ──────────────────────────────────────────────────

    def train(
        self,
        timesteps: Optional[int] = None,
        save_path: Optional[str] = None,
    ) -> None:
        """
        Train the PPO agent on the ThreatEnvironment.

        Args:
            timesteps: Total training timesteps.
            save_path: Where to save the trained model.
        """
        if not _SB3_AVAILABLE or not _GYM_AVAILABLE:
            logger.error("Cannot train: SB3 or Gymnasium not available")
            return

        total_steps = timesteps or self._rl_cfg.training_timesteps
        logger.info("Starting RL training for {} timesteps", total_steps)

        env = Monitor(ThreatEnvironment())
        self._model = PPO(
            "MlpPolicy",
            env,
            learning_rate=self._rl_cfg.learning_rate,
            n_steps=self._rl_cfg.n_steps,
            batch_size=self._rl_cfg.batch_size,
            n_epochs=self._rl_cfg.n_epochs,
            gamma=self._rl_cfg.gamma,
            verbose=1,
        )

        # Callbacks
        callbacks = []
        checkpoint_path = Path(save_path or self._rl_cfg.model_path).parent / "checkpoints"
        checkpoint_path.mkdir(parents=True, exist_ok=True)
        callbacks.append(
            CheckpointCallback(
                save_freq=10_000,
                save_path=str(checkpoint_path),
                name_prefix="rl_sentinel",
            )
        )

        self._model.learn(total_timesteps=total_steps, callback=callbacks)
        self.save(save_path)
        logger.info("RL training complete")

    # ── Inference ─────────────────────────────────────────────────

    def predict(self, state: Dict[str, Any]) -> Tuple[str, float]:
        """
        Predict the best mitigation action for a given threat state.

        Args:
            state: Dict with keys:
                anomaly_score          (float 0-1)
                threat_type            (str)
                affected_systems_count (int)
                attack_stage           (str)
                time_since_detection   (float, seconds)

        Returns:
            Tuple of (action_name: str, confidence: float)
        """
        obs = self._encode_state(state)

        if self._model is None or not _SB3_AVAILABLE:
            return self._heuristic_predict(state)

        try:
            action_idx, _ = self._model.predict(obs, deterministic=True)
            action_name = ACTIONS[int(action_idx)]

            # Estimate confidence from action probabilities
            confidence = self._estimate_confidence(obs)
            logger.debug("RL action: {} (confidence={:.2f})", action_name, confidence)
            return action_name, confidence

        except Exception as exc:
            logger.error("RL prediction failed: {}", exc)
            return self._heuristic_predict(state)

    def _encode_state(self, state: Dict[str, Any]) -> np.ndarray:
        """Encode a state dict to a numpy observation vector."""
        threat_type = state.get("threat_type", "unknown")
        attack_stage = state.get("attack_stage", "unknown")

        threat_enc = (
            THREAT_TYPES.index(threat_type) / len(THREAT_TYPES)
            if threat_type in THREAT_TYPES
            else 0.0
        )
        stage_enc = (
            ATTACK_STAGES.index(attack_stage) / len(ATTACK_STAGES)
            if attack_stage in ATTACK_STAGES
            else 0.0
        )

        return np.array([
            float(state.get("anomaly_score", 0.0)),
            threat_enc,
            min(float(state.get("affected_systems_count", 0)) / 100.0, 1.0),
            stage_enc,
            min(float(state.get("time_since_detection", 0)) / 3600.0, 1.0),
        ], dtype=np.float32)

    def _estimate_confidence(self, obs: np.ndarray) -> float:
        """Estimate action confidence from policy distribution."""
        try:
            import torch
            obs_tensor = torch.FloatTensor(obs).unsqueeze(0)
            with torch.no_grad():
                dist = self._model.policy.get_distribution(obs_tensor)
                probs = dist.distribution.probs.numpy()[0]
            return float(probs.max())
        except Exception:
            return 0.7  # default confidence

    def _heuristic_predict(self, state: Dict[str, Any]) -> Tuple[str, float]:
        """Rule-based fallback when RL model is unavailable."""
        score = float(state.get("anomaly_score", 0.0))
        stage = state.get("attack_stage", "unknown")

        if score >= 0.92 or stage == "actions_on_objectives":
            return "escalate_to_human", 0.95
        if score >= 0.80:
            return "isolate_system", 0.85
        if score >= 0.65:
            return "block_ip", 0.75
        if score >= 0.40:
            return "alert_only", 0.65
        return "do_nothing", 0.90


# ── CLI entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel AI RL Agent")
    parser.add_argument("--train", action="store_true", help="Train the RL agent")
    parser.add_argument("--timesteps", type=int, default=100_000)
    parser.add_argument("--save-path", type=str, default=None)
    args = parser.parse_args()

    agent = RLMitigationAgent()
    if args.train:
        agent.train(timesteps=args.timesteps, save_path=args.save_path)
    else:
        agent.load()
        # Demo inference
        test_state = {
            "anomaly_score": 0.85,
            "threat_type": "lateral_movement",
            "affected_systems_count": 3,
            "attack_stage": "lateral_movement",
            "time_since_detection": 120.0,
        }
        action, confidence = agent.predict(test_state)
        print(f"Recommended action: {action} (confidence: {confidence:.2f})")
