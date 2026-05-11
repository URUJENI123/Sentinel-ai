"""
tests/test_agents.py
─────────────────────
Tests for the agent layer: AnalystAgent, MitreMatcher, RLMitigationAgent.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from agents.analyst_agent import AnalystAgent, ThreatAssessment
from agents.mitre_matcher import MitreMatcher, MitreMatchResult, TechniqueMatch
from agents.rl_agent import (
    RLMitigationAgent,
    ThreatEnvironment,
    ACTIONS,
    THREAT_TYPES,
    ATTACK_STAGES,
)


# ── AnalystAgent ──────────────────────────────────────────────────

class TestAnalystAgent:
    def test_fallback_assessment_on_error(self, sample_alert):
        agent = AnalystAgent.__new__(AnalystAgent)
        agent._settings = MagicMock()
        result = agent._fallback_assessment(sample_alert, "LLM timeout")
        assert isinstance(result, ThreatAssessment)
        assert result.threat_type == "unknown"
        assert "LLM timeout" in result.summary
        assert result.confidence == sample_alert.composite_score

    @pytest.mark.asyncio
    async def test_analyse_returns_assessment(self, sample_alert, mock_llm_chain):
        agent = AnalystAgent.__new__(AnalystAgent)
        agent._settings = MagicMock()
        agent._chain = mock_llm_chain
        agent._parser = MagicMock()
        agent._parser.get_format_instructions = MagicMock(return_value="")

        mock_llm_chain.ainvoke = AsyncMock(return_value={
            "threat_type": "brute_force",
            "confidence": 0.85,
            "affected_systems": ["webserver01"],
            "attack_stage": "exploitation",
            "recommended_actions": ["Block IP"],
            "threat_actor_profile": None,
            "iocs": ["192.168.1.100"],
            "urgency": "high",
            "summary": "Brute force detected.",
            "raw_analysis": "Multiple failed attempts.",
        })

        result = await agent.analyse(sample_alert)
        assert isinstance(result, ThreatAssessment)
        assert result.threat_type == "brute_force"
        assert result.confidence == 0.85

    def test_threat_assessment_model(self):
        assessment = ThreatAssessment(
            threat_type="lateral_movement",
            confidence=0.9,
            affected_systems=["host1", "host2"],
            attack_stage="lateral_movement",
            recommended_actions=["Isolate host1"],
            urgency="critical",
            summary="Lateral movement detected.",
            raw_analysis="SMB traffic between hosts.",
        )
        assert assessment.threat_type == "lateral_movement"
        assert len(assessment.affected_systems) == 2


# ── MitreMatcher ─────────────────────────────────────────────────

class TestMitreMatcher:
    def test_load_mitre_data(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        data = matcher._load_mitre_data()
        assert "techniques" in data
        assert len(data["techniques"]) > 0

    def test_filter_relevant_techniques_brute_force(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        matcher._mitre_data = matcher._load_mitre_data()

        assessment = {"threat_type": "brute_force", "attack_stage": "exploitation", "iocs": []}
        relevant = matcher._filter_relevant_techniques(assessment)
        assert len(relevant) > 0
        # T1110 (Brute Force) should be in results
        ids = [t["technique_id"] for t in relevant]
        assert "T1110" in ids

    def test_filter_returns_max_30(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        matcher._mitre_data = matcher._load_mitre_data()

        assessment = {"threat_type": "unknown", "attack_stage": "unknown", "iocs": []}
        relevant = matcher._filter_relevant_techniques(assessment)
        assert len(relevant) <= 30

    def test_build_attack_chain_ordering(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        matcher._mitre_data = matcher._load_mitre_data()

        # T1046 = Discovery, T1021 = Lateral Movement, T1078 = Initial Access
        chain = matcher.build_attack_chain(["T1021", "T1046", "T1078"])
        # Initial Access should come before Discovery, Discovery before Lateral Movement
        assert chain.index("T1078") < chain.index("T1046")
        assert chain.index("T1046") < chain.index("T1021")

    def test_get_technique_details(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        matcher._mitre_data = matcher._load_mitre_data()

        details = matcher.get_technique_details("T1110")
        assert details is not None
        assert details["technique_id"] == "T1110"
        assert details["name"] == "Brute Force"

    def test_get_technique_details_not_found(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        matcher._mitre_data = matcher._load_mitre_data()

        result = matcher.get_technique_details("T9999")
        assert result is None

    def test_fallback_match(self, settings):
        matcher = MitreMatcher.__new__(MitreMatcher)
        matcher._settings = settings
        result = matcher._fallback_match({"threat_type": "unknown"})
        assert isinstance(result, MitreMatchResult)
        assert result.overall_confidence == 0.0
        assert result.matches == []


# ── RLMitigationAgent ─────────────────────────────────────────────

class TestRLMitigationAgent:
    def test_encode_state_shape(self):
        agent = RLMitigationAgent()
        state = {
            "anomaly_score": 0.8,
            "threat_type": "brute_force",
            "affected_systems_count": 3,
            "attack_stage": "exploitation",
            "time_since_detection": 120.0,
        }
        obs = agent._encode_state(state)
        assert obs.shape == (5,)
        assert obs.dtype == np.float32

    def test_encode_state_values_in_range(self):
        agent = RLMitigationAgent()
        state = {
            "anomaly_score": 0.5,
            "threat_type": "lateral_movement",
            "affected_systems_count": 50,
            "attack_stage": "c2",
            "time_since_detection": 3600.0,
        }
        obs = agent._encode_state(state)
        assert np.all(obs >= 0.0)
        assert np.all(obs <= 1.0)

    def test_encode_unknown_threat_type(self):
        agent = RLMitigationAgent()
        state = {
            "anomaly_score": 0.5,
            "threat_type": "totally_unknown",
            "affected_systems_count": 1,
            "attack_stage": "unknown",
            "time_since_detection": 0.0,
        }
        obs = agent._encode_state(state)
        assert obs[1] == 0.0  # unknown maps to 0

    def test_heuristic_predict_critical(self):
        agent = RLMitigationAgent()
        action, confidence = agent._heuristic_predict({
            "anomaly_score": 0.95,
            "attack_stage": "actions_on_objectives",
        })
        assert action == "escalate_to_human"
        assert confidence > 0.9

    def test_heuristic_predict_high(self):
        agent = RLMitigationAgent()
        action, confidence = agent._heuristic_predict({
            "anomaly_score": 0.82,
            "attack_stage": "exploitation",
        })
        assert action == "isolate_system"

    def test_heuristic_predict_medium(self):
        agent = RLMitigationAgent()
        action, confidence = agent._heuristic_predict({
            "anomaly_score": 0.67,
            "attack_stage": "delivery",
        })
        assert action == "block_ip"

    def test_heuristic_predict_low(self):
        agent = RLMitigationAgent()
        action, confidence = agent._heuristic_predict({
            "anomaly_score": 0.2,
            "attack_stage": "reconnaissance",
        })
        assert action == "do_nothing"

    def test_predict_falls_back_to_heuristic_without_model(self):
        agent = RLMitigationAgent()
        agent._model = None
        action, confidence = agent.predict({
            "anomaly_score": 0.85,
            "threat_type": "brute_force",
            "affected_systems_count": 2,
            "attack_stage": "exploitation",
            "time_since_detection": 60.0,
        })
        assert action in ACTIONS
        assert 0.0 <= confidence <= 1.0


# ── ThreatEnvironment ─────────────────────────────────────────────

class TestThreatEnvironment:
    def test_reset_returns_valid_observation(self):
        pytest.importorskip("gymnasium")
        env = ThreatEnvironment()
        obs, info = env.reset()
        assert obs.shape == (5,)
        assert np.all(obs >= 0.0)
        assert np.all(obs <= 1.0)
        assert isinstance(info, dict)

    def test_step_returns_valid_tuple(self):
        pytest.importorskip("gymnasium")
        env = ThreatEnvironment()
        env.reset()
        obs, reward, terminated, truncated, info = env.step(0)
        assert obs.shape == (5,)
        assert isinstance(reward, float)
        assert isinstance(terminated, bool)
        assert isinstance(truncated, bool)

    def test_reward_true_positive(self):
        pytest.importorskip("gymnasium")
        env = ThreatEnvironment()
        env.reset()
        env._is_threat = True
        env._threat_severity = 0.9
        # isolate_system (action 3) should give high reward for high severity
        reward = env._compute_reward(3)
        assert reward > 0

    def test_reward_false_positive(self):
        pytest.importorskip("gymnasium")
        env = ThreatEnvironment()
        env.reset()
        env._is_threat = False
        # block_ip (action 2) on benign activity = false positive
        reward = env._compute_reward(2)
        assert reward < 0

    def test_episode_terminates_at_max_steps(self):
        pytest.importorskip("gymnasium")
        env = ThreatEnvironment()
        env.reset()
        env._steps = env._max_steps - 1
        _, _, terminated, _, _ = env.step(0)
        assert terminated is True
