"""
agents/mitre_matcher.py
────────────────────────
Matches observed behaviors to MITRE ATT&CK techniques using LLM reasoning
and vector similarity. Builds attack chains from sequences of techniques.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI
from loguru import logger
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import get_settings


# ── Output schema ─────────────────────────────────────────────────


class TechniqueMatch(BaseModel):
    """A single MITRE ATT&CK technique match."""

    technique_id: str = Field(description="MITRE technique ID (e.g., T1078)")
    technique_name: str = Field(description="Technique name")
    tactic: str = Field(description="MITRE tactic (e.g., Initial Access)")
    confidence: float = Field(ge=0.0, le=1.0, description="Match confidence 0-1")
    reasoning: str = Field(description="Why this technique matches the observed behavior")
    indicators_matched: List[str] = Field(description="Which indicators from the technique were observed")


class MitreMatchResult(BaseModel):
    """Result of MITRE ATT&CK matching."""

    matches: List[TechniqueMatch] = Field(description="Top matching techniques")
    attack_chain: List[str] = Field(description="Ordered sequence of technique IDs forming attack chain")
    tactics_observed: List[str] = Field(description="List of tactics observed")
    overall_confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(description="Summary of the attack pattern")


# ── MitreMatcher ──────────────────────────────────────────────────


class MitreMatcher:
    """
    Matches log patterns and threat assessments to MITRE ATT&CK techniques.

    Uses:
        1. LLM reasoning to match behaviors to techniques
        2. Vector similarity (future enhancement)
        3. Attack chain construction from technique sequences

    Usage::

        matcher = MitreMatcher()
        result = await matcher.match(threat_assessment, log_context)
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._llm_cfg = self._settings.llm
        self._mitre_data = self._load_mitre_data()
        self._prompt_template = self._load_prompt()
        self._llm = self._build_llm()
        self._parser = JsonOutputParser(pydantic_object=MitreMatchResult)
        self._chain = self._build_chain()

    # ── Setup ─────────────────────────────────────────────────────

    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK technique database."""
        mitre_path = self._settings.mitre_config_path
        if not mitre_path.exists():
            logger.warning("MITRE config not found at {}", mitre_path)
            return {"techniques": []}

        with open(mitre_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Loaded {} MITRE techniques", len(data.get("techniques", [])))
        return data

    def _load_prompt(self) -> str:
        """Load the MITRE matching prompt."""
        prompt_path = self._settings.prompts_dir / "mitre_prompt.md"
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        return self._default_prompt()

    def _default_prompt(self) -> str:
        return """You are a MITRE ATT&CK expert. Match the observed behaviors to specific techniques.
Threat Assessment: {threat_assessment}
Log Context: {log_context}
Available Techniques: {techniques_json}
Format instructions: {format_instructions}"""

    def _build_llm(self) -> ChatOpenAI:
        return ChatOpenAI(
            model=self._llm_cfg.primary_model,
            api_key=self._llm_cfg.openai_api_key,
            temperature=0.1,  # Lower temperature for more deterministic matching
            max_tokens=self._llm_cfg.max_tokens,
            timeout=self._llm_cfg.request_timeout,
        )

    def _build_chain(self) -> Any:
        prompt = ChatPromptTemplate.from_template(
            self._prompt_template
            + "\n\nThreat Assessment:\n{threat_assessment}"
            + "\n\nLog Context:\n{log_context}"
            + "\n\nAvailable Techniques:\n{techniques_json}"
            + "\n\n{format_instructions}"
        )
        return prompt | self._llm | self._parser

    # ── Matching ──────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def match(
        self,
        threat_assessment: Dict[str, Any],
        log_context: Optional[List[Dict[str, Any]]] = None,
    ) -> MitreMatchResult:
        """
        Match a threat assessment to MITRE ATT&CK techniques.

        Args:
            threat_assessment: ThreatAssessment dict from AnalystAgent
            log_context:       Raw log events for additional context

        Returns:
            MitreMatchResult with top-3 matching techniques and attack chain
        """
        logger.info("MitreMatcher matching threat_type={}", threat_assessment.get("threat_type"))

        # Prepare technique database (send subset to reduce token usage)
        techniques_subset = self._filter_relevant_techniques(threat_assessment)
        techniques_json = json.dumps(techniques_subset, indent=2)

        threat_json = json.dumps(threat_assessment, indent=2)
        log_json = json.dumps((log_context or [])[:10], indent=2, default=str)

        try:
            result = await self._chain.ainvoke({
                "threat_assessment": threat_json,
                "log_context": log_json,
                "techniques_json": techniques_json,
                "format_instructions": self._parser.get_format_instructions(),
            })

            if isinstance(result, dict):
                match_result = MitreMatchResult(**result)
            else:
                match_result = result

            logger.info(
                "Matched {} techniques, attack chain length={}",
                len(match_result.matches),
                len(match_result.attack_chain),
            )
            return match_result

        except Exception as exc:
            logger.error("MitreMatcher failed: {}", exc)
            return self._fallback_match(threat_assessment)

    def _filter_relevant_techniques(
        self, threat_assessment: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Filter MITRE techniques to those relevant to the threat type.
        Reduces token usage by sending only pertinent techniques to LLM.
        """
        threat_type = threat_assessment.get("threat_type", "").lower()
        attack_stage = threat_assessment.get("attack_stage", "").lower()

        # Keyword-based filtering
        keywords = [threat_type, attack_stage]
        keywords.extend(threat_assessment.get("iocs", []))

        relevant = []
        for tech in self._mitre_data.get("techniques", []):
            tech_text = (
                tech.get("name", "")
                + " "
                + tech.get("description", "")
                + " "
                + " ".join(tech.get("indicators", []))
            ).lower()

            if any(kw in tech_text for kw in keywords if kw):
                relevant.append(tech)

        # If no matches, return all (up to 30)
        if not relevant:
            relevant = self._mitre_data.get("techniques", [])[:30]

        return relevant[:30]  # Cap at 30 techniques

    def _fallback_match(self, threat_assessment: Dict[str, Any]) -> MitreMatchResult:
        """Return a conservative fallback when matching fails."""
        return MitreMatchResult(
            matches=[],
            attack_chain=[],
            tactics_observed=[],
            overall_confidence=0.0,
            summary="MITRE matching failed. Manual analysis required.",
        )

    # ── Attack chain construction ─────────────────────────────────

    def build_attack_chain(self, technique_ids: List[str]) -> List[str]:
        """
        Order technique IDs by kill chain progression.

        Tactic order: Initial Access → Execution → Persistence →
        Privilege Escalation → Defense Evasion → Credential Access →
        Discovery → Lateral Movement → Collection → Exfiltration → Impact
        """
        tactic_order = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

        # Map technique IDs to tactics
        id_to_tactic: Dict[str, str] = {}
        for tech in self._mitre_data.get("techniques", []):
            id_to_tactic[tech["technique_id"]] = tech.get("tactic", "Unknown")

        # Sort by tactic order
        def tactic_index(tid: str) -> int:
            tactic = id_to_tactic.get(tid, "Unknown")
            try:
                return tactic_order.index(tactic)
            except ValueError:
                return 999

        return sorted(technique_ids, key=tactic_index)

    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details for a technique ID."""
        for tech in self._mitre_data.get("techniques", []):
            if tech["technique_id"] == technique_id:
                return tech
        return None
