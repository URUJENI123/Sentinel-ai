"""
agents/analyst_agent.py
────────────────────────
LLM-powered analyst agent that takes anomaly alerts and raw log context,
analyses attack patterns, and returns a structured threat assessment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI
from loguru import logger
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import get_settings
from detection.anomaly_detector import AnomalyAlert


# ── Output schema ─────────────────────────────────────────────────


class ThreatAssessment(BaseModel):
    """Structured output from the analyst agent."""

    threat_type: str = Field(description="Type of threat (e.g., brute_force, lateral_movement)")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    affected_systems: List[str] = Field(description="List of affected hostnames/IPs")
    attack_stage: str = Field(
        description="Kill chain stage: reconnaissance, weaponization, delivery, "
                    "exploitation, installation, c2, actions_on_objectives"
    )
    recommended_actions: List[str] = Field(description="Prioritised list of recommended actions")
    threat_actor_profile: Optional[str] = Field(
        default=None, description="Suspected threat actor profile if identifiable"
    )
    iocs: List[str] = Field(default_factory=list, description="Indicators of compromise")
    urgency: str = Field(description="Urgency level: low, medium, high, critical")
    summary: str = Field(description="Executive summary of the threat")
    raw_analysis: str = Field(description="Detailed analyst reasoning")


# ── AnalystAgent ──────────────────────────────────────────────────


class AnalystAgent:
    """
    Senior SOC analyst agent powered by GPT-4 / Claude.

    Takes an AnomalyAlert plus raw log context and returns a
    ThreatAssessment with structured threat intelligence.

    Usage::

        agent = AnalystAgent()
        assessment = await agent.analyse(alert, log_context)
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._llm_cfg = self._settings.llm
        self._prompt_template = self._load_prompt()
        self._llm = self._build_llm()
        self._parser = JsonOutputParser(pydantic_object=ThreatAssessment)
        self._chain = self._build_chain()

    # ── Setup ─────────────────────────────────────────────────────

    def _load_prompt(self) -> str:
        """Load the analyst prompt from the prompts directory."""
        prompt_path = self._settings.prompts_dir / "analyst_prompt.md"
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")
        logger.warning("Analyst prompt not found at {}. Using default.", prompt_path)
        return self._default_prompt()

    def _default_prompt(self) -> str:
        return """You are a senior SOC analyst with 15 years of experience in threat hunting.
Analyse the provided anomaly alert and log data. Return a JSON object matching the schema.
Alert: {alert_json}
Logs: {log_context}
Format instructions: {format_instructions}"""

    def _build_llm(self) -> ChatOpenAI:
        """Instantiate the LLM client."""
        return ChatOpenAI(
            model=self._llm_cfg.primary_model,
            api_key=self._llm_cfg.openai_api_key,
            temperature=self._llm_cfg.temperature,
            max_tokens=self._llm_cfg.max_tokens,
            timeout=self._llm_cfg.request_timeout,
            max_retries=self._llm_cfg.max_retries,
        )

    def _build_chain(self) -> Any:
        """Build the LangChain processing chain."""
        prompt = ChatPromptTemplate.from_template(
            self._prompt_template
            + "\n\nAlert Data:\n{alert_json}\n\nLog Context:\n{log_context}"
            + "\n\n{format_instructions}"
        )
        return prompt | self._llm | self._parser

    # ── Analysis ──────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def analyse(
        self,
        alert: AnomalyAlert,
        log_context: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatAssessment:
        """
        Analyse an anomaly alert and return a structured threat assessment.

        Args:
            alert:       The AnomalyAlert from the detector.
            log_context: Additional raw log events for context (up to 20).

        Returns:
            ThreatAssessment with structured threat intelligence.
        """
        alert_json = json.dumps(alert.to_dict(), indent=2)
        logs_for_context = (log_context or alert.raw_logs)[:20]
        log_context_str = json.dumps(logs_for_context, indent=2, default=str)

        logger.info(
            "AnalystAgent analysing alert {} (severity={})",
            alert.alert_id,
            alert.severity.value,
        )

        try:
            result = await self._chain.ainvoke({
                "alert_json": alert_json,
                "log_context": log_context_str,
                "format_instructions": self._parser.get_format_instructions(),
            })

            # Validate and coerce to ThreatAssessment
            if isinstance(result, dict):
                assessment = ThreatAssessment(**result)
            else:
                assessment = result

            logger.info(
                "Analysis complete: threat_type={} confidence={:.2f} stage={}",
                assessment.threat_type,
                assessment.confidence,
                assessment.attack_stage,
            )
            return assessment

        except Exception as exc:
            logger.error("AnalystAgent failed: {}", exc)
            # Return a safe fallback assessment
            return self._fallback_assessment(alert, str(exc))

    def _fallback_assessment(self, alert: AnomalyAlert, error: str) -> ThreatAssessment:
        """Return a conservative fallback when LLM analysis fails."""
        return ThreatAssessment(
            threat_type="unknown",
            confidence=alert.composite_score,
            affected_systems=alert.affected_hosts,
            attack_stage="unknown",
            recommended_actions=["Investigate manually", "Review raw logs"],
            urgency=alert.severity.value.lower(),
            summary=f"Automated analysis failed ({error}). Manual review required.",
            raw_analysis=f"LLM analysis error: {error}",
            iocs=[alert.source_ip] if alert.source_ip else [],
        )

    # ── Batch analysis ────────────────────────────────────────────

    async def analyse_batch(
        self, alerts: List[AnomalyAlert]
    ) -> List[ThreatAssessment]:
        """Analyse multiple alerts concurrently."""
        import asyncio
        tasks = [self.analyse(alert) for alert in alerts]
        return await asyncio.gather(*tasks, return_exceptions=False)
