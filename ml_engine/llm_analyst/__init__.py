"""
LLM Analyst subpackage — Interactive Security Analyst Copilot.

Provides automated SOC Incident Synthesis, Containment Command Generation,
and Interactive Q&A powered by Google Gemini API.
"""

from ml_engine.llm_analyst.copilot import LLMSecurityCopilot
from ml_engine.llm_analyst.prompt_templates import (
    SOC_SYSTEM_INSTRUCTION,
    THREAT_ANALYSIS_PROMPT,
    REMEDIATION_PROMPT,
    ANALYST_CHAT_PROMPT,
)

__all__ = [
    "LLMSecurityCopilot",
    "SOC_SYSTEM_INSTRUCTION",
    "THREAT_ANALYSIS_PROMPT",
    "REMEDIATION_PROMPT",
    "ANALYST_CHAT_PROMPT",
]
