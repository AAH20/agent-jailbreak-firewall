"""
Agent-Jailbreak-Firewall: Zero-Latency Semantic WAF for Multi-Modal & Tool-Calling Agents.
Supports Claude 3.7 Sonnet, OpenAI o3/GPT-4.5, Gemini 2.5 Pro, and DeepSeek-R1.
"""

from .models import (
    ThreatSeverity,
    ThreatCategory,
    InspectionTarget,
    FirewallAction,
    ThreatAssessment,
    FirewallDecision,
    AgentSessionContext,
)
from .scanner import SemanticFirewallScanner
from .proxy import AgentJailbreakProxy

__version__ = "1.0.0"
__all__ = [
    "ThreatSeverity",
    "ThreatCategory",
    "InspectionTarget",
    "FirewallAction",
    "ThreatAssessment",
    "FirewallDecision",
    "AgentSessionContext",
    "SemanticFirewallScanner",
    "AgentJailbreakProxy",
]
