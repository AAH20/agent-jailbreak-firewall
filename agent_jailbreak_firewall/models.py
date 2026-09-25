"""
Data models and telemetry schemas for Agent-Jailbreak-Firewall.
Supports Claude 3.7 Sonnet, OpenAI o3/GPT-4.5, Gemini 2.5 Pro, and DeepSeek-R1.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class ThreatCategory(str, Enum):
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    GOAL_HIJACKING = "goal_hijacking"
    TOOL_PARAMETER_POISONING = "tool_parameter_poisoning"
    STEGANOGRAPHIC_PAYLOAD = "steganographic_payload"
    ROLEPLAY_ESCAPE = "roleplay_escape"
    THINKING_TRACE_LEAK = "thinking_trace_leak"


class InspectionTarget(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVED_CONTEXT = "retrieved_context"
    TOOL_CALL_INPUT = "tool_call_input"
    TOOL_CALL_OUTPUT = "tool_call_output"
    MODEL_COMPLETION = "model_completion"
    THINKING_TRACE = "thinking_trace"


class FirewallAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"
    TRIPWIRE = "TRIPWIRE"


@dataclass
class ThreatAssessment:
    rule_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float            # 0.0 - 1.0
    matched_pattern: str
    explanation: str
    action: FirewallAction = FirewallAction.BLOCK


@dataclass
class FirewallDecision:
    allowed: bool
    action: FirewallAction
    target: InspectionTarget
    assessments: List[ThreatAssessment] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    original_length: int = 0
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    risk_score: float = 0.0      # 0.0 to 100.0


@dataclass
class AgentSessionContext:
    session_id: str
    original_mandate: str
    model_name: str              # e.g. "claude-opus-5-5", "gpt-6-astra", "gemini-3-8-flash-cyber"
    turn_count: int = 0
    total_blocked_threats: int = 0
    history_plans: List[str] = field(default_factory=list)
    active_circuit_breaker: bool = False
