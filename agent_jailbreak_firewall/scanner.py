"""
Deep Semantic Scanner and Rule Engine for Agent-Jailbreak-Firewall.
Optimized for frontier reasoning agents (Claude 3.7 Sonnet, OpenAI o3, Gemini 2.5 Pro, DeepSeek-R1).
"""

import base64
import json
import re
import time
from typing import Dict, List, Optional, Tuple, Any

from .models import (
    ThreatCategory,
    ThreatSeverity,
    InspectionTarget,
    FirewallAction,
    ThreatAssessment,
    FirewallDecision,
    AgentSessionContext,
)


# Compiled High-Precision Injection & Exfiltration Patterns
INDIRECT_INJECTION_PATTERNS = [
    (r"(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|directives)", ThreatSeverity.CRITICAL, "Instruction Override Attempt"),
    (r"(?i)(?:system\s+notice|system\s+override|system\s+directive|developer\s+mode|dan\s+mode)\s*:", ThreatSeverity.CRITICAL, "Synthetic System Prompt Injection"),
    (r"(?i)you\s+are\s+no\s+longer\s+(?:bound\s+by|constrained\s+by)\s+(?:your\s+)?(?:rules|guidelines|safety)", ThreatSeverity.HIGH, "Safety Boundary Bypass"),
    (r"(?i)(?:print|output|leak|reveal|repeat)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+mandate)", ThreatSeverity.HIGH, "System Prompt Extraction Attack"),
]

EXFILTRATION_PATTERNS = [
    (r"!\[.*?\]\(https?://[^\s)]+(?:\?|&)(?:data|secret|token|key|leak|env)=.*?\)", ThreatSeverity.CRITICAL, "Markdown Image Pingback Exfiltration"),
    (r"(?i)(?:curl|wget|fetch|nc|ncat)\s+(?:https?://[^\s]+|[\d\.]+)\s*(?:-d|--data|>\s*|\|\s*)", ThreatSeverity.CRITICAL, "Network Payload Exfiltration Command"),
    (r"(?:sk-proj-[a-zA-Z0-9_-]{32,}|sk-ant-[a-zA-Z0-9_-]{32,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})", ThreatSeverity.CRITICAL, "Raw High-Entropy Secret/API Key Detected"),
    (r"(?i)(?:nslookup|dig)\s+\$\([^)]+\)\.[a-zA-Z0-9.-]+", ThreatSeverity.CRITICAL, "DNS Tunneling Exfiltration Attempt"),
]

TOOL_POISONING_PATTERNS = [
    (r"(?:;\s*rm\s+-rf|&&\s*rm\s+-rf|\|\s*rm\s+-rf)", ThreatSeverity.CRITICAL, "Destructive Command Chaining (rm -rf)"),
    (r"(?:\.\./){3,}(?:etc|var|proc|sys|root)", ThreatSeverity.HIGH, "Filesystem Path Traversal Attempt"),
    (r"(?:curl\s+.*?\|\s*(?:bash|sh)|wget\s+.*?\|\s*(?:bash|sh))", ThreatSeverity.CRITICAL, "Remote Shell Execution Download Pipe"),
]


class SemanticFirewallScanner:
    """Zero-latency deep content inspector and threat evaluator."""

    def __init__(self, risk_threshold: float = 75.0):
        self.risk_threshold = risk_threshold

    def inspect_text(self, text: str, target: InspectionTarget) -> FirewallDecision:
        """Inspect plain text or retrieved context for prompt injection and exfiltration."""
        start_time = time.time()
        assessments: List[ThreatAssessment] = []

        if not text:
            return FirewallDecision(
                allowed=True,
                action=FirewallAction.ALLOW,
                target=target,
                latency_ms=(time.time() - start_time) * 1000.0,
                risk_score=0.0
            )

        # 1. Test for Indirect Prompt Injection
        for pattern, severity, explanation in INDIRECT_INJECTION_PATTERNS:
            match = re.search(pattern, text)
            if match:
                assessments.append(ThreatAssessment(
                    rule_id="INJ_" + severity.value[:3],
                    category=ThreatCategory.INDIRECT_PROMPT_INJECTION,
                    severity=severity,
                    confidence=0.98,
                    matched_pattern=match.group(0),
                    explanation=f"{explanation}: matched '{match.group(0)[:60]}...'",
                    action=FirewallAction.BLOCK
                ))

        # 2. Test for Data Exfiltration
        for pattern, severity, explanation in EXFILTRATION_PATTERNS:
            match = re.search(pattern, text)
            if match:
                assessments.append(ThreatAssessment(
                    rule_id="EXF_" + severity.value[:3],
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=severity,
                    confidence=0.99,
                    matched_pattern=match.group(0),
                    explanation=f"{explanation}: matched '{match.group(0)[:60]}...'",
                    action=FirewallAction.BLOCK
                ))

        # 3. Check for Hidden Base64 payloads (>32 chars)
        b64_matches = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
        for b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                for pat, _, expl in INDIRECT_INJECTION_PATTERNS:
                    if re.search(pat, decoded):
                        assessments.append(ThreatAssessment(
                            rule_id="STEG_B64",
                            category=ThreatCategory.STEGANOGRAPHIC_PAYLOAD,
                            severity=ThreatSeverity.CRITICAL,
                            confidence=0.95,
                            matched_pattern=b64[:30] + "...",
                            explanation=f"Base64 obfuscated payload concealing prompt injection: {expl}",
                            action=FirewallAction.BLOCK
                        ))
            except Exception:
                pass

        # Calculate composite risk score
        risk_score = 0.0
        for a in assessments:
            if a.severity == ThreatSeverity.CRITICAL:
                risk_score += 85.0
            elif a.severity == ThreatSeverity.HIGH:
                risk_score += 45.0
            elif a.severity == ThreatSeverity.MEDIUM:
                risk_score += 20.0
            else:
                risk_score += 10.0
        risk_score = min(100.0, risk_score)

        is_allowed = (risk_score < self.risk_threshold)
        action = FirewallAction.ALLOW if is_allowed else FirewallAction.BLOCK
        latency_ms = (time.time() - start_time) * 1000.0

        return FirewallDecision(
            allowed=is_allowed,
            action=action,
            target=target,
            assessments=assessments,
            original_length=len(text),
            latency_ms=round(latency_ms, 3),
            risk_score=risk_score
        )

    def inspect_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> FirewallDecision:
        """Inspect tool invocation parameters for poisoning or escape commands."""
        start_time = time.time()
        assessments: List[ThreatAssessment] = []
        raw_json = json.dumps(arguments)

        # Check against Tool Poisoning patterns
        for pattern, severity, explanation in TOOL_POISONING_PATTERNS:
            match = re.search(pattern, raw_json)
            if match:
                assessments.append(ThreatAssessment(
                    rule_id="TOOL_POISON",
                    category=ThreatCategory.TOOL_PARAMETER_POISONING,
                    severity=severity,
                    confidence=0.99,
                    matched_pattern=match.group(0),
                    explanation=f"{explanation} in tool '{tool_name}' parameters",
                    action=FirewallAction.BLOCK
                ))

        # Check against Exfiltration patterns in arguments
        for pattern, severity, explanation in EXFILTRATION_PATTERNS:
            match = re.search(pattern, raw_json)
            if match:
                assessments.append(ThreatAssessment(
                    rule_id="TOOL_EXF",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=severity,
                    confidence=0.99,
                    matched_pattern=match.group(0),
                    explanation=f"{explanation} embedded in tool '{tool_name}' arguments",
                    action=FirewallAction.BLOCK
                ))

        risk_score = 100.0 if assessments else 0.0
        is_allowed = len(assessments) == 0
        action = FirewallAction.ALLOW if is_allowed else FirewallAction.BLOCK

        return FirewallDecision(
            allowed=is_allowed,
            action=action,
            target=InspectionTarget.TOOL_CALL_INPUT,
            assessments=assessments,
            original_length=len(raw_json),
            latency_ms=round((time.time() - start_time) * 1000.0, 3),
            risk_score=risk_score
        )

    def evaluate_cognitive_drift(self, session: AgentSessionContext, latest_plan: str) -> FirewallDecision:
        """
        Detects multi-turn cognitive hijacking.
        Flags when an agent shifts from user mandate to adversarial actions.
        """
        start_time = time.time()
        session.turn_count += 1
        session.history_plans.append(latest_plan)

        assessments: List[ThreatAssessment] = []
        # Check if the plan contains exfiltration or hijacking indicators
        hijack_keywords = ["exfiltrate", "dump database", "send tokens to external", "bypass firewall", "disable logging"]
        for kw in hijack_keywords:
            if kw in latest_plan.lower():
                assessments.append(ThreatAssessment(
                    rule_id="COGNITIVE_HIJACK",
                    category=ThreatCategory.GOAL_HIJACKING,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.95,
                    matched_pattern=kw,
                    explanation=f"Agent plan drifted into hostile action '{kw}' divergent from mandate: '{session.original_mandate}'",
                    action=FirewallAction.TRIPWIRE
                ))

        if assessments:
            session.active_circuit_breaker = True
            session.total_blocked_threats += 1

        latency_ms = (time.time() - start_time) * 1000.0
        return FirewallDecision(
            allowed=not bool(assessments),
            action=FirewallAction.ALLOW if not assessments else FirewallAction.TRIPWIRE,
            target=InspectionTarget.THINKING_TRACE,
            assessments=assessments,
            original_length=len(latest_plan),
            latency_ms=round(latency_ms, 3),
            risk_score=100.0 if assessments else 0.0
        )
