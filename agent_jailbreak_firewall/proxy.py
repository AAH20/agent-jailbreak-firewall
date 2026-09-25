"""
In-line Reverse Proxy and Middleware for Agent-Jailbreak-Firewall.
Wraps LLM agent execution loops with sub-5ms semantic perimeter security.
"""

from typing import Dict, List, Optional, Callable, Any, Tuple
from .models import (
    InspectionTarget,
    FirewallAction,
    FirewallDecision,
    AgentSessionContext,
)
from .scanner import SemanticFirewallScanner


class AgentJailbreakProxy:
    """Security perimeter middleware for autonomous agent tool execution loops."""

    def __init__(self, risk_threshold: float = 75.0):
        self.scanner = SemanticFirewallScanner(risk_threshold=risk_threshold)
        self.sessions: Dict[str, AgentSessionContext] = {}
        self.blocked_audit_log: List[FirewallDecision] = []

    def create_session(self, session_id: str, mandate: str, model: str = "claude-3-7-sonnet-20250219") -> AgentSessionContext:
        """Initialize session tracking with user root mandate."""
        session = AgentSessionContext(
            session_id=session_id,
            original_mandate=mandate,
            model_name=model
        )
        self.sessions[session_id] = session
        return session

    def sanitize_retrieved_context(self, context_text: str) -> Tuple[bool, str, FirewallDecision]:
        """Inspect scraped web pages, PDFs, and external RAG chunks before feeding to LLM."""
        decision = self.scanner.inspect_text(context_text, InspectionTarget.RETRIEVED_CONTEXT)
        if not decision.allowed:
            self.blocked_audit_log.append(decision)
            # Redact or quarantine malicious content
            quarantine_msg = f"[GHOST_FIREWALL_QUARANTINE: {len(decision.assessments)} Injection Threats Blocked. Content Redacted]"
            return False, quarantine_msg, decision
        return True, context_text, decision

    def validate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[bool, FirewallDecision]:
        """Inspect tool invocation parameters before agent executes the call."""
        session = self.sessions.get(session_id)
        if session and session.active_circuit_breaker:
            # Circuit breaker already tripped
            decision = FirewallDecision(
                allowed=False,
                action=FirewallAction.BLOCK,
                target=InspectionTarget.TOOL_CALL_INPUT,
                risk_score=100.0,
                latency_ms=0.01
            )
            return False, decision

        decision = self.scanner.inspect_tool_call(tool_name, arguments)
        if not decision.allowed:
            self.blocked_audit_log.append(decision)
            if session:
                session.total_blocked_threats += 1
            return False, decision
        return True, decision

    def inspect_thinking_trace(
        self,
        session_id: str,
        thinking_text: str
    ) -> Tuple[bool, FirewallDecision]:
        """Inspect Claude 3.7 Sonnet extended thinking / OpenAI o3 reasoning trace."""
        session = self.sessions.get(session_id)
        if not session:
            session = self.create_session(session_id, "Generic Task")

        decision = self.scanner.evaluate_cognitive_drift(session, thinking_text)
        if not decision.allowed:
            self.blocked_audit_log.append(decision)
        return decision.allowed, decision
