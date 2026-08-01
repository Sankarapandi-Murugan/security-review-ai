from __future__ import annotations

from abc import ABC, abstractmethod

from security_review.domain.assessment.models import AgentType, Finding


class Agent(ABC):
    agent_type: AgentType

    @abstractmethod
    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Run the agent against ``target``.

        ``authorized`` signals that the caller has confirmed they have explicit
        permission to actively test ``target`` (mirrors
        ``ScanJob.target_authorization_confirmed``). Agents that perform active,
        intrusive probing of live external targets (e.g. Black Box) should only do
        so when ``authorized`` is ``True``; it is safe for agents that only do
        passive/static analysis to ignore this flag.
        """
        raise NotImplementedError
