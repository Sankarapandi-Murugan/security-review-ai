from __future__ import annotations

from abc import ABC, abstractmethod

from security_review.domain.assessment.models import AgentType, Finding


class Agent(ABC):
    agent_type: AgentType

    @abstractmethod
    def execute(self, target: str | None) -> list[Finding]:
        raise NotImplementedError
