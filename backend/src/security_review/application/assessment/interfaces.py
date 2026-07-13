from abc import ABC, abstractmethod

from security_review.domain.assessment import Assessment


class AssessmentRepository(ABC):
    @abstractmethod
    def save(self, assessment: Assessment) -> Assessment:
        """Persist an assessment."""
        raise NotImplementedError