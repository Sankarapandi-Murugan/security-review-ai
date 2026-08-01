from security_review.domain.assessment.models import AgentType
from security_review.infrastructure.scanners.api_security_agent import ApiSecurityAgent
from security_review.infrastructure.scanners.blue_team_agent import BlueTeamAgent
from security_review.infrastructure.scanners.black_box_agent import BlackBoxAgent
from security_review.infrastructure.scanners.cloud_security_agent import CloudSecurityAgent
from security_review.infrastructure.scanners.dependency_security_agent import DependencySecurityAgent
from security_review.infrastructure.scanners.red_team_agent import RedTeamAgent
from security_review.infrastructure.scanners.secret_detection_agent import SecretDetectionAgent
from security_review.infrastructure.scanners.white_box_agent import WhiteBoxAgent
from security_review.infrastructure.scanners.trivy_agent import TrivyAgent


class AgentFactory:
    @staticmethod
    def create(agent_type: AgentType):
        if agent_type == AgentType.WHITE_BOX:
            return WhiteBoxAgent()
        if agent_type == AgentType.BLACK_BOX:
            return BlackBoxAgent()
        if agent_type == AgentType.DEPENDENCY_SECURITY:
            return DependencySecurityAgent()
        if agent_type == AgentType.API_SECURITY:
            return ApiSecurityAgent()
        if agent_type == AgentType.CLOUD_SECURITY:
            return CloudSecurityAgent()
        if agent_type == AgentType.TRIVY:
            return TrivyAgent()
        if agent_type == AgentType.RED_TEAM:
            return RedTeamAgent()
        if agent_type == AgentType.BLUE_TEAM:
            return BlueTeamAgent()
        if agent_type == AgentType.SECRET_DETECTION:
            return SecretDetectionAgent()

        # Default fallback uses white-box-style findings for unsupported agent types.
        return WhiteBoxAgent()
