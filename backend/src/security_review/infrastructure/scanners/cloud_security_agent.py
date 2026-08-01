import re
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class CloudSecurityAgent(Agent):
    """Cloud infrastructure security assessment (AWS, GCP, Azure config)."""
    
    agent_type = AgentType.CLOUD_SECURITY

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Assess cloud configuration files for security issues."""
        findings = []
        
        if not target:
            return findings
        
        # Check for cloud configuration files
        findings.extend(self._check_terraform_configs(target))
        findings.extend(self._check_cloudformation_configs(target))
        findings.extend(self._check_docker_configs(target))
        findings.extend(self._check_k8s_configs(target))
        
        if not findings:
            findings.append(
                Finding(
                    title="Cloud security assessment completed",
                    severity=FindingSeverity.LOW,
                    description="No obvious cloud security misconfigurations detected in preliminary scan.",
                    evidence=target,
                    remediation="Continue using cloud security scanning tools and follow cloud security best practices.",
                )
            )
        
        return findings
    
    def _check_terraform_configs(self, target: str) -> list[Finding]:
        """Check Terraform configurations for security issues."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for tf_file in target_path.rglob("*.tf"):
                    try:
                        with open(tf_file) as f:
                            content = f.read()
                        
                        # Check for publicly accessible resources
                        if re.search(r'publicly_accessible\s*=\s*true', content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Publicly accessible database detected in Terraform",
                                    severity=FindingSeverity.HIGH,
                                    description="Database resource is configured as publicly accessible.",
                                    evidence=str(tf_file),
                                    remediation="Set publicly_accessible = false and use security groups to restrict access.",
                                )
                            )
                        
                        # Check for default security groups
                        if re.search(r'ingress.*0\.0\.0\.0/0|0\.0\.0\.0.*ingress', content):
                            findings.append(
                                Finding(
                                    title="Overly permissive ingress rule in Terraform",
                                    severity=FindingSeverity.HIGH,
                                    description="Security group allows traffic from any IP address (0.0.0.0/0).",
                                    evidence=str(tf_file),
                                    remediation="Restrict ingress to specific IP ranges or security groups.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_cloudformation_configs(self, target: str) -> list[Finding]:
        """Check CloudFormation templates for security issues."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for cf_file in target_path.rglob("*.yaml") | target_path.rglob("*.json"):
                    if "cloudformation" not in cf_file.name.lower() and cf_file.suffix not in [".yaml", ".yml"]:
                        continue
                    
                    try:
                        with open(cf_file) as f:
                            content = f.read()
                        
                        # Check for S3 bucket public access
                        if re.search(r'PublicRead|PublicReadWrite|AuthenticatedRead', content):
                            findings.append(
                                Finding(
                                    title="Potentially public S3 bucket in CloudFormation",
                                    severity=FindingSeverity.CRITICAL,
                                    description="S3 bucket may have public ACL configured.",
                                    evidence=str(cf_file),
                                    remediation="Remove public ACLs and use bucket policies with least privilege.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_docker_configs(self, target: str) -> list[Finding]:
        """Check Docker configurations for security issues."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for dockerfile in target_path.rglob("Dockerfile*"):
                    try:
                        with open(dockerfile) as f:
                            content = f.read()
                        
                        # Check for running as root
                        if "USER" not in content:
                            findings.append(
                                Finding(
                                    title="Docker container runs as root",
                                    severity=FindingSeverity.MEDIUM,
                                    description="Dockerfile does not specify non-root USER.",
                                    evidence=str(dockerfile),
                                    remediation="Add 'USER <non-root-user>' to Dockerfile.",
                                )
                            )
                        
                        # Check for latest tags
                        if re.search(r'FROM.*:latest', content):
                            findings.append(
                                Finding(
                                    title="Docker image uses :latest tag",
                                    severity=FindingSeverity.MEDIUM,
                                    description="Using :latest tag can lead to unpredictable base images.",
                                    evidence=str(dockerfile),
                                    remediation="Specify explicit version tags for base images.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_k8s_configs(self, target: str) -> list[Finding]:
        """Check Kubernetes configurations for security issues."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for k8s_file in target_path.rglob("*.yaml"):
                    try:
                        with open(k8s_file) as f:
                            content = f.read()
                        
                        # Check for privileged containers
                        if re.search(r'privileged:\s*true', content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Privileged Kubernetes container detected",
                                    severity=FindingSeverity.HIGH,
                                    description="Container is running in privileged mode.",
                                    evidence=str(k8s_file),
                                    remediation="Remove privileged flag unless absolutely necessary.",
                                )
                            )
                        
                        # Check for resource limits
                        if not re.search(r'limits:|requests:', content):
                            findings.append(
                                Finding(
                                    title="Missing Kubernetes resource limits",
                                    severity=FindingSeverity.MEDIUM,
                                    description="Pod lacks CPU/memory resource limits and requests.",
                                    evidence=str(k8s_file),
                                    remediation="Define resources.limits and resources.requests in pod spec.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
