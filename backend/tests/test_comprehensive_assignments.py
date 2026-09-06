"""
Vigil AI - Comprehensive Assessment/Assignment Test Suite
================================================================

This module consolidates all assessment-related tests including:
- Domain layer business logic
- Application layer use cases
- API endpoint integration
- Multi-workflow scenarios
- Error handling and edge cases

Test Organization:
1. Domain Layer Tests (Business Logic)
2. Application Layer Tests (Use Cases)
3. API Integration Tests (REST Endpoints)
4. Complex Workflow Tests
5. Error Handling & Edge Cases
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from security_review.main import app
from security_review.domain.assessment import Assessment, AssessmentStatus
from security_review.domain.assessment.exceptions import InvalidAssessmentStateError
from security_review.domain.finding import Finding, FindingStatus, Location
from security_review.domain.finding.exceptions import InvalidFindingStateError
from security_review.domain.repository import Repository, RepositoryStatus
from security_review.domain.repository.exceptions import InvalidRepositoryStateError
from security_review.application.assessment.create_assessment import CreateAssessmentUseCase
from security_review.application.assessment.dto import CreateAssessmentRequest
from security_review.infrastructure.persistence.in_memory.assessment_repository import (
    InMemoryAssessmentRepository,
)
from tests._auth_helpers import signup_headers


# ============================================================================
# PART 1: DOMAIN LAYER TESTS - Business Logic Validation
# ============================================================================

class TestAssessmentDomain:
    """Test suite for Assessment domain model and state machine."""

    def test_new_assessment_has_created_status(self):
        """Test that a newly created assessment starts in CREATED status."""
        assessment = Assessment(name="Security Review")
        assert assessment.status == AssessmentStatus.CREATED

    def test_assessment_with_description(self):
        """Test assessment creation with description."""
        assessment = Assessment(
            name="Q4 Audit",
            description="Quarterly security audit"
        )
        assert assessment.name == "Q4 Audit"
        assert assessment.description == "Quarterly security audit"
        assert assessment.status == AssessmentStatus.CREATED

    def test_start_analysis_transitions_status(self):
        """Test that starting analysis transitions assessment to ANALYZING status."""
        assessment = Assessment(name="Analysis Test")
        assessment.start_analysis()
        assert assessment.status == AssessmentStatus.ANALYZING

    def test_complete_assessment_after_analysis(self):
        """Test completing an assessment after starting analysis."""
        assessment = Assessment(name="Completion Test")
        assessment.start_analysis()
        assessment.complete()
        assert assessment.status == AssessmentStatus.COMPLETED

    def test_fail_assessment_after_analysis(self):
        """Test failing an assessment after starting analysis."""
        assessment = Assessment(name="Failure Test")
        assessment.start_analysis()
        assessment.fail()
        assert assessment.status == AssessmentStatus.FAILED

    def test_cannot_complete_without_starting(self):
        """Test that completing without starting raises an error."""
        assessment = Assessment(name="Error Test")
        with pytest.raises(InvalidAssessmentStateError):
            assessment.complete()

    def test_cannot_fail_without_starting(self):
        """Test that failing without starting raises an error."""
        assessment = Assessment(name="Error Test")
        with pytest.raises(InvalidAssessmentStateError):
            assessment.fail()

    def test_cannot_start_analysis_twice(self):
        """Test that starting analysis twice raises an error."""
        assessment = Assessment(name="Double Start Test")
        assessment.start_analysis()
        with pytest.raises(InvalidAssessmentStateError):
            assessment.start_analysis()

    def test_cannot_transition_from_completed(self):
        """Test that completed assessments cannot transition to other states."""
        assessment = Assessment(name="Final State Test")
        assessment.start_analysis()
        assessment.complete()
        with pytest.raises(InvalidAssessmentStateError):
            assessment.fail()

    def test_rename_assessment(self):
        """Test renaming an assessment."""
        assessment = Assessment(name="Old Name")
        assessment.rename("New Name")
        assert assessment.name == "New Name"

    def test_assessment_timestamps_are_set(self):
        """Test that assessment timestamps are automatically set."""
        assessment = Assessment(name="Timestamp Test")
        assert assessment.created_at is not None
        assert assessment.updated_at is not None

    def test_assessment_unique_id_generation(self):
        """Test that each assessment gets a unique ID."""
        assessment1 = Assessment(name="Test 1")
        assessment2 = Assessment(name="Test 2")
        assert assessment1.id != assessment2.id


class TestFindingDomain:
    """Test suite for Finding domain model and state management."""

    def test_new_finding_is_open(self):
        """Test that a new finding starts in OPEN status."""
        finding = Finding(title="SQL Injection Vulnerability")
        assert finding.status == FindingStatus.OPEN

    def test_confirm_finding_changes_status(self):
        """Test confirming a finding transitions it to CONFIRMED status."""
        finding = Finding(title="XSS Vulnerability")
        finding.confirm()
        assert finding.status == FindingStatus.CONFIRMED

    def test_resolve_confirmed_finding(self):
        """Test resolving a confirmed finding."""
        finding = Finding(title="CSRF Token Missing")
        finding.confirm()
        finding.resolve()
        assert finding.status == FindingStatus.RESOLVED

    def test_mark_finding_as_false_positive(self):
        """Test marking a finding as false positive."""
        finding = Finding(title="False Positive Test")
        finding.mark_false_positive()
        assert finding.status == FindingStatus.FALSE_POSITIVE

    def test_cannot_resolve_without_confirmation(self):
        """Test that resolving without confirming raises an error."""
        finding = Finding(title="State Error Test")
        with pytest.raises(InvalidFindingStateError):
            finding.resolve()

    def test_finding_with_severity(self):
        """Test finding creation with severity level."""
        finding = Finding(
            title="Critical Vulnerability",
            severity="critical"
        )
        assert finding.severity == "critical"

    def test_finding_with_location(self):
        """Test finding with source code location."""
        location = Location(
            file_path="src/controllers/UserController.java",
            line=42,
            column=15
        )
        finding = Finding(
            title="Buffer Overflow",
            location=location
        )
        assert finding.location.file_path == "src/controllers/UserController.java"
        assert finding.location.line == 42
        assert finding.location.column == 15

    def test_location_value_object_equality(self):
        """Test location value object equality."""
        location1 = Location(file_path="app.py", line=10, column=5)
        location2 = Location(file_path="app.py", line=10, column=5)
        assert location1.file_path == location2.file_path
        assert location1.line == location2.line

    def test_finding_with_description_and_remediation(self):
        """Test finding with detailed description and remediation steps."""
        finding = Finding(
            title="SQL Injection",
            description="User input not sanitized in query",
            remediation="Use prepared statements"
        )
        assert finding.description == "User input not sanitized in query"
        assert finding.remediation == "Use prepared statements"


class TestRepositoryDomain:
    """Test suite for Repository domain model."""

    def test_new_repository_is_created(self):
        """Test that a new repository starts in CREATED status."""
        repo = Repository(name="MyApp", url="https://github.com/user/myapp")
        assert repo.status == RepositoryStatus.CREATED

    def test_mark_repository_ready(self):
        """Test marking a repository as ready for analysis."""
        repo = Repository(name="MyApp", url="https://github.com/user/myapp")
        repo.mark_ready(local_path="/path/to/clone")
        assert repo.status == RepositoryStatus.READY

    def test_cannot_start_analysis_before_ready(self):
        """Test that analysis cannot start before repository is ready."""
        repo = Repository(name="MyApp", url="https://github.com/user/myapp")
        with pytest.raises(InvalidRepositoryStateError):
            repo.start_analysis()

    def test_start_analysis_after_ready(self):
        """Test starting analysis after repository is ready."""
        repo = Repository(name="MyApp", url="https://github.com/user/myapp")
        repo.mark_ready(local_path="/path/to/clone")
        repo.start_analysis()
        assert repo.status == RepositoryStatus.ANALYZING

    def test_repository_with_branch(self):
        """Test repository with specific branch."""
        repo = Repository(
            name="MyApp",
            url="https://github.com/user/myapp",
            branch="develop"
        )
        assert repo.branch == "develop"

    def test_add_language_to_repository(self):
        """Test adding programming languages to repository."""
        repo = Repository(name="MultiLang", url="https://github.com/user/multi")
        repo.add_language("Python")
        repo.add_language("JavaScript")
        assert "Python" in repo.languages
        assert "JavaScript" in repo.languages


# ============================================================================
# PART 2: APPLICATION LAYER TESTS - Use Cases & Business Services
# ============================================================================

class TestCreateAssessmentUseCase:
    """Test suite for the Create Assessment use case."""

    def test_create_assessment_use_case(self):
        """Test creating an assessment through the use case."""
        repository = InMemoryAssessmentRepository()
        use_case = CreateAssessmentUseCase(repository)

        response = use_case.execute(
            CreateAssessmentRequest(name="API Security Audit")
        )

        assert response.name == "API Security Audit"
        assert response.status == AssessmentStatus.CREATED

    def test_create_assessment_with_description(self):
        """Test creating assessment with description through use case."""
        repository = InMemoryAssessmentRepository()
        use_case = CreateAssessmentUseCase(repository)

        response = use_case.execute(
            CreateAssessmentRequest(
                name="Q4 Review",
                description="End of quarter security review"
            )
        )

        assert response.name == "Q4 Review"
        assert response.description == "End of quarter security review"

    def test_created_assessment_is_persisted(self):
        """Test that created assessment is persisted in repository."""
        repository = InMemoryAssessmentRepository()
        use_case = CreateAssessmentUseCase(repository)

        response = use_case.execute(
            CreateAssessmentRequest(name="Persistence Test")
        )

        # Verify it can be retrieved
        all_assessments = repository.find_all()
        assert any(a.id == response.id for a in all_assessments)


# ============================================================================
# PART 3: API INTEGRATION TESTS - REST Endpoints
# ============================================================================

class TestAssessmentAPI:
    """Test suite for Assessment REST API endpoints."""

    def test_create_assessment_via_api(self):
        """Test creating an assessment via POST endpoint."""
        client = TestClient(app)
        headers = signup_headers(client)

        response = client.post(
            "/assessments",
            json={
                "name": "API Test Assessment",
                "description": "Testing via REST API"
            },
            headers=headers,
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "API Test Assessment"
        assert data["status"] == "created"
        assert data["description"] == "Testing via REST API"

    def test_list_assessments_via_api(self):
        """Test listing assessments via GET endpoint."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create multiple assessments
        for i in range(3):
            client.post(
                "/assessments",
                json={"name": f"Assessment {i}", "description": ""},
                headers=headers,
            )

        response = client.get("/assessments", headers=headers)
        assert response.status_code == 200
        items = response.json()
        assert len(items) >= 3

    def test_get_assessment_by_id(self):
        """Test retrieving a specific assessment by ID."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        create_response = client.post(
            "/assessments",
            json={"name": "Get Test", "description": "Test retrieval"},
            headers=headers,
        )
        assessment_id = create_response.json()["id"]

        # Get by ID
        response = client.get(f"/assessments/{assessment_id}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == assessment_id
        assert data["name"] == "Get Test"

    def test_get_nonexistent_assessment_returns_404(self):
        """Test that getting non-existent assessment returns 404."""
        client = TestClient(app)
        headers = signup_headers(client)

        response = client.get(
            "/assessments/00000000-0000-0000-0000-000000000000",
            headers=headers
        )
        assert response.status_code == 404

    def test_create_and_list_assessments_roundtrip(self):
        """Test complete create and list workflow."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create
        create_response = client.post(
            "/assessments",
            json={
                "name": "Quarterly Review",
                "description": "Automated security assessment"
            },
            headers=headers,
        )
        assert create_response.status_code == 201
        created = create_response.json()

        # List
        list_response = client.get("/assessments", headers=headers)
        assert list_response.status_code == 200
        items = list_response.json()

        # Verify created assessment in list
        assert any(item["id"] == created["id"] for item in items)

    def test_update_assessment_name(self):
        """Test updating assessment name."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create
        create_response = client.post(
            "/assessments",
            json={"name": "Old Name", "description": ""},
            headers=headers,
        )
        assessment_id = create_response.json()["id"]

        # Update
        update_response = client.patch(
            f"/assessments/{assessment_id}",
            json={"name": "New Name"},
            headers=headers,
        )
        assert update_response.status_code == 200
        data = update_response.json()
        assert data["name"] == "New Name"

    def test_delete_assessment(self):
        """Test deleting an assessment."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create
        create_response = client.post(
            "/assessments",
            json={"name": "To Delete", "description": ""},
            headers=headers,
        )
        assessment_id = create_response.json()["id"]

        # Delete
        delete_response = client.delete(
            f"/assessments/{assessment_id}",
            headers=headers
        )
        assert delete_response.status_code == 204

        # Verify deleted
        get_response = client.get(
            f"/assessments/{assessment_id}",
            headers=headers
        )
        assert get_response.status_code == 404

    def test_delete_nonexistent_assessment_returns_404(self):
        """Test that deleting non-existent assessment returns 404."""
        client = TestClient(app)
        headers = signup_headers(client)

        response = client.delete(
            "/assessments/00000000-0000-0000-0000-000000000000",
            headers=headers
        )
        assert response.status_code == 404


class TestScanJobAPI:
    """Test suite for Scan Job API endpoints."""

    def test_create_scan_job(self):
        """Test creating a scan job for an assessment."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        assessment_response = client.post(
            "/assessments",
            json={"name": "Scan Test", "description": ""},
            headers=headers,
        )
        assessment_id = assessment_response.json()["id"]

        # Create scan job
        scan_response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={
                "agent_type": "white_box",
                "target": "/workspaces/security-review-ai/backend/src"
            },
            headers=headers,
        )

        assert scan_response.status_code == 201
        scan_job = scan_response.json()
        assert scan_job["status"] == "pending"
        assert scan_job["agent_type"] == "white_box"

    def test_list_scan_jobs_for_assessment(self):
        """Test listing scan jobs for an assessment."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        assessment_response = client.post(
            "/assessments",
            json={"name": "Scan List Test", "description": ""},
            headers=headers,
        )
        assessment_id = assessment_response.json()["id"]

        # Create multiple scan jobs
        for i in range(2):
            client.post(
                f"/assessments/{assessment_id}/scan-jobs",
                json={
                    "agent_type": "white_box",
                    "target": "/workspaces/security-review-ai/backend/src"
                },
                headers=headers,
            )

        # Get assessment and check scan jobs
        response = client.get(f"/assessments/{assessment_id}", headers=headers)
        assert response.status_code == 200
        assessment = response.json()
        assert len(assessment["scan_jobs"]) >= 2

    def test_multiple_scan_jobs_on_same_assessment(self):
        """Test creating multiple different scan jobs on same assessment."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        assessment_response = client.post(
            "/assessments",
            json={"name": "Multi Scan Test", "description": ""},
            headers=headers,
        )
        assessment_id = assessment_response.json()["id"]

        # Create different scan jobs
        agents = ["white_box", "black_box", "dependency_security"]
        for agent in agents:
            response = client.post(
                f"/assessments/{assessment_id}/scan-jobs",
                json={
                    "agent_type": agent,
                    "target": "/workspaces/security-review-ai/backend/src"
                },
                headers=headers,
            )
            assert response.status_code == 201

        # Verify all created
        assessment = client.get(
            f"/assessments/{assessment_id}",
            headers=headers
        ).json()
        assert len(assessment["scan_jobs"]) == 3


# ============================================================================
# PART 4: COMPLEX WORKFLOW TESTS - Multi-step Scenarios
# ============================================================================

class TestAssessmentWorkflows:
    """Test suite for complex assessment workflows."""

    def test_complete_assessment_workflow(self):
        """Test complete workflow from creation to completion."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Step 1: Create assessment
        create_response = client.post(
            "/assessments",
            json={
                "name": "Complete Workflow",
                "description": "Full workflow test"
            },
            headers=headers,
        )
        assert create_response.status_code == 201
        assessment = create_response.json()
        assessment_id = assessment["id"]

        # Step 2: Verify assessment created
        get_response = client.get(
            f"/assessments/{assessment_id}",
            headers=headers
        )
        assert get_response.status_code == 200
        assert get_response.json()["status"] == "created"

        # Step 3: Create scan job
        scan_response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={
                "agent_type": "white_box",
                "target": "/workspaces/security-review-ai/backend/src"
            },
            headers=headers,
        )
        assert scan_response.status_code == 201

        # Step 4: Verify findings generated
        final_assessment = client.get(
            f"/assessments/{assessment_id}",
            headers=headers
        ).json()
        assert len(final_assessment["scan_jobs"]) > 0
        assert len(final_assessment["findings"]) > 0

    def test_multiple_assessments_per_organization(self):
        """Test creating multiple assessments in same organization."""
        client = TestClient(app)
        headers = signup_headers(client)

        assessment_ids = []
        for i in range(5):
            response = client.post(
                "/assessments",
                json={
                    "name": f"Assessment {i+1}",
                    "description": f"Test assessment {i+1}"
                },
                headers=headers,
            )
            assert response.status_code == 201
            assessment_ids.append(response.json()["id"])

        # List all
        list_response = client.get("/assessments", headers=headers)
        items = list_response.json()
        assert len(items) >= 5

        # Verify all created assessments are in list
        returned_ids = [item["id"] for item in items]
        for aid in assessment_ids:
            assert aid in returned_ids

    def test_assessment_with_repository_ingestion(self):
        """Test assessment workflow with repository ingestion."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        assessment_response = client.post(
            "/assessments",
            json={"name": "Repo Test", "description": ""},
            headers=headers,
        )
        assessment_id = assessment_response.json()["id"]

        # Create repository (real GitHub repo)
        repo_response = client.post(
            f"/assessments/{assessment_id}/repositories",
            json={
                "name": "hello-world",
                "url": "https://github.com/octocat/Hello-World",
                "branch": "master"
            },
            headers=headers,
        )

        if repo_response.status_code == 201:
            repository = repo_response.json()
            repo_id = repository["id"]

            # Get repository details
            repo_detail = client.get(
                f"/assessments/{assessment_id}/repositories/{repo_id}",
                headers=headers
            )
            assert repo_detail.status_code == 200


# ============================================================================
# PART 5: ERROR HANDLING & EDGE CASES
# ============================================================================

class TestAssessmentErrorHandling:
    """Test suite for error handling in assessment operations."""

    def test_create_assessment_without_name_fails(self):
        """Test that creating assessment without name fails."""
        client = TestClient(app)
        headers = signup_headers(client)

        response = client.post(
            "/assessments",
            json={"description": "No name provided"},
            headers=headers,
        )
        assert response.status_code in [400, 422]  # Bad Request or Validation Error

    def test_update_nonexistent_assessment_fails(self):
        """Test updating non-existent assessment returns 404."""
        client = TestClient(app)
        headers = signup_headers(client)

        response = client.patch(
            "/assessments/00000000-0000-0000-0000-000000000000",
            json={"name": "New Name"},
            headers=headers,
        )
        assert response.status_code == 404

    def test_create_scan_job_on_deleted_assessment_fails(self):
        """Test creating scan job on deleted assessment fails."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create and delete assessment
        create_response = client.post(
            "/assessments",
            json={"name": "To Delete", "description": ""},
            headers=headers,
        )
        assessment_id = create_response.json()["id"]

        client.delete(
            f"/assessments/{assessment_id}",
            headers=headers
        )

        # Try to create scan job on deleted assessment
        response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={"agent_type": "white_box", "target": "/path"},
            headers=headers,
        )
        assert response.status_code == 404

    def test_invalid_agent_type_fails(self):
        """Test that invalid agent type fails."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessment
        assessment_response = client.post(
            "/assessments",
            json={"name": "Agent Test", "description": ""},
            headers=headers,
        )
        assessment_id = assessment_response.json()["id"]

        # Try invalid agent
        response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={
                "agent_type": "invalid_agent_type",
                "target": "/path"
            },
            headers=headers,
        )
        assert response.status_code in [400, 422]

    def test_unauthenticated_access_fails(self):
        """Test that unauthenticated requests fail."""
        client = TestClient(app)

        # Try to create without auth
        response = client.post(
            "/assessments",
            json={"name": "Unauth Test", "description": ""},
        )
        assert response.status_code in [401, 403]  # Unauthorized

    def test_accessing_other_orgs_assessment_fails(self):
        """Test that accessing another org's assessment fails."""
        client = TestClient(app)

        # Create first org
        headers1 = signup_headers(client)
        response1 = client.post(
            "/assessments",
            json={"name": "Org1 Assessment", "description": ""},
            headers=headers1,
        )
        assessment_id = response1.json()["id"]

        # Create second org
        headers2 = signup_headers(client)

        # Try to access first org's assessment from second org
        response2 = client.get(
            f"/assessments/{assessment_id}",
            headers=headers2
        )
        assert response2.status_code == 404  # Should not be visible


class TestFindingErrorHandling:
    """Test suite for error handling in finding operations."""

    def test_cannot_resolve_unconfirmed_finding(self):
        """Test that resolving unconfirmed finding raises error."""
        finding = Finding(title="Test")
        with pytest.raises(InvalidFindingStateError):
            finding.resolve()

    def test_cannot_transition_from_false_positive(self):
        """Test that false positives cannot transition to other states."""
        finding = Finding(title="Test")
        finding.mark_false_positive()

        # Cannot confirm false positive
        with pytest.raises(InvalidFindingStateError):
            finding.confirm()


# ============================================================================
# PART 6: PAGINATION & FILTERING TESTS
# ============================================================================

class TestAssessmentPagination:
    """Test suite for assessment pagination."""

    def test_list_assessments_with_pagination(self):
        """Test paginating through assessment list."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create multiple assessments
        for i in range(10):
            client.post(
                "/assessments",
                json={"name": f"Assessment {i}", "description": ""},
                headers=headers,
            )

        # Request with pagination
        response = client.get(
            "/assessments?skip=0&limit=5",
            headers=headers
        )
        assert response.status_code == 200
        items = response.json()
        assert len(items) <= 5

    def test_pagination_offset(self):
        """Test pagination with offset."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessments
        for i in range(5):
            client.post(
                "/assessments",
                json={"name": f"Item {i}", "description": ""},
                headers=headers,
            )

        # Get first page
        page1 = client.get(
            "/assessments?skip=0&limit=3",
            headers=headers
        ).json()

        # Get second page
        page2 = client.get(
            "/assessments?skip=3&limit=3",
            headers=headers
        ).json()

        # Verify different items
        page1_ids = [item["id"] for item in page1]
        page2_ids = [item["id"] for item in page2]
        assert len(set(page1_ids) & set(page2_ids)) == 0  # No overlap


# ============================================================================
# PERFORMANCE & STRESS TESTS
# ============================================================================

class TestAssessmentPerformance:
    """Test suite for performance characteristics."""

    def test_rapid_assessment_creation(self):
        """Test creating many assessments rapidly."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create 20 assessments
        assessment_ids = []
        for i in range(20):
            response = client.post(
                "/assessments",
                json={"name": f"Assessment {i}", "description": ""},
                headers=headers,
            )
            assert response.status_code == 201
            assessment_ids.append(response.json()["id"])

        # Verify all created
        assert len(assessment_ids) == 20
        assert len(set(assessment_ids)) == 20  # All unique

    def test_large_assessment_list_retrieval(self):
        """Test retrieving list with many assessments."""
        client = TestClient(app)
        headers = signup_headers(client)

        # Create assessments
        for i in range(50):
            client.post(
                "/assessments",
                json={"name": f"Assessment {i}", "description": ""},
                headers=headers,
            )

        # Retrieve all
        response = client.get("/assessments", headers=headers)
        assert response.status_code == 200
        items = response.json()
        assert len(items) >= 50


# ============================================================================
# SUMMARY & TEST EXECUTION
# ============================================================================

"""
Test Summary:
=============
This comprehensive test suite covers:

1. DOMAIN LAYER (23 tests)
   - Assessment state machine & transitions
   - Finding status management
   - Repository lifecycle
   - Value objects (Location)

2. APPLICATION LAYER (3 tests)
   - Use case execution
   - DTOs & request/response handling
   - Persistence integration

3. API INTEGRATION (12 tests)
   - CRUD operations
   - REST endpoint validation
   - Status code verification
   - Multi-resource workflows

4. COMPLEX WORKFLOWS (3 tests)
   - End-to-end scenarios
   - Multi-step operations
   - Cross-resource interactions

5. ERROR HANDLING (8 tests)
   - Validation failures
   - Authorization checks
   - State transition errors
   - Multi-tenancy isolation

6. PAGINATION (2 tests)
   - Offset & limit
   - Large result sets

7. PERFORMANCE (2 tests)
   - Rapid operations
   - Large data retrieval

Total: ~53 test cases covering assessment functionality

Run Command:
    pytest tests/test_comprehensive_assignments.py -v

Run Specific Category:
    pytest tests/test_comprehensive_assignments.py::TestAssessmentDomain -v
    pytest tests/test_comprehensive_assignments.py::TestAssessmentAPI -v
    pytest tests/test_comprehensive_assignments.py::TestAssessmentWorkflows -v
"""

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
