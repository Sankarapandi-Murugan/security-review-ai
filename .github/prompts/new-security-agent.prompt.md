---
description: "Scaffold a brand-new autonomous security scanning agent (Agent subclass + AgentType/AgentFactory wiring + tests) for the Vigil AI platform."
agent: "Vigil AI Engineer"
argument-hint: "Name and purpose of the new agent, e.g. 'Container Security agent that scans Dockerfiles for root-user and secrets-in-build-args issues'"
---
Scaffold a new autonomous security scanning agent for Vigil AI (security-review-ai) based on
the user's description: ${input:description:What should the new agent detect?}

Follow these steps:

1. **Read for patterns first** — read [white_box_agent.py](../../backend/src/security_review/infrastructure/scanners/white_box_agent.py)
   and one other existing agent fully before writing anything, to match the established style.
2. Add a new `AgentType` enum value in
   [models.py](../../backend/src/security_review/domain/assessment/models.py).
3. Create `backend/src/security_review/infrastructure/scanners/<name>_agent.py` implementing:
   ```python
   class <Name>Agent(Agent):
       agent_type = AgentType.<NAME>

       def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
           ...
   ```
   - Return `Finding` objects with `title`, `severity`, `description`, `evidence`, `remediation`.
   - Wrap I/O in defensive `try/except`, matching existing agents.
   - If the agent performs active/intrusive network probing (not just static analysis of a
     local path), gate that behavior behind the `authorized` flag — see
     [black_box_agent.py](../../backend/src/security_review/infrastructure/scanners/black_box_agent.py)
     for the pattern (skip + explanatory Finding when not authorized).
4. Register it in
   [agent_factory.py](../../backend/src/security_review/infrastructure/scanners/agent_factory.py).
5. Add `<name>_agent` option to the scan-type `<select>` in
   [index.html](../../backend/src/security_review/ui/index.html).
6. Write `backend/tests/test_<name>_agent.py` covering: a detection-positive case, a
   detection-negative/clean case, `execute(None)` returns `[]`, and (if applicable) the
   authorization-gating behavior.
7. Run `cd backend && uv run pytest -q && uv run ruff check src tests` — fix until both are clean.
8. Update `README.md` with a short section documenting the new agent's capability and an
   example `curl` call, following the style of the existing agent sections.

Report back with: files changed, test/lint pass counts, and any capability explicitly left
unimplemented.
