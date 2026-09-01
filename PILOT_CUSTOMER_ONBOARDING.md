# Pilot customer onboarding script

This is a simple onboarding flow for the first pilot customers using Vigil AI.

## Goal

Help a customer validate the product in a real workflow with minimal friction while collecting useful feedback on security review, repo ingestion, findings, and reporting.

---

## 1) Pre-sales / setup

### Customer discovery

- Confirm the customer is a real engineering or security team
- Understand their repo stack and review frequency
- Ask whether they want static analysis, repo review, API testing, or full assessment workflow
- Confirm whether they have a GitHub/GitLab repo they can give access to for testing

### Success criteria

A customer is a fit when they have:
- at least one real repo or sample app
- an engineering/security stakeholder
- a clear review use case
- enthusiasm for validating findings and remediation workflow

---

## 2) Onboarding sequence

### Step 1: account setup

1. Send the customer a link to the app or a dedicated staging/prod environment.
2. Ask them to sign up with their work email.
3. Confirm the organization name, team size, and contact owner.
4. Capture the owner contact and admin contact for support.

### Step 2: plan alignment

1. Confirm they are using the free or Pro plan based on needs.
2. If using Pro, verify pricing and subscription flow.
3. Explain what is included in the pilot:
   - repo ingestion
   - assessment creation
   - security scan execution
   - findings review
   - remediation guidance

### Step 3: repository setup

1. Ask them to provide a public repo or a repo they can authorize for scanning.
2. If the repo is private, confirm the access method is supported by the platform.
3. Validate the repo path, branch, and configuration.
4. Confirm the project is under the right organization scope.

### Step 4: first assessment

1. Create a first assessment.
2. Add the repo.
3. Select scanning workflow desired by the customer.
4. Trigger the assessment run.
5. Observe whether scans complete without errors.

### Step 5: findings review

1. Review the generated findings.
2. Confirm the severity and remediation guidance make sense.
3. Ask the customer whether the output is actionable.
4. Capture which findings look useful versus noisy.

### Step 6: remediation validation

1. Ask the customer to review one or two findings end-to-end.
2. Ask whether the remediation guidance is precise enough for engineering teams.
3. Ask whether they would trust this process for recurring scans.

### Step 7: feedback capture

Capture the following in a brief call or email:
- what worked well
- what was confusing
- what findings were noisy or false-positive-heavy
- what blocked adoption
- what would make them continue after the pilot

---

## 3) Pilot success checklist

Customer onboarding is considered successful when:

- [ ] they signed up successfully
- [ ] they created an organization
- [ ] they created an assessment
- [ ] they added a repo successfully
- [ ] scan jobs completed
- [ ] findings were visible and understandable
- [ ] remediation guidance was useful
- [ ] customer agreed the workflow is valuable
- [ ] a clear next-step plan was created

---

## 4) Customer communication template

### Email / intro message

Subject: Welcome to your Vigil AI pilot

Hi [Customer Name],

Welcome to the Vigil AI pilot. We’ve set up your workspace and you can start by creating your first assessment and connecting a repository.

Your pilot includes:
- assessment creation
- automated repo scanning
- findings review
- remediation guidance
- team management and billing overview

To get started:
1. Log in to your workspace
2. Create your first organization or use the default workspace
3. Add a repo
4. Run the assessment
5. Review the findings with your team

We’ll support you through the first run and will collect feedback after the first review cycle.

Thanks,
[Your Name]

---

## 5) Exit criteria for pilot

The pilot may move to next stage when:

- customer completes a real scan end-to-end
- findings are reviewed by engineering/security stakeholders
- customer identifies clear value in the workflow
- customer is willing to continue on a paid plan or next pilot phase
- issues are captured and prioritized into product backlog

---

## 6) What to capture from each pilot customer

Use a scorecard with these items:

- ease of signup and setup
- repo ingestion reliability
- finding quality and usefulness
- scan performance
- clarity of UI
- security workflow fit
- business value
- willingness to pay
- blockers to adoption

---

## 7) Suggested first pilot customer profile

Best candidates are:
- startup engineering teams
- security-conscious SaaS companies
- product teams with public repos
- teams doing regular code review but lacking security automation

Avoid in the first wave:
- large enterprises with heavy procurement and compliance gates
- teams needing highly customized scanning policies immediately
- organizations with no repo access or review workflow

---

## 8) Recommended next steps after pilot

- collect customer feedback
- prioritize the top issues
- tighten onboarding flow
- improve scan quality and remediation output
- define pricing for pilot expansion
- decide whether to expand to more customers or keep it private beta
