"""Prompt assembly — the templates proven in week-1 calibration.

Two issue classes, two templates:
  baseline — pin bump expected to need no code changes; tightly scoped.
  hero     — major-version upgrade; delegates judgment with boundaries
             (assess first, minimal companion set, justify each, escape hatch).

The scanner classifies each finding (major version jump => hero) and the
issue body carries the class, so prompt choice is deterministic.
"""
from dataclasses import dataclass

CONTRACT = """5. Open a pull request with base {default_branch} of {repo}. The PR body MUST begin with these two lines exactly (they drive the fork's remediation-validation workflow):
Remediation-CVE: {cve}
Validation-Tests: <the pytest path(s) you actually ran, space-separated, all starting with tests/>
Then a short summary: what changed, why, and your verification evidence. Include 'Closes #{issue_number}' so the PR links the issue."""

CONSTRAINTS = """CONSTRAINTS:
- Keep the diff as small as the fix honestly allows; no drive-by refactors; do not 'fix' unrelated flaky tests.
- Do not merge the PR. Do not push to {default_branch}. Do not modify CI workflow files (.github/workflows/).
- If blocked on repo access or anything environmental, stop and report rather than working around it."""

HEADER = """You are remediating a known-vulnerable pinned dependency in the GitHub repository {repo} (default branch: {default_branch}). Work ONLY in {repo}.

FINDING (source: OSV/pip-audit, from GitHub issue #{issue_number}):
- Package: {package}, pinned at {pinned}
- Vulnerability: {vuln_id} ({cve})
- Fixed in: {package} {fixed}
- Requirements files: {req_files}"""

BASELINE_TASK = """
TASK:
1. Create a branch named remediate/{package}-{fixed} off {default_branch}.
2. Update the {package} pin to {fixed} in every requirements file where it appears. Keep the diff minimal — do NOT regenerate lockfiles wholesale, do NOT touch unrelated pins.
3. Search the codebase for direct usage of {package}. If the upgrade requires call-site changes, make them; if there is no direct usage (transitive dep), say so explicitly and make no code changes.
4. Verify in your workspace: install the updated requirements and run a targeted pytest scope that best exercises this dependency's consumers (or a reasonable smoke scope such as tests/unit_tests/core_tests.py plus importing the package under test if purely transitive). Record the exact commands you ran and their results.
"""

HERO_TASK = """
This is a MAJOR-version upgrade. Expect breaking changes and ecosystem coupling.

TASK:
1. FIRST, assess feasibility: determine the minimal set of companion pin bumps required for {package} {fixed} to work, and survey the codebase/config for usages of APIs removed or changed across the major version(s). Run a representative test subset in your workspace to SEE what actually breaks before deciding.
2. ESCAPE HATCH — if the upgrade requires changes across more than ~30 files, or a required companion package has no compatible release, or anything else makes a reviewable PR impossible: STOP. Do not open a PR. Produce a detailed written report (what breaks, where, what it would take) and end the session with that report as your final message. That report is a fully successful outcome.
3. Otherwise proceed: create branch remediate/{package}-{fixed} off {default_branch}; update the {package} pin to {fixed} in every requirements file where it appears; bump companion pins ONLY where required (justify each in the PR body); fix incompatible call sites/config with the smallest possible diff.
4. Verify in your workspace: install the updated requirements, then run a targeted pytest scope covering the app core plus every area you touched. Record exact commands and results.
"""


@dataclass(frozen=True)
class Finding:
    issue_number: int
    package: str
    pinned: str
    fixed: str
    vuln_id: str
    cve: str
    req_files: str
    klass: str  # "baseline" | "hero"


def build_prompt(f: Finding, repo: str, default_branch: str = "master") -> str:
    fields = dict(
        repo=repo, default_branch=default_branch, issue_number=f.issue_number,
        package=f.package, pinned=f.pinned, fixed=f.fixed,
        vuln_id=f.vuln_id, cve=f.cve, req_files=f.req_files,
    )
    task = HERO_TASK if f.klass == "hero" else BASELINE_TASK
    return "\n".join([
        HEADER.format(**fields),
        task.format(**fields),
        CONTRACT.format(**fields),
        "",
        CONSTRAINTS.format(**fields),
    ])


STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "outcome": {"type": "string", "enum": ["pr_opened", "infeasible_report", "blocked"]},
        "pr_url": {"type": "string"},
        "companion_bumps": {"type": "array", "items": {"type": "string"}},
        "tests_run": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string"},
    },
    "required": ["outcome"],
}
