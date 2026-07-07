"""The structured issue body — the contract between scanner and orchestrator.

The scanner renders it; the webhook parses it back into a Finding. Keeping
render/parse in one module means the contract can't drift apart silently,
and the round-trip is unit-tested.
"""
import re

from .prompts import Finding

MARKER = "<!-- devin-remediate:v1 -->"

TEMPLATE = """{marker}
Package: {package}
Pinned: {pinned}
Fixed-Version: {fixed}
Vuln-Id: {vuln_id}
CVE: {cve}
Requirements-Files: {req_files}
Class: {klass}

### Finding

`{package}=={pinned}` is affected by [{vuln_id}](https://osv.dev/vulnerability/{vuln_id}) ({cve}).
Fixed in `{package}>={fixed}`.

{summary}

*Filed automatically by the remediation scanner. The `devin-remediate` label
triggers autonomous remediation; a validated PR will be linked here.*
"""

_FIELD = re.compile(r"^([A-Za-z-]+):\s*(.+?)\s*$", re.M)


def render(package: str, pinned: str, fixed: str, vuln_id: str, cve: str,
           req_files: list[str], klass: str, summary: str = "") -> str:
    return TEMPLATE.format(
        marker=MARKER, package=package, pinned=pinned, fixed=fixed,
        vuln_id=vuln_id, cve=cve, req_files=" ".join(req_files),
        klass=klass, summary=summary,
    )


def parse(issue_number: int, body: str) -> Finding | None:
    """Parse a structured issue body; None if it isn't one of ours."""
    if MARKER not in (body or ""):
        return None
    fields = {m.group(1).lower(): m.group(2) for m in _FIELD.finditer(body)}
    required = ("package", "pinned", "fixed-version", "vuln-id", "cve", "requirements-files", "class")
    if any(k not in fields for k in required):
        return None
    klass = fields["class"].strip().lower()
    if klass not in ("baseline", "hero"):
        return None
    return Finding(
        issue_number=issue_number,
        package=fields["package"],
        pinned=fields["pinned"],
        fixed=fields["fixed-version"],
        vuln_id=fields["vuln-id"],
        cve=fields["cve"],
        req_files=fields["requirements-files"],
        klass=klass,
    )
