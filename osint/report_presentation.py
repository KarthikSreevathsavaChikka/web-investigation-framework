"""Reader-facing wording shared by HTML and Word investigation reports."""

from __future__ import annotations


def report_overview(investigation: dict, summary: dict) -> list[tuple[str, str]]:
    evidence = int(summary.get("confirmed_evidence") or 0)
    documents = int(summary.get("public_documents") or 0)
    sources = int(summary.get("accepted_sources") or 0)
    screenshots = int(summary.get("screenshots_captured") or 0)
    coverage = investigation.get("coverage") or {}
    status = str(coverage.get("status") or "UNKNOWN").upper()
    if evidence or documents:
        finding = f"The collection stored {evidence} web evidence capture(s) and {documents} public document(s) related to the target. Review the source context below before drawing conclusions."
    else:
        finding = "The collection did not confirm target-specific public evidence in the sources it could access."
    limit = (
        "Collection was incomplete. Some sources or collectors could not be checked, so missing findings do not establish that the target is safe."
        if status != "COMPLETE" else
        "The result is limited to the selected collectors, accessible public sources, and collection budgets."
    )
    return [
        ("What was found", finding),
        ("Sources reviewed", f"{sources} accepted source(s) and {screenshots} stored screenshot(s)."),
        ("What this means", "This report records observable public information. It does not verify ownership or prove an allegation."),
        ("Important limitation", limit),
    ]


def observed_identity(profile: dict | None) -> list[tuple[str, str]]:
    """Summarize source-linked identity claims without implying ownership."""
    profile = profile or {}
    target = profile.get("target") or {}
    fields = [("Observed website", str(target.get("url") or "Unavailable"))]
    for key, label in (("aliases", "Other names"), ("organizations", "Organizations"),
                       ("operators", "Operators"), ("social_accounts", "Social accounts"),
                       ("languages", "Languages")):
        values = [str(item.get("value") or "").strip() for item in profile.get(key) or [] if isinstance(item, dict)]
        fields.append((label, ", ".join(value for value in values if value) or "None observed"))
    return fields
