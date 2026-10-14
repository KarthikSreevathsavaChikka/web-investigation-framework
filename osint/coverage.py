"""Collection completeness is separate from the heuristic risk score."""

USABLE_CAPTURE_STATUSES = frozenset({
    "evidence_found", "baseline_captured", "document_viewer_captured", "no_evidence",
})
# Relevance rejection is a completed check, not a transport/collection failure.
FINISHED_CAPTURE_STATUSES = USABLE_CAPTURE_STATUSES | {"rejected_irrelevant", "skipped_non_content"}
DIAGNOSTIC_ENTITY_TYPES = frozenset({
    "COLLECTION_READINESS", "TARGET_PROFILE", "TARGET_IDENTITY_CLAIM", "SOURCE_SELECTION",
    "SOCIAL_COLLECTION_DIAGNOSTIC", "MEDIA_REFERENCE", "NON_CONTENT_RESOURCE",
    "BRAND_ALIAS", "ORGANIZATION_NAME", "OPERATOR_NAME", "PAGE_LANGUAGE",
})
RISK_NOTICE = (
    "Risk scores describe collected indicators only. A zero score is not a safety finding; "
    "missing or blocked evidence cannot establish that a target is safe."
)


def observation_has_gap(item):
    return (
        item.entity_type in {"SEARCH_PROVIDER_ERROR", "SEARCH_PROVIDER_MANUAL_REQUIRED"}
        or (item.entity_type in {"ACCESS_STATUS", "DOCUMENT_REJECTED"}
            and item.value in {"manual_required", "inaccessible", "failed"})
        or (item.entity_type == "SOCIAL_COLLECTION_DIAGNOSTIC"
            and bool(item.metadata.get("extraction_errors") or item.metadata.get("unavailable")
                     or item.metadata.get("authentication") == "unverified"))
        or (item.entity_type == "AUTOMATED_SOCIAL_FINDING" and item.metadata.get("capture_status") == "unavailable")
    )


def summarize_coverage(runs, captures):
    incomplete = [item["collector"] for item in runs if item["status"] != "COMPLETED"
                  and item["collector"] != "collection_readiness" and not item["collector"].startswith("llm_relevance_")]
    usable = sum(item["accessibility_status"] in USABLE_CAPTURE_STATUSES for item in captures)
    unavailable = sum(item["accessibility_status"] not in FINISHED_CAPTURE_STATUSES for item in captures)
    skipped = sum(item["accessibility_status"] == "skipped_non_content" for item in captures)
    attempted = len(captures) - skipped
    status = "PARTIAL" if incomplete or unavailable or not runs else "COMPLETED"
    message = (
        f"{usable} of {attempted} captured pages usable; "
        f"{unavailable} unavailable; {skipped} non-page resources skipped; {len(incomplete)} collectors incomplete. "
        "Coverage is limited to the selected collectors and collection budgets."
    )
    return dict(status=status, usable_pages=usable, attempted_pages=attempted,
                unavailable_pages=unavailable, skipped_non_content=skipped, incomplete_collectors=incomplete,
                message=message, risk_notice=RISK_NOTICE)
