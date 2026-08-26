from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE"

REQUIRED_FORMS = {
    "bug.yml": {
        "version_breakcheck",
        "python_version",
        "operating_system",
        "mode",
        "sanitized_command",
        "reproduction_steps",
        "observed_behavior",
        "expected_behavior",
        "privacy_confirmation",
    },
    "compatibility-case.yml": {
        "version_breakcheck",
        "python_version",
        "operating_system",
        "package_name",
        "current_version",
        "proposed_version",
        "sanitized_command",
        "reproduction_steps",
        "observed_behavior",
        "expected_behavior",
        "privacy_confirmation",
    },
    "revision-claim-case.yml": {
        "version_breakcheck",
        "python_version",
        "operating_system",
        "mode",
        "base_revision",
        "head_revision",
        "target_symbols",
        "fixture_source",
        "sanitized_command",
        "reproduction_steps",
        "observed_behavior",
        "expected_behavior",
        "privacy_confirmation",
    },
}

PR_REQUIREMENTS = (
    "Linked issue",
    "Smallest change",
    "Regression test evidence",
    "Preserved counterexample",
    "Privacy/security",
    "Docs/changelog",
    "Breaking/release assessment",
)

PRIVACY_WARNING_TERMS = (
    "private paths",
    "private source",
    "literals",
    "outputs",
    "credentials",
    ".breakcheck/",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_public_forms_require_supported_version_and_reproduction_details():
    for filename, required_ids in REQUIRED_FORMS.items():
        text = _read(f".github/ISSUE_TEMPLATE/{filename}")
        assert "description:" in text
        assert "title:" in text
        assert "labels:" in text
        assert "body:" in text
        for field_id in required_ids:
            assert f"id: {field_id}" in text, (filename, field_id)
        assert text.count("required: true") >= len(required_ids)


def test_evidence_forms_warn_about_private_material_before_posting():
    for filename in ("bug.yml", "compatibility-case.yml", "revision-claim-case.yml"):
        text = _read(f".github/ISSUE_TEMPLATE/{filename}").lower()
        for term in PRIVACY_WARNING_TERMS:
            assert term in text, (filename, term)
        assert "remove" in text
        assert "before posting" in text


def test_bug_form_supports_every_product_mode_without_forcing_dependency_fields():
    text = _read(".github/ISSUE_TEMPLATE/bug.yml")
    for mode in (
        "Dependency comparison",
        "Revision diff",
        "Baseline freeze",
        "Claim attestation",
        "Demo or capabilities",
        "Other",
    ):
        assert f"- {mode}" in text
    for dependency_only_field in ("package_name", "current_version", "proposed_version"):
        assert f"id: {dependency_only_field}" not in text


def test_revision_claim_form_covers_separation_and_claim_outcomes():
    text = _read(".github/ISSUE_TEMPLATE/revision-claim-case.yml")
    for operation in ("Revision diff", "Baseline freeze", "Claim attestation"):
        assert f"- {operation}" in text
    for outcome in (
        "CLAIM_VERIFIED",
        "CLAIM_REFUTED",
        "CLAIM_UNVERIFIABLE",
        "CLAIM_OUT_OF_SCOPE",
    ):
        assert outcome in text
    assert "base revision" in text.lower()
    assert "fixture" in text.lower()


def test_feature_form_is_structured_and_private_safe():
    text = _read(".github/ISSUE_TEMPLATE/feature.yml").lower()
    for field_id in ("problem", "proposed_solution", "alternatives"):
        assert f"id: {field_id}" in text
    for term in PRIVACY_WARNING_TERMS:
        assert term in text, term


def test_issue_config_disables_blanks_and_links_security_and_readme():
    text = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert "blank_issues_enabled: false" in text
    assert "https://github.com/lovettsendit/breakcheck/security/advisories/new" in text
    assert "https://github.com/lovettsendit/breakcheck#readme" in text


def test_pull_request_template_requires_release_quality_evidence():
    text = _read(".github/pull_request_template.md")
    for requirement in PR_REQUIREMENTS:
        assert requirement.lower() in text.lower(), requirement
