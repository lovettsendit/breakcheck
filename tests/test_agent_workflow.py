from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "SKILL.md"
DISCOVERY = ROOT / "AGENTS.md"
README = ROOT / "README.md"


def _skill_text() -> str:
    return SKILL.read_text(encoding="utf-8")


def test_agent_skill_is_discoverable_and_concise():
    text = _skill_text()
    assert text.startswith("---\n")
    assert "name: verifying-python-changes-with-breakcheck" in text
    assert "description: Use when" in text
    assert len(text.split()) < 500


def test_agent_skill_covers_both_verification_modes_and_fail_closed_results():
    text = _skill_text()
    for command in (
        "breakcheck PACKAGE@NEW_VERSION",
        "--suggest-fixtures",
        "breakcheck diff",
        "breakcheck attest",
        "--strict-separation",
    ):
        assert command in text
    for disposition in (
        "CHANGED",
        "NOT_EXERCISED",
        "CLAIM_REFUTED",
        "CLAIM_UNVERIFIABLE",
        "CLAIM_OUT_OF_SCOPE",
    ):
        assert disposition in text


def test_agent_skill_prohibits_self_grading_and_evidence_mutation():
    text = _skill_text()
    for protected in (
        "report.json",
        "evidence.json",
        "baseline.json",
        "--allow-empty",
        "--min-coverage",
    ):
        assert protected in text
    assert "Never modify a fixture after seeing `CHANGED`" in text
    assert "Never modify verdict or verification logic" in text


def test_agent_skill_requires_prechange_baseline_and_independent_attestation():
    text = _skill_text()
    ordered_steps = (
        "Run `breakcheck freeze`",
        "Make the behavior-preserving code change",
        "Create a claim file",
        "Run `breakcheck attest`",
        "Report every disposition verbatim",
    )
    positions = [text.index(step) for step in ordered_steps]
    assert positions == sorted(positions)
    assert "Never author or modify a fixture for a target after changing" in text


def test_repository_discovery_file_routes_automation_to_the_skill():
    text = DISCOVERY.read_text(encoding="utf-8")
    assert "[SKILL.md](SKILL.md)" in text
    assert "Never weaken coverage or separation policy" in text


def test_fixture_suggestion_guidance_distinguishes_scan_and_replay_modes():
    readme = README.read_text(encoding="utf-8")
    skill = _skill_text()
    for text in (readme, skill):
        lowered = text.lower()
        assert "without `--wheelhouse`" in text
        assert "G2" in text
        assert "G3_UNNORMALIZABLE" in text
        assert 'projection = ""' in text
        assert "outcome" in text
        assert "impure" in lowered
        assert "nondeterministic" in lowered
    assert "isolated replay" in readme
    assert "does not invent a projection" in readme
    assert "human review" in readme
