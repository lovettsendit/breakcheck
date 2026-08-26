from __future__ import annotations

import pytest

from breakcheck.core.claims import (
    BehaviorClaim,
    ClaimRefusal,
    adjudicate_claim,
    claim_exit_code,
    parse_claim,
)


BASE_REVISION = "1" * 40
HEAD_REVISION = "2" * 40


def _claim_text(*symbols: str) -> str:
    blocks = [
        "schema_version = 1",
        'claim = "behavior_preserved"',
        f'base_revision = "{BASE_REVISION}"',
    ]
    for symbol in symbols:
        blocks.extend(("", "[[target]]", f'symbol = "{symbol}"'))
    return "\n".join(blocks) + "\n"


def _finding(
    symbol: str,
    verdict: str,
    *,
    reason_code: str | None = None,
    projection_scope: str | None = None,
) -> dict[str, object]:
    return {
        "symbol": symbol,
        "verdict": verdict,
        "reason_code": reason_code,
        "projection_scope": projection_scope,
    }


def test_claim_parser_is_closed_sorted_and_rejects_vacuous_or_duplicate_targets() -> None:
    """An open, empty, or duplicate claim could hide the actual assertion surface."""
    claim = parse_claim(_claim_text("sample.math:zeta", "sample.math:alpha"))
    assert claim.schema_version == 1
    assert claim.claim == "behavior_preserved"
    assert claim.base_revision == BASE_REVISION
    assert claim.targets == ("sample.math:alpha", "sample.math:zeta")

    with pytest.raises(ClaimRefusal, match="^CLAIM_VACUOUS_REFUSED$"):
        parse_claim(_claim_text())
    with pytest.raises(ClaimRefusal, match="^CLAIM_DUPLICATE_TARGET_REFUSED$"):
        parse_claim(_claim_text("sample.math:value", "sample.math:value"))
    with pytest.raises(ClaimRefusal, match="^CLAIM_SCHEMA_REFUSED$"):
        parse_claim(_claim_text("sample.math:value") + 'extra = "hidden"\n')


def test_claim_adjudication_independently_detects_refuted_unverifiable_and_out_of_scope() -> None:
    """A claim must not control the changed-symbol census or call absence success."""
    claim = parse_claim(
        _claim_text(
            "sample.math:changed",
            "sample.math:stable",
            "sample.math:unavailable",
        )
    )
    report = adjudicate_claim(
        claim,
        head_revision=HEAD_REVISION,
        changed_targets={
            "sample.math:changed",
            "sample.math:stable",
            "sample.math:unavailable",
            "sample.math:omitted",
        },
        findings=[
            _finding("sample.math:changed", "CHANGED"),
            _finding("sample.math:stable", "IDENTICAL"),
            _finding(
                "sample.math:unavailable",
                "NOT_EXERCISED",
                reason_code="IMPORT_FAILED",
            ),
        ],
        fixture_source="base",
        fixture_revision=BASE_REVISION,
        fixture_authored_by="human",
        fixtures_predate_change=True,
        strict_separation=True,
        invocation={"strict_separation": True},
    )

    assert [(row["symbol"], row["disposition"]) for row in report["dispositions"]] == [
        ("sample.math:changed", "CLAIM_REFUTED"),
        ("sample.math:omitted", "CLAIM_OUT_OF_SCOPE"),
        ("sample.math:stable", "CLAIM_VERIFIED"),
        ("sample.math:unavailable", "CLAIM_UNVERIFIABLE"),
    ]
    assert report["summary"] == {
        "verified": 1,
        "refuted": 1,
        "unverifiable": 1,
        "out_of_scope": 1,
        "total": 4,
    }
    assert claim_exit_code(report) == 3


def test_claim_under_projection_states_the_scope_and_exit_precedence_is_stable() -> None:
    """Projection-limited evidence must never be presented as full-observation proof."""
    claim = parse_claim(_claim_text("sample.math:value"))
    verified = adjudicate_claim(
        claim,
        head_revision=HEAD_REVISION,
        changed_targets={"sample.math:value"},
        findings=[
            _finding(
                "sample.math:value",
                "IDENTICAL_UNDER_PROJECTION",
                projection_scope="outcome.as_dict()",
            )
        ],
        fixture_source="base",
        fixture_revision=BASE_REVISION,
        fixture_authored_by="human",
        fixtures_predate_change=True,
        strict_separation=True,
        invocation={},
    )
    row = verified["dispositions"][0]
    assert row["disposition"] == "CLAIM_VERIFIED"
    assert row["verification_scope"] == "UNDER_PROJECTION"
    assert row["projection_scope"] == "outcome.as_dict()"
    assert claim_exit_code(verified) == 0

    for dispositions, expected in (
        ([{"disposition": "CLAIM_REFUTED"}], 1),
        ([{"disposition": "CLAIM_REFUTED"}, {"disposition": "CLAIM_UNVERIFIABLE"}], 2),
        ([{"disposition": "CLAIM_UNVERIFIABLE"}, {"disposition": "CLAIM_OUT_OF_SCOPE"}], 3),
    ):
        assert claim_exit_code({"dispositions": dispositions}) == expected


@pytest.mark.parametrize(
    ("source", "author", "predates", "reason"),
    [
        ("head", "human", False, "FIXTURE_AUTHORED_AGAINST_HEAD"),
        ("base", "unknown", True, "FIXTURE_AUTHOR_UNKNOWN"),
        ("explicit", "human", False, "FIXTURE_POSTDATES_CHANGE"),
    ],
)
def test_strict_separation_never_verifies_unproven_fixture_provenance(
    source: str, author: str, predates: bool, reason: str
) -> None:
    """Inputs chosen after a change cannot independently verify that change."""
    report = adjudicate_claim(
        parse_claim(_claim_text("sample.math:value")),
        head_revision=HEAD_REVISION,
        changed_targets={"sample.math:value"},
        findings=[_finding("sample.math:value", "IDENTICAL")],
        fixture_source=source,
        fixture_revision=HEAD_REVISION if source == "head" else BASE_REVISION,
        fixture_authored_by=author,
        fixtures_predate_change=predates,
        strict_separation=True,
        invocation={},
    )

    row = report["dispositions"][0]
    assert row["disposition"] == "CLAIM_UNVERIFIABLE"
    assert row["reason_code"] == reason
    assert claim_exit_code(report) == 2


def test_non_strict_separation_records_relaxation_without_hiding_it() -> None:
    """An explicit policy relaxation must remain visible in the report evidence."""
    report = adjudicate_claim(
        parse_claim(_claim_text("sample.math:value")),
        head_revision=HEAD_REVISION,
        changed_targets={"sample.math:value"},
        findings=[_finding("sample.math:value", "IDENTICAL")],
        fixture_source="head",
        fixture_revision=HEAD_REVISION,
        fixture_authored_by="unknown",
        fixtures_predate_change=False,
        strict_separation=False,
        invocation={"strict_separation": False},
    )

    assert report["dispositions"][0]["disposition"] == "CLAIM_VERIFIED"
    assert report["fixtures_predate_change"] is False
    assert report["invocation"]["strict_separation"] is False


def test_advisory_claim_exit_records_unverifiable_without_failing() -> None:
    """Only an explicit non-strict claim may treat unverifiable work as advisory."""
    dispositions = [{"disposition": "CLAIM_UNVERIFIABLE"}]

    assert claim_exit_code(
        {"dispositions": dispositions, "invocation": {"strict": False}}
    ) == 0
    assert claim_exit_code(
        {"dispositions": dispositions, "invocation": {"strict": True}}
    ) == 2


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("identical", "IDENTICAL_REVISIONS_REFUSED"),
        ("zero", "CLAIM_NO_CHANGED_TARGETS"),
        ("unknown_finding", "CLAIM_FINDING_REFUSED"),
        ("path", "CLAIM_PATH_REFUSED"),
    ],
)
def test_claim_adjudication_refuses_vacuous_or_open_inputs(mutation: str, code: str) -> None:
    """A vacuous or malformed claim cannot produce a successful attestation."""
    claim = parse_claim(_claim_text("sample.math:value"))
    head = BASE_REVISION if mutation == "identical" else HEAD_REVISION
    changed = set() if mutation == "zero" else {"sample.math:value"}
    findings = [_finding("sample.math:value", "IDENTICAL")]
    if mutation == "unknown_finding":
        findings[0]["extra"] = True
    invocation: dict[str, object] = {}
    if mutation == "path":
        invocation["worktree_root"] = "/private/location"

    with pytest.raises(ClaimRefusal, match=f"^{code}$"):
        adjudicate_claim(
            claim,
            head_revision=head,
            changed_targets=changed,
            findings=findings,
            fixture_source="base",
            fixture_revision=BASE_REVISION,
            fixture_authored_by="human",
            fixtures_predate_change=True,
            strict_separation=True,
            invocation=invocation,
        )


def test_adjudication_revalidates_programmatically_constructed_claims() -> None:
    """Bypassing the text parser must not bypass the closed claim contract."""
    forged = BehaviorClaim(
        schema_version=2,
        claim="different_claim",
        base_revision=BASE_REVISION,
        targets=("sample.math:value",),
    )

    with pytest.raises(ClaimRefusal, match="^CLAIM_SCHEMA_REFUSED$"):
        adjudicate_claim(
            forged,
            head_revision=HEAD_REVISION,
            changed_targets={"sample.math:value"},
            findings=[_finding("sample.math:value", "IDENTICAL")],
            fixture_revision=BASE_REVISION,
            fixture_authored_by="human",
            fixtures_predate_change=True,
            invocation={},
        )
