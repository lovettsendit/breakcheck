#!/bin/sh
set -eu

PYTHON="${PYTHON:-python3}"
KEEP="${BREAKCHECK_DEMO_KEEP:-0}"
CHECKOUT=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
EXAMPLE_ROOT="$CHECKOUT/examples/packaging-change"
DEMO_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/breakcheck-demo.XXXXXX")
DEMO_ROOT=$(CDPATH= cd "$DEMO_ROOT" && pwd -P)
TOOL_SITE="$DEMO_ROOT/tool-site"
RUNTIME_ROOT="$DEMO_ROOT/runtime"
RESULTS_ROOT="$DEMO_ROOT/results"
REPORT_PATH="$RESULTS_ROOT/report.json"
EVIDENCE_PATH="$RESULTS_ROOT/evidence.json"

cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$KEEP" = "1" ]; then
        printf '%s\n' "DEMO_ROOT=$DEMO_ROOT"
    else
        rm -rf "$DEMO_ROOT"
    fi
    exit "$status"
}
trap cleanup 0 HUP INT TERM

"$PYTHON" -c 'import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] < (3, 14) else 1)' || {
    printf '%s\n' "BREAKCHECK_DEMO_REFUSED: Python 3.10 through 3.13 is required" >&2
    exit 2
}

if [ -n "${BREAKCHECK_DEMO_WHEELHOUSE:-}" ]; then
    WHEELHOUSE=$BREAKCHECK_DEMO_WHEELHOUSE
    if [ ! -d "$WHEELHOUSE" ]; then
        printf '%s\n' "BREAKCHECK_DEMO_REFUSED: wheelhouse does not exist: $WHEELHOUSE" >&2
        exit 2
    fi
else
    WHEELHOUSE="$DEMO_ROOT/wheelhouse"
    mkdir -p "$WHEELHOUSE"
    "$PYTHON" -m pip download --only-binary=:all: --no-deps --dest "$WHEELHOUSE" 'packaging==21.3'
    "$PYTHON" -m pip download --only-binary=:all: --no-deps --dest "$WHEELHOUSE" 'packaging==22.0'
    "$PYTHON" -m pip download --only-binary=:all: --no-deps --dest "$WHEELHOUSE" 'pyparsing==3.3.2'
fi

WHEEL_21="$WHEELHOUSE/packaging-21.3-py3-none-any.whl"
WHEEL_22="$WHEELHOUSE/packaging-22.0-py3-none-any.whl"
PYPARSING_WHEEL="$WHEELHOUSE/pyparsing-3.3.2-py3-none-any.whl"
[ -f "$WHEEL_21" ] && [ -f "$WHEEL_22" ] || {
    printf '%s\n' "BREAKCHECK_DEMO_REFUSED: exact packaging wheels are required" >&2
    exit 2
}

verify_sha256() {
    expected=$1
    artifact=$2
    actual=$("$PYTHON" - "$artifact" <<'PY'
import hashlib
import sys
print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())
PY
)
    [ "$actual" = "$expected" ] || {
        printf '%s\n' "BREAKCHECK_DEMO_REFUSED: unexpected wheel digest: $artifact" >&2
        exit 2
    }
}

if [ -z "${BREAKCHECK_DEMO_WHEELHOUSE:-}" ]; then
    verify_sha256 ef103e05f519cdc783ae24ea4e2e0f508a9c99b2d4969652eed6a2e1ea5bd522 "$WHEEL_21"
    verify_sha256 957e2148ba0e1a3b282772e791ef1d8083648bc131c8ab0c1feba110ce1146c3 "$WHEEL_22"
    [ -f "$PYPARSING_WHEEL" ] || {
        printf '%s\n' "BREAKCHECK_DEMO_REFUSED: exact pyparsing wheel is required" >&2
        exit 2
    }
    verify_sha256 850ba148bd908d7e2411587e247a1e4f0327839c40e2e5e6d05a007ecc69911d "$PYPARSING_WHEEL"
    unexpected=$(find "$WHEELHOUSE" -type f ! -name 'packaging-21.3-py3-none-any.whl' ! -name 'packaging-22.0-py3-none-any.whl' ! -name 'pyparsing-3.3.2-py3-none-any.whl' -print -quit)
    [ -z "$unexpected" ] || {
        printf '%s\n' "BREAKCHECK_DEMO_REFUSED: unexpected wheelhouse file: $unexpected" >&2
        exit 2
    }
fi

TOOL_PYTHON="$PYTHON"
if "$PYTHON" -c 'import breakcheck; raise SystemExit(0 if breakcheck.__version__ == "2.0.0" else 1)' 2>/dev/null; then
    BREAKCHECK_IMPORT_ROOT=$("$PYTHON" -c 'from pathlib import Path; import breakcheck; print(Path(breakcheck.__file__).resolve().parent.parent)')
else
    BREAKCHECK_IMPORT_ROOT="$CHECKOUT/src"
fi
mkdir -p "$TOOL_SITE"
"$PYTHON" -m pip install --no-index --no-deps --target "$TOOL_SITE" "$WHEEL_21"
mkdir -p "$RESULTS_ROOT"

run_breakcheck() {
    PYTHONPATH= "$TOOL_PYTHON" - "$TOOL_SITE" "$BREAKCHECK_IMPORT_ROOT" "$@" <<'PY'
import runpy
import sys

tool_site, import_root, *arguments = sys.argv[1:]
sys.path[:0] = [tool_site, import_root]
sys.argv = ["breakcheck", *arguments]
runpy.run_module("breakcheck", run_name="__main__")
PY
}

set +e
(
    cd "$EXAMPLE_ROOT"
    run_breakcheck packaging@22.0 \
        --wheelhouse "$WHEELHOUSE" \
        --runtime-root "$RUNTIME_ROOT" \
        --output "$REPORT_PATH" \
        --evidence "$EVIDENCE_PATH" \
        --json \
        --ci
)
BREAKCHECK_EXIT=$?
set -e
printf '%s\n' "BREAKCHECK_EXIT=$BREAKCHECK_EXIT"
[ "$BREAKCHECK_EXIT" -eq 3 ] || {
    printf '%s\n' "BREAKCHECK_DEMO_REFUSED: expected exit 3" >&2
    exit 2
}

"$TOOL_PYTHON" - "$REPORT_PATH" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("schema_version") != 2 or report.get("artifact_kind") != "dependency_report":
    raise SystemExit("BREAKCHECK_DEMO_REFUSED: expected schema-2 dependency report")
payload = report.get("payload", {})
findings = payload.get("findings")
summary = payload.get("summary")
if not isinstance(findings, list) or len(findings) != 1:
    raise SystemExit("BREAKCHECK_DEMO_REFUSED: expected exactly one finding")
if findings[0].get("verdict") != "CHANGED":
    raise SystemExit("BREAKCHECK_DEMO_REFUSED: expected CHANGED finding")
if not isinstance(summary, dict) or summary.get("changed") != 1:
    raise SystemExit("BREAKCHECK_DEMO_REFUSED: expected summary.changed == 1")
PY

run_breakcheck --verify "$REPORT_PATH" --evidence "$EVIDENCE_PATH"
printf '%s\n' "REPORT_PATH=$REPORT_PATH"
printf '%s\n' "EVIDENCE_PATH=$EVIDENCE_PATH"
printf '%s\n' "DEMO_VERDICT=PASS"
