from __future__ import annotations

import json
from pathlib import Path

WORKLOAD_IDS = ['battery-20-packages', 'coverage-16002-call-sites']
REPRODUCIBILITY_RUNS = 2
TIMING_CHECKS = ['timing-battery', 'timing-bench']
MAXIMUM_MS = {'battery-20-packages': 2700000, 'coverage-16002-call-sites': 120000}

def test_scale_reproducibility_evidence():
    root = Path(__file__).resolve().parents[1] / 'release_evidence'
    for workload in WORKLOAD_IDS:
        value = json.loads((root / f'{workload}.json').read_text(encoding='utf-8'))
        assert set(value) == {'workload_id', 'reproducibility_runs', 'timing_check_id', 'observed_ms'}
        assert value['workload_id'] == workload
        assert type(value['reproducibility_runs']) is int
        assert value['reproducibility_runs'] >= REPRODUCIBILITY_RUNS
        assert value['timing_check_id'] in TIMING_CHECKS
        assert type(value['observed_ms']) is int
        assert 0 <= value['observed_ms'] <= MAXIMUM_MS[workload]
