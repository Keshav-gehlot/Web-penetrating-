import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanners.coverage import COVERAGE_CATALOG, coverage_catalog


def test_coverage_catalog_contains_all_100_items():
    assert len(COVERAGE_CATALOG) == 100
    assert [item[0] for item in COVERAGE_CATALOG] == list(range(1, 101))
    assert len(coverage_catalog()) == 100
