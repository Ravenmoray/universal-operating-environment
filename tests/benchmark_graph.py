"""Run with: python3 tests/benchmark_graph.py (synthetic evidence only)."""
import json
from pathlib import Path
import sys
import time
import tracemalloc
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_graph_limits import fanout
from uoe.graph import GraphError, plan

tracemalloc.start()
start = time.perf_counter()
result = plan(fanout(), 'artifact:demo', 'host:linux')
elapsed = time.perf_counter() - start
_, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
assert len(result['requirements']) == 10
start = time.perf_counter()
try:
    plan(fanout(101), 'artifact:demo', 'host:linux')
except GraphError as exc:
    assert 'pair budget' in str(exc)
else:
    raise AssertionError('over-budget graph was accepted')
print(json.dumps({'accepted_pairs': 100000, 'accepted_seconds': elapsed,
                  'peak_traced_bytes': peak, 'rejected_pairs': 102010,
                  'rejected_seconds': time.perf_counter() - start}, indent=2))
