"""Adversarial graph/JSON regression cases, with deterministic mutation seeds."""
import copy
import io
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from uoe.graph import GraphError, MAX_BYTES, load_graph, plan, validate
from uoe.claims import ClaimError, load_claims
from uoe.json_input import load_document

FIXTURE = Path(__file__).resolve().parents[1] / 'experiments/capability-graph/fixtures/demo.json'


def fanout(count=100, requirements=10):
    graph = json.loads(FIXTURE.read_text())
    originals = {e['relationship']: e for e in graph['edges']}
    graph['edges'] = []
    for relation, original in originals.items():
        for i in range(requirements if relation == 'requires' else count):
            edge = copy.deepcopy(original)
            edge['id'] = f'{relation}:{i}'
            graph['edges'].append(edge)
    return graph


class GraphLimitTests(unittest.TestCase):
    def test_pair_budget_rejects_parallel_edge_explosion(self):
        with self.assertRaisesRegex(GraphError, 'pair budget'):
            plan(fanout(101), 'artifact:demo', 'host:linux')

    def test_budget_boundary_and_permutations_preserve_semantics(self):
        data = fanout()
        baseline = plan(data, 'artifact:demo', 'host:linux')
        self.assertEqual(len(baseline['requirements']), 10)
        self.assertEqual(len(baseline['requirements'][0]['candidates']), 1)
        rng = random.Random(21)
        rng.shuffle(data['edges'])
        rng.shuffle(data['nodes'])
        self.assertEqual(plan(data, 'artifact:demo', 'host:linux'), baseline)

    def test_string_and_reference_bounds(self):
        data = fanout(1, 1)
        data['nodes'][0]['label'] = 'x' * 4097
        with self.assertRaises(GraphError):
            validate(data)
        data = fanout(1, 1)
        data['edges'][0]['evidence'] *= 65
        with self.assertRaises(GraphError):
            validate(data)

    def test_seeded_malformed_field_mutations(self):
        rng = random.Random(21)
        bad_values = [None, [], {}, 3, False, ['nested'], {'nested': []}]
        for i in range(400):
            data = fanout(1, 1)
            row = rng.choice(data[rng.choice(['nodes', 'edges'])])
            key = rng.choice(list(row))
            row[key] = copy.deepcopy(rng.choice(bad_values))
            with self.subTest(case=i), self.assertRaises(GraphError):
                validate(data)

    def test_strict_json_rejections_for_graph_and_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.json'
            for raw in (b'{"nodes":[],"nodes":[]}', b'{"x":NaN}', b'\xff',
                        b'[' * 33 + b']' * 33, b' ' * (MAX_BYTES + 1)):
                path.write_bytes(raw)
                with self.subTest(raw=raw[:30]):
                    with self.assertRaises(GraphError):
                        load_graph(path)
                    with self.assertRaises(ClaimError):
                        load_claims(path, '0' * 64)

    def test_read_is_bounded_even_without_stat(self):
        stream = io.BytesIO(b' ' * (MAX_BYTES + 2))
        class ReadOnlyStream:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count):
                self_size = count
                self_test.assertEqual(self_size, MAX_BYTES + 1)
                return stream.read(count)
        self_test = self
        with patch.object(Path, 'open', return_value=ReadOnlyStream()):
            with self.assertRaisesRegex(GraphError, 'exceeds'):
                load_graph('ignored')
        self.assertEqual(stream.tell(), MAX_BYTES + 1)

    def test_brackets_in_escaped_strings_do_not_count_as_depth(self):
        content = {'value': '[\\"' * 100}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.json'
            path.write_text(json.dumps(content))
            self.assertEqual(load_document(path, MAX_BYTES), content)
