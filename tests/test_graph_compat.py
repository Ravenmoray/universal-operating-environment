"""Regression coverage for the original graph entry point after consolidation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from uoe import graph

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / 'experiments' / 'capability-graph'
ENTRY = EXPERIMENT / 'uoe_graph' / '__main__.py'
FIXTURE = EXPERIMENT / 'fixtures' / 'demo.json'


class GraphCompatibilityTests(unittest.TestCase):
    def test_legacy_api_is_the_shared_implementation(self):
        spec = importlib.util.spec_from_file_location('legacy_graph', ENTRY)
        module = importlib.util.module_from_spec(spec)
        original_path = sys.path[:]
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path[:] = original_path
        for name in ('GraphError', 'load_graph', 'plan', 'validate', 'main'):
            self.assertIs(getattr(module, name), getattr(graph, name), name)

    def invoke(self, mode, *args, cwd):
        env = dict(os.environ, PYTHONPATH=str(EXPERIMENT))
        command = ['-m', 'uoe_graph'] if mode == 'module' else [str(ENTRY)]
        return subprocess.run([sys.executable, *command, *args], cwd=cwd,
                              env=env, text=True, capture_output=True, timeout=10)

    def test_legacy_module_and_script_work_outside_checkout(self):
        expected = graph.plan(graph.load_graph(FIXTURE), 'artifact:demo', 'host:linux')
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ('module', 'script'):
                with self.subTest(mode=mode):
                    result = self.invoke(mode, 'plan', str(FIXTURE), '--artifact',
                                         'artifact:demo', '--host', 'host:linux', cwd=tmp)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_legacy_cli_rejects_forged_evidence(self):
        data = graph.load_graph(FIXTURE)
        for node in data['nodes']:
            if node['kind'] == 'evidence' and node['evidence_type'] == 'test':
                node['result'] = 'fail'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'forged.json'
            path.write_text(json.dumps(data))
            for mode in ('module', 'script'):
                result = self.invoke(mode, 'validate', str(path), cwd=tmp)
                self.assertEqual(result.returncode, 2)
                self.assertIn('passing test evidence', result.stderr)
                self.assertEqual(result.stdout, '')
