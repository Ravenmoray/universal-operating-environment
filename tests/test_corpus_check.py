"""corpus_check hands file names to external tools; none may be able to act as an option."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('corpus_check.py')
ROOT = SCRIPT.parents[1]
sys.path.insert(0, str(SCRIPT.parent))     # the fixture builders live next to this file

try:
    import dnfile  # noqa: F401  (optional independent oracle for managed images)
except ImportError:
    dnfile = None


def run_corpus_check(directory, *options):
    return subprocess.run([sys.executable, '-B', str(SCRIPT), str(directory), *options], text=True,
                          capture_output=True, timeout=120, env=dict(os.environ, PYTHONPATH=str(ROOT)))


@unittest.skipUnless(shutil.which('node'), 'node is the reference tool that evaluates its arguments')
class CorpusCheckArgumentTests(unittest.TestCase):
    def test_a_file_named_like_an_option_is_not_interpreted_by_the_reference_tool(self):
        # ``Path('.') / name`` drops the "./", so walking a relative root used to hand node the
        # bare name ``--eval=...``, which it evaluates as code.
        with tempfile.TemporaryDirectory() as tmp:
            name = '--eval=require("fs").writeFileSync("injected","x")'
            Path(tmp, name).write_bytes(b'\0asm\x01\0\0\0')
            done = subprocess.run([sys.executable, '-B', str(SCRIPT), '.'], cwd=tmp, text=True,
                                  capture_output=True, timeout=120,
                                  env=dict(os.environ, PYTHONPATH=str(ROOT)))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn('matched=1', done.stdout)
            self.assertFalse(Path(tmp, 'injected').exists(), 'file name was evaluated as node code')


class CorpusCheckPeTests(unittest.TestCase):
    """The PE and .NET comparison paths, which the option-injection test above never reaches."""

    @unittest.skipUnless(shutil.which('llvm-readobj'), 'requires llvm-readobj')
    def test_delay_load_pe_is_compared_with_llvm_readobj(self):
        from test_pe_dependencies import with_delay
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'delayed.exe').write_bytes(with_delay())
            done = run_corpus_check(tmp, '--fail-on-reject')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('matched=1', done.stdout)
        self.assertNotIn('disagreed', done.stdout)

    @unittest.skipUnless(shutil.which('llvm-readobj'), 'requires llvm-readobj')
    def test_a_disagreement_with_the_reference_fails_the_run(self):
        # Negative control: if the parser's reading differed from llvm-readobj's, the run must say so.
        import contextlib
        import corpus_check
        from unittest.mock import patch
        from test_pe_dependencies import with_delay
        wrong = lambda report: [('static', 'wrong.dll', [])]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'delayed.exe').write_bytes(with_delay())
            output = io.StringIO()
            with patch.dict(corpus_check.COMPARERS, {'PE': (corpus_check.reference_pe, wrong)}), \
                    contextlib.redirect_stdout(output):
                code = corpus_check.main([tmp])
        self.assertEqual(code, 1)
        self.assertIn('disagreed', output.getvalue())

    def test_a_failed_reference_run_is_not_a_match(self):
        # If llvm-readobj / readelf fail, their empty stdout used to parse as "no imports" and
        # "match" a file for which uoe also reports none. That must be an unusable comparison.
        import contextlib
        import corpus_check
        from types import SimpleNamespace
        from unittest.mock import patch
        from test_pe_dependencies import fixture
        failed = lambda command: SimpleNamespace(returncode=1, stdout='', stderr='boom')
        with patch.object(corpus_check, 'run', failed), \
                patch.object(corpus_check.shutil, 'which', lambda name: '/usr/bin/' + name):
            self.assertEqual(corpus_check.reference_pe('x.exe'), 'rejected')
            self.assertEqual(corpus_check.reference_elf('x'), 'rejected')
            # end to end: a PE with no imports, whose reference run fails, is not counted as matched
            data = fixture()
            data[0x98 + 112 + 8:0x98 + 112 + 16] = bytes(8)        # no import directory
            with tempfile.TemporaryDirectory() as tmp:
                Path(tmp, 'none.exe').write_bytes(bytes(data))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = corpus_check.main([tmp])
        self.assertEqual(code, 0, output.getvalue())
        self.assertIn('reference_also_rejected=1', output.getvalue())
        self.assertNotIn('matched', output.getvalue())

    @unittest.skipUnless(dnfile and shutil.which('llvm-readobj'), 'requires dnfile and llvm-readobj')
    def test_managed_pe_is_compared_with_dnfile(self):
        from test_clr_dependencies import ASSEMBLIES, build_metadata, managed_pe
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'app.dll').write_bytes(managed_pe(build_metadata(ASSEMBLIES, ['native.dll'])))
            done = run_corpus_check(tmp, '--fail-on-reject')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('managed=1', done.stdout)
        self.assertIn('managed_matched=1', done.stdout)

    @unittest.skipUnless(dnfile, 'requires dnfile')
    def test_a_broken_reference_is_an_error_not_a_quiet_pass(self):
        # reference_clr must not swallow failures of its own code: a bug there used to show up as
        # "reference also rejected" and exit 0.
        import corpus_check
        from test_clr_dependencies import ASSEMBLIES, build_metadata, managed_pe
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'app.dll')
            path.write_bytes(managed_pe(build_metadata(ASSEMBLIES, ['native.dll'])))
            self.assertNotIn(corpus_check.reference_clr(path), (None, 'rejected'))
            with patch.object(corpus_check, 'clr_facts', side_effect=AttributeError('harness bug')):
                with self.assertRaises(AttributeError):
                    corpus_check.reference_clr(path)


if __name__ == '__main__':
    unittest.main()
