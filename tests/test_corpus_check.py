"""corpus_check hands file names to external tools; none may be able to act as an option."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('corpus_check.py')
ROOT = SCRIPT.parents[1]


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


if __name__ == '__main__':
    unittest.main()
