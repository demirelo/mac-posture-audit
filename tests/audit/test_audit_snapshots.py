"""Synthetic report-boundary regressions; never runs a host posture scan."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(os.environ.get('MAC_POSTURE_AUDIT_ROOT', Path(__file__).resolve().parents[2]))
SCRIPT = ROOT / 'mac-posture-audit.sh'


def shell(body, *args, stdin=None):
    return subprocess.run(['/bin/bash', '-c', 'source "$1"; shift; '+body, 'audit', str(SCRIPT), *map(str,args)], input=stdin, text=True, capture_output=True, timeout=15)


class SnapshotTests(unittest.TestCase):
    def test_same_second_snapshots_append_without_clobber(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)
            result=shell('SNAPSHOT=true; MSA_HISTORY_DIR="$1"; date() { printf 20260101-000000; }; _build_json_document() { printf \'{"sequence":%s}\\n\' "$SEQ"; }; SEQ=1; maybe_write_snapshot; SEQ=2; maybe_write_snapshot',history)
            self.assertEqual(result.returncode,0,result.stderr)
            docs=[json.loads(p.read_text()) for p in history.glob('posture-*.json')]
            self.assertEqual(sorted(d['sequence'] for d in docs),[1,2])

    def test_twelve_same_second_snapshots_keep_chronological_trend(self):
        with tempfile.TemporaryDirectory() as temp:
            history = Path(temp)
            result = shell('''SNAPSHOT=true; MSA_HISTORY_DIR="$1"
date() { printf 20260101-000000; }
_build_json_document() {
  local state=pass
  [[ "$SEQ" -eq 1 ]] && state=fail
  printf '{"sequence":%s,"results":[{"id":"synthetic.check","status":"%s"}]}\n' "$SEQ" "$state"
}
for SEQ in 1 2 3 4 5 6 7 8 9 10 11 12; do maybe_write_snapshot || exit; done
''', history)
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = sorted(history.glob('posture-*.json'))
            self.assertEqual(len(paths), 12)
            self.assertEqual([json.loads(p.read_text())['sequence'] for p in paths], list(range(1, 13)))
            trend = shell('MSA_HISTORY_DIR="$1"; run_trend', history)
            self.assertEqual(trend.returncode, 0, trend.stderr)
            self.assertIn('Improved: 1   Regressed: 0', trend.stdout)
            self.assertIn('synthetic.check: fail -> pass', trend.stdout)

    def test_concurrent_same_second_snapshots_preserve_every_document(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp)
            history = fixture / 'history'
            history.mkdir()
            gate = fixture / 'release'
            processes = []
            body = '''source "$1"; shift
SNAPSHOT=true; MSA_HISTORY_DIR="$1"; SEQ="$2"
date() { printf 20260101-000000; }
_build_json_document() { printf '{"sequence":%s}\n' "$SEQ"; }
printf ready > "$3/ready-$SEQ"
while [[ ! -f "$3/release" ]]; do sleep 0.01; done
maybe_write_snapshot
'''
            try:
                for sequence in range(1, 9):
                    processes.append(subprocess.Popen(
                        ['/bin/bash', '-c', body, 'audit', str(SCRIPT), str(history), str(sequence), str(fixture)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                deadline = time.monotonic() + 10
                while len(list(fixture.glob('ready-*'))) != 8 and time.monotonic() < deadline:
                    time.sleep(0.01)
                ready = len(list(fixture.glob('ready-*')))
                gate.touch()
                outcomes = [p.communicate(timeout=15) for p in processes]
                self.assertEqual(ready, 8, outcomes)
                self.assertTrue(all(p.returncode == 0 for p in processes), outcomes)
                paths = list(history.glob('posture-*.json'))
                self.assertTrue(all(p.is_file() and not p.is_symlink() for p in paths))
                self.assertEqual(sorted(json.loads(p.read_text())['sequence'] for p in paths), list(range(1, 9)))
            finally:
                gate.touch()
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait()

    def test_existing_snapshot_symlink_target_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)/'history'; history.mkdir()
            sentinel=Path(temp)/'user-config'; sentinel.write_text('do not overwrite')
            (history/'posture-20260101-000000.json').symlink_to(sentinel)
            result=shell('SNAPSHOT=true; MSA_HISTORY_DIR="$1"; date() { printf 20260101-000000; }; _build_json_document() { printf \'{"sequence":1}\\n\'; }; maybe_write_snapshot',history)
            self.assertEqual(sentinel.read_text(),'do not overwrite',result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr)
            regular = [p for p in history.glob('posture-*.json') if p.is_file() and not p.is_symlink()]
            self.assertEqual(len(regular), 1)
            self.assertEqual(json.loads(regular[0].read_text()), {'sequence': 1})

    def test_chronological_history_trend_control(self):
        with tempfile.TemporaryDirectory() as temp:
            history = Path(temp)
            for sequence, status in [(1, 'fail'), (2, 'pass')]:
                (history / f'posture-20260101-00000{sequence}.json').write_text(json.dumps({
                    'results': [{'id': 'synthetic.check', 'status': status}]}))
            trend = shell('MSA_HISTORY_DIR="$1"; run_trend', history)
            self.assertEqual(trend.returncode, 0, trend.stderr)
            self.assertIn('Improved: 1   Regressed: 0', trend.stdout)

    def test_disabled_snapshot_does_not_create_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)/'absent'
            result=shell('SNAPSHOT=false; MSA_HISTORY_DIR="$1"; maybe_write_snapshot',history)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(history.exists())


if __name__=='__main__': unittest.main()
