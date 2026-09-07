"""Real section output with a synthetic app root and inert external probes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(os.environ.get('MAC_POSTURE_AUDIT_ROOT',Path(__file__).resolve().parents[2]))

class RemoteGuidanceTests(unittest.TestCase):
    def row(self,redact,profile='normal',installed=True):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Path(temp);apps=fixture/'apps';apps.mkdir()
            (fixture/'Library/LaunchAgents').mkdir(parents=True)
            if installed:(apps/'AnyDesk.app').mkdir()
            script='''source "$1"
shift
parse_args --json --quick --profile "$3"
REDACT="$2"
APP_ROOTS=("$1/apps")
SANDBOX_CLI_BINS=()
find() { return 0; }
osascript() { return 0; }
crontab() { return 1; }
sudo() { return 1; }
_proc_running() { return 1; }
_check_persist_background_items() { return 0; }
section_22_persistence_tcc
printf '%s\\n' "${JSON_ROWS[@]}"
'''
            env=dict(os.environ,HOME=str(fixture))
            result=subprocess.run(['/bin/bash','-c',script,'audit',str(ROOT/'mac-posture-audit.sh'),str(fixture),str(redact).lower(),profile],env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            rows=[json.loads(x) for x in result.stdout.splitlines()]
            return next(r for r in rows if r['id']=='apps.remote_access.present')

    def test_redacted_label_and_hint_are_brand_free(self):
        row=self.row(True)
        self.assertEqual(row['status'],'warn')
        self.assertIn('1 found',row['label'])
        for brand in ('AnyDesk','TeamViewer'):
            self.assertNotIn(brand,row['label']+' '+row['hint'])

    def test_unredacted_details_remain_visible(self):
        row=self.row(False)
        self.assertEqual(row['status'],'warn')
        self.assertIn('AnyDesk',row['label'])

    def test_profile_escalation_remains_intact(self):
        self.assertEqual(self.row(True,'web3')['status'],'fail')

    def test_absent_app_remains_pass(self):
        self.assertEqual(self.row(True,installed=False)['status'],'pass')

if __name__=='__main__': unittest.main()
