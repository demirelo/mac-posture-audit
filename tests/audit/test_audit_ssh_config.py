"""Only synthetic SSH configs; ssh -G prints configuration and never connects."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(os.environ.get('MAC_POSTURE_AUDIT_ROOT',Path(__file__).resolve().parents[2]))

class SshConfigTests(unittest.TestCase):
    def probe(self,config):
        with tempfile.TemporaryDirectory() as temp:
            fixture_home=Path(temp); (fixture_home/'.ssh').mkdir()
            cfg=fixture_home/'.ssh/config'; cfg.write_text(config)
            effective=subprocess.run(['/usr/bin/ssh','-G','-F',str(cfg),'fixture.invalid'],text=True,capture_output=True,timeout=10)
            self.assertEqual(effective.returncode,0,effective.stderr)
            # Give only the subprocess a synthetic HOME; the real user's files are never used.
            env=dict(os.environ,HOME=str(fixture_home))
            script='source "$1"; parse_args --json; _check_ssh_config_risky_options; printf "%s\\n" "${JSON_ROWS[@]}"'
            checked=subprocess.run(['/bin/bash','-c',script,'audit',str(ROOT/'mac-posture-audit.sh')],env=env,text=True,capture_output=True,timeout=10)
            self.assertEqual(checked.returncode,0,checked.stderr)
            rows=[json.loads(s) for s in checked.stdout.splitlines()]
            return effective.stdout,rows[0]

    def test_unterminated_global_option_is_not_lost(self):
        effective,row=self.probe('Host *\n ForwardAgent yes')
        self.assertIn('forwardagent yes',effective)
        self.assertEqual(row['status'],'warn',row)

    def test_equals_syntax_is_recognized(self):
        effective,row=self.probe('Host *\n ForwardAgent=yes\n')
        self.assertIn('forwardagent yes',effective)
        self.assertEqual(row['status'],'warn',row)

    def test_case_insensitive_keywords_are_recognized(self):
        effective,row=self.probe('Host *\n FORWARDAGENT yes\n')
        self.assertIn('forwardagent yes',effective)
        self.assertEqual(row['status'],'warn',row)

    def test_standard_global_risk_control(self):
        effective,row=self.probe('Host *\n ForwardAgent yes\n')
        self.assertIn('forwardagent yes',effective)
        self.assertEqual(row['status'],'warn',row)

    def test_specific_host_control(self):
        effective,row=self.probe('Host trusted.internal.example\n ForwardAgent yes\n')
        self.assertIn('forwardagent no',effective)
        self.assertEqual(row['status'],'pass',row)

if __name__=='__main__': unittest.main()
