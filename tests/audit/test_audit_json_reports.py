"""Synthetic report-boundary regressions; never runs a host posture scan."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get('MAC_POSTURE_AUDIT_ROOT', Path(__file__).resolve().parents[2]))
SCRIPT = ROOT / 'mac-posture-audit.sh'


def shell(body, *args, stdin=None):
    return subprocess.run(['/bin/bash', '-c', 'source "$1"; shift; '+body, 'audit', str(SCRIPT), *map(str,args)], input=stdin, text=True, capture_output=True, timeout=15)


class JsonEncodingTests(unittest.TestCase):
    def test_all_representable_json_controls_round_trip(self):
        for code in range(1,32):
            with self.subTest(code=code):
                value='prefix'+chr(code)+'suffix'
                result=shell('_json_escape "$1"', value)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads('"'+result.stdout+'"'),value)

    def test_quote_backslash_unicode_control(self):
        value='héllo"\\\n\tworld'
        result=shell('_json_escape "$1"',value)
        self.assertEqual(json.loads('"'+result.stdout+'"'),value)


class DiffParsingTests(unittest.TestCase):
    def test_valid_result_identity_not_shadowed_by_nested_evidence(self):
        doc={'results':[{'id':'system.sip.enabled','status':'fail','label':'x','hint':'','evidence':{'id':'other.id','status':'pass'}}]}
        result=shell('_diff_parse_rows synthetic',stdin=json.dumps(doc))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'system.sip.enabled fail\n')

    def test_results_need_not_be_last_document_member(self):
        doc={'results':[{'id':'system.sip.enabled','status':'pass','label':'x','hint':''}], 'future':{'id':'other.id','status':'fail'}}
        result=shell('_diff_parse_rows synthetic',stdin=json.dumps(doc))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'system.sip.enabled pass\n')

    def test_json_escapes_in_identifiers_are_decoded(self):
        doc=r'{"results":[{"id":"system.\u0073ip.enabled","status":"pass"}]}'
        result=shell('_diff_parse_rows synthetic',stdin=doc)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'system.sip.enabled pass\n')

    def test_malformed_json_is_rejected(self):
        for raw in ['garbage {"results":[{"id":"a.b","status":"pass"}]}', '{"results":[{"id":"a.b","status":"pass",}]}', '{"results":[{"id":"a.b","status":"pass"}]} trailing']:
            with self.subTest(raw=raw):
                result=shell('_diff_parse_rows synthetic',stdin=raw)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)

    def test_truthful_two_rows_control(self):
        doc={'results':[{'id':'system.sip.enabled','status':'fail'},{'id':'network.firewall.enabled','status':'pass'}]}
        result=shell('_diff_parse_rows synthetic',stdin=json.dumps(doc))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'system.sip.enabled fail\nnetwork.firewall.enabled pass\n')


class TrendTests(unittest.TestCase):
    def test_invalid_oldest_or_newest_is_error_not_no_change(self):
        for broken in (0,1):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as temp:
                history=Path(temp)
                for idx in (0,1):
                    (history/f'posture-2026010{idx+1}-000000.json').write_text('not json' if broken==idx else '{"results":[{"id":"system.sip.enabled","status":"pass"}]}')
                result=shell('MSA_HISTORY_DIR="$1"; run_trend',history)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertNotIn('No status changes',result.stdout)

    def test_valid_trend_control(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)
            for idx,st in enumerate(('fail','pass')):
                (history/f'posture-2026010{idx+1}-000000.json').write_text(json.dumps({'results':[{'id':'system.sip.enabled','status':st}]}))
            result=shell('MSA_HISTORY_DIR="$1"; run_trend',history)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Improved: 1',result.stdout)


if __name__=='__main__': unittest.main()
