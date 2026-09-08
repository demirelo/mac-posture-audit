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


class HtmlReportTests(unittest.TestCase):
    def test_untrusted_summary_values_cannot_inject_html(self):
        spec=importlib.util.spec_from_file_location('audit_renderer',ROOT/'tools/render_report.py')
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        for key in ('pass','warn','fail','skip','total'):
            with self.subTest(key=key):
                doc={'results':[],'summary':{key:'<img src=x onerror="canary()">'}}
                result=mod.render(doc)
                self.assertNotIn('<img',result)
                self.assertIn('&lt;img',result)

    def test_malformed_document_shapes_fail_with_usage_status(self):
        for doc in ({'results':None}, {'results':['invalid']}, {'results':[], 'summary':None}, {'results':[], 'executive_verdict':[]}, {'results':[], 'top_risks':[None]}):
            with self.subTest(doc=doc):
                result=subprocess.run(['python3',str(ROOT/'tools/render_report.py')],input=json.dumps(doc),text=True,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertNotIn('Traceback',result.stderr)
                self.assertEqual(result.stdout,'')

    def test_valid_report_control(self):
        result=subprocess.run(['python3',str(ROOT/'tools/render_report.py')],input='{"results":[],"summary":{"pass":1}}',text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('1 pass',result.stdout)


if __name__=='__main__': unittest.main()
