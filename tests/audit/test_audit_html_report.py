"""Synthetic report-boundary regressions; never runs a host posture scan."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
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
                doc={'results':[],'summary':{'pass':0,'warn':0,'fail':0,'skip':0,'total':0}}
                doc['summary'][key]='<img src=x onerror="canary()">'
                # Counters are integers under the stricter contract. Reject
                # hostile counters before any HTML is produced.
                with self.assertRaisesRegex(ValueError, 'summary\\.'+key):
                    mod.render(doc)
                result=subprocess.run([sys.executable,str(ROOT/'tools/render_report.py')],input=json.dumps(doc),text=True,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertEqual(result.stdout,'')
                self.assertNotIn('Traceback',result.stderr)

    def test_untrusted_text_values_are_escaped(self):
        payload='<img src=x onerror="canary()">'
        doc={'host':payload,'results':[{'id':'test.check.one','status':'pass','label':payload,'hint':payload}]}
        result=subprocess.run([sys.executable,str(ROOT/'tools/render_report.py')],input=json.dumps(doc),text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('<img',result.stdout)
        self.assertIn('&lt;img',result.stdout)

    def test_malformed_document_shapes_fail_with_usage_status(self):
        for doc in ({'results':None}, {'results':['invalid']}, {'results':[], 'summary':None}, {'results':[], 'executive_verdict':[]}, {'results':[], 'top_risks':[None]}):
            with self.subTest(doc=doc):
                result=subprocess.run([sys.executable,str(ROOT/'tools/render_report.py')],input=json.dumps(doc),text=True,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertNotIn('Traceback',result.stderr)
                self.assertEqual(result.stdout,'')

    def test_valid_report_control(self):
        doc={'results':[{'id':'test.check.one','status':'pass','label':'Synthetic passing check','hint':''}],
             'summary':{'pass':1,'warn':0,'fail':0,'skip':0,'total':1}}
        result=subprocess.run([sys.executable,str(ROOT/'tools/render_report.py')],input=json.dumps(doc),text=True,capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('1 pass',result.stdout)


if __name__=='__main__': unittest.main()
