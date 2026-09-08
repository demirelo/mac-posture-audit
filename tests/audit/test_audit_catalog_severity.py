"""Synthetic inventories validate the documented info/warn/critical mapping."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('MAC_POSTURE_AUDIT_ROOT',Path(__file__).resolve().parents[2]))

class CatalogSeverityTests(unittest.TestCase):
    def check(self,surface,severity,profile='normal'):
        with tempfile.TemporaryDirectory() as temp:
            fixture=Path(temp)
            catalog=fixture/'catalog.txt'
            severities = [severity] if isinstance(severity, str) else list(severity)
            entries = []
            if surface=='editor':
                for index, level in enumerate(severities):
                    name = 'example.test' + str(index)
                    (fixture/'extensions'/(name+'-1.0.0')).mkdir(parents=True)
                    entries.append('editor_extension|'+name+'|'+level+'|synthetic'+str(index))
                setup='EDITOR_EXT_ROOTS=("fixture|$1/extensions"); _check_editor_extensions'
                ident='dev.editor_extensions.suspicious'
            elif surface=='browser':
                for index, level in enumerate(severities):
                    extension = chr(ord('a')+index)*32
                    manifest=fixture/'browser'/'Default'/'Extensions'/extension/'1.0'/'manifest.json'
                    manifest.parent.mkdir(parents=True); manifest.write_text('{}')
                    entries.append('browser_extension_id|'+extension+'|'+level+'|synthetic'+str(index))
                setup='BROWSER_EXT_CHROMIUM_ROOTS=("fixture|$1/browser"); BROWSER_EXT_FIREFOX_ROOTS=(); _check_browser_extensions_inventory'
                ident='browser.extensions.suspicious'
            elif surface=='firefox':
                addons = []
                for index, level in enumerate(severities):
                    addon = 'synthetic' + str(index) + '@example.test'
                    addons.append({'id': addon, 'version': '1.0', 'type': 'extension', 'active': True})
                    entries.append('browser_extension_id|'+addon+'|'+level+'|synthetic'+str(index))
                addons.append({'id': 'theme-not-counted@example.test', 'version': '1.0', 'type': 'theme', 'active': True})
                extensions = fixture/'firefox'/'profile.default'/'extensions.json'
                extensions.parent.mkdir(parents=True)
                extensions.write_text(json.dumps({'schemaVersion': 33, 'addons': addons}))
                setup='BROWSER_EXT_CHROMIUM_ROOTS=(); BROWSER_EXT_FIREFOX_ROOTS=("fixture|$1/firefox"); _check_browser_extensions_inventory'
                ident='browser.extensions.suspicious'
            else:
                servers = {}
                for index, level in enumerate(severities):
                    name = 'synthetic'+str(index)
                    servers[name] = {'command': '/usr/bin/true', 'args': []}
                    entries.append('mcp_server|'+name+'|'+level+'|synthetic'+str(index))
                (fixture/'mcp.json').write_text(json.dumps({'mcpServers': servers}))
                setup='MCP_CONFIG_PATHS=("$1/mcp.json"); _check_mcp_servers'
                ident='mcp.servers.suspicious'
            catalog.write_text('\n'.join(entries)+'\n')
            script='source "$1"; shift; parse_args --json --profile "$2"; EXPOSURE_CATALOG_PATH="$1/catalog.txt"; load_exposure_catalog; '+setup+'; printf "%s\\n" "${JSON_ROWS[@]}"'
            result=subprocess.run(['/bin/bash','-c',script,'audit',str(ROOT/'mac-posture-audit.sh'),str(fixture),profile],text=True,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            rows=[json.loads(line) for line in result.stdout.splitlines()]
            return next(row for row in rows if row['id']==ident)

    def test_info_does_not_escalate_to_warning(self):
        for surface in ('editor','browser','firefox','mcp'):
            with self.subTest(surface=surface):
                row=self.check(surface,'info')
                self.assertEqual(row['status'],'skip',row)

    def test_warn_mapping_control(self):
        for surface in ('editor','browser','firefox','mcp'):
            with self.subTest(surface=surface):
                row=self.check(surface,'warn')
                self.assertEqual(row['status'],'warn',row)

    def test_critical_mapping_control(self):
        for surface in ('editor','browser','firefox','mcp'):
            with self.subTest(surface=surface):
                row=self.check(surface,'critical')
                self.assertEqual(row['status'],'fail',row)

    def test_mixed_severities_use_highest_risk_in_both_orders(self):
        for surface in ('editor', 'browser', 'firefox', 'mcp'):
            for pair, expected in [(('info', 'warn'), 'warn'), (('info', 'critical'), 'fail'), (('warn', 'critical'), 'fail')]:
                for ordered in (pair, tuple(reversed(pair))):
                    with self.subTest(surface=surface, severities=ordered):
                        row = self.check(surface, ordered)
                        self.assertEqual(row['status'], expected, row)

    def test_info_remains_informational_under_stricter_profiles(self):
        for surface in ('editor', 'browser', 'firefox', 'mcp'):
            for profile in ('founder', 'paranoid', 'web3'):
                with self.subTest(surface=surface, profile=profile):
                    row = self.check(surface, 'info', profile)
                    self.assertEqual(row['status'], 'skip', row)

if __name__=='__main__': unittest.main()
