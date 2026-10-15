"""Execute the actual release tag validation with hostile dispatch inputs."""
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text()
RESOLVE = WORKFLOW.split("      - name: Resolve version tag\n", 1)[1]
RESOLVE = RESOLVE.split("      - name:", 1)[0].split("        run: |\n", 1)[1]
RESOLVE = textwrap.dedent(RESOLVE)


def step_script(name):
    step = WORKFLOW.split("      - name: " + name + "\n", 1)[1]
    step = step.split("      - name:", 1)[0].split("        run: |\n", 1)[1]
    return textwrap.dedent(step)


class ReleaseTagTests(unittest.TestCase):
    def run_tag(self, tag, event="workflow_dispatch", ref=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = dict(os.environ, INPUT_TAG=tag, GITHUB_EVENT_NAME=event,
                       GITHUB_REF=ref or "refs/tags/" + tag, GITHUB_OUTPUT=str(output))
            result = subprocess.run(["/bin/bash", "-c", RESOLVE], env=env,
                                    capture_output=True, text=True, cwd=directory)
            contents = output.read_text() if output.exists() else ""
            self.assertFalse((Path(directory) / "EXECUTED").exists())
            return result.returncode, contents

    def test_version_tags(self):
        for tag in ("v1.2.3", "v10.0.2", "v1.2.3-rc.1"):
            for event in ("push", "workflow_dispatch"):
                with self.subTest(tag=tag, event=event):
                    self.assertEqual(self.run_tag(tag, event), (0, "tag=" + tag + "\n"))

    def test_ref_shell_and_output_injection_are_rejected(self):
        for tag in ("main", "refs/heads/main", "../v1.2.3", "--help", "v1.2",
                    "v1.2.3\nsha=attacker", "v1.2.3$(touch EXECUTED)",
                    "v1.2.3`touch EXECUTED`", 'v1.2.3"; touch EXECUTED; #', ""):
            with self.subTest(tag=tag):
                status, output = self.run_tag(tag)
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")

    def test_dispatch_cannot_misstate_build_provenance(self):
        status, output = self.run_tag("v1.2.3", ref="refs/heads/main")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")

    def test_publish_uses_tested_commit_and_does_not_replace_assets(self):
        self.assertIn("needs: validate", WORKFLOW)
        self.assertIn("ref: ${{ needs.validate.outputs.sha }}", WORKFLOW)
        self.assertNotIn("--clobber", WORKFLOW)
        # Values enter commands through environment variables, not shell source.
        scripts = re.findall(r"^        run: \|\n((?:(?: {10}.*)?\n)*)", WORKFLOW, re.M)
        self.assertGreater(len(scripts), 2)
        for script in scripts:
            self.assertNotIn("${{", script)


# Run the workflow's actual shell against a stateful, local GitHub API double.
# Unknown requests fail closed; no credentials or network calls are used.
MOCK_GH = r"""#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

path = Path(os.environ['MOCK_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]
state.setdefault('calls', []).append(args)
path.write_text(json.dumps(state))

def save():
    path.write_text(json.dumps(state))

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

def option(name, default=None):
    return args[args.index(name) + 1] if name in args else default

repo = 'repos/example/project'
if args[:2] == ['release', 'upload']:
    if state.get('upload_error'):
        fail('upload failed')
    assert args[2:] == ['v1.2.3', 'asset.tar.gz', 'asset.tar.gz.sha256',
                        'asset.tar.gz.sigstore', 'asset.tar.gz.intoto.jsonl']
    release = next(r for r in state['releases'] if r['tag_name'] == args[2])
    assert release['draft'] and not release.get('immutable') and not release['assets']
    release['assets'] = args[3:]
    save()
    sys.exit(0)
assert args[0] == 'api', args
endpoint = args[1]
method = option('--method', 'GET')
query = option('--jq')
fields = [args[i + 1] for i, a in enumerate(args) if a in ('-f', '-F')]
if endpoint == repo + '/releases':
    if method == 'GET':
        assert '--paginate' in args
        assert query == '.[] | select(.tag_name == "v1.2.3") | .id'
        if state.get('list_error'):
            fail('list failed')
        for release in state['releases']:
            if release['tag_name'] == 'v1.2.3':
                print(release['id'])
    else:
        assert method == 'POST' and query == '.id'
        assert fields == ['tag_name=v1.2.3', 'target_commitish=' + 'a' * 40,
                          'name=v1.2.3', 'draft=true']
        if state.get('create_error'):
            fail('create failed')
        state['releases'].append(dict(id=42, tag_name='untagged-new', draft=True, assets=[]))
        save()
        print(state.get('created_id', 42))
elif endpoint.startswith(repo + '/releases/'):
    release = next(r for r in state['releases'] if str(r['id']) == endpoint.rsplit('/', 1)[1])
    if method == 'PATCH':
        assert release['id'] == 42 and fields == ['tag_name=v1.2.3']
        if state.get('patch_error'):
            fail('patch failed')
        if not state.get('keep_temporary_tag'):
            release['tag_name'] = 'v1.2.3'
        save()
    else:
        assert method == 'GET'
        assert query == '[.tag_name, .draft, (.immutable // false), (.assets | length)] | @tsv'
        if state.get('detail_error'):
            fail('detail failed')
        print('{}\t{}\t{}\t{}'.format(release['tag_name'], str(release['draft']).lower(),
              str(release.get('immutable', False)).lower(), len(release['assets'])))
elif endpoint == repo + '/git/ref/tags/v1.2.3':
    assert method == 'GET'
    if state.get('tag_error'):
        fail('tag lookup failed')
    if query == '.object.sha':
        print('b' * 40 if state.get('moved_tag') else 'a' * 40)
    else:
        assert query == '.object.type'
        print('tag' if state.get('annotated') else 'commit')
elif endpoint == repo + '/git/tags/' + 'a' * 40:
    assert state.get('annotated') and method == 'GET'
    print('commit' if query == '.object.type' else 'a' * 40)
else:
    fail('unexpected request: ' + repr(args))
"""


class DraftReleaseTests(unittest.TestCase):
    def run_steps(self, releases=None, upload=False, **options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_file = root / 'state.json'
            state_file.write_text(json.dumps(dict(releases=releases or [], **options)))
            gh = root / 'gh'
            gh.write_text(MOCK_GH)
            gh.chmod(0o700)
            output = root / 'output'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       MOCK_STATE=str(state_file), GITHUB_OUTPUT=str(output),
                       GITHUB_REPOSITORY='example/project', RELEASE_TAG='v1.2.3',
                       SOURCE_SHA='a' * 40, ASSET='asset.tar.gz', RELEASE_ID='7',
                       GH_TOKEN='synthetic-not-a-credential')
            script = step_script('Upload assets to release' if upload else 'Ensure empty draft release')
            result = subprocess.run(['/bin/bash', '-c', script], env=env, cwd=directory,
                                    capture_output=True, text=True)
            return (result, json.loads(state_file.read_text()),
                    output.read_text() if output.exists() else '')

    @staticmethod
    def draft(**changes):
        return dict(dict(id=7, tag_name='v1.2.3', draft=True, assets=[]), **changes)

    def test_missing_draft_is_created_and_temporary_tag_is_corrected(self):
        result, state, output = self.run_steps()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, 'release_id=42\n')
        self.assertEqual(state['releases'][0]['tag_name'], 'v1.2.3')
        self.assertTrue(state['releases'][0]['draft'])

    def test_existing_empty_draft_is_reused_without_mutation(self):
        result, state, output = self.run_steps([self.draft()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, 'release_id=7\n')
        self.assertFalse(any('--method' in c for c in state['calls']))

    def test_unrelated_temporary_draft_is_never_retagged(self):
        unrelated = self.draft(tag_name='untagged-other')
        result, state, output = self.run_steps([unrelated])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state['releases'][0], unrelated)
        self.assertEqual(output, 'release_id=42\n')

    def test_published_immutable_and_populated_releases_are_rejected(self):
        for change in (dict(draft=False), dict(immutable=True), dict(assets=['existing'])):
            with self.subTest(change=change):
                result, state, output = self.run_steps([self.draft(**change)])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, '')
                self.assertFalse(any('--method' in c for c in state['calls']))

    def test_api_failures_do_not_proceed_or_become_missing_releases(self):
        for error in ('list_error', 'create_error', 'patch_error', 'detail_error'):
            with self.subTest(error=error):
                result, state, output = self.run_steps(**{error: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, '')
                if error == 'list_error':
                    self.assertFalse(any('--method' in c for c in state['calls']))

    def test_uncorrected_temporary_tag_and_invalid_ids_are_rejected(self):
        for options in (dict(keep_temporary_tag=True), dict(created_id='bad\nrelease_id=99')):
            with self.subTest(options=options):
                result, state, output = self.run_steps(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, '')

    def test_duplicate_draft_ids_are_rejected(self):
        result, state, output = self.run_steps([self.draft(), self.draft(id=8)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, '')

    def test_upload_rechecks_draft_and_tag_before_any_asset_write(self):
        for change in (dict(draft=False), dict(immutable=True), dict(assets=['existing']),
                       dict(tag_name='untagged-changed')):
            with self.subTest(change=change):
                result, state, output = self.run_steps([self.draft(**change)], upload=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c[:2] == ['release', 'upload'] for c in state['calls']))
        for error in ('moved_tag', 'tag_error', 'detail_error'):
            with self.subTest(error=error):
                result, state, output = self.run_steps([self.draft()], upload=True, **{error: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c[:2] == ['release', 'upload'] for c in state['calls']))

    def test_upload_accepts_lightweight_and_annotated_tested_tags(self):
        for annotated in (False, True):
            with self.subTest(annotated=annotated):
                result, state, output = self.run_steps([self.draft()], upload=True, annotated=annotated)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(state['releases'][0]['assets']), 4)

    def test_preflight_rejects_moved_or_missing_tag_before_creating_draft(self):
        for error in ('moved_tag', 'tag_error'):
            with self.subTest(error=error):
                result, state, output = self.run_steps(**{error: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, '')
                self.assertFalse(any('--method' in c for c in state['calls']))

    def test_upload_failure_is_not_hidden(self):
        result, state, output = self.run_steps([self.draft()], upload=True, upload_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['releases'][0]['assets'], [])

    def test_preflight_precedes_build_and_signing(self):
        self.assertLess(WORKFLOW.index('- name: Ensure empty draft release'),
                        WORKFLOW.index('- name: Build release tarball'))
        self.assertLess(WORKFLOW.index('- name: Ensure empty draft release'),
                        WORKFLOW.index('- name: Sign tarball'))


if __name__ == "__main__":
    unittest.main()
