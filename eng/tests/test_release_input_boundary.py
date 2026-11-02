"""Execute the actual workflow metadata command. Git is real/local; gh is a fixture.

No GitHub token, hosted dispatcher, permission enforcement, registry or publish
operation is exercised. Harmless injection markers must never be created.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/treehammock-release.yml').read_text())
STEP = next(s for s in WORKFLOW['jobs']['release-preflight']['steps'] if s.get('id') == 'release-meta')
spec = importlib.util.spec_from_file_location('release_boundary_guard', ROOT / 'eng/check-release-input-boundary.py')
guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='release metadata ')
        self.folder = Path(self.temp.name)
        self.root = self.folder / 'checkout with spaces'; self.root.mkdir()
        self.real_git = shutil.which('git')
        def git(*args):
            return subprocess.run([self.real_git, *args], cwd=self.root, capture_output=True, text=True, check=True).stdout.strip()
        self.git = git
        git('init', '-q', '-b', 'main'); git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid')
        (self.root / 'file').write_text('initial'); git('add', '.'); git('commit', '-qm', 'initial')
        self.initial = git('rev-parse', 'HEAD')
        git('tag', 'bootstrap'); git('tag', '-a', 'annotated', '-m', 'bootstrap annotated')
        git('branch', 'recovery/bootstrap')
        (self.root / 'file').write_text('later'); git('commit', '-qam', 'later')
        self.later = git('rev-parse', 'HEAD')
        remote = self.folder / 'origin.git'; git('clone', '-q', '--bare', str(self.root), str(remote)); git('remote', 'add', 'origin', str(remote))
        git('fetch', '-q', 'origin', '+refs/heads/*:refs/remotes/origin/*')
        git('branch', '-D', 'recovery/bootstrap')  # Real checkout has remote-only branches too.
        (self.root / 'eng').mkdir(); shutil.copy2(ROOT / 'eng/release-metadata.py', self.root / 'eng/release-metadata.py')
        shutil.copy2(ROOT / 'eng/release_identity.py', self.root / 'eng/release_identity.py')
        self.bin = self.folder / 'bin'; self.bin.mkdir()
        shim = '''#!PYTHON
import json,os,subprocess,sys
args=sys.argv[1:]; name=os.path.basename(sys.argv[0])
with open(os.environ['COMMAND_LOG'],'a') as f: f.write(json.dumps([name,*args])+'\\n')
if name=='git':
    if args and args[0]==os.environ.get('FAIL_GIT_STAGE'): sys.exit(19)
    if args and args[0]=='rev-list' and os.environ.get('BAD_ROOT'): print('not-a-sha'); sys.exit(0)
    if args and args[0]=='rev-parse' and os.environ.get('BAD_COMMIT'): print('not-a-sha'); sys.exit(0)
    sys.exit(subprocess.run([os.environ['REAL_GIT'],*args]).returncode)
if len(args)!=5 or args[:4]!=['api','--include','--method','GET']: sys.exit(99)
kind='RELEASE' if '/releases/tags/' in args[-1] else 'TAG'
status=int(os.environ.get('GH_'+kind+'_STATUS','404'))
if os.environ.get('GH_BAD_HEADER'): print('not an HTTP response')
else: print('HTTP/2.0 '+str(status)+' fixture\\nContent-Type: application/json\\n\\n{}')
sys.exit(int(os.environ.get('GH_EXIT_CODE', '0' if 200<=status<300 else '1')))
'''.replace('PYTHON', sys.executable)
        for name in ['git', 'gh']:
            path=self.bin/name; path.write_text(shim); path.chmod(0o755)
        self.log=self.folder/'commands.jsonl'; self.output=self.folder/'outputs'; self.marker=self.folder/'injection-marker'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'], REAL_GIT=self.real_git,
                        COMMAND_LOG=str(self.log), GITHUB_OUTPUT=str(self.output), GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_SHA=self.later, GITHUB_REF='refs/heads/main', GITHUB_REPOSITORY='fixture/treehammock',
                        RELEASE_PACKAGE_NAME='treehammock-api', INPUT_RELEASE_TAG='v1.0.0', INPUT_TARGET_REF=self.initial,
                        INPUT_CREATE_RELEASE='true', INPUT_PUBLISH_GHCR='false')
        # The fixture intentionally has no token or external repository credentials.
        for key in ['GH_TOKEN', 'GITHUB_TOKEN']:
            self.env.pop(key, None)

    def tearDown(self): self.temp.cleanup()

    def run_metadata(self, **changes):
        self.log.unlink(missing_ok=True); self.output.unlink(missing_ok=True)
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c', STEP['run']], cwd=self.root,
                                env=dict(self.env, **changes), capture_output=True, text=True, timeout=20)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        values=dict(line.split('=',1) for line in self.output.read_text().splitlines()) if self.output.exists() else {}
        self.assertFalse(self.marker.exists(), 'Input became executable code')
        self.assertFalse(any(c[0]=='gh' and c[1]!='api' for c in calls), 'Metadata attempted publication')
        return result, calls, values

    def rejected(self, key, value, **changes):
        result, calls, values=self.run_metadata(**{key:value, **changes})
        self.assertEqual(result.returncode,2); self.assertEqual(values,{})
        self.assertEqual(calls,[], 'Malformed data reached an external command')
        self.assertNotIn(value,result.stderr+result.stdout)

    def test_manual_initial_sha_and_validated_outputs(self):
        result,calls,values=self.run_metadata()
        self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(values['should_release'],'true')
        self.assertEqual(values['checkout_ref'],self.initial); self.assertNotEqual(values['checkout_ref'],self.later)
        self.assertEqual(values['release_archive'],'treehammock-api-v1.0.0.tar.gz')
        self.assertEqual(values['release_checksum'],'treehammock-api-v1.0.0.sha256')
        self.assertEqual(values['release_assembly_version'],'1.0.0.0')
        self.assertEqual(values['create_release'],'true'); self.assertEqual(values['publish_ghcr'],'false')
        for call in calls:
            if call[:2]==['git','rev-parse']: self.assertEqual(call[2:4],['--verify','--end-of-options'])

    def test_bootstrap_push_initial_commit(self):
        r,c,v=self.run_metadata(GITHUB_EVENT_NAME='push',GITHUB_SHA=self.initial,PUBLISH_GHCR='true')
        self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'true'); self.assertEqual(v['release_mode'],'bootstrap')
        self.assertEqual(v['publish_ghcr'],'true'); self.assertEqual(v['create_release'],'true')

    def test_bootstrap_push_ignores_irrelevant_manual_strings(self):
        r,c,v=self.run_metadata(GITHUB_EVENT_NAME='push',GITHUB_SHA=self.initial,INPUT_RELEASE_TAG='$(touch '+shlex.quote(str(self.marker))+')',INPUT_TARGET_REF='--help')
        self.assertEqual(r.returncode,0); self.assertEqual(v['release_tag'],'v1.0.0'); self.assertEqual(v['publish_ghcr'],'false')

    def test_later_push_skips_before_github_lookup(self):
        r,c,v=self.run_metadata(GITHUB_EVENT_NAME='push')
        self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false'); self.assertFalse(any(x[0]=='gh' for x in c))

    def test_non_main_push_skips(self):
        r,c,v=self.run_metadata(GITHUB_EVENT_NAME='push',GITHUB_SHA=self.initial,GITHUB_REF='refs/heads/topic')
        self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false')

    def test_manual_later_main_skips(self):
        r,c,v=self.run_metadata(INPUT_TARGET_REF='main')
        self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false'); self.assertFalse(any(x[0]=='gh' for x in c))

    def test_branch_tag_annotated_tag_full_ref_remote_and_short_sha_recovery(self):
        for target in ['bootstrap','annotated','refs/tags/bootstrap','recovery/bootstrap','refs/remotes/origin/recovery/bootstrap',self.initial[:12]]:
            with self.subTest(target=target):
                r,c,v=self.run_metadata(INPUT_TARGET_REF=target)
                self.assertEqual(r.returncode,0,r.stderr); self.assertEqual(v['should_release'],'true'); self.assertEqual(v['checkout_ref'],self.initial)

    def test_false_create_and_true_publish_are_carried_as_outputs(self):
        r,c,v=self.run_metadata(INPUT_CREATE_RELEASE='false',INPUT_PUBLISH_GHCR='true')
        self.assertEqual(r.returncode,0); self.assertEqual(v['create_release'],'false'); self.assertEqual(v['publish_ghcr'],'true')

    def test_later_version_and_prerelease_preserve_bootstrap_limit(self):
        for tag in ['v1.1.0','v1.0.0-rc.1']:
            with self.subTest(tag=tag):
                r,c,v=self.run_metadata(INPUT_RELEASE_TAG=tag)
                self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false'); self.assertFalse(any(x[0]=='gh' for x in c))

    def test_untrusted_manual_version_is_validated_as_data_before_privileged_shell(self):
        for payload in ['v1.0.0$(touch '+shlex.quote(str(self.marker))+')','v1.0.0`touch '+shlex.quote(str(self.marker))+'`','v1.0.0"; touch '+shlex.quote(str(self.marker))+'; #']:
            with self.subTest(payload=payload): self.rejected('INPUT_RELEASE_TAG',payload)

    def test_invalid_version_and_command_substitution_cannot_execute_or_publish(self):
        for payload in [self.initial+'$(touch '+shlex.quote(str(self.marker))+')','"; touch '+shlex.quote(str(self.marker))+'; #','`touch '+shlex.quote(str(self.marker))+'`']:
            with self.subTest(payload=payload): self.rejected('INPUT_TARGET_REF',payload)

    def test_malformed_tags_fail_before_commands(self):
        for value in ['', '-v1.0.0','v01.0.0','1.0.0','v1.0','v1.0.0.','v1.0.0-','v1.0.0-rc..1','v1.0.0\nshould_release=true','v1.0.0\r','v1.0.0\n','v1.0.0 '+str(self.marker),'v1.0.0/'+'x'*150]:
            with self.subTest(value=value):
                # Empty input has no meaningful echo assertion.
                if not value:
                    r,c,v=self.run_metadata(INPUT_RELEASE_TAG=value); self.assertEqual((r.returncode,c,v),(2,[],{}))
                else: self.rejected('INPUT_RELEASE_TAG',value)

    def test_options_multiline_revision_and_malformed_refs_fail_before_commands(self):
        for value in ['--help','-n','main\ncheckout_ref='+self.initial,'main\r','main\n','main^','HEAD~1','main:eng/script','main@{0}','main..other','bad//ref','bad/.hidden','bad/name.lock','bad/end.','bad/','refs/pull/1/head','a'*256,'a b','../escape','main;echo','main|echo',"main'quote"]:
            with self.subTest(value=value): self.rejected('INPUT_TARGET_REF',value)

    def test_empty_target_ref_is_rejected(self):
        r,c,v=self.run_metadata(INPUT_TARGET_REF=''); self.assertEqual((r.returncode,c,v),(2,[],{}))

    def test_boolean_strings_are_strict(self):
        for key in ['INPUT_CREATE_RELEASE','INPUT_PUBLISH_GHCR']:
            for value in ['True','1','true\n','$(touch '+shlex.quote(str(self.marker))+')']:
                with self.subTest(key=key,value=value): self.rejected(key,value)

    def test_push_registry_setting_is_validated(self):
        self.rejected('PUBLISH_GHCR','TRUE',GITHUB_EVENT_NAME='push',GITHUB_SHA=self.initial)

    def test_event_trigger_repository_and_package_are_validated(self):
        for key,value in [('GITHUB_EVENT_NAME','pull_request'),('GITHUB_SHA','--help'),('GITHUB_REPOSITORY','../evil\n'),('RELEASE_PACKAGE_NAME','../../evil')]:
            with self.subTest(key=key): self.rejected(key,value)

    def test_missing_output_path_is_rejected_before_fetch(self):
        r,c,v=self.run_metadata(GITHUB_OUTPUT=''); self.assertEqual((r.returncode,c,v),(2,[],{}))

    def test_missing_ref_cannot_emit_release_outputs(self):
        r,c,v=self.run_metadata(INPUT_TARGET_REF='missing/ref'); self.assertEqual(r.returncode,2); self.assertEqual(v,{})
        self.assertFalse(any(x[0]=='gh' for x in c))

    def test_ambiguous_branch_and_tag_cannot_select_arbitrary_commit(self):
        self.git('branch','bootstrap',self.later)
        r,c,v=self.run_metadata(INPUT_TARGET_REF='bootstrap'); self.assertEqual(r.returncode,2); self.assertEqual(v,{})

    def test_existing_github_release_skips(self):
        r,c,v=self.run_metadata(GH_RELEASE_STATUS='200'); self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false')
        self.assertEqual(len([x for x in c if x[0]=='gh']),1)

    def test_existing_tag_skips(self):
        r,c,v=self.run_metadata(GH_TAG_STATUS='200'); self.assertEqual(r.returncode,0); self.assertEqual(v['should_release'],'false')

    def test_auth_permission_server_and_transport_errors_fail_closed(self):
        for changes in [dict(GH_RELEASE_STATUS=str(status)) for status in [401,403,429,500]]+[dict(GH_TAG_STATUS='403'),dict(GH_BAD_HEADER='true'),dict(GH_EXIT_CODE='0'),dict(GH_RELEASE_STATUS='200',GH_EXIT_CODE='1')]:
            with self.subTest(changes=changes):
                r,c,v=self.run_metadata(**changes); self.assertEqual(r.returncode,2); self.assertEqual(v,{})

    def test_git_fetch_failure_stops_resolution_and_github(self):
        r,c,v=self.run_metadata(FAIL_GIT_STAGE='fetch'); self.assertEqual(r.returncode,2); self.assertEqual(v,{})
        self.assertEqual([x[1] for x in c],['check-ref-format','fetch'])

    def test_bad_root_or_commit_output_cannot_enter_github_output(self):
        for changes in [dict(BAD_ROOT='true'),dict(BAD_COMMIT='true'),dict(FAIL_GIT_STAGE='rev-list')]:
            with self.subTest(changes=changes):
                r,c,v=self.run_metadata(**changes); self.assertEqual(r.returncode,2); self.assertEqual(v,{})
                self.assertFalse(any(x[0]=='gh' for x in c))


class ReleaseWorkflowMutationTests(unittest.TestCase):
    def rejected(self, mutate):
        workflow=copy.deepcopy(WORKFLOW); mutate(workflow)
        with self.assertRaises((ValueError,KeyError)): guard.validate_document(workflow)
    def test_current_source_consistency_does_not_qualify_hosted_permissions(self): self.assertEqual(guard.validate(ROOT)['qualification'],'NotRun')
    def test_workflow_cannot_default_to_write(self): self.rejected(lambda w:w['permissions'].update(contents='write'))
    def test_preflight_cannot_gain_write(self): self.rejected(lambda w:w['jobs']['release-preflight']['permissions'].update(contents='write'))
    def test_unit_gate_cannot_gain_package_write(self): self.rejected(lambda w:w['jobs']['release-dotnet-unit-gate']['permissions'].update(packages='write'))
    def test_svs_builder_cannot_gain_write(self): self.rejected(lambda w:w['jobs']['release-package-svs']['permissions'].update(contents='write'))
    def test_release_cannot_skip_svs_job(self): self.rejected(lambda w:w['jobs']['create-github-release']['needs'].remove('release-package-svs'))
    def test_release_cannot_ignore_svs_failure(self): self.rejected(lambda w:w['jobs']['create-github-release'].update({'if': "${{ needs.release-preflight.outputs.should_release == 'true' }}"}))
    def test_svs_builder_cannot_omit_tests(self): self.rejected(lambda w:w['jobs']['release-package-svs']['steps'].__setitem__(4, {'name': 'removed', 'run': 'true'}))
    def test_package_builder_cannot_gain_write(self): self.rejected(lambda w:w['jobs']['release-package-api']['permissions'].update(contents='write'))
    def test_ghcr_cannot_gain_contents_write(self): self.rejected(lambda w:w['jobs']['release-ghcr-image']['permissions'].update(contents='write'))
    def test_release_cannot_gain_packages_write(self): self.rejected(lambda w:w['jobs']['create-github-release']['permissions'].update(packages='write'))
    def test_shell_cannot_interpolate_context(self): self.rejected(lambda w:w['jobs']['release-preflight']['steps'][1].update(run='echo "${{ inputs.release_tag }}"'))
    def test_input_transport_cannot_leave_environment(self): self.rejected(lambda w:w['jobs']['release-preflight']['steps'][1]['env'].update(INPUT_TARGET_REF='main'))
    def test_publish_condition_cannot_reparse_raw_inputs(self): self.rejected(lambda w:w['jobs']['release-ghcr-image'].update({'if':"${{ inputs.publish_ghcr == 'true' }}"}))
    def test_consumer_cannot_checkout_mutable_input(self): self.rejected(lambda w:w['jobs']['release-package-api']['steps'][0]['with'].update(ref='${{ inputs.target_ref }}'))
    def test_publish_checkout_cannot_persist_credentials(self): self.rejected(lambda w:w['jobs']['release-ghcr-image']['steps'][0]['with'].update({'persist-credentials':True}))
    def test_preflight_cannot_checkout_dispatch_input(self): self.rejected(lambda w:w['jobs']['release-preflight']['steps'][0]['with'].update(ref='${{ inputs.target_ref }}'))
    def test_preflight_requires_complete_main_history(self): self.rejected(lambda w:w['jobs']['release-preflight']['steps'][0]['with'].update({'fetch-depth':1}))
    def test_consumer_cannot_bypass_metadata_gate(self): self.rejected(lambda w:w['jobs']['release-package-api'].update({'if':'always()'}))


if __name__ == '__main__': unittest.main()
