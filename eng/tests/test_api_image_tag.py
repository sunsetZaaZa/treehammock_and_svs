"""Source mutations and actual Bash argv fixtures; PowerShell is never emulated."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('api_image_guard',ROOT/'eng/check-api-image-tag.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

class OutputTagWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);(self.root/'eng').mkdir()
        shutil.copy2(ROOT/'eng/docker-api-image.ps1',self.root/'eng/docker-api-image.ps1')
    def tearDown(self):self.temp.cleanup()
    def reject(self,before,after):
        file=self.root/'eng/docker-api-image.ps1';text=file.read_text();self.assertIn(before,text);file.write_text(text.replace(before,after,1))
        with self.assertRaises(ValueError):guard.validate(self.root)
    def test_source_consistency_is_not_powershell_qualification(self):self.assertEqual(guard.validate(self.root)['qualification'],'NotRun')
    def test_case_insensitive_parameter_loop_collision_rejected(self):self.reject('foreach ($baseImage in $requiredImages)','foreach ($image in $requiredImages)')
    def test_output_capture_must_be_read_only(self):self.reject('-Option ReadOnly','-Option None')
    def test_build_must_use_captured_output(self):self.reject("'-t', $outputImage","'-t', $Image")
    def test_pull_must_use_base_not_output(self):self.reject("@('pull', $baseImage)","@('pull', $outputImage)")
    def test_sdk_override_forwarded(self):self.reject('DOTNET_SDK_IMAGE=$sdkImage','UNUSED=$sdkImage')
    def test_runtime_override_forwarded(self):self.reject('DOTNET_RUNTIME_IMAGE=$runtimeImage','UNUSED=$runtimeImage')
    def test_configuration_forwarded(self):self.reject('BUILD_CONFIGURATION=$Configuration','BUILD_CONFIGURATION=Debug')
    def test_native_result_not_masked_by_later_commands(self):
        file=self.root/'eng/docker-api-image.ps1';text=file.read_text();file.write_text(text.rstrip()[:-1]+"Write-Output 'later'\n}\n")
        with self.assertRaises(ValueError):guard.validate(self.root)
    def test_known_base_collision_must_be_rejected(self):self.reject('$outputImage -eq $sdkImage -or $outputImage -eq $runtimeImage','$false')
    def test_no_cache_forwarded(self):self.reject("$buildArgs += '--no-cache'","$buildArgs += '--cache'")
    def test_progress_forwarded(self):self.reject("'--progress', $Progress","'--progress', 'auto'")

class BashParityFixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces';self.eng=self.root/'eng';self.eng.mkdir(parents=True)
        for name in ['docker-api-image.sh','docker-cli.sh','build-identity.sh']:shutil.copy2(ROOT/'eng'/name,self.eng/name)
        (self.eng/'check-locks.sh').write_text('#!/usr/bin/env bash\nexit 0\n');(self.eng/'check-locks.sh').chmod(0o755)
        binary=Path(self.temp.name)/'bin';binary.mkdir();self.trace=Path(self.temp.name)/'calls.jsonl'
        fake=binary/'docker';fake.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open(os.environ["COR23V_TRACE"],"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\nif sys.argv[1:2]==["build"]:sys.exit(int(os.environ.get("COR23V_BUILD_EXIT","0")))\nprint("Docker controlled executable")\n');fake.chmod(0o755)
        self.env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],COR23V_TRACE=str(self.trace),TREEHAMMOCK_DOTNET_SDK_IMAGE='fixture/sdk:custom',TREEHAMMOCK_DOTNET_RUNTIME_IMAGE='fixture/runtime:custom',TREEHAMMOCK_DISABLE_SDK_RUNTIME_FALLBACK='true')
        self.env.pop('TREEHAMMOCK_DOCKER_SELECTED',None);self.env.pop('TREEHAMMOCK_DOCKER_CLI',None)
    def tearDown(self):self.temp.cleanup()
    def invoke(self,args):
        result=subprocess.run(['bash',str(self.eng/'docker-api-image.sh'),*args],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=15)
        calls=[json.loads(line) for line in self.trace.read_text().splitlines()]
        return result,calls
    def test_default_requested_tag_survives_multiple_base_checks(self):
        result,calls=self.invoke([]);self.assertEqual(result.returncode,0);build=next(a for a in calls if a[:1]==['build']);self.assertEqual(build[build.index('-t')+1],'treehammock:api')
        self.assertIn(['pull','fixture/sdk:custom'],calls);self.assertIn(['pull','fixture/runtime:custom'],calls)
    def test_custom_tag_configuration_flags_and_overrides_match_contract(self):
        result,calls=self.invoke(['--image','fixture.example/team/api:requested','--configuration','Sandbox','--no-cache','--progress','plain'])
        self.assertEqual(result.returncode,0);build=next(a for a in calls if a[:1]==['build']);self.assertEqual(build[build.index('-t')+1],'fixture.example/team/api:requested')
        for value in ['BUILD_CONFIGURATION=Sandbox','DOTNET_SDK_IMAGE=fixture/sdk:custom','DOTNET_RUNTIME_IMAGE=fixture/runtime:custom','--no-cache']:self.assertIn(value,build)
        self.assertEqual(build[build.index('--progress')+1],'plain');self.assertEqual(build[-1],'.')
    def test_failed_native_build_keeps_exit_and_requested_tag(self):
        self.env['COR23V_BUILD_EXIT']='47';result,calls=self.invoke(['--image','fixture:failed']);self.assertEqual(result.returncode,47)
        self.assertEqual(calls[-1][calls[-1].index('-t')+1],'fixture:failed');self.assertEqual(calls[-1][0],'build')

class NativeFixturePrerequisites(unittest.TestCase):
    def test_missing_host_cannot_fabricate_powershell_or_docker_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'report.json';result=subprocess.run([sys.executable,str(ROOT/'eng/test-api-image-wrapper.py'),'--host','cor23v-no-such-real-host','--output',str(file)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2);report=json.loads(file.read_text());self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['cases'],[]);self.assertEqual(report['docker_cases'],[])
