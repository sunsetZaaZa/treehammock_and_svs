"""Source mutation/plumbing checks. Actual PowerShell matrix never emulated or reported as executed here."""
import importlib.util,shutil,tempfile,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
boundary=load('ps_boundary','eng/check-powershell-native-boundaries.py');fixture=load('ps_fixture','eng/test-powershell-runners.py')
class PowerShellBoundaryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.correction-results','.artifacts','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
  with self.assertRaises(ValueError):boundary.validate(self.root)
 def test_consistent_source_is_not_native_execution(self):self.assertEqual('NotRun',boundary.validate(self.root)['qualification'])
 def test_capture_is_immediate(self):self.reject(boundary.HELPER,'& $tool.Source @Arguments\n        $nativeExitCode = $LASTEXITCODE','& $tool.Source @Arguments\n        Write-Output success\n        $nativeExitCode = $LASTEXITCODE')
 def test_no_success_without_exit_oracle(self):self.reject(boundary.HELPER,'if ($null -eq $nativeExitCode)','if ($false)')
 def test_failure_is_not_ignored(self):self.reject(boundary.HELPER,'if ($nativeExitCode -ne 0)','if ($false)')
 def test_original_code_is_retained(self):self.reject(boundary.HELPER,'New-TreehammockStageFailure $Stage $nativeExitCode','New-TreehammockStageFailure $Stage 0')
 def test_profile_alias_cannot_replace_executable(self):self.reject(boundary.HELPER,'-CommandType Application','')
 def test_native_error_preference_is_not_the_oracle(self):self.reject(boundary.HELPER,'$PSNativeCommandUseErrorActionPreference = $false','$PSNativeCommandUseErrorActionPreference = $true')
 def test_stderr_with_zero_exit_is_allowed(self):self.reject(boundary.HELPER,"$ErrorActionPreference = 'Continue'","$ErrorActionPreference = 'Stop'")
 def test_child_script_result_is_captured(self):self.reject(boundary.HELPER,'& $Path @Parameters\n    $scriptExitCode = $LASTEXITCODE','& $Path @Parameters\n    $scriptExitCode = 0')
 def test_child_nonthrowing_exit_must_fail(self):self.reject(boundary.HELPER,'if ($scriptExitCode -ne 0)','if ($false)')
 def test_nested_exception_code_is_retained(self):self.reject(boundary.HELPER,'$current = $current.InnerException','$current = $null')
 def test_top_level_exit_is_explicit(self):self.reject(boundary.HELPER,'    exit $runnerExitCode\n','    exit 0\n')
 def test_top_level_catch_uses_captured_primary(self):self.reject(boundary.HELPER,'$runnerExitCode = Get-TreehammockFailureCode $_.Exception','$runnerExitCode = 0')
 def test_validate_cannot_use_unchecked_restore(self):self.reject('eng/validate.ps1',"Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments $restoreArgs",'dotnet @restoreArgs')
 def test_docker_output_suppression_does_not_skip_check(self):self.reject('eng/docker-system-stack-tests.ps1',"Invoke-TreehammockNative -Stage 'docker-info' -FilePath 'docker' -Arguments @('info')",'& docker info')
 def test_build_proof_cannot_call_unchecked_child(self):self.reject('eng/build-proof.ps1',"Invoke-TreehammockScript -Stage 'validate' -Path './eng/validate.ps1'",'& ./eng/validate.ps1')
 def test_each_entrypoint_uses_shared_runner(self):self.reject('eng/docker-down.ps1',"Invoke-TreehammockRunner -Stage 'docker-down' -Body {","& {")
 def test_uninventoried_entrypoint_fails(self):
  (self.root/'eng/unchecked.ps1').write_text('dotnet build\n')
  with self.assertRaises(ValueError):boundary.validate(self.root)
 def test_no_retry_that_masks_first_pull_failure(self):self.reject('eng/docker-api-image.ps1',"Invoke-TreehammockNative -Stage 'docker-pull'",'Invoke-DockerPullWithRetry')
 def test_cleanup_cannot_replace_primary_error(self):self.reject(boundary.HOST,'if ($null -eq $primaryFailure)','if ($true)')
 def test_primary_is_rethrown_after_cleanup(self):self.reject(boundary.HOST,'if ($null -ne $primaryFailure) { throw $primaryFailure }','')
 def test_early_API_exit_is_a_real_failure(self):self.reject(boundary.HOST,"-Stage 'host-api' -FilePath $ApiPython","-Stage 'host-api' -FilePath 'missing-host'")
 def test_native_matrix_checks_exit_values(self):self.reject('eng/test-powershell-runners.py','failed.returncode!=47','False')
 def test_native_matrix_checks_later_work(self):self.reject('eng/test-powershell-runners.py','prefix!=baseline[:number]','False')
 def test_both_entry_modes_required(self):self.reject('eng/test-powershell-runners.py',"['File','Command']","['File']")
 def test_native_matrix_is_mandatory_in_CI(self):self.reject('.github/workflows/treehammock-ci.yml','python eng/test-powershell-runners.py --host ${{ matrix.host }}','true')
 def test_windows_legacy_host_is_in_matrix(self):self.reject('.github/workflows/treehammock-ci.yml','host: powershell.exe','host: none')
 def test_fixture_cases_exactly_cover_source_entrypoints(self):self.assertEqual({name+'.ps1' for name in boundary.RUNNERS},set(fixture.CASES))
 def test_fixture_arg_quoting_preserves_spaces_and_literal_quotes(self):self.assertEqual("'x y''z'",fixture.quote("x y'z"))
 def test_trace_records_actual_argv_values(self):
  p=self.root/'trace.jsonl';values=[dict(tool='dotnet',args=['restore','fixture assembly.dll']),dict(tool='docker',args=['compose','up'])];p.write_text('\n'.join(json.dumps(v) for v in values));self.assertEqual(values,fixture.entries(p))
if __name__=='__main__':unittest.main()
