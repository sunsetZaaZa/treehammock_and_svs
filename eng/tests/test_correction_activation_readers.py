"""Scope counterexamples are structural tests, not provider execution."""
import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('reader_scopes',ROOT/'eng/check-activation-reader-scopes.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


class ActivationReaderScopeTests(unittest.TestCase):
    def valid(self):
        return '''public async Task<Result> PlaceActivation() {
            Result result;
            await using (var reader = await command.ExecuteReaderAsync(token)) {
                if (await reader.ReadAsync(token)) result = found;
                else result = denied;
            }
            await operation.CommitAsync(result);
            return result;
        }'''

    def test_current_six_methods_have_closed_reader_scopes(self):
        self.assertEqual(guard.validate(ROOT),list(guard.METHODS))

    def test_commit_inside_reader_rejects_original_review_counterexample(self):
        source=self.valid().replace('            }\n            await operation.CommitAsync(result);','            await operation.CommitAsync(result);\n            }')
        with self.assertRaises(ValueError):guard.validate_method(source,'PlaceActivation')

    def test_scope_level_using_declaration_is_rejected(self):
        source=self.valid().replace('await using (var reader = await command.ExecuteReaderAsync(token)) {','await using var reader = await command.ExecuteReaderAsync(token); {')
        with self.assertRaises(ValueError):guard.validate_method(source,'PlaceActivation')

    def test_commit_before_reader_is_rejected(self):
        source=self.valid().replace('            await operation.CommitAsync(result);','').replace('Result result;','Result result; await operation.CommitAsync(result);')
        with self.assertRaises(ValueError):guard.validate_method(source,'PlaceActivation')

    def test_nested_mapping_and_literal_braces_do_not_hide_reader_boundary(self):
        source=self.valid().replace('result = found;','result = new Result(new { Payload = "} await op.CommitAsync(result);" }); // }')
        self.assertEqual(guard.validate_method(source,'PlaceActivation'),'PlaceActivation')

    def test_all_six_commit_inside_mutations_are_rejected(self):
        source=(ROOT/'Repos/ActivationRepo.cs').read_text()
        for name in guard.METHODS:
            # Mutate one method in isolation by removing its reader close before commit.
            text=guard.mask(source);signature=list(__import__('re').finditer(r'\bpublic\s+(?:async\s+)?[\w<>?,.]+\s+'+name+r'\s*\(',text))[0]
            brace=text.index('{',guard.closing(text,signature.end()-1,'(',')'));end=guard.closing(text,brace)
            body=source[brace:end+1];masked=guard.mask(body)
            using=list(__import__('re').finditer(r'await\s+using\s*\(',masked))[0]
            opening=masked.index('{',guard.closing(masked,using.end()-1,'(',')'));close=guard.closing(masked,opening)
            commit=__import__('re').search(r'\b\w+\.CommitAsync\([^;]+;',masked)
            mutated=body[:close]+body[close+1:commit.end()]+'}'+body[commit.end():]
            with self.assertRaises(ValueError,msg=name):guard.validate_method(source[:brace]+mutated+source[end+1:],name)

    def test_missing_reader_is_rejected(self):
        with self.assertRaises(ValueError):guard.validate_method('public Task<Result> PlaceActivation() { return result; }','PlaceActivation')


if __name__=='__main__':unittest.main()
