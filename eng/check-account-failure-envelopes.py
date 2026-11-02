#!/usr/bin/env python3
"""Source guard only. Actual HTTP/assertion/mutation qualification is a separate CLR lane."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
HELPER='treehammock.Tests/Infrastructure/AccountFailureAssertions.cs'
SUITES=['treehammock.Tests/Integration/ApiValidationEnvelopeTests.cs','treehammock.Tests/Integration/AccountAdjustIntegrationTests.cs']
UNIT='treehammock.Tests/Unit/AccountFailureAssertionTests.cs'
def require(value,message):
    if not value:raise ValueError(message)
def validate(root=ROOT):
    helper=(root/HELPER).read_text()
    for token in ['((int)httpStatus).ShouldBe(statusCode);','Required(root, "success", JsonValueKind.False);','Required(root, "statusCode", JsonValueKind.Number)','status.TryGetInt32(out int envelopeStatus).ShouldBeTrue();','envelopeStatus.ShouldBe(statusCode);','Required(root, "code", JsonValueKind.String).GetString().ShouldBe(code);','if (code == ApiResponses.ValidationFailedCode)','ValidationErrors(document);','Required(document.RootElement, "errors", JsonValueKind.Array)','errors.GetArrayLength().ShouldBeGreaterThan(0);','foreach (JsonElement error in errors.EnumerateArray())','Required(error, "field", JsonValueKind.String)','Required(error, "messages", JsonValueKind.Array)','messages.GetArrayLength().ShouldBeGreaterThan(0);','foreach (JsonElement message in messages.EnumerateArray())','message.ValueKind.ShouldBe(JsonValueKind.String);','message.GetString().ShouldNotBeNullOrWhiteSpace();','field, StringComparison.Ordinal))','names.Distinct(StringComparer.Ordinal).Count().ShouldBe(names.Length','root.TryGetProperty("data", out _).ShouldBeFalse','root.TryGetProperty("errors", out _).ShouldBeFalse','(response.Content.Headers.ContentType?.MediaType).ShouldBe("application/json");','json.ShouldNotBeNullOrWhiteSpace();']:
        require(token in helper,'Strict account contract missing: '+token)
    require(helper.index('Failure(response.StatusCode, document, statusCode, code, dataField, dataValue);')<helper.index('(response.Content.Headers.ContentType?.MediaType).ShouldBe'), 'Wire schema must be asserted before media type')
    for path in SUITES:
        text=(root/path).read_text()
        require('private static void AssertFailureEnvelope' not in text and 'root.GetProperty("status")' not in text and 'errors.EnumerateObject()' not in text,'Legacy alternate failure contract remains')
        require('AccountFailureAssertions.Failure(response, document,' in text and 'await AccountFailureAssertions.ReadJson(response)' in text,'Actual response contract is not asserted')
        require('AccountFailureAssertions.ValidationField(document,' in text,'Expected validation field is not asserted')
    unit=(root/UNIT).read_text()
    for token in ['[MemberData(nameof(InvalidEnvelopes))]','Should.Throw<ShouldAssertException>','HttpStatusCode.PreconditionRequired','IDEMPOTENCY_KEY_REQUIRED','application/problem+json','Should.ThrowAsync<JsonException>']:
        require(token in unit,'Compiled adversarial fixture absent: '+token)
    native=(root/'eng/test-account-failure-envelopes.py').read_text()
    for token in ['framework-model-state','required-key-wrong-code','required-key-missing-code','test(\'restored-\'+kind)','changed.write_bytes(original)','Shouldly.ShouldAssertException','AccountFailureAssertions.Failure','Suite discovery is incomplete','--locked-mode','Native .NET SDK unavailable; zero cases executed']:
        require(token in native,'Actual native mutation/result boundary absent: '+token)
    return dict(status='SourceContractsConsistent',qualification='NotRun',scope='Strict account envelope/validation/data assertions; actual CLR/HTTP mutation proof required')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root)));return 0
    except (OSError,ValueError):print('Strict account envelope source contract failed.');return 1
if __name__=='__main__':raise SystemExit(main())
