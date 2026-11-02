#!/usr/bin/env python3
"""Source guard only: committed SQL/proxy registration requires actual System execution."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SYSTEM='treehammock.Tests.System/SystemStackAccountFlowTests.cs'
ASSERTION='treehammock.Tests/Infrastructure/RegistrationVerificationAssertions.cs'
HTTP='treehammock.Tests/Integration/RegistrationVerificationHttpTests.cs'
PROJECT='treehammock.Tests.System/treehammock.Tests.System.csproj'
def require(value,message):
    if not value:raise ValueError(message)
def validate(root=ROOT):
    system=(root/SYSTEM).read_text();assertion=(root/ASSERTION).read_text();http=(root/HTTP).read_text()
    case=system.split('public async Task Registration_verify_succeeds_through_haproxy()',1)[1].split('    [Fact]',1)[0]
    for token in ['await RegisterAndVerify(','await LoginAndReturnAccessToken(', 'accessToken.ShouldNotBeNullOrWhiteSpace();','using JsonDocument profile = await AuthenticatedGetJson(client, "/account/view", accessToken,','GetProperty("emailAddress").GetString().ShouldBe(email);','GetProperty("verifyStatus").GetString().ShouldBe("SUCCESSFUL");','GetProperty("code").GetString().ShouldBe("ACCOUNT_VIEW_SUCCEEDED");']:
        require(token in case,'Independent committed account proof missing: '+token)
    require(case.index('await RegisterAndVerify(')<case.index('await LoginAndReturnAccessToken(')<case.index('await AuthenticatedGetJson('),'Independent proof must follow verification')
    helper=system.split('private static async Task RegisterAndVerify(',1)[1].split('private static async Task SetupEmailTwoFactor',1)[0]
    require('LoginAndReturnAccessToken' not in helper and 'AuthenticatedGetJson' not in helper,'Registration helper must not issue a hidden session')
    for token in ['using JsonDocument setup = await PostJson(', 'using var response=await client.GetAsync(', 'RegistrationVerificationAssertions.AssertSuccessPage(response, body,','RegistrationVerificationAssertions.LoadTemplate("success")','body != "<p>Your verification delivery is pending. Try again shortly.</p>"','Verification publication did not complete.']:
        require(token in helper,'Bounded owned verification outcome missing: '+token)
    require('body.Contains(' not in helper,'Substring success/pending classification forbidden')
    for token in ['expectedHtml.ShouldNotBeNullOrWhiteSpace();','response.StatusCode.ShouldBe(HttpStatusCode.OK);','(response.Content.Headers.ContentType?.MediaType).ShouldBe("text/html");','body.ShouldBe(expectedHtml);','throw new FileNotFoundException(']:
        require(token in assertion,'Controlled exact HTML contract missing: '+token)
    require('RegistrationVerificationAssertions.cs' in (root/PROJECT).read_text(),'System must compile the same HTTP assertion')
    names=re.findall(r'\[Fact\]\s*public (?:async Task|void) (\w+)\(',http)
    require(len(names)==10,'All ten compiled HTTP/assertion regressions required')
    for token in ['Independent_observer_proves_only_intended_account_verified','Http_200_error_page_cannot_satisfy_verification_success','Invalid_token_returns_failure_html_without_committing','Expired_token_returns_expired_html_without_committing','Unavailable_completion_returns_failure_html_without_committing','Unavailable_lookup_returns_failure_html_without_committing','Already_verified_returns_its_template_without_another_commit','Successful_marker_inside_failure_html_is_insufficient','Successful_content_requires_html_media_type','Successful_content_requires_a_content_type_header','completion: false','completion: null','if (completion == true) _state[AccountId] = VerificationStatus.SUCCESSFUL;','Observe(OtherAccountId).ShouldBe(VerificationStatus.SENT);','fixture.AssertUncommitted(1);','Should.Throw<ShouldAssertException>','await using var fixture','await _factory.DisposeAsync();']:
        require(token in http,'Actual negative/state/ownership fixture boundary missing: '+token)
    return dict(status='SourceContractsConsistent',qualification='NotRun',http_facts=len(names),system_case='Registration_verify_succeeds_through_haproxy',native='Actual Program HTTP regressions plus full SQL/proxy System execution required')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root)));return 0
    except (OSError,ValueError):print('Registration verification source contract failed.');return 1
if __name__=='__main__':raise SystemExit(main())
