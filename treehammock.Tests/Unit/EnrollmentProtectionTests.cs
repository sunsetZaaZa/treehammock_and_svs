using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using treehammock.Repos;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;
using treehammock.Rigging.Config;
using treehammock.Services;
namespace treehammock.Tests.Unit;

public class Cor15EnrollmentProtectionTests
{
    // RFC 6238 Appendix B, including the errata's algorithm-specific secret lengths.
    public static IEnumerable<object[]> RfcVectors()
    {
        long[] times = [59,1111111109,1111111111,1234567890,2000000000,20000000000];
        string[][] codes = [["94287082","07081804","14050471","89005924","69279037","65353130"],
            ["46119246","68084774","67062674","91819424","90698825","77737706"],
            ["90693936","25091201","99943326","93441116","38618901","47863826"]];
        string[] algorithms = ["SHA1","SHA256","SHA512"]; int[] lengths = [20,32,64];
        for(int a=0;a<3;a++) for(int t=0;t<times.Length;t++) yield return [algorithms[a],lengths[a],times[t],codes[a][t]];
    }
    [Theory, MemberData(nameof(RfcVectors))]
    public void All_Rfc_vectors_verify(string algorithm,int length,long time,string code)
    {
        byte[] secret = Enumerable.Range(0,length).Select(i => (byte)('0'+(i+1)%10)).ToArray();
        new TotpCodeVerifier().Verify(secret,code,Instant.FromUnixTimeSeconds(time),null,new(algorithm,8,30,0)).Verified.ShouldBeTrue();
    }
    [Theory, InlineData(30,60), InlineData(60,30)]
    public void Stored_parameters_survive_default_changes_in_both_directions(int enrolledPeriod,int newPeriod)
    {
        var settings = Settings("old"); settings.PeriodSeconds=enrolledPeriod;
        var context = new TotpEnrollmentContext(Guid.NewGuid(),Guid.NewGuid(),TotpParameters.FromDefaults(settings));
        byte[] secret=RandomNumberGenerator.GetBytes(20); long time=1700000010;
        string code=TotpCodeVerifier.ComputeCode(secret,time/enrolledPeriod,6,"SHA1");
        settings.PeriodSeconds=newPeriod; settings.Digits=8; settings.HashAlgorithm="SHA512"; settings.AllowedClockSkewSteps=0;
        new TotpCodeVerifier().Verify(secret,code,Instant.FromUnixTimeSeconds(time),null,context.Parameters).Verified.ShouldBeTrue();
    }
    [Theory, InlineData("account"), InlineData("enrollment"), InlineData("algorithm"), InlineData("digits"), InlineData("period"), InlineData("skew"), InlineData("key-id"), InlineData("nonce"), InlineData("tag"), InlineData("ciphertext")]
    public void Envelope_rejects_tampering_and_wrong_row_binding(string changed)
    {
        var settings=Settings("old"); settings.ProtectionKeys["alias"]=settings.ProtectionKeys["old"];
        var protector=new TotpSecretProtector(Options.Create(settings));
        var context=new TotpEnrollmentContext(Guid.NewGuid(),Guid.NewGuid(),new("SHA1",6,30,1));
        var envelope=protector.Protect(RandomNumberGenerator.GetBytes(20),context);
        envelope=changed switch {
            "account"=>envelope with {Context=context with {AccountId=Guid.NewGuid()}},
            "enrollment"=>envelope with {Context=context with {EnrollmentId=Guid.NewGuid()}},
            "algorithm"=>envelope with {Context=context with {Parameters=context.Parameters with {HashAlgorithm="SHA256"}}},
            "digits"=>envelope with {Context=context with {Parameters=context.Parameters with {Digits=8}}},
            "period"=>envelope with {Context=context with {Parameters=context.Parameters with {PeriodSeconds=60}}},
            "skew"=>envelope with {Context=context with {Parameters=context.Parameters with {AllowedClockSkewSteps=0}}},
            "key-id"=>envelope with {KeyId="alias"}, _=>envelope };
        if(changed=="nonce") envelope.Nonce[0]^=1;
        if(changed=="tag") envelope.Tag[0]^=1;
        if(changed=="ciphertext") envelope.Ciphertext[0]^=1;
        Should.Throw<CryptographicException>(()=>protector.Unprotect(envelope));
    }
    [Fact]
    public void Retained_key_ring_reads_both_keys_and_missing_old_key_requires_recovery()
    {
        var settings=Settings("old"); var protector=new TotpSecretProtector(Options.Create(settings));
        byte[] secret=RandomNumberGenerator.GetBytes(20);
        var context=new TotpEnrollmentContext(Guid.NewGuid(),Guid.NewGuid(),new("SHA1",6,30,1));
        var old=protector.Protect(secret,context);settings.ProtectionKeys["new"]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));settings.ActiveProtectionKeyId="new";
        var current=protector.Protect(secret,context);current.KeyId.ShouldBe("new");
        protector.Unprotect(old).ShouldBe(secret);protector.Unprotect(current).ShouldBe(secret);
        settings.ActiveProtectionKeyId="old";protector.Unprotect(current).ShouldBe(secret); // Roll back active writer while retaining both keys.
        settings.ProtectionKeys.Remove("old");Should.Throw<InvalidOperationException>(()=>protector.Unprotect(old));
    }
    [Theory, InlineData(false), InlineData(true)]
    public void Published_sample_key_is_rejected_even_with_base64_whitespace(bool whitespace)
    {
        string key=Convert.ToBase64String("0123456789abcdef0123456789abcdef"u8);
        if(whitespace) key=key.Insert(8," \n");
        var settings=Settings("old");settings.ProtectionKeys["old"]=key;
        Validator.TryValidateObject(settings,new ValidationContext(settings),new List<ValidationResult>(),true).ShouldBeFalse();
        var protector=new TotpSecretProtector(Options.Create(settings));
        Should.Throw<InvalidOperationException>(()=>protector.Protect(RandomNumberGenerator.GetBytes(20),new(Guid.NewGuid(),Guid.NewGuid(),new("SHA1",6,30,1))));
    }
    [Fact]
    public void Unconfigured_key_ring_and_legacy_envelope_fail_closed()
    {
        var settings=new TotpSettings();Validator.TryValidateObject(settings,new ValidationContext(settings),new List<ValidationResult>(),true).ShouldBeFalse();
        settings=Settings("old");var protector=new TotpSecretProtector(Options.Create(settings));
        var envelope=protector.Protect(RandomNumberGenerator.GetBytes(20),new(Guid.NewGuid(),Guid.NewGuid(),new("SHA1",6,30,1)));
        Should.Throw<InvalidOperationException>(()=>protector.Unprotect(envelope with {Version=1}));
    }
    [Theory, InlineData(30,60,false), InlineData(60,30,false), InlineData(30,60,true), InlineData(60,30,true)]
    public async Task Login_and_reset_use_enrollment_parameters_after_configuration_changes(int enrolledPeriod,int newPeriod,bool reset)
    {
        var settings=Settings("old"); settings.PeriodSeconds=enrolledPeriod;
        var context=new TotpEnrollmentContext(Guid.NewGuid(),Guid.NewGuid(),TotpParameters.FromDefaults(settings));
        var protector=new TotpSecretProtector(Options.Create(settings));byte[] secret=RandomNumberGenerator.GetBytes(20);
        var envelope=protector.Protect(secret,context);
        var enrollment=new VerifiedTotpEnrollmentRecord(context.AccountId,1,3,1,null,null,envelope.Ciphertext,envelope.Nonce,envelope.Tag,2,null,envelope.KeyId,context,1);
        var repo=Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(context.AccountId,Arg.Any<Instant>(),Arg.Any<CancellationToken>()).Returns(enrollment);
        repo.MarkTotpStepUsedAsync(context.AccountId,1,Arg.Any<long>(),context.EnrollmentId,Arg.Any<CancellationToken>()).Returns(new TotpStepReplayCommandResult(true,"TOTP_STEP_ACCEPTED"));
        settings.PeriodSeconds=newPeriod;settings.Digits=8;settings.HashAlgorithm="SHA512";
        Instant now=SystemClock.Instance.GetCurrentInstant();
        string code=TotpCodeVerifier.ComputeCode(secret,now.ToUnixTimeSeconds()/enrolledPeriod,6,"SHA1");
        if(reset) (await new PasswordResetTotpVerifier(repo,protector,new TotpCodeVerifier(),NullLogger<PasswordResetTotpVerifier>.Instance)
            .VerifyTotpForPasswordReset(context.AccountId,code,CancellationToken.None)).Verified.ShouldBeTrue();
        else (await new AuthenticatorAppLoginVerifier(repo,protector,new TotpCodeVerifier(),NullLogger<AuthenticatorAppLoginVerifier>.Instance)
            .VerifyForLoginAsync(context.AccountId,code,now)).Verified.ShouldBeTrue();
        await repo.Received(1).MarkTotpStepUsedAsync(context.AccountId,1,Arg.Any<long>(),context.EnrollmentId,Arg.Any<CancellationToken>());
    }
    private static TotpSettings Settings(string id)=>new(){ActiveProtectionKeyId=id,ProtectionKeys=new(){{id,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
}
