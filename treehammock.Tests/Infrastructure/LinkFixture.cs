using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.DataLayer.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Infrastructure;

// Real AccountService producer + real MVC consumers; declared in-memory authority/delivery doubles.
internal sealed class Cor23GLinkFixture
{
    internal readonly Guid AccountId=Guid.NewGuid(),Stamp=Guid.NewGuid();
    internal readonly IAccountRepo Repo=Substitute.For<IAccountRepo>();
    internal readonly CapturingDurableDelivery Delivery=new();
    internal readonly HttpContextAccessor Accessor=new();
    internal int Verified,EmailConfirmed,DeleteVerified;
    internal RegistrationSettings Registration = null!;
    internal Cor23GLinkFixture()
    {
        Delivery.Account=new(AccountId,Stamp,"owner@example.test",2);
        Repo.CheckSignupAvailability(Arg.Any<string>(),Arg.Any<string?>(),Arg.Any<CancellationToken>()).Returns((HttpMessage?)null);
        Repo.SetupAccount(Arg.Any<Account>(),Arg.Any<string>(),Arg.Any<Period>(),Arg.Any<AccountSetupAction>(),Arg.Do<DeliveryIntent>(Delivery.Intents.Add),Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<(long?,HttpMessage,string?)>((1,HttpMessage.ACCOUNT_CREATION_SUCCESSED,null)));
        Repo.ViewAccount(AccountId,Stamp,Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountViewResult?>(new(true,"ACCOUNT_VIEW_SUCCEEDED",new AccountProfile {
            emailAddress="owner@example.test",createdOn=SystemClock.Instance.GetCurrentInstant(),verifyStatus=VerificationStatus.SUCCESSFUL,country=Country.USA,features=FeatureSet.basic,twoFactorEnabled=false })));
        Repo.AdmitAccountDelete(AccountId,Stamp,Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<Period>(),Arg.Any<Period>(),Arg.Any<short>(),Arg.Any<SensitiveActionGrant>(),Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new(true,"ACCOUNT_DELETE_ADMITTED",DeletionWorkflow.ONETIME,"owner@example.test",AccountId)));
        Repo.VerifyAccountForUse(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call=>
        {
            string hash=AccountVerificationTokenUtility.HashToken(call.ArgAt<string>(0));
            return Task.FromResult<AccountVerification?>(Delivery.Intents.Any(i=>i.Purpose=="verify"&&i.ProofHash==hash)
                ? new(AccountId,hash,VerificationStatus.SENT,SystemClock.Instance.GetCurrentInstant(),Period.FromHours(1)){proofVersion=Guid.NewGuid(),accountSecurityStamp=Stamp} : null);
        });
        Repo.AccountPassedVerification(Arg.Any<AccountVerification>(),Arg.Any<CancellationToken>()).Returns(_=> { Interlocked.Increment(ref Verified);return Task.FromResult<bool?>(true); });
        Repo.CompleteEmailChange(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call=>
        {
            bool valid=Delivery.Intents.Any(i=>i.Purpose=="email"&&i.ProofHash==call.ArgAt<string>(0));
            if(valid)Interlocked.Increment(ref EmailConfirmed);
            return Task.FromResult<AccountAdjustResult?>(new(valid,valid?"ACCOUNT_ADJUST_SUCCEEDED":"ACCOUNT_ADJUST_TOKEN_MISMATCH"));
        });
        Repo.VerifyDeleteAccountToken(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call=>
        {
            bool valid=Delivery.Intents.Any(i=>i.Purpose=="delete"&&i.ProofHash==call.ArgAt<string>(0));
            if(valid)Interlocked.Increment(ref DeleteVerified);
            return Task.FromResult<AccountDeleteCommandResult?>(new(valid,valid?"ACCOUNT_DELETE_VERIFIED":"ACCOUNT_DELETE_TOKEN_MISMATCH",DeletionWorkflow.ONETIME));
        });
    }
    internal AccountService Service(string origin)
    {
        var work=Substitute.For<IPasswordWorkService>();work.HashBytesAsync(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(new byte[AccountCryptoSizes.PasswordHashBytes]);
        var admission=Substitute.For<ISignupAdmissionPolicy>();admission.CheckAsync(Arg.Any<string>(),Arg.Any<string?>(),Arg.Any<string?>(),Arg.Any<CancellationToken>()).Returns((HttpMessage?)null);
        Registration = new RegistrationSettings {PublicOrigin=origin,AccountMetaDataRetries=2,VerifyAccountPeriodDays=1};
        return new(Delivery,Repo,Options.Create(new LoginSettings()),Options.Create(Registration),Options.Create(new EmailSubjectSettings {
            AccountVerify="verify",AccountVerifyResend="resend",AccountEmailChangeVerify="change",AccountDeleteVerify="delete" }),Substitute.For<IUserSecretHasher>(),
            abuseControlSettings:Options.Create(new AbuseControlSettings {Enabled=false}),httpContextAccessor:Accessor,passwordWork:work,signupAdmission:admission);
    }
    internal async Task CaptureAsync(AccountService service,CancellationToken token)
    {
        Assert.Equal(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING,await service.SetupUserAccount("new@example.test","new-user","valid-secret",Country.USA,SystemClock.Instance.GetCurrentInstant(),AccountSetupAction.BOTH,token));
        Assert.Equal(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING,await service.ResendAccountVerification("owner@example.test",token));
        var emailGrant=new SensitiveActionGrant("family","grant","target",SensitiveActionTargets.EmailChange("changed@example.test"));
        Assert.True((await service.RequestEmailChange(AccountId,Stamp,"changed@example.test",token,emailGrant))!.Result);
        var deleteGrant=new SensitiveActionGrant("family","grant","target",SensitiveActionTargets.AccountDelete(null));
        Assert.True((await service.RequestAccountDelete(AccountId,Stamp,null,token,deleteGrant))!.Result);
        Assert.Equal(4,Delivery.Intents.Count);
    }
}
