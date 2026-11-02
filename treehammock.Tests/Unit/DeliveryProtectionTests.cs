using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class Cor12DeliveryProtectionTests
{
    [Theory]
    [InlineData(false,false)]
    [InlineData(true,false)]
    [InlineData(true,true)]
    public void Companion_envelopes_share_one_bounded_deadline_with_independent_authenticated_identity(bool clipped,bool earlierCompanion)
    {
        var now=SystemClock.Instance.GetCurrentInstant();var requested=now.Plus(clipped?Duration.FromDays(2):Duration.FromMinutes(15));
        var companionDeadline=earlierCompanion?now.Plus(Duration.FromMinutes(2)):requested;
        var settings=new DeliveryOutboxSettings {PayloadRetentionHours=1,EncryptionKeys=new(){{1,Convert.ToBase64String(new byte[32])}}};
        var protector=new DeliveryPayloadProtector(Options.Create(settings));Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();
        var notice=new DeliveryIntent(account,stamp,"email-notice","hash",companionDeadline,new{originEmail="old@example.test",requestProofHash="hash"},new("email-change-notice","email","old@example.test","notice","owner notice"));
        var intent=new DeliveryIntent(account,stamp,"email","hash",requested,new{newEmailAddress="new@example.test"},new("email","email","new@example.test","verify","new proof"),notice);
        var primary=protector.Protect(intent);var companion=primary.Companion.ShouldNotBeNull();
        primary.ExpiresAt.ShouldBe(companion.ExpiresAt);primary.Id.ShouldNotBe(companion.Id);primary.Nonce.ShouldNotBe(companion.Nonce);
        primary.ExpiresAt.ShouldBeLessThanOrEqualTo(requested);primary.ExpiresAt.ShouldBeLessThanOrEqualTo(companionDeadline);
        primary.ExpiresAt.ShouldBeLessThanOrEqualTo(SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)));
        (primary.ExpiresAt.ToUnixTimeTicks()%10).ShouldBe(0);
        protector.Open(primary).ShouldBe(intent.Payload);protector.Open(companion).ShouldBe(notice.Payload);
        Should.Throw<CryptographicException>(()=>protector.Open(companion with {ExpiresAt=companion.ExpiresAt.Plus(Duration.FromTicks(10))}));
    }

    [Fact]
    public void Encryption_roundtrip_preserves_exact_metadata_and_hides_raw_proof()
    {
        var protector=CapturingDurableDelivery.Protector();
        var intent=new DeliveryIntent(Guid.NewGuid(),Guid.NewGuid(),"email","hashed-proof",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)),new {newEmailAddress="reader@example.test"},new("email","email","reader@example.test","test","raw-secret"));
        var first=protector.Protect(intent);var second=protector.Protect(intent);
        protector.Open(first).ShouldBe(intent.Payload);first.Nonce.ShouldNotBe(second.Nonce);first.Id.ShouldNotBe(second.Id);
        System.Text.Encoding.UTF8.GetString(first.Ciphertext).ShouldNotContain("raw-secret");first.MetadataJson.ShouldNotContain("raw-secret");
    }
    [Theory]
    [InlineData("id")][InlineData("account")][InlineData("stamp")][InlineData("purpose")][InlineData("hash")][InlineData("deadline")][InlineData("metadata")][InlineData("nonce")][InlineData("cipher")][InlineData("tag")]
    public void Envelope_cannot_be_rebound_or_tampered(string field)
    {
        var p=CapturingDurableDelivery.Protector();var d=p.Protect(new(Guid.NewGuid(),Guid.NewGuid(),"verify","hash",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)),new {mode="resend"},new("verify","email","reader@example.test","test","secret")));
        d=field switch {"id"=>d with {Id=Guid.NewGuid()},"account"=>d with {AccountId=Guid.NewGuid()},"stamp"=>d with {AccountStamp=Guid.NewGuid()},"purpose"=>d with {Purpose="delete"},"hash"=>d with {ProofHash="another-hash"},"deadline"=>d with {ExpiresAt=d.ExpiresAt.Plus(Duration.FromSeconds(1))},"metadata"=>d with {MetadataJson=d.MetadataJson+" "},"nonce"=>d with {Nonce=new byte[12]},"cipher"=>d with {Ciphertext=new byte[d.Ciphertext.Length]},_=>d with {Tag=new byte[16]}};
        Should.Throw<CryptographicException>(()=>p.Open(d));
    }
    [Fact]
    public void Rotation_retains_old_key_for_existing_jobs_and_clamps_payload_retention()
    {
        var settings=new DeliveryOutboxSettings {PayloadRetentionHours=1,EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])},{2,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
        var p=new DeliveryPayloadProtector(Options.Create(settings));var d=p.Protect(new(Guid.NewGuid(),Guid.NewGuid(),"verify","hash",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromDays(7)),new {},new("verify","email","reader@example.test","test","secret")));
        d.ExpiresAt.ShouldBeLessThanOrEqualTo(SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)));settings.ActiveKeyVersion=2;p.Open(d).Value.ShouldBe("secret");
        settings.EncryptionKeys.Remove(1);Should.Throw<KeyNotFoundException>(()=>p.Open(d));
    }
}
