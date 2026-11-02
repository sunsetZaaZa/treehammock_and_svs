namespace treehammock.Entities;

using NodaTime;
using Newtonsoft.Json;
using System.Diagnostics.CodeAnalysis;
using treehammock.RiggingSupport.Enum;

public class Account
{
    [SetsRequiredMembers]
    public Account(Guid accountId, string emailAddress, string? username, byte[] hashedPassword, Instant createdOn, string webKey, VerificationStatus verifyStatus)
    {
        (this.accountId, this.emailAddress, this.username, this.hashedPassword, this.createdOn, this.webKey, this.verifyStatus) = 
        (accountId, emailAddress, username, hashedPassword, createdOn, webKey, verifyStatus);
        (this.saltOne, this.siv, this.nonce) = (Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>());
    }

    [SetsRequiredMembers]
    public Account(Guid accountId, string emailAddress, string? username, byte[] hashedPassword, Instant createdOn, string webKey, VerificationStatus verifyStatus,
                    byte[] saltOne, byte[] siv, byte[] nonce, Instant? unlockWhen, short loginFailures, short? twoAuthUsage, Country country, 
                    Instant? cutOff, AccountLockDown? lockedDown)
    {
        (this.accountId, this.emailAddress, this.username, this.hashedPassword, this.createdOn, this.webKey, this.verifyStatus, this.saltOne, this.siv, this.nonce, 
            this.unlockWhen, this.loginFailures, this.twoAuthUsage, this.country, this.cutOff, this.lockedDown) =
        (accountId, emailAddress, username, hashedPassword, createdOn, webKey, verifyStatus, saltOne, siv, nonce, unlockWhen, loginFailures,
            twoAuthUsage, country, cutOff, lockedDown);
    }

    [JsonIgnore]
    public required Guid accountId { get; set; }
    [JsonIgnore]
    public required string emailAddress { get; set; }
    [JsonIgnore]
    public string? username { get; set; }
    [JsonIgnore]
    public required byte[] hashedPassword { get; set; }
    [JsonIgnore]
    public required Instant createdOn { get; set; }
    [JsonIgnore]
    public required string webKey { get; set; }
    [JsonIgnore]
    public required VerificationStatus verifyStatus { get; set; }
    [JsonIgnore]
    public byte[] saltOne { get; set; }
    [JsonIgnore]
    public byte[] siv { get; set; }
    [JsonIgnore]
    public byte[] nonce { get; set; }
    [JsonIgnore]
    public Instant? unlockWhen { get; set; }
    [JsonIgnore]
    public short loginFailures { get; set; }
    [JsonIgnore]
    public string? twoFactorAccessToken { get; set; }
    [JsonIgnore]
    public short? twoAuthUsage { get; set; }
    [JsonIgnore]
    public Country country { get; set; }
    [JsonIgnore]
    public Instant? cutOff { get; set; }
    [JsonIgnore]
    public AccountLockDown? lockedDown { get; set; }
}