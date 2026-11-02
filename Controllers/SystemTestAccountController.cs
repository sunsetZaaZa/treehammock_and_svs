using System.Security.Cryptography;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Models.SystemTesting;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Config;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Controllers;

[AllowAnonymous]
[ApiController]
[Route("__system-test/accounts")]
[Produces("application/json")]
public sealed class SystemTestAccountController : ControllerBase
{
    public const string TestKeyHeaderName = SystemTestCapability.TestKeyHeaderName;

    private readonly StorageContext _database;
    private readonly SystemTestCapability _capability;
    private readonly LoginSettings _loginSettings;
    private readonly IPasswordWorkService _passwordWork;

    public SystemTestAccountController(
        StorageContext database,
        SystemTestCapability capability,
        IOptions<LoginSettings> loginSettings, IPasswordWorkService? passwordWork = null)
    {
        _database = database;
        _capability = capability;
        _loginSettings = loginSettings.Value;
        _passwordWork = passwordWork ?? PasswordWorkService.Default(loginSettings);
    }

    [HttpPost("verified")]
    public async Task<IActionResult> SeedVerified([FromBody] SystemTestSeedVerifiedAccountRequest request)
    {
        IActionResult? guard = GuardAccess();
        if (guard is not null)
        {
            return guard;
        }

        if (request is null || string.IsNullOrWhiteSpace(request.emailAddress) || string.IsNullOrWhiteSpace(request.password))
        {
            return BadRequest(new { success = false, code = "SYSTEM_TEST_ACCOUNT_SEED_INVALID" });
        }

        Guid accountId = Guid.NewGuid();
        byte[] transit = RandomNumberGenerator.GetBytes(AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes + AccountCryptoSizes.NonceBytes);
        byte[] webKeyBytes = transit[..AccountCryptoSizes.WebKeyBytes];
        byte[] saltOne = transit[AccountCryptoSizes.WebKeyBytes..(AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes)];
        byte[] siv = transit[(AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes)..(AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes)];
        byte[] nonce = transit[(AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes)..];
        string webKey = AccountVerificationTokenUtility.EncodeBase64Url(webKeyBytes);
        byte[] passwordHash = await _passwordWork.HashBytesAsync(request.password, HttpContext.RequestAborted);

        await using NpgsqlConnection conn = await _database.CreateConnection();
        await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
        await using NpgsqlCommand command = new(@"
insert into accounts(
    account_id,
    email_address,
    username,
    hashed_password,
    created_on,
    web_key,
    verify_status,
    salt_one,
    siv,
    nonce,
    unlock_when,
    login_failures,
    features,
    two_factor_auth_method,
    two_auth_usage,
    country,
    cut_off,
    locked_down)
values(
    @accountId,
    @emailAddress,
    @username,
    @hashedPassword,
    @createdOn,
    @webKey,
    @verifyStatus,
    @saltOne,
    @siv,
    @nonce,
    null,
    0,
    @features,
    @twoFactorAuthMethod,
    null,
    @country,
    null,
    null)
returning security_stamp;", conn, tran);

        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
        command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = request.emailAddress.Trim();
        command.Parameters.Add("@username", NpgsqlDbType.Text).Value = string.IsNullOrWhiteSpace(request.username) ? DBNull.Value : request.username.Trim();
        command.Parameters.Add("@hashedPassword", NpgsqlDbType.Bytea).Value = passwordHash;
        command.Parameters.Add("@createdOn", NpgsqlDbType.TimestampTz).Value = SystemClock.Instance.GetCurrentInstant();
        command.Parameters.Add("@webKey", NpgsqlDbType.Text).Value = webKey;
        command.Parameters.Add("@verifyStatus", NpgsqlDbType.Smallint).Value = (short)VerificationStatus.SUCCESSFUL;
        command.Parameters.Add("@saltOne", NpgsqlDbType.Bytea).Value = saltOne;
        command.Parameters.Add("@siv", NpgsqlDbType.Bytea).Value = siv;
        command.Parameters.Add("@nonce", NpgsqlDbType.Bytea).Value = nonce;
        command.Parameters.Add("@features", NpgsqlDbType.Smallint).Value = (short)FeatureSet.basic;
        command.Parameters.Add("@twoFactorAuthMethod", NpgsqlDbType.Smallint).Value = (short)TwoFactorAuthMethod.NONE;
        command.Parameters.Add("@country", NpgsqlDbType.Smallint).Value = (short)request.country;

        Guid accountSecurityStamp = (Guid)(await command.ExecuteScalarAsync() ?? Guid.Empty);
        await tran.CommitAsync();

        return Ok(new
        {
            success = true,
            code = "SYSTEM_TEST_ACCOUNT_SEEDED",
            data = new SystemTestSeedVerifiedAccountResponse(accountId, accountSecurityStamp, request.emailAddress.Trim(), request.username)
        });
    }

    private IActionResult? GuardAccess()
    {
        if (!_capability.InspectionEnabled) return NotFound();
        return _capability.Authorizes(Request)
            ? null
            : Unauthorized(new { success = false, code = "SYSTEM_TEST_KEY_INVALID" });
    }
}
