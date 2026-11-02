using Shouldly;

using treehammock.Repos;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class SessionRepoBooleanContractTests
{
    [Theory]
    [InlineData("get_session", "accessTokenHash", "select * from get_session(@accessTokenHash);")]
    [InlineData("set_session", "accessTokenHash,accountId,refreshToken,refreshes,limit,createdOn,sessionLifespan,accessExpiration,sessionExpiration,cutOff,features,securityStamp,accountSecurityStamp", "select * from set_session(@accessTokenHash, @accountId, @refreshToken, @refreshes, @limit, @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);")]
    [InlineData("expire_session", "accessTokenHash,expiration", "select * from expire_session(@accessTokenHash, @expiration);")]
    [InlineData("revoke_session", "accessTokenHash", "select * from revoke_session(@accessTokenHash);")]
    [InlineData("rotate_active_session", "accountId,expectedOldAccessTokenHash,newAccessTokenHash,refreshToken,refreshes,limit,createdOn,sessionLifespan,accessExpiration,sessionExpiration,cutOff,features,securityStamp,accountSecurityStamp", "select * from rotate_active_session(@accountId, @expectedOldAccessTokenHash, @newAccessTokenHash, @refreshToken, @refreshes, @limit, @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);")]
    [InlineData("validate_cached_session_trust", "accessTokenHash,accountId,securityStamp,accountSecurityStamp", "select * from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);")]
    [InlineData("logout_current_session", "accountId,accessTokenHash,accountSecurityStamp", "select * from logout_current_session(@accountId, @accessTokenHash, @accountSecurityStamp);")]
    [InlineData("logout_all_sessions", "accountId,accountSecurityStamp", "select * from logout_all_sessions(@accountId, @accountSecurityStamp);")]
    [InlineData("list_active_sessions", "accountId,accountSecurityStamp,currentAccessTokenHash", "select * from list_active_sessions(@accountId, @accountSecurityStamp, @currentAccessTokenHash);")]
    [InlineData("revoke_session_for_account", "accountId,targetSessionId,accountSecurityStamp,currentAccessTokenHash", "select * from revoke_session_for_account(@accountId, @targetSessionId, @accountSecurityStamp, @currentAccessTokenHash);")]
    public void Session_repository_commands_use_function_result_contract(
        string functionName,
        string commaSeparatedParameterNames,
        string expected)
    {
        string[] parameterNames = commaSeparatedParameterNames
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        RepositoryCommands.BuildFunctionSelect(functionName, parameterNames).ShouldBe(expected);
    }

    [Theory]
    [InlineData((short)1, SessionRotationStatus.Succeeded)]
    [InlineData((short)2, SessionRotationStatus.OldSessionMismatch)]
    [InlineData((short)3, SessionRotationStatus.NewSessionConflict)]
    [InlineData((short)4, SessionRotationStatus.Failed)]
    [InlineData((short)99, SessionRotationStatus.Failed)]
    [InlineData(null, SessionRotationStatus.Failed)]
    public void Session_rotation_status_maps_database_values_to_typed_status(short? databaseValue, SessionRotationStatus expected)
    {
        object? value = databaseValue.HasValue ? databaseValue.Value : null;

        SessionRepo.ReadSessionRotationStatus(value).ShouldBe(expected);
    }


    [Theory]
    [InlineData((short)1, CachedSessionTrustStatus.Valid)]
    [InlineData((short)2, CachedSessionTrustStatus.SessionNotFound)]
    [InlineData((short)3, CachedSessionTrustStatus.AccountNotFound)]
    [InlineData((short)4, CachedSessionTrustStatus.SecurityStampMismatch)]
    [InlineData((short)5, CachedSessionTrustStatus.SessionExpired)]
    [InlineData((short)6, CachedSessionTrustStatus.AccountSecurityStampMismatch)]
    [InlineData((short)99, CachedSessionTrustStatus.Failed)]
    [InlineData(null, CachedSessionTrustStatus.Failed)]
    public void Cached_session_trust_status_maps_database_values_to_typed_status(short? databaseValue, CachedSessionTrustStatus expected)
    {
        object? value = databaseValue.HasValue ? databaseValue.Value : null;

        SessionRepo.ReadCachedSessionTrustStatus(value).ShouldBe(expected);
    }


    [Fact]
    public void Session_repository_exposes_logout_contracts()
    {
        typeof(ISessionRepo).GetMethod(nameof(ISessionRepo.LogoutCurrentSession)).ShouldNotBeNull();
        typeof(ISessionRepo).GetMethod(nameof(ISessionRepo.LogoutAllSessions)).ShouldNotBeNull();
        typeof(ISessionRepo).GetMethod(nameof(ISessionRepo.ListActiveSessions)).ShouldNotBeNull();
        typeof(ISessionRepo).GetMethod(nameof(ISessionRepo.RevokeSessionForAccount)).ShouldNotBeNull();

        SessionRepo.LogoutCurrentSessionProcedure.ShouldBe("logout_current_session");
        SessionRepo.LogoutAllSessionsProcedure.ShouldBe("logout_all_sessions");
        SessionRepo.ListActiveSessionsProcedure.ShouldBe("list_active_sessions");
        SessionRepo.RevokeSessionForAccountProcedure.ShouldBe("revoke_session_for_account");
    }

    [Fact]
    public void Logout_result_records_preserve_database_codes()
    {
        var commandResult = new DbCommandResult(true, "CURRENT_SESSION_LOGGED_OUT");
        commandResult.Result.ShouldBeTrue();
        commandResult.Code.ShouldBe("CURRENT_SESSION_LOGGED_OUT");

        Guid newStamp = Guid.NewGuid();
        var rotationResult = new AccountStampRotationResult(true, "ALL_SESSIONS_LOGGED_OUT", newStamp);
        rotationResult.Result.ShouldBeTrue();
        rotationResult.Code.ShouldBe("ALL_SESSIONS_LOGGED_OUT");
        rotationResult.AccountSecurityStamp.ShouldBe(newStamp);
    }

}
