using Shouldly;

using treehammock.Repos;

namespace treehammock.Tests.Unit;

public class AccountRepoBooleanContractTests
{
    [Theory]
    [MemberData(nameof(BooleanResultCases))]
    public void Boolean_procedure_contract_maps_rows_and_values_to_success_result(bool hasRow, object? value, bool expected)
    {
        AccountRepo.ReadBooleanContractResult(hasRow, value).ShouldBe(expected);
    }

    [Theory]
    [MemberData(nameof(BooleanValueCases))]
    public void Boolean_values_are_read_consistently_from_supported_database_shapes(object? value, bool expected)
    {
        AccountRepo.ReadBooleanValue(value).ShouldBe(expected);
    }

    [Theory]
    [InlineData("setup_account_email", "accountId,emailAddress,webKey,hashedPassword,saltOne,siv,nonce,country,verifyKeyHash,createdOn,verificationExpiration", "select * from setup_account_email(@accountId, @emailAddress, @webKey, @hashedPassword, @saltOne, @siv, @nonce, @country, @verifyKeyHash, @createdOn, @verificationExpiration);")]
    [InlineData("setup_account_both", "accountId,username,emailAddress,webKey,hashedPassword,saltOne,siv,nonce,country,verifyKeyHash,createdOn,verificationExpiration", "select * from setup_account_both(@accountId, @username, @emailAddress, @webKey, @hashedPassword, @saltOne, @siv, @nonce, @country, @verifyKeyHash, @createdOn, @verificationExpiration);")]
    [InlineData("start_verify_account", "accountGuid,verificationIndex", "select * from start_verify_account(@accountGuid, @verificationIndex);")]
    [InlineData("resend_verify_account", "emailAddress,verifyKeyHash,verificationExpiration", "select * from resend_verify_account(@emailAddress, @verifyKeyHash, @verificationExpiration);")]
    [InlineData("verify_account_for_use", "verifyKeyHash", "select * from verify_account_for_use(@verifyKeyHash);")]
    [InlineData("complete_verify_account", "accountId,verifyKeyHash,proofVersion,accountSecurityStamp", "select * from complete_verify_account(@accountId, @verifyKeyHash, @proofVersion, @accountSecurityStamp);")]
    [InlineData("expire_verify_account", "accountId,verifyKeyHash,proofVersion,accountSecurityStamp", "select * from expire_verify_account(@accountId, @verifyKeyHash, @proofVersion, @accountSecurityStamp);")]
    [InlineData("set_account_lockout", "accountGuid,expiration", "select * from set_account_lockout(@accountGuid, @expiration);")]
    [InlineData("remove_account_lockout", "accountGuid", "select * from remove_account_lockout(@accountGuid);")]
    [InlineData("set_account_login_failures", "accountGuid,failures", "select * from set_account_login_failures(@accountGuid, @failures);")]
    [InlineData("successful_login", "accountId,accountSecurityStamp", "select * from successful_login(@accountId, @accountSecurityStamp);")]
    [InlineData("rotate_account_security_stamp", "accountId", "select * from rotate_account_security_stamp(@accountId);")]
    [InlineData("begin_twofactor_setup", "accountId,accountSecurityStamp,method,tokenHash,createdOn,expiration,emailAddress,phoneNumber,phoneCountryCode,authId,required", "select * from begin_twofactor_setup(@accountId, @accountSecurityStamp, @method, @tokenHash, @createdOn, @expiration, @emailAddress, @phoneNumber, @phoneCountryCode, @authId, @required);")]
    [InlineData("cancel_twofactor_setup", "accountId,accountSecurityStamp,method,tokenHash", "select * from cancel_twofactor_setup(@accountId, @accountSecurityStamp, @method, @tokenHash);")]
    [InlineData("verify_twofactor_setup", "accountId,accountSecurityStamp,method,tokenHash,maxAttempts,now,requestId,requestVersion,familyId", "select * from verify_twofactor_setup(@accountId, @accountSecurityStamp, @method, @tokenHash, @maxAttempts, @now, @requestId, @requestVersion, @familyId);")]
    [InlineData("edit_account_username", "accountId,accountSecurityStamp,username", "select * from edit_account_username(@accountId, @accountSecurityStamp, @username);")]
    [InlineData("request_account_email_change", "accountId,accountSecurityStamp,newEmailAddress,verifyKeyHash,expiration", "select * from request_account_email_change(@accountId, @accountSecurityStamp, @newEmailAddress, @verifyKeyHash, @expiration);")]
    [InlineData("cancel_account_email_change_request", "accountId,accountSecurityStamp,verifyKeyHash", "select * from cancel_account_email_change_request(@accountId, @accountSecurityStamp, @verifyKeyHash);")]
    [InlineData("complete_account_email_change", "verifyKeyHash", "select * from complete_account_email_change(@verifyKeyHash);")]
    [InlineData("purge_expired_account_email_change_requests", "moment", "select * from purge_expired_account_email_change_requests(@moment);")]
    [InlineData("request_account_delete", "accountId,accountSecurityStamp,passPhraseHash,deleteTokenHash,expiration,requestCooldown,requestWindow,maxRequestsPerWindow", "select * from request_account_delete(@accountId, @accountSecurityStamp, @passPhraseHash, @deleteTokenHash, @expiration, @requestCooldown, @requestWindow, @maxRequestsPerWindow);")]
    [InlineData("cancel_account_delete_request", "accountId,accountSecurityStamp,deleteTokenHash", "select * from cancel_account_delete_request(@accountId, @accountSecurityStamp, @deleteTokenHash);")]
    [InlineData("verify_account_delete_token", "deleteTokenHash", "select * from verify_account_delete_token(@deleteTokenHash);")]
    [InlineData("prepare_account_delete_finalize", "accountId,accountSecurityStamp,deleteTokenHash,maxFailedFinalizeAttempts,finalizeLockout,sessionHash", "select * from prepare_account_delete_finalize(@accountId, @accountSecurityStamp, @deleteTokenHash, @maxFailedFinalizeAttempts, @finalizeLockout, @sessionHash);")]
    [InlineData("commit_account_delete_finalize", "accountId,accountSecurityStamp,deleteTokenHash,passPhraseSatisfied,maxFailedFinalizeAttempts,finalizeLockout,requestId,expectedPassPhraseHash,sessionHash", "select * from commit_account_delete_finalize(@accountId, @accountSecurityStamp, @deleteTokenHash, @passPhraseSatisfied, @maxFailedFinalizeAttempts, @finalizeLockout, @requestId, @expectedPassPhraseHash, @sessionHash);")]
    [InlineData("purge_expired_delete_standby", "moment", "select * from purge_expired_delete_standby(@moment);")]
    [InlineData("check_account_emailaddress_creds", "emailAddress", "select * from check_account_emailaddress_creds(@emailAddress);")]
    [InlineData("check_account_username_creds", "username", "select * from check_account_username_creds(@username);")]
    [InlineData("check_account_both_creds", "username,emailAddress", "select * from check_account_both_creds(@username, @emailAddress);")]
    [InlineData("get_current_active_session_hash", "accountId", "select * from get_current_active_session_hash(@accountId);")]
    [InlineData("get_twofactor_details", "accountId", "select * from get_twofactor_details(@accountId);")]
    [InlineData("view_account", "accountId,accountSecurityStamp", "select * from view_account(@accountId, @accountSecurityStamp);")]
    [InlineData("lookup_locked_recovery_account", "identifier,now", "select * from lookup_locked_recovery_account(@identifier, @now);")]
    [InlineData("start_unlock_account", "accountId,tokenHash,createdOn,expiration,status,method,accountSecurityStamp,lockoutUnlockWhen,lockoutAttemptVersion", "select * from start_unlock_account(@accountId, @tokenHash, @createdOn, @expiration, @status, @method, @accountSecurityStamp, @lockoutUnlockWhen, @lockoutAttemptVersion);")]
    [InlineData("cancel_unlock_account", "accountId,tokenHash", "select * from cancel_unlock_account(@accountId, @tokenHash);")]
    [InlineData("verify_unlock_account", "tokenHash", "select * from verify_unlock_account(@tokenHash);")]
    [InlineData("place_activation", "accountId,accountSecurityStamp,emailAddress,code,createdOn,term,interval,closeOff,featureSet,platformBacker,platformText,status,delayedStart", "select * from place_activation(@accountId, @accountSecurityStamp, @emailAddress, @code, @createdOn, @term, @interval, @closeOff, @featureSet, @platformBacker, @platformText, @status, @delayedStart);")]
    [InlineData("disable_activation", "accountId,accountSecurityStamp,emailAddress,createdOn,closeOff,status", "select * from disable_activation(@accountId, @accountSecurityStamp, @emailAddress, @createdOn, @closeOff, @status);")]
    [InlineData("verify_activation", "accountId,accountSecurityStamp,emailAddress,code,createdOn,position,upperLimit", "select * from verify_activation(@accountId, @accountSecurityStamp, @emailAddress, @code, @createdOn, @position, @upperLimit);")]
    [InlineData("cancel_activation_request", "accountId,accountSecurityStamp,code,cancelledOn", "select * from cancel_activation_request(@accountId, @accountSecurityStamp, @code, @cancelledOn);")]
    public void Repository_function_commands_use_select_shape_for_result_rows(
        string functionName,
        string commaSeparatedParameterNames,
        string expected)
    {
        string[] parameterNames = commaSeparatedParameterNames
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        RepositoryCommands.BuildFunctionSelect(functionName, parameterNames).ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("successful-login")]
    [InlineData("public.successful_login")]
    public void Repository_function_commands_reject_unsafe_identifiers(string functionName)
    {
        Should.Throw<ArgumentException>(() => RepositoryCommands.BuildFunctionSelect(functionName, "accountId"));
    }

    public static TheoryData<bool, object?, bool> BooleanResultCases()
    {
        return new TheoryData<bool, object?, bool>
        {
            { false, true, false },
            { false, false, false },
            { false, null, false },
            { true, true, true },
            { true, false, false },
            { true, DBNull.Value, false },
            { true, 1, true },
            { true, 0, false },
        };
    }

    public static TheoryData<object?, bool> BooleanValueCases()
    {
        return new TheoryData<object?, bool>
        {
            { null, false },
            { DBNull.Value, false },
            { true, true },
            { false, false },
            { (short)1, true },
            { (short)0, false },
            { 1, true },
            { 0, false },
            { 1L, true },
            { 0L, false },
        };
    }
}
