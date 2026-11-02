using Shouldly;

using treehammock.Repos;

namespace treehammock.Tests.Unit;

public class AccountRepoVerificationTests
{

    [Fact]
    public void SetupAccount_uses_registration_function_names()
    {
        AccountRepo.SetupAccountEmailFunction.ShouldBe("setup_account_email");
        AccountRepo.SetupAccountBothFunction.ShouldBe("setup_account_both");
        AccountRepo.StartVerifyAccountFunction.ShouldBe("start_verify_account");
        AccountRepo.ResendVerifyAccountFunction.ShouldBe("resend_verify_account");
    }
    [Fact]
    public void VerifyAccountForUse_uses_read_specific_function_name()
    {
        AccountRepo.VerifyAccountForUseProcedure.ShouldBe("verify_account_for_use");
    }

    [Fact]
    public void AccountPassedVerification_uses_complete_specific_function_name()
    {
        AccountRepo.CompleteVerifyAccountProcedure.ShouldBe("complete_verify_account");
    }

    [Fact]
    public void AccountVerificationExpired_uses_expire_specific_function_name()
    {
        AccountRepo.ExpireVerifyAccountProcedure.ShouldBe("expire_verify_account");
    }

    [Fact]
    public void TwoFactorSetup_uses_setup_function_names()
    {
        AccountRepo.BeginTwoFactorSetupFunction.ShouldBe("begin_twofactor_setup");
        AccountRepo.CancelTwoFactorSetupFunction.ShouldBe("cancel_twofactor_setup");
        AccountRepo.VerifyTwoFactorSetupFunction.ShouldBe("verify_twofactor_setup");
        AccountRepo.RemoveTwoFactorMethodFunction.ShouldBe("cor08_authorized_remove_twofactor_method");
    }

    [Fact]
    public void AccountEmailChange_uses_email_change_function_names()
    {
        AccountRepo.RequestAccountEmailChangeFunction.ShouldBe("request_account_email_change");
        AccountRepo.CancelAccountEmailChangeRequestFunction.ShouldBe("cancel_account_email_change_request");
        AccountRepo.CompleteAccountEmailChangeFunction.ShouldBe("complete_account_email_change");
    }

    [Fact]
    public void AccountDelete_uses_delete_function_names()
    {
        AccountRepo.RequestAccountDeleteFunction.ShouldBe("request_account_delete");
        AccountRepo.CancelAccountDeleteRequestFunction.ShouldBe("cancel_account_delete_request");
        AccountRepo.VerifyAccountDeleteTokenFunction.ShouldBe("verify_account_delete_token");
        AccountRepo.PrepareAccountDeleteFinalizeFunction.ShouldBe("prepare_account_delete_finalize");
        AccountRepo.CommitAccountDeleteFinalizeFunction.ShouldBe("commit_account_delete_finalize");
        AccountRepo.PurgeExpiredDeleteStandbyFunction.ShouldBe("purge_expired_delete_standby");
    }

}
