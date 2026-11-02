using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class EmailSubjectSettings
{
    [Required]
    public string AccountVerify { get; set; } = "Verify your Treehammock account";

    [Required]
    public string AccountVerifyResend { get; set; } = "Verify your Treehammock account";

    [Required]
    public string AccountEmailChangeVerify { get; set; } = "Verify your new email address";

    [Required]
    public string AccountDeleteVerify { get; set; } = "Confirm account deletion";

    [Required]
    public string AccountUnlock { get; set; } = "Unlock your Treehammock account";

    [Required]
    public string TwoFactorSetup { get; set; } = "Confirm two-factor setup";

    [Required]
    public string TwoFactorKeyOutbound { get; set; } = "Your Treehammock two-factor code";

    [Required]
    public string TwoFactorDelete { get; set; } = "Confirm two-factor removal";

    [Required]
    public string ActivationCode { get; set; } = "Your Treehammock activation code";

    [Required]
    public string PasswordResetCode { get; set; } = "Your Treehammock password reset code";
}
