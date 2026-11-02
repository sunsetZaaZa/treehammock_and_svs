using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class EmailTemplateSettings
{
    [Required]
    public string AccountVerify { get; set; } = string.Empty;

    [Required]
    public string AccountVerifyResend { get; set; } = string.Empty;

    [Required]
    public string AccountEmailChangeVerify { get; set; } = string.Empty;

    [Required]
    public string AccountDeleteVerify { get; set; } = string.Empty;

    [Required]
    public string AccountUnlock { get; set; } = string.Empty;

    [Required]
    public string TwoFactorSetup { get; set; } = string.Empty;

    [Required]
    public string TwoFactorKeyOutbound { get; set; } = string.Empty;

    [Required]
    public string TwoFactorDelete { get; set; } = string.Empty;

    [Required]
    public string PasswordResetCode { get; set; } = string.Empty;

    [Required]
    public string PasswordResetSmsCode { get; set; } = string.Empty;

    // Browser-facing account verification result pages. Optional so existing deployments
    // keep using controller fallbacks until templates are copied into place.
    public string AccountVerificationSuccessPage { get; set; } = string.Empty;
    public string AccountVerificationFailurePage { get; set; } = string.Empty;
    public string AccountVerificationExpiredPage { get; set; } = string.Empty;
    public string AccountVerificationAlreadyVerifiedPage { get; set; } = string.Empty;

    // Legacy names kept so older configuration files bind without breaking while the callers migrate.
    public string SMSTwoFactorSetup { get; set; } = string.Empty;
    public string SMSTwoFactorRemove { get; set; } = string.Empty;
}
