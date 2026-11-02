using treehammock.Rigging.Hosting;
using treehammock.Services.SystemTesting;

namespace treehammock.Services;

public sealed class SystemTestSmtpService : ISMTPService
{
    private readonly ISystemTestDeliveryCapture _capture;

    public SystemTestSmtpService(ISystemTestDeliveryCapture capture, SystemTestCapability capability)
    {
        capability.RequireCapture();
        _capture = capture;
    }

    public async Task<treehammock.Rigging.Delivery.DeliverySendResult> SendDurable(Guid jobId,treehammock.Rigging.Delivery.DeliveryPayload p,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        bool? accepted = await (p.Kind switch
        {
            "verify-start"=>VerificationLetter(p.Destination,p.Subject,p.Value, token),
            "verify"=>ResendVerifyLetter(p.Destination,p.Subject,p.Value, token),
            "email"=>EmailChangeVerifyLetter(p.Destination,p.Subject,p.Value, token),
            "email-change-notice"=>CaptureDurable("email_change_notice",jobId,p,null,token),
            "activation-code"=>CaptureDurable("activation",jobId,p,p.Value,token),
            "delete"=>DeleteAccountTwoStepLetter(p.Destination,p.Subject,p.Value,p.Secondary!, token),
            "unlock"=>AccountUnlockLetter(p.Destination,p.Subject,p.Value, token),
            "factor"=>TwoFactorSetupLetter(p.Destination,p.Subject,p.Value, token),
            "reset"=>PasswordResetCodeLetter(p.Destination,p.Subject,p.Value,p.Secondary!,p.MaskedDestination!, token),
            _=>throw new InvalidOperationException("Unsupported system-test delivery kind")
        });
        return new(accepted==true?treehammock.Rigging.Delivery.DeliverySendState.Accepted:treehammock.Rigging.Delivery.DeliverySendState.Unknown,"DELIVERY_TEST_CAPTURE",Provider:"system-test",ReceiptId:jobId.ToString("N"));
    }

    private async Task<bool?> CaptureDurable(string purpose, Guid jobId,
        treehammock.Rigging.Delivery.DeliveryPayload payload, string? code, CancellationToken token)
    {
        await _capture.CaptureEmail(purpose, payload.Destination, payload.Subject, payload.Value,
            code, jobId.ToString("N"), token);
        return true;
    }

    public async Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        await _capture.CaptureEmail("account_verify", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl), token: token);
        return true;
    }

    public async Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        await _capture.CaptureEmail("account_verify", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl), token: token);
        return true;
    }

    public async Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        await _capture.CaptureEmail("email_change", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl), token: token);
        return true;
    }

    public async Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence, CancellationToken token = default)
    {
        await _capture.CaptureEmail("account_delete", userEmailAddress, subject, $"Confirm account deletion: {verificationUrl}\nCode: {verifySequence}", verifySequence, token: token);
        return true;
    }

    public async Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken, CancellationToken token = default)
    {
        await _capture.CaptureEmail("account_unlock", userEmailAddress, subject, $"Unlock token: {unlockToken}", unlockToken, token: token);
        return true;
    }

    public async Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        await _capture.CaptureEmail("two_factor_setup", userEmailAddress, subject, $"Two-factor setup code: {verifyKey}", verifyKey, token: token);
        return true;
    }

    public async Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        await _capture.CaptureEmail("two_factor_login", userEmailAddress, subject, $"Two-factor login code: {verifyKey}", verifyKey, token: token);
        return true;
    }

    public async Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        await _capture.CaptureEmail("two_factor_delete", userEmailAddress, subject, $"Two-factor delete code: {verifyKey}", verifyKey, token: token);
        return true;
    }

    public async Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked, CancellationToken token = default)
    {
        await _capture.CaptureEmail("password_reset", userEmailAddress, subject, $"Password reset code: {keyCode}\nExpires at: {expiresAt}\nDestination: {destinationMasked}", keyCode, token: token);
        return true;
    }

    public async Task<bool?> Send(string userEmailAddress, string subject, string body, CancellationToken token = default)
    {
        string purpose = subject.Contains("activation", StringComparison.OrdinalIgnoreCase)
            ? "activation"
            : "email";
        await _capture.CaptureEmail(purpose, userEmailAddress, subject, body, token: token);
        return true;
    }

    private static string BuildVerificationBody(string verificationUrl) => $"Verify account: {verificationUrl}";

    private static string? ExtractVerificationPayload(string verificationUrl)
    {
        int marker = verificationUrl.IndexOf("payload=", StringComparison.OrdinalIgnoreCase);
        if (marker < 0)
        {
            return null;
        }

        string payload = verificationUrl[(marker + "payload=".Length)..];
        int separator = payload.IndexOfAny(new[] { '&', '#', ' ', '\r', '\n' });
        if (separator >= 0)
        {
            payload = payload[..separator];
        }

        return Uri.UnescapeDataString(payload);
    }
}
