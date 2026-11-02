using treehammock.Rigging.Delivery;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;

using treehammock.Rigging.Config;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Authentication;

namespace treehammock.Services;

public interface ISMTPService
{
    Task<DeliverySendResult> SendDurable(Guid attemptId,DeliveryPayload payload,CancellationToken token);
    Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default);
    Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default);
    Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default);
    Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence, CancellationToken token = default);
    Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken, CancellationToken token = default);
    Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default);
    Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default);
    Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default);
    Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked, CancellationToken token = default);
    Task<bool?> Send(string userEmailAddress, string subject, string body, CancellationToken token = default);
}

public class SMTPService : ISMTPService
{
    private readonly SmtpTransportPolicy _transport;
    private readonly ISmtpClientFactory _clientFactory;
    private readonly ILogger<SMTPService> _logger;
    private readonly DeliveryExecutionPolicy _execution;
    private readonly IProviderHealthService _health;

    private readonly string _verificationTemplate;
    private readonly string _verificationResendTemplate;
    private readonly string _emailChangeVerifyTemplate;
    private readonly string _accountDeleteVerifyTemplate;
    private readonly string _accountUnlockTemplate;
    private readonly string _twoFactorSetupTemplate;
    private readonly string _twoFactorKeyOutboundTemplate;
    private readonly string _twoFactorDeleteTemplate;
    private readonly string _passwordResetCodeTemplate;

    public SMTPService(
        IOptions<SMTPSettings> smtpSettings,
        IOptions<EmailTemplateSettings> emailTemplateSettings,
        ILogger<SMTPService> logger,
        SmtpTransportPolicy? transport = null,
        ISmtpClientFactory? clientFactory = null,
        DeliveryExecutionPolicy? execution = null, IProviderHealthService? health = null)
    {
        _transport = transport ?? new SmtpTransportPolicy(smtpSettings.Value, null);
        _clientFactory = clientFactory ?? new SmtpClientFactory();
        _execution = execution ?? DeliveryExecutionPolicy.Default;
        _health = health ?? NullProviderHealthService.Instance;
        _logger = logger;
        var templates = emailTemplateSettings.Value;

        _verificationTemplate = LoadTemplate(templates.AccountVerify, "<p>Verify your account: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _verificationResendTemplate = LoadTemplate(templates.AccountVerifyResend, "<p>Verify your account: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _emailChangeVerifyTemplate = LoadTemplate(templates.AccountEmailChangeVerify, "<p>Confirm your new email address: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _accountDeleteVerifyTemplate = LoadTemplate(templates.AccountDeleteVerify, "<p>Confirm account deletion: <a href='%verifyUrl'>%verifyUrl</a></p><p>Verification code: %verifySequence</p>");
        _accountUnlockTemplate = LoadTemplate(templates.AccountUnlock, "<p>Your account unlock code is: %verifySequence</p>");
        _twoFactorSetupTemplate = LoadTemplate(templates.TwoFactorSetup, "<p>Confirm two-factor setup: %verifySequence</p>");
        _twoFactorKeyOutboundTemplate = LoadTemplate(templates.TwoFactorKeyOutbound, "<p>Your two-factor code is: %verifySequence</p>");
        _twoFactorDeleteTemplate = LoadTemplate(templates.TwoFactorDelete, "<p>Confirm two-factor removal: %verifySequence</p>");
        _passwordResetCodeTemplate = LoadTemplate(templates.PasswordResetCode, "<p>Your password reset code is: %verifySequence</p><p>It expires at %expiresAt.</p><p>Do not share this code.</p>");
    }

    private static string ApplyVerificationTemplate(string template, string verificationUrl)
    {
        return template
            .Replace("%verifyUrl", verificationUrl)
            .Replace("%verifySequence", verificationUrl);
    }

    private static string ApplySequenceTemplate(string template, string verifySequence)
    {
        return template.Replace("%verifySequence", verifySequence);
    }

    private static string ApplyDeleteVerifyTemplate(string template, string verificationUrl, string verifySequence)
    {
        return template
            .Replace("%verifyUrl", verificationUrl)
            .Replace("%verifySequence", verifySequence);
    }

    private static string ApplyPasswordResetTemplate(string template, string keyCode, string expiresAt, string destinationMasked)
    {
        return template
            .Replace("%verifySequence", keyCode)
            .Replace("%keyCode", keyCode)
            .Replace("%expiresAt", expiresAt)
            .Replace("%destinationMasked", destinationMasked);
    }

    private static string LoadTemplate(string configuredPath, string fallback)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return fallback;
        }

        string rootedPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.Combine(AppContext.BaseDirectory, configuredPath);

        if (!File.Exists(rootedPath))
        {
            rootedPath = Path.Combine(Directory.GetCurrentDirectory(), configuredPath);
        }

        return File.Exists(rootedPath)
            ? File.ReadAllText(rootedPath)
            : fallback;
    }

    private async Task<bool?> SendTemplatedMessage(string userEmailAddress, string subject, string body, string emailKind, Guid? jobId = null, CancellationToken token = default)
    {
        var result = await SendTransportMessage(userEmailAddress,subject,body,emailKind,jobId,token);
        return result.State == DeliverySendState.Unknown ? null : result.State == DeliverySendState.Accepted;
    }

    private Task<DeliverySendResult> SendTransportMessage(string userEmailAddress,string subject,string body,string emailKind,Guid? jobId=null,CancellationToken token=default)
        => _execution.RunAsync(token,async budget =>
        {
            using var attempt=await budget.BeginAttemptAsync(token);
            if(attempt is null)return new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_NOT_STARTED",Provider:"smtp");
            var permit=await _health.AcquireAsync(DeliveryRoute.Smtp,attempt.Token);
            if(!permit.Allowed)return new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_HEALTH_BLOCKED",true,"smtp");
            if(!await budget.CheckAuthorityAsync())
            {
                await _health.CompleteAsync(permit,ProviderHealthEvidence.Neutral,attempt.Token);
                return new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_NOT_STARTED",Provider:"smtp");
            }
            DeliverySendResult result;
            try {result=await SendTransportCore(userEmailAddress,subject,body,emailKind,jobId,attempt.Token);}
            catch {result=new(DeliverySendState.NotSubmitted,"DELIVERY_INVALID_PAYLOAD",Provider:"smtp");}
            await _health.CompleteAsync(permit,result.Health,attempt.Token);
            return result;
        },()=>new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_NOT_STARTED",Provider:"smtp"),
          ()=>new DeliverySendResult(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN",Provider:"smtp"));

    private async Task<DeliverySendResult> SendTransportCore(string userEmailAddress, string subject, string body, string emailKind, Guid? jobId = null, CancellationToken token = default)
    {
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(_transport.Sender));
        email.To.Add(MailboxAddress.Parse(userEmailAddress));
        email.Subject = subject;
        if(jobId is Guid id)email.MessageId=$"{id:N}@treehammock.delivery";
        email.Body = new TextPart(TextFormat.Html) { Text = body };

        using var smtp = _clientFactory.Create();
        bool submissionStarted = false;
        try
        {
            token.ThrowIfCancellationRequested();
            await smtp.ConnectAsync(_transport.Host, _transport.Port, _transport.SocketOptions,token);
            if (_transport.RequireEncryption && (!smtp.IsSecure || smtp.SslProtocol is not (SslProtocols.Tls12 or SslProtocols.Tls13)))
                throw new System.Security.Authentication.AuthenticationException("Required SMTP TLS was not established.");
            await smtp.AuthenticateAsync(_transport.Username, _transport.Password,token);
            token.ThrowIfCancellationRequested();
            submissionStarted = true;
            await smtp.SendAsync(email,token);
            // The provider accepted DATA. A disconnect failure cannot undo acceptance.
            try { await smtp.DisconnectAsync(true,token); } catch { }
            return new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED",Provider:"smtp",ReceiptId:jobId?.ToString("N"),Health:ProviderHealthEvidence.Healthy);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "SMTP delivery failed for {EmailKind} email to {RecipientDomain}; error {ErrorType}.",
                emailKind,
                GetRecipientDomain(userEmailAddress),ex.GetType().Name);
            var health=!token.IsCancellationRequested && (ex is System.Net.Sockets.SocketException || ex is IOException || ex is SmtpCommandException service && (int)service.StatusCode==421)
                ? ProviderHealthEvidence.Outage : ProviderHealthEvidence.Neutral;
            if (!submissionStarted) return new(DeliverySendState.NotSubmitted,"DELIVERY_NOT_SUBMITTED",Provider:"smtp",Health:health);
            if (ex is SmtpCommandException command && command.ErrorCode is SmtpErrorCode.SenderNotAccepted or SmtpErrorCode.RecipientNotAccepted or SmtpErrorCode.MessageNotAccepted)
                return (int)command.StatusCode is >=400 and <500
                    ? new(DeliverySendState.NotSubmitted,"DELIVERY_TEMPORARILY_REJECTED",true,"smtp",Health:health)
                    : new(DeliverySendState.Rejected,"DELIVERY_REJECTED",Provider:"smtp",Health:health);
            return new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN",Provider:"smtp",Health:health);
        }
    }

    private static string GetRecipientDomain(string userEmailAddress)
    {
        int atIndex = userEmailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < userEmailAddress.Length - 1
            ? userEmailAddress[(atIndex + 1)..]
            : "unknown";
    }

    public Task<DeliverySendResult> SendDurable(Guid jobId,DeliveryPayload p,CancellationToken token)
    {
        if(p.Kind=="email-change-notice" && (p.Channel!="email" || string.IsNullOrWhiteSpace(p.Destination) || string.IsNullOrWhiteSpace(p.Value)))
            throw new InvalidOperationException("Invalid email notification payload");
        string body=p.Kind switch
        {
            "verify-start"=>ApplyVerificationTemplate(_verificationTemplate,p.Value),
            "verify"=>ApplyVerificationTemplate(_verificationResendTemplate,p.Value),
            "email"=>ApplyVerificationTemplate(_emailChangeVerifyTemplate,p.Value),
            "email-change-notice"=>$"<p>{System.Net.WebUtility.HtmlEncode(p.Value)}</p>",
            "delete"=>ApplyDeleteVerifyTemplate(_accountDeleteVerifyTemplate,p.Value,p.Secondary!),
            "unlock"=>ApplySequenceTemplate(_accountUnlockTemplate,p.Value),
            "activation-code"=>$"<p>Your Treehammock activation code is:</p><p><strong>{System.Net.WebUtility.HtmlEncode(p.Value)}</strong></p>",
            "factor"=>ApplySequenceTemplate(_twoFactorSetupTemplate,p.Value),
            "reset"=>ApplyPasswordResetTemplate(_passwordResetCodeTemplate,p.Value,p.Secondary!,p.MaskedDestination!),
            _=>throw new InvalidOperationException("Unsupported delivery kind")
        };
        return SendTransportMessage(p.Destination,p.Subject,body,p.Kind,jobId,token);
    }

    public async Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_verificationTemplate, verificationUrl),
            nameof(VerificationLetter), token: token);
    }

    public async Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_verificationResendTemplate, verificationUrl),
            nameof(ResendVerifyLetter), token: token);
    }

    public async Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_emailChangeVerifyTemplate, verificationUrl),
            nameof(EmailChangeVerifyLetter), token: token);
    }

    public async Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyDeleteVerifyTemplate(_accountDeleteVerifyTemplate, verificationUrl, verifySequence),
            nameof(DeleteAccountTwoStepLetter), token: token);
    }

    public async Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_accountUnlockTemplate, unlockToken),
            nameof(AccountUnlockLetter), token: token);
    }

    public async Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorSetupTemplate, verifyKey),
            nameof(TwoFactorSetupLetter), token: token);
    }

    public async Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorKeyOutboundTemplate, verifyKey),
            nameof(TwoFactorKeyOutboundLetter), token: token);
    }

    public async Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorDeleteTemplate, verifyKey),
            nameof(TwoFactorDeleteLetter), token: token);
    }

    public async Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked, CancellationToken token = default)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyPasswordResetTemplate(_passwordResetCodeTemplate, keyCode, expiresAt, destinationMasked),
            nameof(PasswordResetCodeLetter), token: token);
    }

    public async Task<bool?> Send(string userEmailAddress, string subject, string body, CancellationToken token = default)
    {
        return await SendTemplatedMessage(userEmailAddress, subject, body, nameof(Send), token: token);
    }
}
