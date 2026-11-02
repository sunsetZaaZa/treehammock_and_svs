using treehammock.Rigging.Delivery;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using Microsoft.Extensions.Options;

namespace treehammock.Services;

public interface ITwoFactorAuthenticateService
{
    Task<bool> Email(string emailAddress, string codeKey, Guid? accountId = null, CancellationToken token = default);
    Task<bool?> SMS(string phonenumber, string codeKey, Guid? accountId = null, CancellationToken token = default);
}

public class TwoFactorAuthenticateService : ITwoFactorAuthenticateService
{
    private readonly ISMTPService _smtpService;
    private readonly DeliveryExecutionPolicy _execution;
    private readonly ISmsSender _smsSender;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;

    public TwoFactorAuthenticateService(
        ISMTPService smtpService,
        ISmsSender smsSender,
        IOptions<EmailSubjectSettings>? emailSubjectSettings = null,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null, DeliveryExecutionPolicy? execution = null)
    {
        _smtpService = smtpService;
        _execution = execution ?? DeliveryExecutionPolicy.Default;
        _smsSender = smsSender;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
    }


    public Task<bool> Email(string emailAddress,string codeKey,Guid? accountId=null,CancellationToken token=default)
        => _execution.RunAsync(token,budget=>EmailCore(emailAddress,codeKey,accountId,budget.Token),()=>false,()=>throw new DeliveryAcceptanceUnknownException());
    private async Task<bool> EmailCore(string emailAddress, string codeKey, Guid? accountId = null, CancellationToken token = default)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle;
        try {throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest, token);}
        catch(OperationCanceledException) when(token.IsCancellationRequested){return false;}
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool? sent = await _smtpService.TwoFactorKeyOutboundLetter(emailAddress, _emailSubjectSettings.TwoFactorKeyOutbound, codeKey, token);
            if (sent is null) throw new treehammock.Rigging.Delivery.DeliveryAcceptanceUnknownException();
            if (sent != true)
            {
                await RecordFailureAsync(throttleRequest, token);
            }

            return sent == true;
        }
        catch
        {
            await RecordFailureAsync(throttleRequest, token);
            throw;
        }
    }



    public Task<bool?> SMS(string phonenumber,string codeKey,Guid? accountId=null,CancellationToken token=default)
        => _execution.RunAsync<bool?>(token,budget=>SmsCore(phonenumber,codeKey,accountId,budget.Token),()=>false,()=>throw new DeliveryAcceptanceUnknownException());
    private async Task<bool?> SmsCore(string phonenumber, string codeKey, Guid? accountId = null, CancellationToken token = default)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "sms", accountId, DeliveryAbuseThrottleService.SafeDestination("sms", phonenumber));
        AbuseDecision throttle;
        try {throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest, token);}
        catch(OperationCanceledException) when(token.IsCancellationRequested){return false;}
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool sent = _smsSender is ISystemTestPurposeAwareSmsSender systemTestSender
                ? await systemTestSender.SendCode(phonenumber, codeKey, "two_factor_login", token)
                : await _smsSender.SendCode(phonenumber, codeKey, token);
            if (!sent)
            {
                await RecordFailureAsync(throttleRequest, token);
            }

            return sent;
        }
        catch
        {
            await RecordFailureAsync(throttleRequest, token);
            throw;
        }
    }


    private async Task RecordFailureAsync(DeliveryAbuseThrottleRequest request,CancellationToken token)
    {
        // Diagnostic counting cannot turn a known provider outcome into another delivery outcome.
        try {await _deliveryAbuseThrottleService.RecordProviderFailureAsync(request,token);}catch { }
    }

}
