using treehammock.Rigging.Hosting;
using treehammock.Services.SystemTesting;

namespace treehammock.Services;

public interface ISystemTestPurposeAwareSmsSender
{
    Task<bool> SendCode(string phoneNumber, string codeKey, string purpose, CancellationToken token = default);
}

public sealed class SystemTestSmsSender : ISmsSender, ISystemTestPurposeAwareSmsSender
{
    private readonly ISystemTestDeliveryCapture _capture;

    public SystemTestSmsSender(ISystemTestDeliveryCapture capture, SystemTestCapability capability)
    {
        capability.RequireCapture();
        _capture = capture;
    }

    public async Task<treehammock.Rigging.Sidewalk.ProviderDeliveryResult> SendDurable(Guid jobId,treehammock.Rigging.Delivery.DeliveryPayload payload,CancellationToken token)
    {
        string? destination=NormalizeTestPhoneNumber(payload.Destination);
        if(destination is null)return treehammock.Rigging.Sidewalk.ProviderDeliveryResult.InvalidRequest("system-test","INVALID_DESTINATION");
        string purpose=payload.Kind switch {"factor"=>"two_factor_setup","unlock"=>"account_unlock","reset"=>"password_reset",_=>"sms_code"};
        await _capture.CaptureSms(purpose,destination,payload.Value,payload.Value,token: token);
        return treehammock.Rigging.Sidewalk.ProviderDeliveryResult.Sent("system-test",jobId.ToString("D"));
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey, CancellationToken token = default)
    {
        return await SendCode(phoneNumber, codeKey, "sms_code", token);
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey, string purpose, CancellationToken token = default)
    {
        string? destination = NormalizeTestPhoneNumber(phoneNumber);
        if (destination is null)
        {
            return false;
        }

        await _capture.CaptureSms(purpose, destination, $"Your Treehammock security code is {codeKey}.", codeKey, token: token);
        return true;
    }

    public async Task<bool> SendMessage(string phoneNumber, string messageBody, CancellationToken token = default)
    {
        string? destination = NormalizeTestPhoneNumber(phoneNumber);
        if (destination is null)
        {
            return false;
        }

        await _capture.CaptureSms(InferPurpose(messageBody), destination, messageBody, token: token);
        return true;
    }

    private static string? NormalizeTestPhoneNumber(string phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return null;
        }

        string trimmed = phoneNumber.Trim();
        if (trimmed.StartsWith('+'))
        {
            return trimmed;
        }

        return trimmed.StartsWith("1", StringComparison.Ordinal)
            ? $"+{trimmed}"
            : $"+1{trimmed}";
    }

    private static string InferPurpose(string messageBody)
    {
        if (messageBody.Contains("password reset", StringComparison.OrdinalIgnoreCase))
        {
            return "password_reset";
        }

        if (messageBody.Contains("unlock", StringComparison.OrdinalIgnoreCase))
        {
            return "account_unlock";
        }

        return "sms_message";
    }
}
