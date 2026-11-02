using treehammock.Rigging.Delivery;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;
using treehammock.Rigging.Sidewalk;

namespace treehammock.Services;

public interface ISmsSender
{
    Task<ProviderDeliveryResult> SendDurable(Guid jobId,DeliveryPayload payload,CancellationToken token);
    Task<bool> SendCode(string phoneNumber, string codeKey, CancellationToken cancellationToken = default);
    Task<bool> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default);
}

public class SmsSender : ISmsSender
{
    private readonly IAWSService _awsService;
    private readonly ITwilioSmsService _twilioSmsService;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<SmsSender> _logger;
    private readonly DeliveryExecutionPolicy _execution;
    private readonly IProviderHealthService _health;

    public SmsSender(
        IAWSService awsService,
        ITwilioSmsService twilioSmsService,
        IOptions<SidewalkSettings> settings,
        ILogger<SmsSender>? logger = null, DeliveryExecutionPolicy? execution = null, IProviderHealthService? health = null)
    {
        _awsService = awsService;
        _twilioSmsService = twilioSmsService;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<SmsSender>.Instance;
        _execution = execution ?? DeliveryExecutionPolicy.Default;
        _health = health ?? NullProviderHealthService.Instance;
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey, CancellationToken cancellationToken = default)
    {
        return await Send(phoneNumber, codeKey, sendRawMessage: false, cancellationToken);
    }

    public async Task<bool> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default)
    {
        return await Send(phoneNumber, messageBody, sendRawMessage: true, cancellationToken);
    }

    public Task<ProviderDeliveryResult> SendDurable(Guid jobId,DeliveryPayload payload,CancellationToken token)
    {
        bool raw=payload.Kind=="reset";
        string body=raw?$"Your Treehammock password reset code is {payload.Value}. It expires at {payload.Secondary}. Do not share this code.":payload.Value;
        return SendOutcome(payload.Destination,body,raw,token);
    }
    private Task<ProviderDeliveryResult> SendOutcome(string phoneNumber,string body,bool raw,CancellationToken token)
        => _execution.RunAsync(token,async budget =>
        {
            if(!_settings.SmsEnabled)return ProviderDeliveryResult.Disabled("sms");
            if(string.IsNullOrWhiteSpace(phoneNumber)||string.IsNullOrWhiteSpace(body))return ProviderDeliveryResult.InvalidRequest("sms","INVALID_PAYLOAD");
            ProviderDeliveryResult? last=null;
            foreach(string provider in Providers())
            {
                using var attempt=await budget.BeginAttemptAsync(token);
                if(attempt is null)return last??ProviderDeliveryResult.InvalidRequest("sms","DELIVERY_NOT_STARTED");
                var route=provider==SmsProviderNames.Twilio?DeliveryRoute.Twilio:DeliveryRoute.AwsSns;
                var permit=await _health.AcquireAsync(route,attempt.Token);
                if(!permit.Allowed){last=ProviderDeliveryResult.HealthBlocked(provider);continue;}
                if(!await budget.CheckAuthorityAsync())
                {
                    await _health.CompleteAsync(permit,ProviderHealthEvidence.Neutral,attempt.Token);
                    return ProviderDeliveryResult.InvalidRequest(provider,"DELIVERY_NOT_STARTED");
                }
                ProviderDeliveryResult result;
                try {result=await SendWithProvider(provider,phoneNumber,body,raw,attempt.Token);}
                catch {result=ProviderDeliveryResult.Unknown(provider);}
                await _health.CompleteAsync(permit,result.Health,attempt.Token);
                if(result.Succeeded || !result.CanFallback) return result;
                if(attempt.Token.IsCancellationRequested)return result;
                last=result;
            }
            return last??ProviderDeliveryResult.Disabled("sms");
        },()=>ProviderDeliveryResult.InvalidRequest("sms","DELIVERY_NOT_STARTED"),()=>ProviderDeliveryResult.Unknown("sms"));
    private async Task<bool> Send(string phoneNumber,string bodyOrCode,bool sendRawMessage,CancellationToken cancellationToken=default)
    {
        var result=await SendOutcome(phoneNumber,bodyOrCode,sendRawMessage,cancellationToken);
        if(result.Succeeded)return true;
        if (!result.CanFallback) throw new DeliveryAcceptanceUnknownException();
        return false;
    }

    private async Task<ProviderDeliveryResult> SendWithProvider(string provider, string phoneNumber, string bodyOrCode, bool sendRawMessage, CancellationToken cancellationToken = default)
    {
        try
        {
            return SmsProviderNames.Normalize(provider) switch
            {
                SmsProviderNames.AwsSns => _settings.AwsSnsEnabled
                    ? sendRawMessage
                        ? await _awsService.SendMessage(phoneNumber, bodyOrCode, cancellationToken)
                        : await _awsService.SendSMS(phoneNumber, bodyOrCode, cancellationToken)
                    : ProviderDeliveryResult.Disabled(SmsProviderNames.AwsSns),
                SmsProviderNames.Twilio => _settings.TwilioEnabled
                    ? sendRawMessage
                        ? await _twilioSmsService.SendMessage(phoneNumber, bodyOrCode, cancellationToken)
                        : await _twilioSmsService.SendSMS(phoneNumber, bodyOrCode, cancellationToken)
                    : ProviderDeliveryResult.Disabled(SmsProviderNames.Twilio),
                _ => ProviderDeliveryResult.InvalidRequest(provider, "UNKNOWN_SMS_PROVIDER")
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning( "SMS delivery provider {Provider} failed unexpectedly.", provider);
            return ProviderDeliveryResult.Unknown(provider);
        }
    }

    private IEnumerable<string> Providers()
    {
        foreach (string provider in SmsProviderNames.NormalizeConfiguredProviders(_settings).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            yield return provider;
        }
    }
}

public interface ITwilioMessageClient
{
    Task<ProviderDeliveryResult> SendMessage(
        string accountSid,
        string authToken,
        string fromPhoneNumber,
        string toPhoneNumber,
        string body, CancellationToken cancellationToken = default);
}

public sealed class TwilioMessageClient : ITwilioMessageClient
{
    private const string ProviderName = "twilio";
    private readonly IHttpClientFactory _httpClientFactory;

    public TwilioMessageClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ProviderDeliveryResult> SendMessage(
        string accountSid,
        string authToken,
        string fromPhoneNumber,
        string toPhoneNumber,
        string body, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://api.twilio.com/2010-04-01/Accounts/{Uri.EscapeDataString(accountSid)}/Messages.json");

        string encodedCredentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{accountSid}:{authToken}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", encodedCredentials);
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["From"] = fromPhoneNumber,
            ["To"] = toPhoneNumber,
            ["Body"] = body
        });

        HttpClient httpClient = _httpClientFactory.CreateClient("treehammock-twilio");
        HttpResponseMessage response;
        try { response = await httpClient.SendAsync(request,cancellationToken); }
        catch(HttpRequestException) when(!cancellationToken.IsCancellationRequested) { return ProviderDeliveryResult.Unknown(ProviderName) with {Health=ProviderHealthEvidence.Outage}; }
        catch { return ProviderDeliveryResult.Unknown(ProviderName); }
        using var ownedResponse = response;

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return ProviderDeliveryResult.RateLimited(ProviderName, ((int)response.StatusCode).ToString());
        }

        if ((int)response.StatusCode is 400 or 401 or 403 or 404 or 422)
        {
            return ProviderDeliveryResult.Rejected(ProviderName, ((int)response.StatusCode).ToString());
        }

        if ((int)response.StatusCode >= 500)
        {
            return ProviderDeliveryResult.Unknown(ProviderName, "SERVER_RESPONSE_UNCERTAIN") with {Health=ProviderHealthEvidence.Outage};
        }

        if(response.StatusCode!=HttpStatusCode.Created)return ProviderDeliveryResult.Unknown(ProviderName,"UNEXPECTED_SUCCESS_STATUS");
        string responseBody;
        try { responseBody = await response.Content.ReadAsStringAsync(cancellationToken); }
        catch { return ProviderDeliveryResult.Unknown(ProviderName); }
        string? sid = TryReadSid(responseBody);
        return string.IsNullOrWhiteSpace(sid)
            ? ProviderDeliveryResult.Unknown(ProviderName, "INVALID_PROVIDER_RECEIPT")
            : ProviderDeliveryResult.Sent(ProviderName, sid);
    }

    private static string? TryReadSid(string responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseBody);
            if(document.RootElement.ValueKind!=JsonValueKind.Object || !document.RootElement.TryGetProperty("sid",out var sid) || sid.ValueKind!=JsonValueKind.String)return null;
            string? value=sid.GetString();
            return value is not null && value.Length==34 && System.Text.RegularExpressions.Regex.IsMatch(value,"^SM[0-9a-fA-F]{32}$") ? value : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }


}

public interface ITwilioSmsService
{
    Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey, CancellationToken cancellationToken = default);
    Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default);
}

public class TwilioSmsService : ITwilioSmsService
{
    private const string ProviderName = "twilio";

    private readonly ITwilioMessageClient _client;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<TwilioSmsService> _logger;

    public TwilioSmsService(
        ITwilioMessageClient client,
        IOptions<SidewalkSettings> settings,
        ILogger<TwilioSmsService>? logger = null)
    {
        _client = client;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<TwilioSmsService>.Instance;
    }

    public async Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey, CancellationToken cancellationToken = default)
    {
        return await SendMessage(phoneNumber, $"Your Treehammock security code is {codeKey}.", cancellationToken);
    }

    public async Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default)
    {
        if (!_settings.SmsEnabled || !_settings.TwilioEnabled)
        {
            return ProviderDeliveryResult.Disabled(ProviderName);
        }

        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return ProviderDeliveryResult.InvalidRequest(ProviderName, "PHONE_NUMBER_REQUIRED");
        }

        if (string.IsNullOrWhiteSpace(messageBody))
        {
            return ProviderDeliveryResult.InvalidRequest(ProviderName, "BODY_REQUIRED");
        }

        var invalidSettings=TwilioTransportConfiguration.InvalidSettings(_settings);
        if(invalidSettings.Count!=0)
            return ProviderDeliveryResult.ConfigurationMissing(ProviderName,invalidSettings[0]);

        try
        {
            ProviderDeliveryResult result = await _client.SendMessage(
                _settings.TwilioAccountSid,
                _settings.TwilioAuthToken,
                _settings.TwilioFromPhoneNumber,
                phoneNumber,
                messageBody, cancellationToken);

            if (!result.Succeeded)
            {
                _logger.LogWarning(
                    "Twilio SMS delivery returned a delivery outcome. Status: {Status}; Code: {FailureCode}.",
                    result.Status,
                    result.Outcome.Code);
            }

            return result;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning( "Twilio SMS delivery could not reach the provider.");
            return ProviderDeliveryResult.Unknown(ProviderName);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning( "Twilio SMS delivery timed out.");
            return ProviderDeliveryResult.Unknown(ProviderName, "TIMEOUT");
        }
        catch (Exception ex)
        {
            _logger.LogWarning( "Twilio SMS delivery failed unexpectedly.");
            return ProviderDeliveryResult.Unknown(ProviderName);
        }
    }
}
