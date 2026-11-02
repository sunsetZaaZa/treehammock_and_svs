using treehammock.Rigging.Delivery;
using Amazon.Runtime;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Rigging.Sidewalk;

public interface IAwsSnsSmsClient
{
    Task<string?> PublishSms(string phoneNumber, string body, CancellationToken cancellationToken = default);
}

public sealed class AwsSnsSmsClient : IAwsSnsSmsClient
{
    public async Task<string?> PublishSms(string phoneNumber, string body, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var client = new AmazonSimpleNotificationServiceClient(new AmazonSimpleNotificationServiceConfig { MaxErrorRetry = 0 });
        var response = await client.PublishAsync(new PublishRequest
        {
            PhoneNumber = phoneNumber,
            Message = body
        }, cancellationToken);

        return response.MessageId;
    }
}

public interface IAWSService
{
    Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey, CancellationToken cancellationToken = default);
    Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default);
}

public class AWSService : IAWSService
{
    private const string ProviderName = "aws-sns";

    private readonly IAwsSnsSmsClient _client;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<AWSService> _logger;

    public AWSService(
        IAwsSnsSmsClient client,
        IOptions<SidewalkSettings> settings,
        ILogger<AWSService>? logger = null)
    {
        _client = client;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<AWSService>.Instance;
    }

    public async Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey, CancellationToken cancellationToken = default)
    {
        return await SendMessage(phoneNumber, $"Your Treehammock security code is {codeKey}.", cancellationToken);
    }

    public async Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody, CancellationToken cancellationToken = default)
    {
        if (!_settings.SmsEnabled || !_settings.AwsSnsEnabled)
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

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? messageId = await _client.PublishSms(
                phoneNumber,
                messageBody, cancellationToken);

            return !Guid.TryParse(messageId,out _)
                ? ProviderDeliveryResult.Unknown(ProviderName, "INVALID_PROVIDER_RECEIPT")
                : ProviderDeliveryResult.Sent(ProviderName, messageId);
        }
        catch (AmazonServiceException ex) when ((int)ex.StatusCode == 429 || ((int)ex.StatusCode == 400 && IsThrottleError(ex.ErrorCode)))
        {
            _logger.LogWarning( "AWS SNS SMS delivery was rate limited by the provider.");
            return ProviderDeliveryResult.RateLimited(ProviderName, "THROTTLED");
        }
        catch (AmazonServiceException ex) when ((int)ex.StatusCode is 400 or 401 or 403 or 404 or 422)
        {
            _logger.LogWarning( "AWS SNS SMS delivery was explicitly rejected by the provider.");
            return ProviderDeliveryResult.Rejected(ProviderName, "REQUEST_REJECTED");
        }
        catch (AmazonServiceException ex)
        {
            _logger.LogWarning( "AWS SNS SMS delivery acceptance is unknown.");
            return ProviderDeliveryResult.Unknown(ProviderName) with {Health=(int)ex.StatusCode>=500?ProviderHealthEvidence.Outage:ProviderHealthEvidence.Neutral};
        }
        catch (System.Net.Http.HttpRequestException) when (!cancellationToken.IsCancellationRequested)
        {
            return ProviderDeliveryResult.Unknown(ProviderName) with {Health=ProviderHealthEvidence.Outage};
        }
        catch (Exception ex)
        {
            _logger.LogWarning( "AWS SNS SMS delivery failed unexpectedly.");
            return ProviderDeliveryResult.Unknown(ProviderName);
        }
    }

    private static bool IsThrottleError(string? errorCode) =>
        errorCode is "Throttling" or "Throttled" or "ThrottlingException" or "ThrottledException";
}
