using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;

namespace treehammock.Models.PasswordReset;

public static class PasswordResetDeliveryChannels
{
    public const string Email = "email";
    public const string Sms = "sms";
    public const string SupportedDeliveryChannelsDescription = "email or sms";

    private static readonly HashSet<string> SupportedDeliveryChannels = new(StringComparer.Ordinal)
    {
        Email,
        Sms
    };

    public static string Normalize(string? deliveryChannel)
    {
        return deliveryChannel?.Trim().ToLowerInvariant() ?? string.Empty;
    }

    public static bool IsSupported(string? deliveryChannel)
    {
        return SupportedDeliveryChannels.Contains(Normalize(deliveryChannel));
    }
}

public sealed class RequestPasswordResetRequest
{
    public const int MaxIdentifierLength = 1024;
    public const int MaxDeliveryChannelLength = 32;

    [SetsRequiredMembers]
    public RequestPasswordResetRequest()
    {
        identifier = string.Empty;
        deliveryChannel = string.Empty;
    }

    [SetsRequiredMembers]
    public RequestPasswordResetRequest(string identifier, string deliveryChannel)
    {
        this.identifier = identifier;
        this.deliveryChannel = deliveryChannel;
    }

    public required string identifier { get; set; } = string.Empty;
    public required string deliveryChannel { get; set; } = string.Empty;
    public string? captchaToken { get; set; }
    public string? captchaContinuation { get; set; }
}

public sealed class FinalizePasswordResetRequest
{
    public const int MaxKeyCodeLength = 64;
    public const int MaxTotpCodeLength = 16;
    public const int MaxPasswordLength = 512;
    public const int MaxResetAccessTokenLength = 2048;

    [SetsRequiredMembers]
    public FinalizePasswordResetRequest()
    {
        password = string.Empty;
        verifyPassword = string.Empty;
    }

    [SetsRequiredMembers]
    public FinalizePasswordResetRequest(
        Guid resetId,
        string? keyCode,
        string? totpCode,
        string password,
        string verifyPassword,
        string? resetAccessToken = null)
    {
        this.resetId = resetId;
        this.keyCode = keyCode;
        this.totpCode = totpCode;
        this.password = password;
        this.verifyPassword = verifyPassword;
        this.resetAccessToken = resetAccessToken;
    }

    public Guid resetId { get; set; }
    public string? keyCode { get; set; }
    public string? totpCode { get; set; }
    public string? resetAccessToken { get; set; }
    public required string password { get; set; } = string.Empty;
    public required string verifyPassword { get; set; } = string.Empty;
}

public sealed class VerifyPasswordResetTokenRequest
{
    public const int MaxKeyCodeLength = 64;

    [SetsRequiredMembers]
    public VerifyPasswordResetTokenRequest()
    {
    }

    [SetsRequiredMembers]
    public VerifyPasswordResetTokenRequest(Guid resetId, string keyCode)
    {
        this.resetId = resetId;
        this.keyCode = keyCode;
    }

    public required Guid resetId { get; set; }
    public required string keyCode { get; set; } = string.Empty;
}

public sealed class PasswordResetRequestResponse
{
    public const string GenericAcceptedMessage = "If the account can use this reset delivery channel, continue with the required reset proof.";

    [SetsRequiredMembers]
    public PasswordResetRequestResponse(string status, Guid resetId, string message)
    {
        this.status = status;
        this.resetId = resetId;
        this.message = message;
    }

    public required string status { get; set; }
    public required Guid resetId { get; set; }
    public required string message { get; set; }
    public treehammock.Services.PasswordResetCaptchaChallenge? captchaChallenge { get; set; }
}

public sealed class VerifyPasswordResetTokenResponse
{
    [SetsRequiredMembers]
    public VerifyPasswordResetTokenResponse(
        string status,
        string? resetAccessToken,
        bool requiresTwoFactor,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations,
        Instant? expiresAt)
    {
        this.status = status;
        this.resetAccessToken = resetAccessToken;
        this.requiresTwoFactor = requiresTwoFactor;
        this.availableTwoFactorAuthConfigurations = availableTwoFactorAuthConfigurations ?? [];
        this.expiresAt = expiresAt;
    }

    public required string status { get; set; }
    public string? resetAccessToken { get; set; }
    public required bool requiresTwoFactor { get; set; }
    public required List<TwoFactorAuthConfiguration> availableTwoFactorAuthConfigurations { get; set; } = [];
    public Instant? expiresAt { get; set; }
}

public sealed class SelectPasswordResetTwoFactorConfigurationRequest
{
    public const int MaxResetAccessTokenLength = 2048;

    [SetsRequiredMembers]
    public SelectPasswordResetTwoFactorConfigurationRequest()
    {
        resetAccessToken = string.Empty;
        configuration = TwoFactorAuthConfiguration.NONE;
        destination = null;
    }

    [SetsRequiredMembers]
    public SelectPasswordResetTwoFactorConfigurationRequest(
        string resetAccessToken,
        TwoFactorAuthConfiguration configuration,
        short? destination = null)
    {
        this.resetAccessToken = resetAccessToken;
        this.configuration = configuration;
        this.destination = destination;
    }

    public required string resetAccessToken { get; set; } = string.Empty;
    public required TwoFactorAuthConfiguration configuration { get; set; } = TwoFactorAuthConfiguration.NONE;
    public short? destination { get; set; }
}

public sealed class SelectPasswordResetTwoFactorConfigurationResponse
{
    [SetsRequiredMembers]
    public SelectPasswordResetTwoFactorConfigurationResponse(
        string status,
        string? resetAccessToken,
        TwoFactorAuthConfiguration? selectedConfiguration,
        TwoFactorAuthMethod? currentRequiredMethod,
        Instant? challengeExpiration,
        List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods,
        List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations,
        Instant? expiresAt,
        bool canChangePassword)
    {
        this.status = status;
        this.resetAccessToken = resetAccessToken;
        this.selectedConfiguration = selectedConfiguration;
        this.currentRequiredMethod = currentRequiredMethod;
        this.challengeExpiration = challengeExpiration;
        this.completedTwoFactorAuthMethods = completedTwoFactorAuthMethods ?? [];
        this.remainingTwoFactorAuthMethods = remainingTwoFactorAuthMethods ?? [];
        this.availableTwoFactorAuthConfigurations = availableTwoFactorAuthConfigurations ?? [];
        this.expiresAt = expiresAt;
        this.canChangePassword = canChangePassword;
    }

    public required string status { get; set; }
    public string? resetAccessToken { get; set; }
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }
    public TwoFactorAuthMethod? currentRequiredMethod { get; set; }
    public Instant? challengeExpiration { get; set; }
    public required List<TwoFactorAuthMethod> completedTwoFactorAuthMethods { get; set; } = [];
    public required List<TwoFactorAuthMethod> remainingTwoFactorAuthMethods { get; set; } = [];
    public required List<TwoFactorAuthConfiguration> availableTwoFactorAuthConfigurations { get; set; } = [];
    public Instant? expiresAt { get; set; }
    public required bool canChangePassword { get; set; }
}


public sealed class VerifyPasswordResetTwoFactorRequest
{
    public const int MaxResetAccessTokenLength = 2048;
    public const int MaxCodeLength = 64;

    [SetsRequiredMembers]
    public VerifyPasswordResetTwoFactorRequest()
    {
        resetAccessToken = string.Empty;
        method = TwoFactorAuthMethod.NONE;
        code = string.Empty;
    }

    [SetsRequiredMembers]
    public VerifyPasswordResetTwoFactorRequest(
        string resetAccessToken,
        TwoFactorAuthMethod method,
        string code)
    {
        this.resetAccessToken = resetAccessToken;
        this.method = method;
        this.code = code;
    }

    public required string resetAccessToken { get; set; } = string.Empty;
    public required TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;
    public required string code { get; set; } = string.Empty;
}

public sealed class VerifyPasswordResetTwoFactorResponse
{
    [SetsRequiredMembers]
    public VerifyPasswordResetTwoFactorResponse(
        string status,
        string? resetAccessToken,
        TwoFactorAuthConfiguration? selectedConfiguration,
        TwoFactorAuthMethod? currentRequiredMethod,
        List<TwoFactorAuthMethod>? completedTwoFactorAuthMethods,
        List<TwoFactorAuthMethod>? remainingTwoFactorAuthMethods,
        Instant? expiresAt,
        bool canChangePassword)
    {
        this.status = status;
        this.resetAccessToken = resetAccessToken;
        this.selectedConfiguration = selectedConfiguration;
        this.currentRequiredMethod = currentRequiredMethod;
        this.completedTwoFactorAuthMethods = completedTwoFactorAuthMethods ?? [];
        this.remainingTwoFactorAuthMethods = remainingTwoFactorAuthMethods ?? [];
        this.expiresAt = expiresAt;
        this.canChangePassword = canChangePassword;
    }

    public required string status { get; set; }
    public string? resetAccessToken { get; set; }
    public TwoFactorAuthConfiguration? selectedConfiguration { get; set; }
    public TwoFactorAuthMethod? currentRequiredMethod { get; set; }
    public required List<TwoFactorAuthMethod> completedTwoFactorAuthMethods { get; set; } = [];
    public required List<TwoFactorAuthMethod> remainingTwoFactorAuthMethods { get; set; } = [];
    public Instant? expiresAt { get; set; }
    public required bool canChangePassword { get; set; }
}

public sealed class FinalizePasswordResetResponse
{
    [SetsRequiredMembers]
    public FinalizePasswordResetResponse(string status)
    {
        this.status = status;
    }

    public required string status { get; set; }
}

public sealed record RequestPasswordResetCommand(
    string Identifier,
    string DeliveryChannel,
    string? RequestIpAddress,
    string? UserAgent,
    string? CaptchaToken = null,
    string? CaptchaContinuation = null);

public sealed record VerifyPasswordResetTokenCommand(
    Guid ResetId,
    string KeyCode,
    string? RequestIpAddress,
    string? UserAgent);

public sealed record SelectPasswordResetTwoFactorConfigurationCommand(
    string ResetAccessToken,
    TwoFactorAuthConfiguration Configuration,
    short? Destination,
    string? RequestIpAddress,
    string? UserAgent);


public sealed record VerifyPasswordResetTwoFactorCommand(
    string ResetAccessToken,
    TwoFactorAuthMethod Method,
    string Code,
    string? RequestIpAddress,
    string? UserAgent);

public sealed record FinalizePasswordResetCommand(
    Guid ResetId,
    string? KeyCode,
    string? TotpCode,
    string Password,
    string VerifyPassword,
    string? RequestIpAddress,
    string? UserAgent,
    string? ResetAccessToken = null);
