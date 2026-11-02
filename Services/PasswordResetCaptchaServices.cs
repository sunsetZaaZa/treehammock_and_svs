using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;

namespace treehammock.Services;

public interface ICaptchaVerifier
{
    Task<bool> VerifyAsync(string token, string action, string nonce, CancellationToken cancellationToken);
}
public interface ICaptchaContinuationStore
{
    Task<bool> CreateAsync(string nonce, TimeSpan lifetime, CancellationToken cancellationToken);
    Task<bool> ConsumeAsync(string nonce, CancellationToken cancellationToken);
}

public sealed class TurnstileCaptchaVerifier(IHttpClientFactory clients, IOptions<PasswordResetSettings> options) : ICaptchaVerifier
{
    public const string ClientName = "PasswordResetTurnstile";
    public const string Endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    public async Task<bool> VerifyAsync(string token, string action, string nonce, CancellationToken cancellationToken)
    {
        if (token.Length is 0 or > 2048) return false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Value.CaptchaTimeoutMilliseconds);
        try
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["secret"] = options.Value.CaptchaSecretKey, ["response"] = token });
            // No identifier, reset ID, IP, User-Agent or continuation is sent to Siteverify.
            using var response = await clients.CreateClient(ClientName).PostAsync(Endpoint, content, timeout.Token);
            if (!response.IsSuccessStatusCode) return false;
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: timeout.Token);
            var root = json.RootElement;
            return root.GetProperty("success").GetBoolean() && root.GetProperty("action").GetString() == action &&
                root.GetProperty("cdata").GetString() == nonce &&
                options.Value.CaptchaAllowedHostnames.Contains(root.GetProperty("hostname").GetString(), StringComparer.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return false; }
        catch (HttpRequestException) { return false; }
        catch (JsonException) { return false; }
        catch (KeyNotFoundException) { return false; }
        catch (InvalidOperationException) { return false; }
    }
}

public sealed class DragonflyCaptchaContinuationStore(CacheConnectionOwner connections,
    IOptions<AbuseCounterCacheSettings> options) : ICaptchaContinuationStore
{
    // Missing/evicted state denies. Consumed entries retain the original expiry, so replay cannot resurrect authority.
    public static string ConsumeScript => treehammock.Rigging.Abuse.AbuseCounterScripts.CaptchaConsume;
    public async Task<bool> CreateAsync(string nonce, TimeSpan lifetime, CancellationToken cancellationToken)
    {
        try { return await connections.Get(CacheProfile.AbuseCounters).Database.StringSetAsync("reset-captcha:" + nonce, "issued", lifetime, When.NotExists)
                .WaitAsync(TimeSpan.FromMilliseconds(options.Value.asyncTimeoutMilliseconds), cancellationToken); }
        catch (Exception ex) when (Unavailable(ex, cancellationToken)) { return false; }
    }
    public async Task<bool> ConsumeAsync(string nonce, CancellationToken cancellationToken)
    {
        try { return (long)await connections.Get(CacheProfile.AbuseCounters).Database.ScriptEvaluateAsync(ConsumeScript,
                [(RedisKey)("reset-captcha:" + nonce)], []).WaitAsync(TimeSpan.FromMilliseconds(options.Value.asyncTimeoutMilliseconds), cancellationToken) == 1; }
        catch (Exception ex) when (Unavailable(ex, cancellationToken)) { return false; }
    }
    private static bool Unavailable(Exception ex, CancellationToken ct) => ex is RedisException or TimeoutException or
        DependencyUnavailableException or InvalidOperationException || ex is OperationCanceledException && !ct.IsCancellationRequested;
}

// Runs before serving traffic; replacing the verifier/store with a permissive test fake cannot enable CAPTCHA.
public sealed class PasswordResetCaptchaStartupGuard(IOptions<PasswordResetSettings> settings,
    ICaptchaVerifier verifier, ICaptchaContinuationStore store) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (settings.Value.CaptchaChallengeEnabled &&
            (verifier.GetType() != typeof(TurnstileCaptchaVerifier) || store.GetType() != typeof(DragonflyCaptchaContinuationStore)))
            throw new InvalidOperationException("Enabled CAPTCHA requires the production Turnstile adapter and atomic continuation store.");
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
