using treehammock.Tests.System.Support;
using System.Net;
using System.Text.Json;

using Shouldly;

namespace treehammock.Tests.System;

public sealed class SystemStackHealthTests
{
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(90);

    [Fact]
    public async Task HAProxy_liveness_endpoint_returns_live_status()
    {
        using HttpClient client = CreateClient();
        using HttpResponseMessage response = await RetryUntilSuccessAsync(client, "/health/live", TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        document.RootElement.GetProperty("status").GetString().ShouldBe("live");
    }

    [Fact]
    public async Task HAProxy_readiness_endpoint_verifies_backend_postgresql_and_dragonfly()
    {
        using HttpClient client = CreateClient();
        using HttpResponseMessage response = await RetryUntilSuccessAsync(client, "/health/ready", TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        JsonElement root = document.RootElement;
        root.GetProperty("status").GetString().ShouldBe("ready");

        Dictionary<string, string> dependencies = root
            .GetProperty("dependencies")
            .EnumerateArray()
            .ToDictionary(
                dependency => dependency.GetProperty("name").GetString() ?? string.Empty,
                dependency => dependency.GetProperty("status").GetString() ?? string.Empty,
                StringComparer.OrdinalIgnoreCase);

        dependencies["postgresql"].ShouldBe("healthy");
        dependencies["dragonfly_active_sessions"].ShouldBe("healthy");
        dependencies["dragonfly_two_factor_sessions"].ShouldBe("healthy");
        dependencies["dragonfly_abuse_counters"].ShouldBe("healthy");
    }

    private static HttpClient CreateClient()
    {
        string baseUrl = TreehammockEnvironment.GetValue("TREEHAMMOCK_SYSTEM_BASE_URL", "http://haproxy:8080");
        return new HttpClient { BaseAddress = new Uri(baseUrl, UriKind.Absolute) };
    }

    private static async Task<HttpResponseMessage> RetryUntilSuccessAsync(
        HttpClient client,
        string requestUri,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.Add(ReadyTimeout);
        Exception? lastException = null;
        HttpStatusCode? lastStatusCode = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                HttpResponseMessage response = await client.GetAsync(requestUri, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }

                lastStatusCode = response.StatusCode;
                response.Dispose();
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastException = ex;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }

        string reason = lastStatusCode is not null
            ? $"Last status code was {(int)lastStatusCode.Value} ({lastStatusCode.Value})."
            : $"Last exception was {lastException?.GetType().Name}: {lastException?.Message}";
        throw new TimeoutException($"Timed out waiting for {requestUri} to become healthy. {reason}", lastException);
    }
}
