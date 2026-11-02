using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Integration;

public partial class AccountFlowRegressionTests
{
    [Fact]
    public async Task Harness_normal_exit_stops_and_disposes_owned_host_once_after_client_scope()
    {
        var probe = new FlowLifetimeProbe();
        await using (LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL], probe.Register))
        {
            using HttpClient client = CreateHttpsClient(harness.Factory);
            using HttpResponseMessage response = await client.GetAsync("/account/view");
            response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
            probe.Starts.ShouldBe(1);
            probe.Stops.ShouldBe(0);
            probe.Disposals.ShouldBe(0);
        }
        probe.AssertStoppedExactlyOnce();
    }

    [Fact]
    public async Task Harness_exception_after_start_retains_original_error_and_disposes_host_once()
    {
        var probe = new FlowLifetimeProbe();
        var original = new InvalidOperationException("Intentional flow lifecycle failure.");
        InvalidOperationException observed = await Should.ThrowAsync<InvalidOperationException>(async () =>
        {
            await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL], probe.Register);
            using HttpClient client = CreateHttpsClient(harness.Factory);
            using HttpResponseMessage response = await client.GetAsync("/account/view");
            probe.Starts.ShouldBe(1);
            throw original;
        });
        observed.ShouldBeSameAs(original);
        probe.AssertStoppedExactlyOnce();
    }

    [Fact]
    public async Task Harness_without_started_factory_disposes_once_without_creating_host_services()
    {
        var probe = new FlowLifetimeProbe();
        LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL], probe.Register);
        Task first = harness.DisposeAsync().AsTask();
        Task second = harness.DisposeAsync().AsTask();
        await Task.WhenAll(first, second);
        first.ShouldBeSameAs(second);
        probe.Attachments.ShouldBe(0);
        probe.Starts.ShouldBe(0);
        probe.Stops.ShouldBe(0);
        probe.Disposals.ShouldBe(0);
        Should.Throw<ObjectDisposedException>(() => { _ = harness.Factory; });
    }

    [Fact]
    public async Task Harness_repeated_normal_and_exceptional_exits_leave_no_live_probe_in_one_process()
    {
        var probes = new List<FlowLifetimeProbe>();
        for (int iteration = 0; iteration < 12; iteration++)
        {
            var probe = new FlowLifetimeProbe();
            probes.Add(probe);
            if (iteration % 2 == 0)
            {
                await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL], probe.Register);
                using (HttpClient client = CreateHttpsClient(harness.Factory))
                {
                    using HttpResponseMessage response = await client.GetAsync("/account/view");
                    response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
                }
                // Concurrent/repeated cleanup callers share the same disposal operation.
                Task first = harness.DisposeAsync().AsTask();
                Task second = harness.DisposeAsync().AsTask();
                await Task.WhenAll(first, second);
                first.ShouldBeSameAs(second);
            }
            else
            {
                var original = new InvalidOperationException("Intentional repeated flow failure.");
                InvalidOperationException observed = await Should.ThrowAsync<InvalidOperationException>(async () =>
                {
                    await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL], probe.Register);
                    using HttpClient client = CreateHttpsClient(harness.Factory);
                    using HttpResponseMessage response = await client.GetAsync("/account/view");
                    throw original;
                });
                observed.ShouldBeSameAs(original);
            }
            probe.AssertStoppedExactlyOnce();
            probes.Count(value => value.Starts != value.Stops || value.Attachments != value.Disposals).ShouldBe(0);
        }
        probes.Count.ShouldBe(12);
    }

    private sealed class FlowLifetimeProbe : IHostedService, IDisposable, IAsyncDisposable
    {
        private int _attachments, _starts, _stops, _disposals, _stopping, _stopped;
        private CancellationTokenRegistration _stoppingRegistration, _stoppedRegistration;
        public int Attachments => Volatile.Read(ref _attachments);
        public int Starts => Volatile.Read(ref _starts);
        public int Stops => Volatile.Read(ref _stops);
        public int Disposals => Volatile.Read(ref _disposals);

        public void Register(IServiceCollection services)
        {
            // Factory registration makes DI own this instance; instance registration would not dispose it.
            // One service descriptor also avoids capturing the same disposable through two call sites.
            services.AddSingleton<IHostedService>(provider =>
            {
                Interlocked.Increment(ref _attachments);
                IHostApplicationLifetime lifetime = provider.GetRequiredService<IHostApplicationLifetime>();
                _stoppingRegistration = lifetime.ApplicationStopping.Register(() => Interlocked.Increment(ref _stopping));
                _stoppedRegistration = lifetime.ApplicationStopped.Register(() => Interlocked.Increment(ref _stopped));
                return this;
            });
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _starts);
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _stops);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            // Count every provider disposal call rather than masking duplicate disposal.
            Interlocked.Increment(ref _disposals);
            _stoppingRegistration.Dispose();
            _stoppedRegistration.Dispose();
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        public void AssertStoppedExactlyOnce()
        {
            Attachments.ShouldBe(1);
            Starts.ShouldBe(1);
            Stops.ShouldBe(1);
            Volatile.Read(ref _stopping).ShouldBe(1);
            Volatile.Read(ref _stopped).ShouldBe(1);
            Disposals.ShouldBe(1);
        }
    }
}
