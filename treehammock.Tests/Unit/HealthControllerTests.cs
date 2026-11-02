using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Shouldly;

using treehammock.Controllers;
using treehammock.Models.Api;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Health;

namespace treehammock.Tests.Unit;

public class HealthControllerTests
{
    [Fact]
    public void Health_controller_is_public_controller_based_api_surface()
    {
        typeof(HealthController)
            .GetCustomAttributes(typeof(ApiControllerAttribute), inherit: true)
            .ShouldNotBeEmpty();

        typeof(HealthController)
            .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
            .ShouldNotBeEmpty();

        typeof(HealthController)
            .GetCustomAttributes(typeof(Authenticate), inherit: true)
            .ShouldBeEmpty("health checks must remain reachable without an authenticated session");

        RouteAttribute route = typeof(HealthController)
            .GetCustomAttributes(typeof(RouteAttribute), inherit: true)
            .Cast<RouteAttribute>()
            .Single();

        route.Template.ShouldBe("health");
    }

    [Theory]
    [InlineData(nameof(HealthController.Live), "live", false)]
    [InlineData(nameof(HealthController.Ready), "ready", true)]
    [InlineData(nameof(HealthController.Dependencies), "dependencies", true)]
    public void Health_actions_advertise_expected_routes_and_status_codes(string methodName, string routeTemplate, bool dependencyAware)
    {
        var method = typeof(HealthController).GetMethod(methodName);

        method.ShouldNotBeNull();
        HttpGetAttribute get = method!
            .GetCustomAttributes(typeof(HttpGetAttribute), inherit: true)
            .Cast<HttpGetAttribute>()
            .Single();

        get.Template.ShouldBe(routeTemplate);

        var responseTypes = method
            .GetCustomAttributes(typeof(ProducesResponseTypeAttribute), inherit: true)
            .Cast<ProducesResponseTypeAttribute>()
            .ToArray();

        responseTypes.Select(response => response.StatusCode).OrderBy(status => status).ToArray()
            .ShouldBe(dependencyAware
                ? new[] { StatusCodes.Status200OK, StatusCodes.Status503ServiceUnavailable }
                : new[] { StatusCodes.Status200OK });

        responseTypes.Select(response => response.Type).Distinct().Single()
            .ShouldBe(typeof(HealthStatusResponse));
    }

    [Fact]
    public void Live_returns_200_live_status_without_dependency_checks()
    {
        var dependencyService = new FakeHealthDependencyService(HealthDependencyReportBuilder.Ready());
        var controller = new HealthController(dependencyService);

        ActionResult<HealthStatusResponse> result = controller.Live();

        var ok = result.Result.ShouldBeOfType<OkObjectResult>();
        ok.StatusCode.ShouldBe(StatusCodes.Status200OK);
        ok.Value.ShouldBeOfType<HealthStatusResponse>().status.ShouldBe("live");
        dependencyService.CallCount.ShouldBe(0);
    }

    [Fact]
    public async Task Ready_returns_200_when_dependencies_are_healthy()
    {
        var dependencyService = new FakeHealthDependencyService(HealthDependencyReportBuilder.Ready());
        var controller = new HealthController(dependencyService);

        ActionResult<HealthStatusResponse> result = await controller.Ready();

        var ok = result.Result.ShouldBeOfType<OkObjectResult>();
        ok.StatusCode.ShouldBe(StatusCodes.Status200OK);
        HealthStatusResponse response = ok.Value.ShouldBeOfType<HealthStatusResponse>();
        response.status.ShouldBe("ready");
        response.dependencies.ShouldAllBe(dependency => dependency.status == "healthy");
        dependencyService.CallCount.ShouldBe(1);
    }

    [Fact]
    public async Task Ready_returns_503_when_any_dependency_is_unhealthy()
    {
        var dependencyService = new FakeHealthDependencyService(HealthDependencyReportBuilder.NotReady());
        var controller = new HealthController(dependencyService);

        ActionResult<HealthStatusResponse> result = await controller.Ready();

        var serviceUnavailable = result.Result.ShouldBeOfType<ObjectResult>();
        serviceUnavailable.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        HealthStatusResponse response = serviceUnavailable.Value.ShouldBeOfType<HealthStatusResponse>();
        response.status.ShouldBe("not_ready");
        response.dependencies.ShouldContain(dependency => dependency.name == "postgresql" && dependency.status == "unhealthy");
    }

    [Fact]
    public async Task Dependencies_returns_same_dependency_report_shape_as_readiness()
    {
        var dependencyService = new FakeHealthDependencyService(HealthDependencyReportBuilder.NotReady());
        var controller = new HealthController(dependencyService);

        ActionResult<HealthStatusResponse> result = await controller.Dependencies();

        var serviceUnavailable = result.Result.ShouldBeOfType<ObjectResult>();
        serviceUnavailable.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        HealthStatusResponse response = serviceUnavailable.Value.ShouldBeOfType<HealthStatusResponse>();
        response.status.ShouldBe("not_ready");
        response.dependencies.Select(dependency => dependency.name).ToArray()
            .ShouldContain("dragonfly_abuse_counters");
    }

    private sealed class FakeHealthDependencyService : IHealthDependencyService
    {
        private readonly HealthDependencyReport _report;

        public FakeHealthDependencyService(HealthDependencyReport report)
        {
            _report = report;
        }

        public int CallCount { get; private set; }

        public Task<HealthDependencyReport> CheckAsync(CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(_report);
        }
    }

    private static class HealthDependencyReportBuilder
    {
        public static HealthDependencyReport Ready()
        {
            return new HealthDependencyReport(new[]
            {
                new HealthDependencyResult("postgresql", "healthy"),
                new HealthDependencyResult("dragonfly_active_sessions", "healthy"),
                new HealthDependencyResult("dragonfly_two_factor_sessions", "healthy"),
                new HealthDependencyResult("dragonfly_abuse_counters", "healthy")
            });
        }

        public static HealthDependencyReport NotReady()
        {
            return new HealthDependencyReport(new[]
            {
                new HealthDependencyResult("postgresql", "unhealthy", "database_unavailable"),
                new HealthDependencyResult("dragonfly_active_sessions", "healthy"),
                new HealthDependencyResult("dragonfly_two_factor_sessions", "healthy"),
                new HealthDependencyResult("dragonfly_abuse_counters", "healthy")
            });
        }
    }
}
