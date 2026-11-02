using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using treehammock.Models.Api;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Health;

namespace treehammock.Controllers;

[ApiController]
[AllowAnonymous]
[Route("health")]
[Produces("application/json")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class HealthController : ControllerBase
{
    private readonly IHealthDependencyService _healthDependencyService;

    public HealthController(IHealthDependencyService healthDependencyService)
    {
        _healthDependencyService = healthDependencyService;
    }

    [HttpGet("live")]
    [ProducesResponseType(typeof(HealthStatusResponse), StatusCodes.Status200OK)]
    public ActionResult<HealthStatusResponse> Live()
    {
        return Ok(new HealthStatusResponse(HealthDependencyStatus.Live));
    }

    [HttpGet("ready")]
    [ProducesResponseType(typeof(HealthStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(HealthStatusResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<HealthStatusResponse>> Ready(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HealthDependencyReport report = await _healthDependencyService.CheckAsync(cancellationToken);
        HealthStatusResponse response = HealthStatusResponse.FromReport(report);

        return report.Ready
            ? Ok(response)
            : StatusCode(StatusCodes.Status503ServiceUnavailable, response);
    }

    [HttpGet("dependencies")]
    [ProducesResponseType(typeof(HealthStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(HealthStatusResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<HealthStatusResponse>> Dependencies(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HealthDependencyReport report = await _healthDependencyService.CheckAsync(cancellationToken);
        HealthStatusResponse response = HealthStatusResponse.FromReport(report);

        return report.Ready
            ? Ok(response)
            : StatusCode(StatusCodes.Status503ServiceUnavailable, response);
    }
}
