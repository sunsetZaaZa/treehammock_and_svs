using Microsoft.AspNetCore.Mvc;

using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Hosting;
using treehammock.Services.SystemTesting;

namespace treehammock.Controllers;

[AllowAnonymous]
[ApiController]
[Route("__system-test/deliveries")]
[Produces("application/json")]
public sealed class SystemTestDeliveryController : ControllerBase
{
    public const string TestKeyHeaderName = SystemTestCapability.TestKeyHeaderName;

    private readonly ISystemTestDeliveryCapture _capture;
    private readonly SystemTestCapability _capability;

    public SystemTestDeliveryController(
        ISystemTestDeliveryCapture capture,
        SystemTestCapability capability)
    {
        _capture = capture;
        _capability = capability;
    }

    [HttpGet("latest")]
    public async Task<IActionResult> Latest([FromQuery] string channel, [FromQuery] string purpose, [FromQuery] string destination)
    {
        IActionResult? guard = GuardAccess();
        if (guard is not null)
        {
            return guard;
        }

        if (string.IsNullOrWhiteSpace(channel) || string.IsNullOrWhiteSpace(purpose) || string.IsNullOrWhiteSpace(destination))
        {
            return BadRequest(new { success = false, code = "SYSTEM_TEST_DELIVERY_QUERY_INVALID" });
        }

        SystemTestDeliveryRecord? record = await _capture.GetLatest(channel.Trim(), purpose.Trim(), destination.Trim());
        if (record is null)
        {
            return NotFound(new { success = false, code = "SYSTEM_TEST_DELIVERY_NOT_FOUND" });
        }

        return Ok(new { success = true, code = "SYSTEM_TEST_DELIVERY_FOUND", data = record });
    }

    [HttpDelete]
    public async Task<IActionResult> Clear()
    {
        IActionResult? guard = GuardAccess();
        if (guard is not null)
        {
            return guard;
        }

        int cleared = await _capture.Clear();
        return Ok(new { success = true, code = "SYSTEM_TEST_DELIVERIES_CLEARED", data = new { cleared } });
    }

    private IActionResult? GuardAccess()
    {
        if (!_capability.InspectionEnabled) return NotFound();
        return _capability.Authorizes(Request)
            ? null
            : Unauthorized(new { success = false, code = "SYSTEM_TEST_KEY_INVALID" });
    }
}
