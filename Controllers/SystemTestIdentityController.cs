using Microsoft.AspNetCore.Mvc;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Hosting;

namespace treehammock.Controllers;

[AllowAnonymous]
[ApiController]
[Route("__system-test/identity")]
[Produces("application/json")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class SystemTestIdentityController : ControllerBase
{
    private readonly SystemTestCapability capability;
    private readonly HostSystemTestIdentity identity;
    public SystemTestIdentityController(SystemTestCapability capability, HostSystemTestIdentity identity)
    {
        this.capability = capability;
        this.identity = identity;
    }
    [HttpGet]
    public IActionResult Current()
    {
        if (!capability.InspectionEnabled) return NotFound();
        if (!capability.Authorizes(Request)) return Unauthorized(new { success = false, code = "SYSTEM_TEST_KEY_INVALID" });
        return identity.Value is null ? NotFound() : Ok(identity.Value);
    }
}
