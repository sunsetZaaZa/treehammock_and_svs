namespace Treehammock.SessionValidation.HostTests;
// Test-assembly bridge only; no new production friend assembly or runtime hook.
internal static class QualificationHostFactory
{
    internal static Microsoft.AspNetCore.Builder.WebApplication Build(Treehammock.SessionValidation.Api.HostSettings settings,RpcResources resources)
        => Treehammock.SessionValidation.Api.SvsHost.Build(settings,_=>resources);
}
