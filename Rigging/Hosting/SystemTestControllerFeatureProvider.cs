using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using treehammock.Controllers;

namespace treehammock.Rigging.Hosting;

public sealed class SystemTestControllerFeatureProvider(SystemTestCapability capability)
    : IApplicationFeatureProvider<ControllerFeature>
{
    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        if (capability.InspectionEnabled) return;
        foreach (TypeInfo type in feature.Controllers.Where(type =>
            type.AsType() == typeof(SystemTestAccountController) ||
            type.AsType() == typeof(SystemTestDeliveryController) ||
            type.AsType() == typeof(SystemTestIdentityController)).ToArray())
            feature.Controllers.Remove(type);
    }
}
