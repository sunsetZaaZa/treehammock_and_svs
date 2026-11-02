using treehammock.Models.Activation;
using treehammock.Repos;
namespace treehammock.Services;

// Deliberately absent from API DI and routes; database identity authorizes issuance independently.
public sealed class EntitlementGrantIssuerService(EntitlementGrantRepo repository)
{
    public Task<ActivationLifecycleResult> IssueAsync(EntitlementGrantApproval approval, CancellationToken token = default)
        => repository.IssueAsync(approval, token);
}
