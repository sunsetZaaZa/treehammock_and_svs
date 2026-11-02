namespace treehammock.Services;
// Exact peer FleetPolicyHashes/Gate use this resource adapter, without a web-app dependency.
internal static class DatabaseRoleBoundary
{ internal static string Policy=>Treehammock.SessionValidation.Storage.DatabaseIdentityPolicy.Resource("SVS07_THS_POLICY.json"); }
