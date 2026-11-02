using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.DataLayer.Entitlements;
using treehammock.Entities;
using treehammock.RiggingSupport.Enum;
namespace treehammock.Tests.Support;
public static class EntitlementTestData
{
    public static EntitlementProjection ForAccount(Guid id, FeatureSet features = FeatureSet.basic, Instant? evaluated = null) => new(id, 1, features,
        ["account.read", "account.manage"], features == FeatureSet.premium, evaluated ?? SystemClock.Instance.GetCurrentInstant(), null, null, []);
    public static ActiveSession Attach(ActiveSession session) { session.entitlements = ForAccount(session.accountId, session.features); return session; }
    public static Session Attach(Session session) { session.entitlements = ForAccount(session.accountId, session.features); return session; }
}
