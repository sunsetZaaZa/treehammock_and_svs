using NodaTime;
namespace treehammock.DataLayer.Security;

public sealed record LoginAttemptTransition(bool Result, string Code, short Failures, Instant? UnlockWhen, Guid Version);
