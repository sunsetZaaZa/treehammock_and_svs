using NodaTime;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Entities;

public sealed class AccountDeleteEvent
{
    [SetsRequiredMembers]
    public AccountDeleteEvent(long deleteEventId, Guid? accountId, string eventType, string code, Instant createdAt) =>
        (this.deleteEventId, this.accountId, this.eventType, this.code, this.createdAt) =
        (deleteEventId, accountId, eventType, code, createdAt);

    public required long deleteEventId { get; set; }
    public Guid? accountId { get; set; }
    public Guid? requestId { get; set; }
    public Guid? credentialStamp { get; set; }
    public required string eventType { get; set; }
    public required string code { get; set; }
    public required Instant createdAt { get; set; }
}
