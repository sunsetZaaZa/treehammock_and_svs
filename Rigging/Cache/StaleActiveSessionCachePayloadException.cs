namespace treehammock.Rigging.Cache;

/// <summary>
/// Indicates an active-session Redis payload exists but cannot be trusted because
/// its serialized shape is stale, malformed, or missing required security fields.
/// Infrastructure failures such as Redis connectivity should not be translated to
/// this exception.
/// </summary>
public sealed class StaleActiveSessionCachePayloadException : Exception
{
    public StaleActiveSessionCachePayloadException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
