namespace treehammock.Rigging.Cache;

/// <summary>
/// Indicates a pending two-factor Redis payload exists but cannot be trusted because
/// its serialized shape is stale, malformed, or missing required security fields.
/// Infrastructure failures such as Redis connectivity should not be translated to
/// this exception.
/// </summary>
public sealed class StalePendingTwoFactorCachePayloadException : Exception
{
    public StalePendingTwoFactorCachePayloadException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
