namespace treehammock.Rigging.Config;

/// <summary>
/// Redis connection settings for pending two-factor sessions.
/// Kept separate from active-session cache settings so pre-auth sessions can live
/// in their own Redis database and be purged/observed independently.
/// </summary>
public class TwoFactorSessionCacheSettings : UserCacheSettings
{
}
