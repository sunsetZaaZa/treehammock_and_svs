using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

using NodaTime;
using NodaTime.Serialization.JsonNet;

namespace treehammock.Rigging.Cache;

/// <summary>
/// Shared JSON settings for Redis-backed cache payloads.
/// Keep this separate from MVC JSON settings so cache round trips do not depend on
/// controller serialization configuration.
/// </summary>
public static class CacheJsonSettings
{
    private static readonly JsonSerializerSettings Settings = CreateSettings();

    public static JsonSerializerSettings CreateSettings()
    {
        var settings = new JsonSerializerSettings();

        settings.Converters.Add(new StringEnumConverter());
        settings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);

        return settings;
    }

    public static string Serialize<T>(T value)
    {
        return JsonConvert.SerializeObject(value, Settings);
    }

    public static T? Deserialize<T>(string value)
    {
        return JsonConvert.DeserializeObject<T>(value, Settings);
    }
}
