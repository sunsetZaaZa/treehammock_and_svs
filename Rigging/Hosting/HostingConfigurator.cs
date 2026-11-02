using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Hosting;

public static class HostingConfigurator
{
    public static void ConfigureKestrel(KestrelServerOptions options, HostingSettings settings)
    {
        options.Limits.Http2.KeepAlivePingTimeout = TimeSpan.FromSeconds(30);
        options.Limits.Http2.KeepAlivePingDelay = TimeSpan.FromMinutes(1);

        if (!settings.ConfigureKestrel)
        {
            return;
        }

        void ConfigureListenOptions(ListenOptions listenOptions)
        {
            listenOptions.Protocols = settings.GetProtocols();

            if (settings.UseHttps)
            {
                listenOptions.UseHttps();
            }
        }

        if (IsAnyAddress(settings.BindAddress))
        {
            options.ListenAnyIP(settings.Port, ConfigureListenOptions);
            return;
        }

        options.Listen(IPAddress.Parse(settings.BindAddress), settings.Port, ConfigureListenOptions);
    }

    public static ForwardedHeadersOptions CreateForwardedHeadersOptions(HostingSettings settings)
    {
        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = settings.ForwardLimit,
            RequireHeaderSymmetry = settings.RequireHeaderSymmetry
        };

        if (settings.TrustAllForwardedHeaderProxies)
        {
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
            return options;
        }

        string[] knownProxies = (settings.KnownProxies ?? Array.Empty<string>())
            .Where(proxy => !string.IsNullOrWhiteSpace(proxy))
            .ToArray();
        string[] knownNetworks = (settings.KnownNetworks ?? Array.Empty<string>())
            .Where(network => !string.IsNullOrWhiteSpace(network))
            .ToArray();

        if (knownProxies.Length > 0 || knownNetworks.Length > 0)
        {
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
        }

        foreach (string proxy in knownProxies)
        {
            options.KnownProxies.Add(IPAddress.Parse(proxy));
        }

        foreach (string network in knownNetworks)
        {
            options.KnownNetworks.Add(ParseNetwork(network));
        }

        return options;
    }

    private static bool IsAnyAddress(string bindAddress)
    {
        return string.Equals(bindAddress, "AnyIP", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(bindAddress, "*", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(bindAddress, "0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(bindAddress, "::", StringComparison.OrdinalIgnoreCase);
    }

    private static Microsoft.AspNetCore.HttpOverrides.IPNetwork ParseNetwork(string value)
    {
        string[] parts = value.Split('/', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse(parts[0]), int.Parse(parts[1]));
    }
}
