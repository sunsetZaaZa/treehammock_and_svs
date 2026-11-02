using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using treehammock.Controllers;

namespace treehammock.Tests.Infrastructure;

public sealed class TreehammockWebApplicationFactory : WebApplicationFactory<AccountLoginController>
{
    private readonly string _environment = "Testing";
    private readonly IReadOnlyDictionary<string, string?>? _settings;
    private readonly bool _loadExampleConfig;
    private readonly Action<IServiceCollection>? _configureTestServices;

    public TreehammockWebApplicationFactory()
        : this(settings: null, loadExampleConfig: true, configureTestServices: null)
    {
    }

    public TreehammockWebApplicationFactory(IReadOnlyDictionary<string, string?> settings)
        : this(settings, loadExampleConfig: false, configureTestServices: null)
    {
    }

    public TreehammockWebApplicationFactory(
        IReadOnlyDictionary<string, string?> settings,
        Action<IServiceCollection> configureTestServices)
        : this(settings, loadExampleConfig: false, configureTestServices)
    {
    }

    public TreehammockWebApplicationFactory(IReadOnlyDictionary<string, string?> settings, string environment,
        Action<IServiceCollection>? configureTestServices = null)
        : this(settings, loadExampleConfig: false, configureTestServices)
    {
        _environment = environment;
    }

    private TreehammockWebApplicationFactory(
        IReadOnlyDictionary<string, string?>? settings,
        bool loadExampleConfig,
        Action<IServiceCollection>? configureTestServices)
    {
        _settings = settings;
        _loadExampleConfig = loadExampleConfig;
        _configureTestServices = configureTestServices;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting(WebHostDefaults.ApplicationKey, typeof(AccountLoginController).Assembly.GetName().Name);
        builder.UseEnvironment(_environment);
        builder.ConfigureAppConfiguration((_, configBuilder) =>
        {
            configBuilder.Sources.Clear();

            if (_loadExampleConfig)
            {
                string projectRoot = ProjectRoot();
                configBuilder.AddJsonFile(Path.Combine(projectRoot, "appsettings.Example.json"), optional: false, reloadOnChange: false);
                configBuilder.AddJsonFile(Path.Combine(projectRoot, "appsettings.Testing.json"), optional: false, reloadOnChange: false);
            }
            else if (_settings is not null)
            {
                configBuilder.AddInMemoryCollection(_settings);
            }
        });

        if (_configureTestServices is not null)
        {
            builder.ConfigureTestServices(services => {
                Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions.RemoveAll<treehammock.Rigging.Delivery.IDurableDeliveryService>(services);
                services.AddSingleton<treehammock.Rigging.Delivery.IDurableDeliveryService>(new CapturingDurableDelivery());
                // The fast fixture supplies mocked domain authority; the native suite drives the actual worker.
                foreach(var descriptor in services.Where(d=>d.ServiceType==typeof(Microsoft.Extensions.Hosting.IHostedService) && d.ImplementationType==typeof(treehammock.Services.DeliveryOutboxWorker)).ToArray())services.Remove(descriptor);
                _configureTestServices(services);
            });
        }
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new InvalidOperationException("The test could not locate the project root containing treehammock.sln.");
        }

        return directory.FullName;
    }
}
