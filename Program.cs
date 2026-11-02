using System.IO.Compression;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.ResponseCompression;

using Newtonsoft.Json;

using treehammock.Rigging.Database;
using treehammock.Services;
using treehammock.Rigging.Cache;
using treehammock.Repos;
using treehammock.Rigging.Config;
using NodaTime.Serialization.JsonNet;
using NodaTime;
using treehammock.Rigging.Sidewalk;
using treehammock.Rigging.Provider;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Models.Api;


if (args.Length > 0 && args[0] == "migrate")
{
    Environment.ExitCode = await treehammock.Rigging.Database.Migrations.DatabaseMigrationCommand.RunAsync(args[1..]);
    return;
}

bool reencryptTotp = args.Length > 0 && args[0] == "reencrypt-totp";
bool validateSms = args.Length > 0 && args[0] == "validate-sms-config";
var builder = WebApplication.CreateBuilder(reencryptTotp || validateSms ? [] : args);
if (validateSms)
{
    Environment.ExitCode = SmsConfigurationCommand.Run(builder.Configuration,builder.Environment,Console.Out);
    return;
}
// Hosting/request logging includes raw query strings and form bodies. Proof URLs must not enter logs.
builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics",LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging",LogLevel.Warning);
{
    var services = builder.Services;
    var env = builder.Environment;

    // HTTP/S 3 : br - brotli
    services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.Providers.Add<BrotliCompressionProvider>();
    });

    services.Configure<BrotliCompressionProviderOptions>(options =>
    {
        options.Level = CompressionLevel.Fastest;
    });


    services.AddTreehammockServices(builder.Configuration, builder.Environment);

    services.AddControllers()
        .ConfigureApiBehaviorOptions(options =>
        {
            options.InvalidModelStateResponseFactory = context => ApiResponses.InvalidModelState(context.ModelState);
        })
        .AddApplicationPart(typeof(treehammock.Controllers.AccountLoginController).Assembly)
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        })
        .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        options.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);
    });

}

builder.Services.AddHttpClient();

// Configure HTTP request pipeline
builder.WebHost.ConfigureKestrel((context, options) =>
{
    var hostingSettings = context.Configuration
        .GetRequiredSection("HostingSettings")
        .Get<HostingSettings>() ?? new HostingSettings();

    var body = context.Configuration.GetSection("RequestBodySettings").Get<RequestBodySettings>() ?? new RequestBodySettings();
    options.Limits.MaxRequestBodySize = body.EncodedBytes + 1L;
    HostingConfigurator.ConfigureKestrel(options, hostingSettings);
});

var app = builder.Build();
if (reencryptTotp)
{
    using var stop = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
    try { Environment.ExitCode = await TotpReencryptionCommand.RunAsync(app.Services, args[1..], stop.Token); }
    catch (OperationCanceledException) { Environment.ExitCode = 3; Console.Error.WriteLine("TOTP rotation canceled; resume from its checkpoint."); }
    catch { Environment.ExitCode = 1; Console.Error.WriteLine("TOTP rotation stopped; check injected keys and database state privately. No plaintext was logged; resume with the retained checkpoint."); }
    await app.DisposeAsync(); return;
}

// Apply privacy policy before transport, body decoding, operation errors and authentication.
app.UseMiddleware<SecurityResponseCacheMiddleware>();
app.UseMiddleware<HttpExceptionFallbackMiddleware>();

var hostingSettings = app.Configuration
    .GetRequiredSection("HostingSettings")
    .Get<HostingSettings>() ?? new HostingSettings();

if (hostingSettings.UseForwardedHeaders)
{
    app.UseForwardedHeaders(HostingConfigurator.CreateForwardedHeadersOptions(hostingSettings));
}

if (hostingSettings.UseHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseResponseCompression();

app.UseMiddleware<RequestBodyMiddleware>();

app.UseMiddleware<treehammock.Rigging.Operations.SecurityOperationMiddleware>();
app.UseMiddleware<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>();
app.UseMiddleware<JsonWebTokenMiddleware>();

app.MapControllers().WithMetadata(app.Services.GetRequiredService<RequestBodyPolicy>().Limits);

app.Run();
public partial class Program { }
