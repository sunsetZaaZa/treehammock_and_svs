using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;
public sealed class Cor23MBudgetStartupTests
{
    private static TreehammockWebApplicationFactory Host(Dictionary<string,string?> settings) => new(settings,services=>
    {
        services.RemoveAll<IHostedService>();services.RemoveAll<IPostgreSqlAbuseBudgetStore>();services.AddSingleton(Substitute.For<IPostgreSqlAbuseBudgetStore>());
    });
    [Theory][InlineData("Login",null)][InlineData("Delivery",null)][InlineData("Login","Delivery")]
    public void Real_host_accepts_explicit_supported_versioned_selection(string primary,string? secondary)
    {
        var settings=TestConfiguration.ValidSettings();settings["AbuseControlSettings:CounterFailureMode"]="RequirePostgreSqlBudgetV1";settings["AbuseControlSettings:PostgreSqlFallbackPolicies:0"]=primary;
        if(secondary is not null)settings["AbuseControlSettings:PostgreSqlFallbackPolicies:1"]=secondary;
        using var factory=Host(settings);using var http=factory.CreateClient();Assert.Equal(AbuseCounterFailureMode.RequirePostgreSqlBudgetV1,factory.Services.GetRequiredService<IOptions<AbuseControlSettings>>().Value.CounterFailureMode);
    }
    [Theory]
    [InlineData("RequirePostgreSqlBudgetV1",null,null)][InlineData("RequirePostgreSqlBudgetV1","Signup",null)]
    [InlineData("RequirePostgreSqlBudgetV1","Login","Login")][InlineData("RequirePostgreSqlBudgetV1","99",null)]
    [InlineData("FailClosed","Login",null)][InlineData("AllowWhenPostgreSqlAuthoritativeStateExists",null,null)]
    public void Real_host_rejects_missing_duplicate_unsupported_or_unversioned_fallback(string mode,string? primary,string? secondary)
    {
        var settings=TestConfiguration.ValidSettings();settings["AbuseControlSettings:CounterFailureMode"]=mode;
        if(primary is not null)settings["AbuseControlSettings:PostgreSqlFallbackPolicies:0"]=primary;if(secondary is not null)settings["AbuseControlSettings:PostgreSqlFallbackPolicies:1"]=secondary;
        using var factory=Host(settings);var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);Assert.Contains("AbuseControlSettings",error.ToString());
    }
    [Fact]
    public void Real_host_keeps_FailClosed_as_the_default_with_no_selected_SQL_policies()
    {
        using var factory=Host(TestConfiguration.ValidSettings());using var http=factory.CreateClient();var settings=factory.Services.GetRequiredService<IOptions<AbuseControlSettings>>().Value;Assert.Equal(AbuseCounterFailureMode.FailClosed,settings.CounterFailureMode);Assert.Empty(settings.PostgreSqlFallbackPolicies);
    }
}
