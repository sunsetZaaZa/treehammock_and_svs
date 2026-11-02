using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Shouldly;

using treehammock.Rigging.Observability;

namespace treehammock.Tests.Unit;

public class AbuseOperationalTelemetryTests
{
    [Fact]
    public void Abuse_operational_event_names_are_stable()
    {
        string[] names = StringConstants(typeof(AbuseOperationalEventNames));

        names.ShouldContain("abuse.policy_allowed");
        names.ShouldContain("abuse.policy_denied");
        names.ShouldContain("abuse.cooldown_started");
        names.ShouldContain("abuse.counter_store_timeout");
        names.ShouldContain("abuse.counter_store_failed");
        names.ShouldContain("delivery.throttled");
        names.ShouldContain("login.throttled");
        names.ShouldContain("password_reset.throttled");
        names.ShouldContain("two_factor.throttled");
        names.ShouldContain("cloudflare.challenge_detected");
        names.ShouldContain("cloudflare.bot_signal_high");
        names.ShouldContain("edge.origin_bypass_denied");
        names.Distinct(StringComparer.Ordinal).Count().ShouldBe(names.Length);
    }

    [Fact]
    public void Abuse_metric_names_are_stable_treehammock_counters()
    {
        string[] names = StringConstants(typeof(AbuseMetricNames));

        names.ShouldContain("treehammock_abuse_counter_admissions_v2_total");
        names.ShouldContain("treehammock_abuse_cooldowns_created_v2_total");
        names.ShouldContain("treehammock_abuse_counter_store_failures_total");
        names.ShouldContain("treehammock_delivery_throttled_total");
        names.ShouldContain("treehammock_login_throttled_total");
        names.ShouldContain("treehammock_password_reset_throttled_total");
        names.ShouldContain("treehammock_two_factor_throttled_total");
        names.ShouldContain("treehammock_edge_abuse_events_total");
        names.ShouldAllBe(name => name.StartsWith("treehammock_", StringComparison.Ordinal));
        names.ShouldAllBe(name => name.EndsWith("_total", StringComparison.Ordinal));
        names.Distinct(StringComparer.Ordinal).Count().ShouldBe(names.Length);
    }

    [Fact]
    public void Abuse_metric_labels_are_low_cardinality_only()
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "event",
            "feature",
            "dimension",
            "outcome",
            "reason",
            "delivery_method",
            "operation",
            "dependency"
        };

        AbuseMetricLabels.Allowed.SetEquals(expected).ShouldBeTrue();

        foreach (string forbidden in AbuseMetricLabels.Forbidden)
        {
            AbuseMetricLabels.Allowed.Any(label => string.Equals(label, forbidden, StringComparison.OrdinalIgnoreCase))
                .ShouldBeFalse($"Metric label {forbidden} must not be allowed.");
        }
    }

    [Fact]
    public void Abuse_metric_labels_forbid_raw_pii_and_secret_fields()
    {
        string[] forbidden = AbuseMetricLabels.Forbidden.ToArray();

        forbidden.ShouldContain("emailAddress");
        forbidden.ShouldContain("phoneNumber");
        forbidden.ShouldContain("username");
        forbidden.ShouldContain("identifier");
        forbidden.ShouldContain("token");
        forbidden.ShouldContain("sensitiveActionToken");
        forbidden.ShouldContain("setupId");
        forbidden.ShouldContain("manualEntryKey");
        forbidden.ShouldContain("otpauthUri");
        forbidden.ShouldContain("resetCode");
        forbidden.ShouldContain("totpCode");
        forbidden.ShouldContain("totpSecret");
        forbidden.ShouldContain("password");
        forbidden.ShouldContain("passwordHash");
        forbidden.ShouldContain("ipAddress");
        forbidden.ShouldContain("accountId");
        forbidden.ShouldContain("resetId");
        forbidden.ShouldContain("challengeId");
        forbidden.ShouldContain("sessionId");
        forbidden.ShouldContain("connectionString");
    }

    [Fact]
    public void Structured_log_fields_do_not_use_raw_abuse_proof_or_secret_names()
    {
        string[] forbiddenPlaceholders =
        [
            "{EmailAddress}",
            "{PhoneNumber}",
            "{Username}",
            "{Identifier}",
            "{Password}",
            "{PasswordHash}",
            "{ResetCode}",
            "{ActivationCode}",
            "{UnlockCode}",
            "{CodeKey}",
            "{TotpCode}",
            "{TotpSecret}",
            "{SensitiveActionToken}",
            "{SetupId}",
            "{ManualEntryKey}",
            "{OtpauthUri}",
            "{AccessToken}",
            "{RefreshToken}",
            "{AuthToken}",
            "{ConnectionString}"
        ];

        string[] roots = ["Controllers", "Services", "Repos", "Rigging"];
        foreach (string root in roots)
        {
            foreach (string file in Directory.EnumerateFiles(ProjectFile(root), "*.cs", SearchOption.AllDirectories))
            {
                string source = File.ReadAllText(file);
                string relative = Path.GetRelativePath(ProjectRoot(), file);

                foreach (string placeholder in forbiddenPlaceholders)
                {
                    source.Contains(placeholder, StringComparison.Ordinal).ShouldBeFalse(relative);
                }
            }
        }
    }

    [Fact]
    public void Abuse_grafana_dashboard_uses_only_expected_metric_names()
    {
        string dashboard = File.ReadAllText(ProjectFile("ops", "grafana", "dashboards", "abuse-controls-1-0-0.json"));
        using JsonDocument document = JsonDocument.Parse(dashboard);

        document.RootElement.GetProperty("title").GetString().ShouldBe("Treehammock Abuse Controls 1.0.0");
        dashboard.ShouldContain("treehammock_abuse_counter_admissions_v2_total");
        dashboard.ShouldContain("treehammock_abuse_cooldowns_created_v2_total");
        dashboard.ShouldContain("treehammock_abuse_counter_store_failures_total");
        dashboard.ShouldContain("treehammock_delivery_throttled_total");
        dashboard.ShouldContain("treehammock_login_throttled_total");
        dashboard.ShouldContain("treehammock_password_reset_throttled_total");
        dashboard.ShouldContain("treehammock_two_factor_throttled_total");
        dashboard.ShouldContain("treehammock_edge_abuse_events_total");

        foreach (string forbidden in AbuseMetricLabels.Forbidden)
        {
            Regex.IsMatch(dashboard, $"(?i)[{{,]\\s*{Regex.Escape(forbidden)}\\s*=", RegexOptions.CultureInvariant)
                .ShouldBeFalse($"Dashboard must not use high-cardinality label {forbidden}.");
        }
    }
    private static string[] StringConstants(Type type)
    {
        return type
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(field => field.IsLiteral && !field.IsInitOnly && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
