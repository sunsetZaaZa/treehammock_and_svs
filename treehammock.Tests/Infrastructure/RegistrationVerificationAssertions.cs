using System.Net;
using Shouldly;

namespace treehammock.Tests.Infrastructure;

// A rendering contract only. Callers must independently observe committed verification.
internal static class RegistrationVerificationAssertions
{
    internal static void AssertSuccessPage(HttpResponseMessage response, string body, string expectedHtml)
    {
        expectedHtml.ShouldNotBeNullOrWhiteSpace();
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (response.Content.Headers.ContentType?.MediaType).ShouldBe("text/html");
        body.ShouldBe(expectedHtml);
    }

    internal static string LoadTemplate(string outcome)
    {
        string relative = Path.Combine("html_templates", "account_verification", outcome + ".html");
        string published = Path.Combine(AppContext.BaseDirectory, relative);
        if (File.Exists(published)) return File.ReadAllText(published);
        for (DirectoryInfo? directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory is not null; directory = directory.Parent)
        {
            if (!File.Exists(Path.Combine(directory.FullName, "treehammock.sln"))) continue;
            return File.ReadAllText(Path.Combine(directory.FullName, relative));
        }
        throw new FileNotFoundException("The controlled verification template must be available to the test.", relative);
    }
}
