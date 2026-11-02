using Xunit;
namespace Treehammock.SessionValidation.HostTests;
internal static class TestWait
{
    internal static async Task Until(Func<bool> condition)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);budget.CancelAfter(3000);
        while(!condition())await Task.Delay(5,budget.Token);
    }
}
