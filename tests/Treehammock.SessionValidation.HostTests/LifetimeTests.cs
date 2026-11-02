using Treehammock.SessionValidation.Api;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;
public sealed class LifetimeTests
{
    [Theory][InlineData(true)][InlineData(false)] public void Response_and_downstream_must_both_finish_before_releasing_the_slot(bool responseFirst)
    {
        var requests=new RequestLifetime(1);var context=new Microsoft.AspNetCore.Http.DefaultHttpContext();
        var owner=new ResponseLifetime(context,requests.TryEnter()!,null,2000);
        if(responseFirst)owner.ResponseDone();else owner.DownstreamDone();Assert.Equal(1,requests.Active);
        if(responseFirst)owner.DownstreamDone();else owner.ResponseDone();Assert.Equal(0,requests.Active);
        owner.ResponseDone();owner.DownstreamDone();Assert.Equal(0,requests.Active);
    }
    [Fact] public async Task Saturation_and_drain_never_release_a_live_slot()
    {
        var gate = new RequestLifetime(1); using var first = gate.TryEnter(); Assert.NotNull(first); Assert.Null(gate.TryEnter());
        using var cancel = new CancellationTokenSource(); var drain = gate.DrainAsync(cancel.Token); Assert.False(drain.IsCompleted); Assert.Null(gate.TryEnter());
        cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => drain); Assert.Equal(1, gate.Active); Assert.False(gate.Open);
        first!.Dispose(); first.Dispose(); Assert.Equal(0, gate.Active); await gate.DrainAsync(TestContext.Current.CancellationToken);
    }
}
