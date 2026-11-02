using treehammock.Rigging.Replay;

namespace treehammock.Tests.Infrastructure;

public sealed class AllowingAuthenticatedMutationIdempotencyService : IAuthenticatedMutationIdempotencyService
{
    public List<AuthenticatedMutationIdempotencyRequest> Requests { get; } = new();

    public Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default)
    {
        Requests.Add(request);

        if (request.IdempotencyKey is null)
        {
            return Task.FromResult(request.RequireKey
                ? AuthenticatedMutationIdempotencyBeginResult.MissingRequiredKeyResult()
                : AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult());
        }

        string? normalized = DragonflyAuthenticatedMutationIdempotencyService.NormalizeClientKey(
            request.IdempotencyKey,
            minLength: 16,
            maxLength: 128);

        return Task.FromResult(normalized is null
            ? AuthenticatedMutationIdempotencyBeginResult.InvalidKeyResult()
            : AuthenticatedMutationIdempotencyBeginResult.StartedResult(
                new AuthenticatedMutationIdempotencyReservation(
                    $"test-idempotency:{request.AccountId:N}:{request.Method}:{request.Route}",
                    Guid.NewGuid().ToString("N"))));
    }

    public Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}
