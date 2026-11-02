namespace Treehammock.SessionValidation.Core;

public enum SessionDecision { Unspecified, Active, Unauthenticated, Forbidden, Unavailable }
public enum PolicyOutcome { Unspecified, Eligible, Unauthenticated, Forbidden, Unavailable }
public enum PolicyReason
{
    None, Deadline, MissingAuthority, AccountIneligible, InvalidIdentity, AuthorityMismatch,
    LifetimeExpired, StaleEntitlements, CapabilityDenied, MissingActionPolicy
}
public readonly record struct PolicyEvaluation(PolicyOutcome Outcome, PolicyReason Reason);

public enum TokenStatus { Unspecified, Passed, AtExpiration, Expired, Malformed, Failed, UnexpectedException }
public enum TokenFailureReason { None, TokenHandlerRejected, MissingRequiredClaims, PurposeMismatch, SecurityTokenException, UnexpectedException }

// Exception type is bounded to a CLR type name, never a message, exception object or stack.
public sealed record TokenVerificationResult(TokenStatus Status, string? WebKey,
    TokenFailureReason Reason = TokenFailureReason.None, string? ExceptionType = null)
{
    public override string ToString() => $"TokenVerificationResult({Status}, {Reason})";
}
