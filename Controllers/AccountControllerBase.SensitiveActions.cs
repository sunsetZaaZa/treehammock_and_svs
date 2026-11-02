using treehammock.DataLayer.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Controllers;

public abstract partial class AccountControllerBase
{
    // All account mutations use the same account/stamp/session/purpose/target binding.
    // The service validates the grant; consumption stays in the durable mutation transaction.
    protected async Task<SensitiveActionValidationResult> ValidateSensitiveActionToken(
        IAccountSensitiveActionService service,
        ActiveSession activeSession,
        string sessionBindingHash,
        bool consume,
        SensitiveActionPurpose purpose = SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP,
        string? target = null)
    {
        string token = Request.Headers.TryGetValue(SensitiveActionTokenConstants.HeaderName, out var values)
            ? values.FirstOrDefault() ?? string.Empty
            : string.Empty;

        return await service.ValidateAsync(
            new SensitiveActionValidationCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                sessionBindingHash,
                token,
                purpose,
                consume,
                target),
            HttpContext.RequestAborted);
    }

    protected bool MissingSensitiveActionToken()
    {
        return !Request.Headers.TryGetValue(SensitiveActionTokenConstants.HeaderName, out var values)
            || string.IsNullOrWhiteSpace(values.FirstOrDefault());
    }
}
