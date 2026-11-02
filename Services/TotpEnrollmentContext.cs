using treehammock.Rigging.Config;
namespace treehammock.Services;

public sealed record TotpParameters(string HashAlgorithm, int Digits, int PeriodSeconds, int AllowedClockSkewSteps)
{
    public static TotpParameters FromDefaults(TotpSettings settings) => new(settings.HashAlgorithm.ToUpperInvariant(), settings.Digits, settings.PeriodSeconds, settings.AllowedClockSkewSteps);
    public void Validate()
    {
        if (!TotpSettings.IsSupportedHashAlgorithm(HashAlgorithm) || HashAlgorithm != HashAlgorithm.ToUpperInvariant() ||
            Digits is not (6 or 7 or 8) || PeriodSeconds is < 15 or > 120 || AllowedClockSkewSteps is < 0 or > 2)
            throw new InvalidOperationException("Invalid enrolled TOTP parameters.");
    }
}
public sealed record TotpEnrollmentContext(Guid AccountId, Guid EnrollmentId, TotpParameters Parameters)
{
    public void Validate()
    {
        if (AccountId == Guid.Empty || EnrollmentId == Guid.Empty) throw new InvalidOperationException("TOTP enrollment identity is required.");
        Parameters.Validate();
    }
}
