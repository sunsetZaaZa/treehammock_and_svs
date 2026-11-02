namespace treehammock.Rigging.Security;

internal static class PhoneDestinationNormalizer
{
    internal static string Normalize(string? countryCode, string phoneNumber)
    {
        string phone = phoneNumber.Trim();
        if (phone.StartsWith('+')) return phone;
        string country = countryCode?.Trim() ?? string.Empty;
        if (country.Length == 0) return phone;
        return (country.StartsWith('+') ? country : "+" + country) + phone;
    }
}
