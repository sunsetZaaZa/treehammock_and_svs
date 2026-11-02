using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer.Account;

public class TwoFactorDetails
{
    [SetsRequiredMembers]
    public TwoFactorDetails(List<TwoFactorAuthMethod> methods, List<string>? userAuthIds, List<string>? phoneNumbers,
                                List<string>? phoneCountryCode, List<string>? emailAddresses)
    {
        (this.methods, this.userAuthIds, this.phoneNumbers, this.phoneCountryCode, this.emailAddresses) =
        (methods, userAuthIds, phoneNumbers, phoneCountryCode, emailAddresses);
    }

    public required List<TwoFactorAuthMethod> methods { get; set; } // sync'd in order via index
    public required List<string>? userAuthIds { get; set; } // sync'd in order via index
    public required List<string>? phoneNumbers { get; set; } // sync'd in order via index
    public required List<string>? phoneCountryCode { get; set; } // sync'd in order via index
    public required List<string>? emailAddresses { get; set; } // sync'd in order via index
}
