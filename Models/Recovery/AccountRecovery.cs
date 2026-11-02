using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Recovery;

public class AccountRecoveryRequest
{
    public const int MaxIdentifierLength = 1024;

    [SetsRequiredMembers]
    public AccountRecoveryRequest()
    {
        identifier = string.Empty;
    }

    [SetsRequiredMembers]
    public AccountRecoveryRequest(string identifier)
        : this(identifier, AccountUnlockDeliveryMethod.EMAIL)
    {
    }

    [SetsRequiredMembers]
    public AccountRecoveryRequest(string identifier, AccountUnlockDeliveryMethod deliveryMethod)
    {
        (this.identifier, this.deliveryMethod) = (identifier, deliveryMethod);
    }

    public required string identifier { get; set; } = string.Empty;

    [EnumDataType(typeof(AccountUnlockDeliveryMethod))]
    public AccountUnlockDeliveryMethod deliveryMethod { get; set; } = AccountUnlockDeliveryMethod.EMAIL;
}

public class AccountRecoveryVerifyRequest
{
    public const int MaxTokenLength = 256;

    public AccountRecoveryVerifyRequest()
    {
    }

    [SetsRequiredMembers]
    public AccountRecoveryVerifyRequest(string token)
    {
        this.token = token;
    }

    public string token { get; set; } = string.Empty;
}

public class AccountRecoveryResponse
{
    [SetsRequiredMembers]
    public AccountRecoveryResponse(HttpMessage result)
    {
        this.result = result;
    }

    public required HttpMessage result { get; set; }
}
