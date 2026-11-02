using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Models.Account;

public class AccountDeleteRequest
{
    public const int MaxPassPhraseLength = 256;

    public AccountDeleteRequest()
    {
    }

    [SetsRequiredMembers]
    public AccountDeleteRequest(string? passPhrase)
    {
        this.passPhrase = passPhrase;
    }

    [StringLength(MaxPassPhraseLength)]
    public string? passPhrase { get; set; }
}

public class AccountDeleteResponse
{
    [SetsRequiredMembers]
    public AccountDeleteResponse(HttpMessage result, DeletionWorkflow workflow = DeletionWorkflow.NONE)
    {
        (this.result, this.workflow) = (result, workflow);
    }

    public required HttpMessage result { get; set; }
    public DeletionWorkflow workflow { get; set; }
    public Guid? completedCredentialStamp { get; set; }
}

public class AccountDeleteVerifyRequest
{
    public const int MaxDeleteTokenLength = 512;

    [SetsRequiredMembers]
    public AccountDeleteVerifyRequest(string deleteToken)
    {
        (this.deleteToken) = (deleteToken);
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxDeleteTokenLength)]
    public required string deleteToken { get; set; }
}

public class AccountDeleteFinalizeRequest
{
    public const int MaxDeleteTokenLength = 512;
    public const int MaxPassPhraseLength = 256;

    public AccountDeleteFinalizeRequest()
    {
    }

    [SetsRequiredMembers]
    public AccountDeleteFinalizeRequest(string deleteToken, string? passPhrase = null)
    {
        (this.deleteToken, this.passPhrase) = (deleteToken, passPhrase);
    }

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxDeleteTokenLength)]
    public required string deleteToken { get; set; }

    [StringLength(MaxPassPhraseLength)]
    public string? passPhrase { get; set; }
}
