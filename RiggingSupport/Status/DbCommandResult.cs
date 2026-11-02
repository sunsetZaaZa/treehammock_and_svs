using treehammock.Models.Account;
using treehammock.RiggingSupport.Enum;

namespace treehammock.RiggingSupport.Status;

public sealed record DbCommandResult(bool Result, string Code);

public sealed record AccountStampRotationResult(
    bool Result,
    string Code,
    Guid? AccountSecurityStamp);

public sealed record AccountViewResult(
    bool Result,
    string Code,
    AccountProfile? Profile);

public sealed record AccountAdjustResult(
    bool Result,
    string Code,
    Guid? AccountSecurityStamp = null,
    string? EmailAddress = null);

public sealed record AccountDeleteCommandResult(
    bool Result,
    string Code,
    DeletionWorkflow Workflow = DeletionWorkflow.NONE,
    string? EmailAddress = null,
    Guid? AccountId = null);

public sealed record AccountDeleteFinalizePreparationResult(
    bool Result,
    string Code,
    Guid? AccountId,
    DeletionWorkflow Workflow,
    string? PassPhraseHash,
    Guid? RequestId = null);

public sealed record AccountDeletePurgeResult(
    bool Result,
    string Code,
    int DeletedCount);

public sealed record AccountEmailChangePurgeResult(
    bool Result,
    string Code,
    int DeletedCount);
