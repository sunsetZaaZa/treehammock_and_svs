using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer;

public sealed record ActivationCommandResult(bool Result, string Code, ActivationStatus? Status);

public sealed record ActivationVerifyCommandResult(
    bool Result,
    string Code,
    ActivationQuery? Activation);
