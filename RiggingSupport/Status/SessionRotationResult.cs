namespace treehammock.RiggingSupport.Status;

public enum SessionRotationStatus
{
    Unknown = 0,
    Succeeded = 1,
    OldSessionMismatch = 2,
    NewSessionConflict = 3,
    Failed = 4
}

public sealed record SessionRotationResult(SessionRotationStatus Status)
{
    public bool Succeeded => Status == SessionRotationStatus.Succeeded;
}
