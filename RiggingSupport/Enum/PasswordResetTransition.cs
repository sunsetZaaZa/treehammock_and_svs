namespace treehammock.RiggingSupport.Enum;

// Every write names its intent and compares the session and challenge it read.
public enum PasswordResetTransition
{
    Create = 1,
    Select = 2,
    Resend = 3,
    InvalidProof = 4,
    ValidProof = 5
}
