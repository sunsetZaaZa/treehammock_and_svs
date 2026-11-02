namespace treehammock.RiggingSupport.Enum;

public enum PasswordResetBootstrapProof
{
    None = 0,
    EmailResetToken = 1,
    SmsResetToken = 2,
    AdminIssuedToken = 3
}
