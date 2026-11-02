using System.Globalization;
namespace Treehammock.SessionValidation.Storage;
internal readonly record struct AuthorityRevision
{
    internal long Value { get; }
    internal AuthorityRevision(long value) { if(value<0) throw new ArgumentOutOfRangeException(nameof(value)); Value=value; }
    internal static AuthorityRevision Parse(string value)
    {
        if(!long.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out long parsed) || parsed<0 || parsed.ToString(CultureInfo.InvariantCulture)!=value)
            throw new FormatException("Noncanonical authority revision.");
        return new(parsed);
    }
    internal AuthorityRevision Next()=>new(checked(Value+1));
    public override string ToString()=>Value.ToString(CultureInfo.InvariantCulture);
}
internal sealed record AuthorityVersion(Guid AccountId,AuthorityRevision Revision,string Lifecycle);
