namespace Treehammock.SessionValidation.Storage;
internal sealed class PublicationCacheUnavailableException:Exception
{private PublicationCacheUnavailableException(string operation):base("Authority publication cache unavailable: "+operation){} internal static PublicationCacheUnavailableException For(string operation)=>new(operation);}
