using System.Net;
namespace treehammock.Rigging.Config;
internal static class PrivateAuthorityAddress
{
    internal static bool IsPrivateAddress(string value)
    {
        if(!IPAddress.TryParse(value,out var address))return false;
        if(IPAddress.IsLoopback(address))return true;
        var bytes=address.GetAddressBytes();
        return bytes.Length==4?(bytes[0]==10||bytes[0]==172&&bytes[1] is >=16 and <=31||bytes[0]==192&&bytes[1]==168)
            :bytes.Length==16&&(bytes[0]&0xfe)==0xfc;
    }
}
