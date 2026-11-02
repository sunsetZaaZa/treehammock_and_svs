namespace treehammock.Rigging.Provider;

public interface IAspenTrees
{

}

public class Aspen
{
    public string Uri { get; set; } = string.Empty;
    public string authCred { get; set; } = string.Empty;
    public string hashedPassword { get; set; } = string.Empty;
    public string sslCert { get; set; } = string.Empty;
    public string protocol { get; set; } = string.Empty;
    public string port { get; set; } = string.Empty;
    public string expiration { get; set; } = string.Empty;
    public string name { get; set; } = string.Empty;
    public string company { get; set; } = string.Empty;
}

public class AspenTrees : IAspenTrees
{
    public List<Aspen> aspenRoots { get; set; } = new();
}
