using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Delivery;

public sealed class DeliveryPayloadProtector(IOptions<DeliveryOutboxSettings> options)
{
    private readonly DeliveryOutboxSettings _settings = options.Value;
    private static readonly JsonSerializerSettings Metadata = new JsonSerializerSettings { ContractResolver=new CamelCasePropertyNamesContractResolver() }.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);
    private static byte[] Binding(ProtectedDelivery item) => Encoding.UTF8.GetBytes(
        $"treehammock:delivery:v1:{item.Id:D}:{item.AccountId:D}:{item.AccountStamp:D}:{item.Purpose}:{item.ProofHash}:{item.ExpiresAt.ToUnixTimeTicks()}:{item.KeyVersion}:{item.MetadataJson}");
    public ProtectedDelivery Protect(DeliveryIntent intent)
    {
        Instant limit = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(_settings.PayloadRetentionHours));
        Instant requested = intent.ExpiresAt;
        for (var companion = intent.Companion; companion is not null; companion = companion.Companion)
            if (companion.ExpiresAt < requested) requested = companion.ExpiresAt;
        Instant expires=Instant.FromUnixTimeTicks((requested < limit ? requested : limit).ToUnixTimeTicks()/10*10);
        return ProtectAt(intent, expires);
    }
    private ProtectedDelivery ProtectAt(DeliveryIntent intent, Instant expires)
    {
        string metadata=JsonConvert.SerializeObject(intent.Metadata,Metadata);
        using var document=JsonDocument.Parse(metadata);
        Guid id=intent.Purpose=="reset"?document.RootElement.GetProperty("resetId").GetGuid():Guid.NewGuid();
        var item = new ProtectedDelivery(id, intent.AccountId, intent.AccountStamp, intent.Purpose,
            intent.ProofHash, expires, metadata,
            _settings.ActiveKeyVersion, RandomNumberGenerator.GetBytes(12), [], []);
        byte[] plain = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(intent.Payload);
        byte[] key = Convert.FromBase64String(_settings.EncryptionKeys[item.KeyVersion]);
        try
        {
            byte[] cipher = new byte[plain.Length], tag = new byte[16];
            using var aes = new AesGcm(key,16); aes.Encrypt(item.Nonce,plain,cipher,tag,Binding(item));
            return item with { Ciphertext=cipher, Tag=tag, Companion=intent.Companion is null ? null : ProtectAt(intent.Companion, expires) };
        }
        finally { CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(key); }
    }
    public DeliveryPayload Open(ProtectedDelivery item)
    {
        byte[] key = Convert.FromBase64String(_settings.EncryptionKeys[item.KeyVersion]);
        byte[] plain = new byte[item.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key,16); aes.Decrypt(item.Nonce,item.Ciphertext,item.Tag,plain,Binding(item));
            return System.Text.Json.JsonSerializer.Deserialize<DeliveryPayload>(plain) ?? throw new CryptographicException("Invalid delivery envelope");
        }
        finally { CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(key); }
    }
}
