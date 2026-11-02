using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using treehammock.Repos;
using treehammock.Rigging.Config;
namespace treehammock.Services;

public sealed record TotpRotationCheckpoint(int Version, string TargetKeyId, Guid? AfterEnrollment, long Reencrypted, long Conflicts, bool Completed);
public static class TotpReencryptionCommand
{
    public static async Task<int> RunAsync(IServiceProvider services, string[] args, CancellationToken ct)
    {
        string? path = null; int batch = 50, maximumBatches = 100;
        try
        {
            for (int i=0; i<args.Length; i+=2)
            {
                if (i+1>=args.Length) throw new ArgumentException();
                switch(args[i]) { case "--checkpoint": path=args[i+1]; break; case "--batch-size": batch=int.Parse(args[i+1]); break;
                    case "--max-batches": maximumBatches=int.Parse(args[i+1]); break; default: throw new ArgumentException(); }
            }
            if (path is null || !Path.IsPathFullyQualified(path) || batch is < 1 or > 200 || maximumBatches is < 1 or > 10000)
                throw new ArgumentException();
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
        { Console.Error.WriteLine("Use reencrypt-totp --checkpoint /absolute/path.json [--batch-size 1..200] [--max-batches 1..10000]."); return 2; }
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Keep one checkpoint writer per path; independent commands remain safe through SQL CAS.
        await using var checkpointLock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var settings = services.GetRequiredService<IOptions<TotpSettings>>().Value;
        Validator.ValidateObject(settings, new ValidationContext(settings), true);
        var protector = services.GetRequiredService<ITotpSecretProtector>(); var repo = services.GetRequiredService<TotpReencryptionRepo>();
        var checkpoint = File.Exists(path) ? JsonSerializer.Deserialize<TotpRotationCheckpoint>(await File.ReadAllTextAsync(path, ct)) : null;
        if (checkpoint is not null && (checkpoint.Version!=2 || checkpoint.TargetKeyId!=settings.ActiveProtectionKeyId))
            throw new InvalidOperationException("Checkpoint target differs; use a distinct checkpoint for each rotation target.");
        checkpoint ??= new(2, settings.ActiveProtectionKeyId, null, 0, 0, false);
        checkpoint = checkpoint with { Completed=false };
        for (int number=0; number<maximumBatches; number++)
        {
            var rows = await repo.ReadBatchAsync(checkpoint.TargetKeyId, checkpoint.AfterEnrollment, batch, ct);
            if (rows.Count==0)
            {
                // Check all IDs before completion. Conflicts/rolling old writers cannot hide below the cursor.
                if (await repo.RemainingAsync(checkpoint.TargetKeyId, ct)==0)
                {
                    // A resumed command also authenticates already-rotated rows before declaring completion.
                    Guid? cursor = null;
                    while (true)
                    {
                        var verificationRows = await repo.ReadBatchAsync(checkpoint.TargetKeyId, cursor, batch, ct, includeTarget: true);
                        if (verificationRows.Count == 0) break;
                        foreach (var verificationRow in verificationRows)
                        {
                            byte[] decoded = protector.Unprotect(verificationRow.Envelope);
                            CryptographicOperations.ZeroMemory(decoded);
                            cursor = verificationRow.Envelope.Context.EnrollmentId;
                        }
                    }
                    if (await repo.RemainingAsync(checkpoint.TargetKeyId, ct) != 0)
                    { checkpoint = checkpoint with { AfterEnrollment=null }; await Save(path, checkpoint, ct); continue; }
                    checkpoint=checkpoint with { Completed=true, AfterEnrollment=null }; await Save(path, checkpoint, ct); Console.WriteLine("TOTP re-encryption completed; reconcile backups and stop old-key writers before key retirement."); return 0; }
                checkpoint=checkpoint with { AfterEnrollment=null }; await Save(path, checkpoint, ct); continue;
            }
            foreach (var row in rows)
            {
                byte[]? plaintext=null, verified=null, storedPlaintext=null;
                try
                {
                    plaintext=protector.Unprotect(row.Envelope);
                    var replacement=protector.Protect(plaintext, row.Envelope.Context);
                    verified=protector.Unprotect(replacement);
                    if (!CryptographicOperations.FixedTimeEquals(plaintext, verified)) throw new CryptographicException("Rotation verification failed.");
                    bool applied=await repo.CompareExchangeAsync(row,replacement,ct);
                    if (applied)
                    {
                        var stored = await repo.ReadEnrollmentAsync(row.Envelope.Context.EnrollmentId, ct);
                        if (stored is not null)
                        {
                            storedPlaintext = protector.Unprotect(stored.Envelope);
                            if (stored.Envelope.Context != replacement.Context || !CryptographicOperations.FixedTimeEquals(plaintext, storedPlaintext))
                                throw new CryptographicException("Stored rotation verification failed.");
                        }
                    }
                    checkpoint=checkpoint with { AfterEnrollment=row.Envelope.Context.EnrollmentId,
                        Reencrypted=checkpoint.Reencrypted+(applied?1:0), Conflicts=checkpoint.Conflicts+(applied?0:1) };
                    await Save(path,checkpoint,ct);
                }
                finally { if(plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); if(verified is not null) CryptographicOperations.ZeroMemory(verified); if(storedPlaintext is not null) CryptographicOperations.ZeroMemory(storedPlaintext); }
            }
        }
        Console.WriteLine("TOTP re-encryption checkpoint saved; rows remain or concurrent writers require another pass."); return 3;
    }
    private static async Task Save(string path, TotpRotationCheckpoint checkpoint, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); string temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try { await File.WriteAllTextAsync(temporary,JsonSerializer.Serialize(checkpoint)+"\n",ct); File.Move(temporary,path,true); }
        finally { if(File.Exists(temporary)) File.Delete(temporary); }
    }
}
