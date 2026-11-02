using Npgsql;

namespace treehammock.Rigging.Database.Migrations;

public static class DatabaseMigrationCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        string schema = "public";
        string connectionEnvironment = "TREEHAMMOCK_MIGRATION_CONNECTION";
        bool maintenance = false, adopt = false;
        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--schema": schema = args[++i]; break;
                    case "--connection-env": connectionEnvironment = args[++i]; break;
                    case "--maintenance-confirmed": maintenance = true; break;
                    case "--adopt-baseline": adopt = true; break;
                    default: throw new ArgumentException("Unknown migration argument.");
                }
            }
            if (!maintenance) throw new ArgumentException("Migration requires --maintenance-confirmed after draining application writes.");
            string? connection = Environment.GetEnvironmentVariable(connectionEnvironment);
            if (string.IsNullOrWhiteSpace(connection)) throw new ArgumentException("Migration connection environment variable is missing.");
            using var cancel = new CancellationTokenSource();
            ConsoleCancelEventHandler interrupt = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += interrupt;
            try
            {
                var result = await DatabaseMigrationRunner.ApplyAsync(connection, schema, adopt, cancel.Token);
                Console.WriteLine($"Migrations committed: applied={result.Applied}; adoptedLegacy={result.AdoptedLegacy}.");
                return 0;
            }
            finally { Console.CancelKeyPress -= interrupt; }
        }
        catch (Exception error)
        {
            // Never emit connection strings, SQL, provider messages or parameter values.
            string state = error is PostgresException postgres ? postgres.SqlState : "none";
            Console.Error.WriteLine($"Migration failed: type={error.GetType().Name}; sqlState={state}. Inspect migration history before retrying.");
            return 1;
        }
    }
}
