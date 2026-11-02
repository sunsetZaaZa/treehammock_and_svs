namespace Treehammock.SessionValidation.Storage;
// Same backend discriminant as THS-12C NpgsqlReadonlySnapshot. Foreground SVS
// retains its typed read-only identity adapter and never selects local mode.
public enum SessionAuthorityBackend { Yugabyte, PostgreSqlLocal }
