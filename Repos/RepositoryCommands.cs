using System.Data;

using Npgsql;

namespace treehammock.Repos;

internal static class RepositoryCommands
{
    internal static NpgsqlCommand CreateFunctionCommand(
        string functionName,
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        params string[] parameterNames)
    {
        return new NpgsqlCommand(BuildFunctionSelect(functionName, parameterNames), connection, transaction)
        {
            CommandType = CommandType.Text
        };
    }

    internal static string BuildFunctionSelect(string functionName, params string[] parameterNames)
    {
        ValidateIdentifier(functionName, nameof(functionName));

        string arguments = string.Join(", ", parameterNames.Select(parameterName =>
        {
            ValidateIdentifier(parameterName, nameof(parameterNames));
            return $"@{parameterName}";
        }));

        return $"select * from {functionName}({arguments});";
    }

    private static void ValidateIdentifier(string value, string argumentName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Repository function identifiers cannot be blank.", argumentName);
        }

        foreach (char character in value)
        {
            bool valid = character is '_' || char.IsAsciiLetterOrDigit(character);
            if (!valid)
            {
                throw new ArgumentException($"Repository function identifier '{value}' contains an invalid character.", argumentName);
            }
        }
    }
}
