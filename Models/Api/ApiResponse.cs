using System.Diagnostics.CodeAnalysis;

namespace treehammock.Models.Api;

public sealed class ApiResponse<T>
{
    [SetsRequiredMembers]
    public ApiResponse(bool success, int statusCode, string code, T? data = default, IReadOnlyList<ApiValidationError>? errors = null)
    {
        this.success = success;
        this.statusCode = statusCode;
        this.code = code;
        this.data = data;
        this.errors = errors;
    }

    public required bool success { get; set; }
    public required int statusCode { get; set; }
    public required string code { get; set; }
    public T? data { get; set; }
    public IReadOnlyList<ApiValidationError>? errors { get; set; }

    public static ApiResponse<T> Success(int statusCode, string code, T data)
    {
        return new ApiResponse<T>(true, statusCode, code, data);
    }

    public static ApiResponse<T> Failure(int statusCode, string code, T? data = default, IReadOnlyList<ApiValidationError>? errors = null)
    {
        return new ApiResponse<T>(false, statusCode, code, data, errors);
    }
}

public sealed class ApiValidationError
{
    [SetsRequiredMembers]
    public ApiValidationError(string field, IReadOnlyList<string> messages)
    {
        this.field = field;
        this.messages = messages;
    }

    public required string field { get; set; }
    public required IReadOnlyList<string> messages { get; set; }
}
