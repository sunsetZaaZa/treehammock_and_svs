namespace treehammock.RiggingSupport.Status;

/// <summary>
/// Transitional status values used by legacy request/response models that have not
/// yet been migrated to the main HttpMessage response model.
/// </summary>
public enum Pass
{
    NONE = 0,
    SUCCESSFUL = 1,
    FAILED = 2,
    INVALID = 3,
    UNAUTHORIZED = 4,
    NOT_FOUND = 5
}

/// <summary>
/// Transitional HTTP-style outcome values used by legacy account models.
/// Keep these small and generic until the API response shape is normalized.
/// </summary>
public enum HttpOutcome
{
    NONE = 0,
    SUCCESSFUL = 1,
    FAILED = 2,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    CONFLICT = 409
}
