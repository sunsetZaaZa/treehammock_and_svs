namespace treehammock.RiggingSupport.Enum;

public enum Compression
{
    NONE = 0,
    LZMA = 1,
    FASTLZMA = 2,
    BROTLI = 3,
    ZSTD = 4,
    LIZARD = 5
}

public enum DayDuration
{
    DAILY = 1,
    WEEKLY = 2,
    BIWEEKLY = 3,
    MONTHFIRST = 4,
    MONTHLAST = 5,
    MONTHLY = 6,
    QUARTERYEAR = 7,
    SEMIYEAR = 8,
    TRIQUARTERYEAR = 9,
    YEAR = 10,
    INDEFINITE = 11
}

public enum DurationRepeat
{
    NONE = 0,
    TERM = 1 // Repeat the approved calendar term, bounded by maxCycles and authorizedEnd.
}

