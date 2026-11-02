using NodaTime;
using treehammock.RiggingSupport.Enum;
namespace treehammock.Services;

// All boundaries are computed from the original UTC anchor, avoiding repeated month-end drift.
public static class CalendarTermCalculator
{
    public static bool Supported(DayDuration term) => term is DayDuration.DAILY or DayDuration.WEEKLY or
        DayDuration.BIWEEKLY or DayDuration.MONTHLY or DayDuration.QUARTERYEAR or DayDuration.SEMIYEAR or
        DayDuration.TRIQUARTERYEAR or DayDuration.YEAR or DayDuration.INDEFINITE;
    public static Instant? Boundary(Instant start, DayDuration term, int cycle)
    {
        if (!Supported(term) || cycle is < 0 or > 1000) throw new ArgumentOutOfRangeException(nameof(cycle));
        if (start.InUtc().Year is < 1 or > 9999) throw new ArgumentOutOfRangeException(nameof(start));
        if (cycle == 0) return start;
        if (term == DayDuration.INDEFINITE) return null;
        var local = start.InUtc().LocalDateTime;
        local = term switch
        {
            DayDuration.DAILY => local.PlusDays(cycle),
            DayDuration.WEEKLY => local.PlusDays(checked(7 * cycle)),
            DayDuration.BIWEEKLY => local.PlusDays(checked(14 * cycle)),
            DayDuration.MONTHLY => local.PlusMonths(cycle),
            DayDuration.QUARTERYEAR => local.PlusMonths(checked(3 * cycle)),
            DayDuration.SEMIYEAR => local.PlusMonths(checked(6 * cycle)),
            DayDuration.TRIQUARTERYEAR => local.PlusMonths(checked(9 * cycle)),
            DayDuration.YEAR => local.PlusMonths(checked(12 * cycle)),
            _ => throw new ArgumentOutOfRangeException(nameof(term))
        };
        if (local.Year is < 1 or > 9999) throw new ArgumentOutOfRangeException(nameof(start));
        return DateTimeZone.Utc.AtStrictly(local).ToInstant();
    }
    public static int CycleAt(Instant start, DayDuration term, int maxCycles, Instant? until, Instant now)
    {
        if (maxCycles is < 1 or > 1000 || !Supported(term) || term == DayDuration.INDEFINITE && maxCycles != 1)
            throw new ArgumentOutOfRangeException(nameof(maxCycles));
        var total = Boundary(start, term, maxCycles);
        if (now < start || until is not null && now >= until.Value || total is not null && now >= total.Value) return 0;
        if (term == DayDuration.INDEFINITE) return 1;
        int low = 1, high = maxCycles;
        while (low < high)
        {
            int middle = (low + high) / 2;
            if (now < Boundary(start, term, middle)!.Value) high = middle; else low = middle + 1;
        }
        return low;
    }
}
