//! Calendar time to Unix time, for reading the firmware's clock.
//!
//! Proleptic Gregorian calendar, UTC, no leap seconds (a `:60` second is
//! read as `:59`, as Unix time has no place for it). The day count is
//! Howard Hinnant's `days_from_civil`.

#![no_std]
#![forbid(unsafe_code)]

/// A calendar date and time of day, as a real-time clock reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u8) -> u8 {
    match m {
        2 if leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to `y-m-d`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl Civil {
    /// Seconds since the Unix epoch, or `None` if a field is out of range
    /// (years 1970..=9999).
    pub fn unix_seconds(&self) -> Option<u64> {
        let y = i64::from(self.year);
        if !(1970..=9999).contains(&y)
            || !(1..=12).contains(&self.month)
            || self.day == 0
            || self.day > days_in_month(y, self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 60
        {
            return None;
        }
        let days = days_from_civil(y, i64::from(self.month), i64::from(self.day));
        let secs = days * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second.min(59));
        u64::try_from(secs).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<u64> {
        Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
        .unix_seconds()
    }

    #[test]
    fn known_instants() {
        assert_eq!(t(1970, 1, 1, 0, 0, 0), Some(0));
        assert_eq!(t(1999, 12, 31, 23, 59, 59), Some(946_684_799));
        assert_eq!(t(2000, 3, 1, 0, 0, 0), Some(951_868_800));
        assert_eq!(t(2024, 2, 29, 12, 34, 56), Some(1_709_210_096));
        assert_eq!(t(2026, 11, 15, 9, 30, 0), Some(1_794_735_000));
    }

    #[test]
    fn rejects_impossible_dates() {
        assert_eq!(t(2023, 2, 29, 0, 0, 0), None);
        assert_eq!(t(2100, 2, 29, 0, 0, 0), None);
        assert_eq!(t(2024, 4, 31, 0, 0, 0), None);
        assert_eq!(t(2024, 13, 1, 0, 0, 0), None);
        assert_eq!(t(2024, 1, 1, 24, 0, 0), None);
        assert_eq!(t(1969, 12, 31, 0, 0, 0), None);
        assert_eq!(t(2024, 0, 1, 0, 0, 0), None);
    }

    #[test]
    fn leap_second_reads_as_59() {
        assert_eq!(t(2016, 12, 31, 23, 59, 60), t(2016, 12, 31, 23, 59, 59));
    }
}
