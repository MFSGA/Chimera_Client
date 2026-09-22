use std::io;

use rand::RngExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRange {
    pub min: u64,
    pub max: u64,
}

impl ValueRange {
    pub fn parse(raw: &str, field: &str) -> io::Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("xhttp {field} must not be empty"),
            ));
        }

        let parse = |value: &str| {
            value.trim().parse::<u64>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid xhttp {field} '{raw}': {err}"),
                )
            })
        };

        let (min, max) = if let Some((min, max)) = raw.split_once('-') {
            (parse(min)?, parse(max)?)
        } else {
            let value = parse(raw)?;
            (value, value)
        };

        if min > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid xhttp {field} range: {raw}"),
            ));
        }

        Ok(Self { min, max })
    }

    fn sample(self) -> u64 {
        if self.min >= self.max {
            self.min
        } else {
            rand::rng().random_range(self.min..=self.max)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReuseLimits {
    pub max_concurrency: u64,
    pub c_max_reuse_times: u64,
    pub h_max_request_times: u64,
    pub h_max_reusable_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReusePolicy {
    pub max_concurrency: Option<ValueRange>,
    pub max_connections: Option<ValueRange>,
    pub c_max_reuse_times: Option<ValueRange>,
    pub h_max_request_times: Option<ValueRange>,
    pub h_max_reusable_secs: Option<ValueRange>,
    pub h_keep_alive_period: i64,
}

impl ReusePolicy {
    pub fn validate(&self) -> io::Result<()> {
        if self.max_concurrency.is_some() && self.max_connections.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xhttp reuse-settings max-concurrency conflicts with max-connections",
            ));
        }

        Ok(())
    }

    pub fn sample_max_connections(&self) -> Option<u64> {
        self.max_connections.map(ValueRange::sample)
    }

    pub fn sample_limits(&self) -> ReuseLimits {
        ReuseLimits {
            max_concurrency: self
                .max_concurrency
                .map(ValueRange::sample)
                .unwrap_or(0),
            c_max_reuse_times: self
                .c_max_reuse_times
                .map(ValueRange::sample)
                .unwrap_or(0),
            h_max_request_times: self
                .h_max_request_times
                .map(ValueRange::sample)
                .unwrap_or(0),
            h_max_reusable_secs: self
                .h_max_reusable_secs
                .map(ValueRange::sample)
                .unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_range_parses_single_and_range_values() {
        assert_eq!(
            ValueRange::parse("16", "max-concurrency").unwrap(),
            ValueRange { min: 16, max: 16 }
        );
        assert_eq!(
            ValueRange::parse("16-32", "max-concurrency").unwrap(),
            ValueRange { min: 16, max: 32 }
        );
    }

    #[test]
    fn value_range_preserves_zero_as_unlimited() {
        let range = ValueRange::parse("0", "c-max-reuse-times").unwrap();
        assert_eq!(range, ValueRange { min: 0, max: 0 });
    }

    #[test]
    fn value_range_rejects_reversed_range() {
        let err = ValueRange::parse("32-16", "max-concurrency")
            .expect_err("reversed range must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn policy_rejects_concurrency_and_connection_limits_together() {
        let policy = ReusePolicy {
            max_concurrency: Some(ValueRange { min: 16, max: 16 }),
            max_connections: Some(ValueRange { min: 4, max: 4 }),
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: 0,
        };

        let err = policy.validate().expect_err("conflicting limits must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn max_connections_is_sampled_once_from_its_range() {
        let policy = ReusePolicy {
            max_concurrency: None,
            max_connections: Some(ValueRange { min: 2, max: 4 }),
            c_max_reuse_times: None,
            h_max_request_times: None,
            h_max_reusable_secs: None,
            h_keep_alive_period: 0,
        };

        let sampled = policy
            .sample_max_connections()
            .expect("max-connections should be present");
        assert!((2..=4).contains(&sampled));
    }

    #[test]
    fn sampled_limits_stay_within_configured_ranges() {
        let policy = ReusePolicy {
            max_concurrency: Some(ValueRange { min: 16, max: 32 }),
            max_connections: None,
            c_max_reuse_times: Some(ValueRange { min: 4, max: 8 }),
            h_max_request_times: Some(ValueRange { min: 600, max: 900 }),
            h_max_reusable_secs: Some(ValueRange {
                min: 1800,
                max: 3000,
            }),
            h_keep_alive_period: 0,
        };

        let limits = policy.sample_limits();
        assert!((16..=32).contains(&limits.max_concurrency));
        assert!((4..=8).contains(&limits.c_max_reuse_times));
        assert!((600..=900).contains(&limits.h_max_request_times));
        assert!((1800..=3000).contains(&limits.h_max_reusable_secs));
    }

    #[test]
    fn keep_alive_period_allows_negative_disable_value() {
        let policy = ReusePolicy {
            max_concurrency: Some(ValueRange { min: 16, max: 16 }),
            max_connections: None,
            c_max_reuse_times: Some(ValueRange { min: 0, max: 0 }),
            h_max_request_times: Some(ValueRange { min: 600, max: 900 }),
            h_max_reusable_secs: Some(ValueRange {
                min: 1800,
                max: 3000,
            }),
            h_keep_alive_period: -1,
        };

        policy.validate().unwrap();
        assert_eq!(policy.h_keep_alive_period, -1);
    }
}
