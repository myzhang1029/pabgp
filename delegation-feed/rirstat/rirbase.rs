//! Base types for Regional Internet Registries

// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

/// Error type for dealing with RIR names
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    #[error("Invalid RIR name")]
    InvalidRirName,
    #[error("Missing RIR name")]
    MissingRirName,
    #[error("Invalid country code")]
    InvalidCountryCode,
    #[error("Missing country code")]
    MissingCountryCode,
}

/// Names of the five Regional Internet Registries
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum RirName {
    Arin,
    Ripencc,
    Apnic,
    Lacnic,
    Afrinic,
}

impl Display for RirName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arin => write!(f, "ARIN"),
            Self::Ripencc => write!(f, "RIPE NCC"),
            Self::Apnic => write!(f, "APNIC"),
            Self::Lacnic => write!(f, "LACNIC"),
            Self::Afrinic => write!(f, "AFRINIC"),
        }
    }
}

impl FromStr for RirName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        match s.as_str() {
            "arin" => Ok(Self::Arin),
            "ripencc" | "ripe" => Ok(Self::Ripencc),
            "apnic" => Ok(Self::Apnic),
            "lacnic" => Ok(Self::Lacnic),
            "afrinic" => Ok(Self::Afrinic),
            _ => Err(Error::InvalidRirName),
        }
    }
}

/// Internet country-level entity
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CountrySpec {
    /// Regional Internet Registry that manages this country's internet numbers
    rir: RirName,
    /// ISO 3166-1 alpha-2 country code
    country_code: [u8; 2],
}

impl CountrySpec {
    /// Create a new country specification
    pub fn new(rir: RirName, country_code: &str) -> Result<Self, Error> {
        if country_code.len() != 2 {
            return Err(Error::InvalidCountryCode);
        }
        let country_code = country_code.to_ascii_uppercase();
        Ok(Self {
            rir,
            country_code: [country_code.as_bytes()[0], country_code.as_bytes()[1]],
        })
    }

    // Mainly for maps which require a reference
    #[allow(clippy::trivially_copy_pass_by_ref)]
    /// Get the RIR that manages this country's internet numbers
    pub fn rir(&self) -> RirName {
        self.rir
    }
}

impl Display for CountrySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.rir,
            std::str::from_utf8(&self.country_code).unwrap()
        )
    }
}

impl FromStr for CountrySpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let rir_name = parts.next().ok_or(Error::MissingRirName)?;
        let country_code = parts
            .next()
            .ok_or(Error::MissingCountryCode)?
            .to_ascii_uppercase();
        if country_code.len() != 2 {
            return Err(Error::InvalidCountryCode);
        }
        let country_code = country_code.as_bytes();
        Ok(Self {
            rir: rir_name.parse()?,
            country_code: [country_code[0], country_code[1]],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rir_name_from_str() {
        assert_eq!("arin".parse(), Ok(RirName::Arin));
        assert_eq!("ripencc".parse(), Ok(RirName::Ripencc));
        assert_eq!("APNIC".parse(), Ok(RirName::Apnic));
        assert_eq!("LACNIC".parse(), Ok(RirName::Lacnic));
        assert_eq!("AFRINIC".parse(), Ok(RirName::Afrinic));
        assert_eq!("".parse::<RirName>(), Err(Error::InvalidRirName));
        assert_eq!("invalid".parse::<RirName>(), Err(Error::InvalidRirName));
    }

    #[test]
    fn test_country_spec_from_str() {
        assert_eq!(
            "arin:US".parse(),
            Ok(CountrySpec {
                rir: RirName::Arin,
                country_code: *b"US"
            })
        );
        assert_eq!(
            "ripencc:GB".parse(),
            Ok(CountrySpec {
                rir: RirName::Ripencc,
                country_code: *b"GB"
            })
        );
        assert!("".parse::<CountrySpec>().is_err());
        assert!("arin".parse::<CountrySpec>().is_err());
        assert!(":US".parse::<CountrySpec>().is_err());
        assert!("arin:".parse::<CountrySpec>().is_err());
    }
}
